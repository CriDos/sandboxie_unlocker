/*
 * sbieapi.h - talking to SbieDrv through Sandboxie's own SbieDll
 *
 * SbieDrv validates the certificate in DriverEntry and whenever it is
 * asked with SBIE_CONF_FLAG_RELOAD_CERT; a plain license query only reads
 * the cached state.  After the kernel key has been swapped the cache is
 * still the one from driver load time (validated against the original
 * key), so the unlock stays half-applied until the service is restarted
 * or SandMan is started twice.  Asking for the reload is what Sandboxie
 * itself does (About dialog, service startup).
 *
 * The calls go through the installed SbieDll.dll, so the API numbering
 * and the calling convention always match the installed driver instead of
 * being hardcoded here.
 */
#ifndef SBIEAPI_H
#define SBIEAPI_H

#include <windows.h>
#include "log.h"

#define SBIE_CONF_FLAG_RELOAD_CERT 0x80000000UL
#define SBIE_FEATURE_FLAG_CERTIFIED 0x80000000UL

/* Session id Sandboxie's About dialog uses for a global reload. */
#define SBIE_RELOAD_SESSION_ID ((ULONG) - 1)

typedef LONG(WINAPI *fn_SbieApi_ReloadConf)(ULONG session_id, ULONG flags);
typedef LONG(WINAPI *fn_SbieApi_QueryDrvInfo)(ULONG info_class, void *info_data, ULONG info_size);

/* Load SbieDll.dll from the Sandboxie directory and resolve one export.
 * The module is left loaded: unloading it could undo hooking it does for
 * a host process.  Returns NULL (with a log line) when unavailable. */
static void *sbie_dll_proc(const char *sbie_dir, const char *name)
{
    /* Loaded once: LoadLibraryEx bumps the refcount on every call and the
     * module is never freed on purpose (see above).  One attempt only, so
     * a machine without Sandboxie does not retry and re-log per call. */
    static HMODULE dll = NULL;
    static BOOL tried = FALSE;
    if (!dll && !tried) {
        tried = TRUE;
        char path[MAX_PATH];
        strcpy_s(path, MAX_PATH, sbie_dir);
        strcat_s(path, MAX_PATH, "\\SbieDll.dll");

        dll = LoadLibraryExA(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!dll) LOGW("sbieapi: %s not loadable: %lu", path, GetLastError());
    }
    if (!dll) return NULL;

    void *fn = (void *)GetProcAddress(dll, name);
    if (!fn) LOGW("sbieapi: SbieDll.dll has no %s export", name);
    return fn;
}

/* Ask the driver to re-read Certificate.dat.  Returns 0 when accepted;
 * every failure is only a warning - the kernel key swap itself is done. */
static int sbie_reload_certificate(const char *sbie_dir)
{
    fn_SbieApi_ReloadConf reload =
        (fn_SbieApi_ReloadConf)sbie_dll_proc(sbie_dir, "SbieApi_ReloadConf");
    if (!reload) return 1;

    LONG status = reload(SBIE_RELOAD_SESSION_ID, SBIE_CONF_FLAG_RELOAD_CERT);
    if (status) {
        LOGW("sbieapi: certificate reload returned 0x%lX", (ULONG)status);
        return 2;
    }
    return 0;
}

/* Log whether the driver now considers the certificate valid - this is
 * the state the UI and the feature gates read.  Best effort. */
static void sbie_log_cert_state(const char *sbie_dir)
{
    fn_SbieApi_QueryDrvInfo query =
        (fn_SbieApi_QueryDrvInfo)sbie_dll_proc(sbie_dir, "SbieApi_QueryDrvInfo");
    if (!query) return;

    ULONG flags = 0;
    LONG status = query(0, &flags, sizeof(flags));
    if (status) {
        LOGW("sbieapi: driver info query returned 0x%lX", (ULONG)status);
        return;
    }
    LOGI("Driver feature flags 0x%lX: certificate %s", flags,
         (flags & SBIE_FEATURE_FLAG_CERTIFIED) ? "active" : "NOT active");
}

#endif /* SBIEAPI_H */
