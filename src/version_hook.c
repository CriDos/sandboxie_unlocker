/*
 * version_hook.c - DLL proxy for version.dll with full kernel unlock
 *
 * When placed next to SandMan.exe as version.dll, Windows loads this DLL
 * before SandMan initializes.  A background thread:
 *   1. Writes the embedded driver to %WINDIR%\Temp\sbie_unlock_<pid>.sys
 *      (restrictive DACL: SYSTEM + Administrators only)
 *   2. Loads the driver as a service for kernel R/W
 *   3. Finds SbieDrv.sys base in kernel and key RVA from PE on disk
 *   4. Generates an ECDSA P-256 keypair (or reuses saved one)
 *   5. Overwrites the public key in kernel memory
 *   6. Generates Certificate.dat signed with our key
 *   7. Re-signs all .exe.sig files
 *
 * All 17 version.dll exports are forwarded to the real System32 version.dll
 * via lazy-resolved function pointers.  No external files needed.
 *
 * Author:  HardTest
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
/* C6553 fires inside winreg.h's SAL on every RegOpenKeyExA(..., 0, ...) -
 * it is SDK-header noise, reported at the header line, so suppress it
 * globally before the includes. */
#pragma warning(disable: 6553)
#include <windows.h>
#include <winreg.h>
#include "version.h"
#include "log.h"

/* ------------------------------------------------------------------ */
/*  Real version.dll loaded from System32                             */
/* ------------------------------------------------------------------ */

static HMODULE g_realVersion = NULL;

static void load_real_version(void)
{
    wchar_t sysPath[MAX_PATH];
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, MAX_PATH, L"\\version.dll");
    g_realVersion = LoadLibraryExW(sysPath, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!g_realVersion)
        LOGE("Failed to load real version.dll: %lu", GetLastError());
}

/* ------------------------------------------------------------------ */
/*  Export wrappers - correct signatures, forward to real version.dll */
/* ------------------------------------------------------------------ */

typedef BOOL   (WINAPI *fn_GetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL   (WINAPI *fn_GetFileVersionInfoW)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef BOOL   (WINAPI *fn_GetFileVersionInfoExA)(DWORD, LPCSTR, BOOL, DWORD, LPVOID);
typedef BOOL   (WINAPI *fn_GetFileVersionInfoExW)(DWORD, LPCWSTR, BOOL, DWORD, LPVOID);
typedef DWORD  (WINAPI *fn_GetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
typedef DWORD  (WINAPI *fn_GetFileVersionInfoSizeW)(LPCWSTR, LPDWORD);
typedef DWORD  (WINAPI *fn_GetFileVersionInfoSizeExA)(DWORD, LPCSTR, LPDWORD);
typedef DWORD  (WINAPI *fn_GetFileVersionInfoSizeExW)(DWORD, LPCWSTR, LPDWORD);
typedef BOOL   (WINAPI *fn_GetFileVersionInfoByHandle)(DWORD, HANDLE, LPVOID);
typedef DWORD  (WINAPI *fn_VerFindFileA)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
typedef DWORD  (WINAPI *fn_VerFindFileW)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
typedef DWORD  (WINAPI *fn_VerInstallFileA)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
typedef DWORD  (WINAPI *fn_VerInstallFileW)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
typedef DWORD  (WINAPI *fn_VerLanguageNameA)(DWORD, LPSTR, DWORD);
typedef DWORD  (WINAPI *fn_VerLanguageNameW)(DWORD, LPWSTR, DWORD);
typedef BOOL   (WINAPI *fn_VerQueryValueA)(LPCVOID, LPCSTR, LPVOID *, PUINT);
typedef BOOL   (WINAPI *fn_VerQueryValueW)(LPCVOID, LPCWSTR, LPVOID *, PUINT);

#define RESOLVE(name, fn_type) \
    static fn_type real_##name = NULL; \
    if (!real_##name && g_realVersion) \
        real_##name = (fn_type)GetProcAddress(g_realVersion, #name)

__pragma(comment(linker, "/export:GetFileVersionInfoA=my_GetFileVersionInfoA"))
BOOL WINAPI my_GetFileVersionInfoA(LPCSTR a, DWORD b, DWORD c, LPVOID d) {
    RESOLVE(GetFileVersionInfoA, fn_GetFileVersionInfoA);
    if (real_GetFileVersionInfoA) return real_GetFileVersionInfoA(a, b, c, d);
    return FALSE;
}

__pragma(comment(linker, "/export:GetFileVersionInfoW=my_GetFileVersionInfoW"))
BOOL WINAPI my_GetFileVersionInfoW(LPCWSTR a, DWORD b, DWORD c, LPVOID d) {
    RESOLVE(GetFileVersionInfoW, fn_GetFileVersionInfoW);
    if (real_GetFileVersionInfoW) return real_GetFileVersionInfoW(a, b, c, d);
    return FALSE;
}

__pragma(comment(linker, "/export:GetFileVersionInfoExA=my_GetFileVersionInfoExA"))
BOOL WINAPI my_GetFileVersionInfoExA(DWORD a, LPCSTR b, BOOL c, DWORD d, LPVOID e) {
    RESOLVE(GetFileVersionInfoExA, fn_GetFileVersionInfoExA);
    if (real_GetFileVersionInfoExA) return real_GetFileVersionInfoExA(a, b, c, d, e);
    return FALSE;
}

__pragma(comment(linker, "/export:GetFileVersionInfoExW=my_GetFileVersionInfoExW"))
BOOL WINAPI my_GetFileVersionInfoExW(DWORD a, LPCWSTR b, BOOL c, DWORD d, LPVOID e) {
    RESOLVE(GetFileVersionInfoExW, fn_GetFileVersionInfoExW);
    if (real_GetFileVersionInfoExW) return real_GetFileVersionInfoExW(a, b, c, d, e);
    return FALSE;
}

__pragma(comment(linker, "/export:GetFileVersionInfoSizeA=my_GetFileVersionInfoSizeA"))
DWORD WINAPI my_GetFileVersionInfoSizeA(LPCSTR a, LPDWORD b) {
    RESOLVE(GetFileVersionInfoSizeA, fn_GetFileVersionInfoSizeA);
    if (real_GetFileVersionInfoSizeA) return real_GetFileVersionInfoSizeA(a, b);
    return 0;
}

__pragma(comment(linker, "/export:GetFileVersionInfoSizeW=my_GetFileVersionInfoSizeW"))
DWORD WINAPI my_GetFileVersionInfoSizeW(LPCWSTR a, LPDWORD b) {
    RESOLVE(GetFileVersionInfoSizeW, fn_GetFileVersionInfoSizeW);
    if (real_GetFileVersionInfoSizeW) return real_GetFileVersionInfoSizeW(a, b);
    return 0;
}

__pragma(comment(linker, "/export:GetFileVersionInfoSizeExA=my_GetFileVersionInfoSizeExA"))
DWORD WINAPI my_GetFileVersionInfoSizeExA(DWORD a, LPCSTR b, LPDWORD c) {
    RESOLVE(GetFileVersionInfoSizeExA, fn_GetFileVersionInfoSizeExA);
    if (real_GetFileVersionInfoSizeExA) return real_GetFileVersionInfoSizeExA(a, b, c);
    return 0;
}

__pragma(comment(linker, "/export:GetFileVersionInfoSizeExW=my_GetFileVersionInfoSizeExW"))
DWORD WINAPI my_GetFileVersionInfoSizeExW(DWORD a, LPCWSTR b, LPDWORD c) {
    RESOLVE(GetFileVersionInfoSizeExW, fn_GetFileVersionInfoSizeExW);
    if (real_GetFileVersionInfoSizeExW) return real_GetFileVersionInfoSizeExW(a, b, c);
    return 0;
}

__pragma(comment(linker, "/export:GetFileVersionInfoByHandle=my_GetFileVersionInfoByHandle"))
BOOL WINAPI my_GetFileVersionInfoByHandle(DWORD a, HANDLE b, LPVOID c) {
    RESOLVE(GetFileVersionInfoByHandle, fn_GetFileVersionInfoByHandle);
    if (real_GetFileVersionInfoByHandle) return real_GetFileVersionInfoByHandle(a, b, c);
    return FALSE;
}

__pragma(comment(linker, "/export:VerFindFileA=my_VerFindFileA"))
DWORD WINAPI my_VerFindFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPSTR e, PUINT f, LPSTR g, PUINT h) {
    RESOLVE(VerFindFileA, fn_VerFindFileA);
    if (real_VerFindFileA) return real_VerFindFileA(a, b, c, d, e, f, g, h);
    return 0;
}

__pragma(comment(linker, "/export:VerFindFileW=my_VerFindFileW"))
DWORD WINAPI my_VerFindFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPWSTR e, PUINT f, LPWSTR g, PUINT h) {
    RESOLVE(VerFindFileW, fn_VerFindFileW);
    if (real_VerFindFileW) return real_VerFindFileW(a, b, c, d, e, f, g, h);
    return 0;
}

__pragma(comment(linker, "/export:VerInstallFileA=my_VerInstallFileA"))
DWORD WINAPI my_VerInstallFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPCSTR e, LPCSTR f, LPSTR g, PUINT h) {
    RESOLVE(VerInstallFileA, fn_VerInstallFileA);
    if (real_VerInstallFileA) return real_VerInstallFileA(a, b, c, d, e, f, g, h);
    return 0;
}

__pragma(comment(linker, "/export:VerInstallFileW=my_VerInstallFileW"))
DWORD WINAPI my_VerInstallFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR e, LPCWSTR f, LPWSTR g, PUINT h) {
    RESOLVE(VerInstallFileW, fn_VerInstallFileW);
    if (real_VerInstallFileW) return real_VerInstallFileW(a, b, c, d, e, f, g, h);
    return 0;
}

__pragma(comment(linker, "/export:VerLanguageNameA=my_VerLanguageNameA"))
DWORD WINAPI my_VerLanguageNameA(DWORD a, LPSTR b, DWORD c) {
    RESOLVE(VerLanguageNameA, fn_VerLanguageNameA);
    if (real_VerLanguageNameA) return real_VerLanguageNameA(a, b, c);
    return 0;
}

__pragma(comment(linker, "/export:VerLanguageNameW=my_VerLanguageNameW"))
DWORD WINAPI my_VerLanguageNameW(DWORD a, LPWSTR b, DWORD c) {
    RESOLVE(VerLanguageNameW, fn_VerLanguageNameW);
    if (real_VerLanguageNameW) return real_VerLanguageNameW(a, b, c);
    return 0;
}

__pragma(comment(linker, "/export:VerQueryValueA=my_VerQueryValueA"))
BOOL WINAPI my_VerQueryValueA(LPCVOID a, LPCSTR b, LPVOID *c, PUINT d) {
    RESOLVE(VerQueryValueA, fn_VerQueryValueA);
    if (real_VerQueryValueA) return real_VerQueryValueA(a, b, c, d);
    return FALSE;
}

__pragma(comment(linker, "/export:VerQueryValueW=my_VerQueryValueW"))
BOOL WINAPI my_VerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID *c, PUINT d) {
    RESOLVE(VerQueryValueW, fn_VerQueryValueW);
    if (real_VerQueryValueW) return real_VerQueryValueW(a, b, c, d);
    return FALSE;
}

#undef RESOLVE

/* ------------------------------------------------------------------ */
/*  Unlock modules                                                    */
/* ------------------------------------------------------------------ */

#include "driver_bin.h"
#include "ecrypto.h"
#include "kdrv.h"
#include "kmod.h"
#include "pesearch.h"
#include "certgen.h"
#include "sysguard.h"

/* ------------------------------------------------------------------ */
/*  Crash safety - prevents BSOD boot loops                            */
/*                                                                    */
/*  HKCU stores an active attempt marker and a failure counter.        */
/*  If a previous process died while attempt_active=1, the next run    */
/*  increments fail_count. Controlled errors clear attempt_active and  */
/*  do not count as crashes. Successful unlock resets both values.     */
/*                                                                    */
/*  After CRASH_LIMIT interrupted attempts, the DLL enters safe mode   */
/*  and acts as a transparent proxy until the user resets the key.     */
/* ------------------------------------------------------------------ */

#define SAFETY_REGKEY          "SOFTWARE\\sandboxie_unlocker"
#define SAFETY_REG_FAIL_COUNT  "fail_count"
#define SAFETY_REG_ACTIVE      "attempt_active"
#define CRASH_LIMIT            3

/* Unlock error codes, in step order. */
enum {
    ERR_SBIEDRV_MISSING = 1,  /* SbieDrv.sys not found next to the DLL    */
    ERR_STAGE,                /* helper driver staging failed             */
    ERR_NOT_IN_KERNEL,        /* SbieDrv not in kernel module list        */
    ERR_KEY_RVA,              /* ECS1 key not found in SbieDrv.sys on disk */
    ERR_KDRV_LOAD,            /* helper driver load failed                */
    ERR_READ_KEY,             /* kernel read at key VA failed             */
    ERR_BAD_MAGIC,            /* no ECS1 magic at key VA                  */
    ERR_KEYGEN,               /* keypair generation failed                */
    ERR_EXPORT,               /* public blob export failed                */
    ERR_WRITE_KEY,            /* kernel write at key VA failed            */
    ERR_VERIFY,               /* write verification failed                */
    ERR_CERT,                 /* Certificate.dat write failed             */
};

static volatile LONG g_safety_attempt_owned = 0;

static DWORD safety_read_dword(const char *name, DWORD def)
{
    HKEY hKey;
    DWORD result = def;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, SAFETY_REGKEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0, type = 0, sz = sizeof(val);
        if (RegQueryValueExA(hKey, name, NULL, &type, (LPBYTE)&val, &sz) == ERROR_SUCCESS &&
            type == REG_DWORD && sz == sizeof(val))
            result = val;
        RegCloseKey(hKey);
    }
    return result;
}

static void safety_write_dword(const char *name, DWORD val)
{
    HKEY hKey;
    DWORD disp = 0;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, SAFETY_REGKEY, 0, NULL, 0,
                        KEY_WRITE, NULL, &hKey, &disp) == ERROR_SUCCESS) {
        LONG st = RegSetValueExA(hKey, name, 0, REG_DWORD, (LPBYTE)&val, sizeof(val));
        if (st != ERROR_SUCCESS)
            LOGW("Safe-fail registry write failed: %s err=%ld", name, st);
        RegCloseKey(hKey);
    } else {
        LOGW("Safe-fail registry key open failed: %s", SAFETY_REGKEY);
    }
}

static BOOL safety_begin_attempt(void)
{
    DWORD failures = safety_read_dword(SAFETY_REG_FAIL_COUNT, 0);
    DWORD active = safety_read_dword(SAFETY_REG_ACTIVE, 0);

    if (active) {
        failures++;
        safety_write_dword(SAFETY_REG_FAIL_COUNT, failures);
        safety_write_dword(SAFETY_REG_ACTIVE, 0);
        LOGW("Previous unlock attempt was interrupted; fail count=%lu", failures);
    }

    if (failures >= CRASH_LIMIT) {
        LOGW("SAFE MODE: fail count=%lu >= %d, skipping unlock", failures, CRASH_LIMIT);
        LOGW("Reset via unlock.bat or delete HKCU\\%s", SAFETY_REGKEY);
        return FALSE;
    }

    InterlockedExchange(&g_safety_attempt_owned, 1);
    safety_write_dword(SAFETY_REG_ACTIVE, 1);
    LOGI("Unlock attempt started (fail count=%lu)", failures);
    return TRUE;
}

static void safety_finish_success(void)
{
    safety_write_dword(SAFETY_REG_FAIL_COUNT, 0);
    safety_write_dword(SAFETY_REG_ACTIVE, 0);
    InterlockedExchange(&g_safety_attempt_owned, 0);
    LOGI("Safe-fail state reset after successful unlock");
}

static void safety_finish_failure(void)
{
    safety_write_dword(SAFETY_REG_ACTIVE, 0);
    InterlockedExchange(&g_safety_attempt_owned, 0);
    LOGI("Unlock attempt ended with a controlled failure");
}

static void safety_clear_active_attempt(void)
{
    safety_write_dword(SAFETY_REG_ACTIVE, 0);
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static void get_self_dir(char *out, ULONG cap)
{
    out[0] = 0;
    HMODULE hSelf = GetModuleHandleA("version.dll");
    GetModuleFileNameA(hSelf, out, cap);
    char *p = strrchr(out, '\\');
    if (p) *p = 0;
}

/* Remove sbie_unlock_*.sys leftovers from previous runs.  Files still
 * image-mapped in the kernel or open by a concurrent instance are
 * skipped - they are picked up again on a later run after reboot.
 *
 * Deletion is done by opening with DELETE access and share mode 0:
 * the open fails for any file that is currently held (staging writer,
 * kernel image section), which makes the delete atomic and race-free
 * even across sessions.  Files younger than REUSE_GRACE_SEC are left
 * alone too - they may belong to an instance that staged them but has
 * not loaded them yet. */
#define REUSE_GRACE_SEC 30

static void cleanup_stale_temp_drivers(const char *tempDir)
{
    char pattern[MAX_PATH];
    strcpy_s(pattern, MAX_PATH, tempDir);
    strcat_s(pattern, MAX_PATH, "\\sbie_unlock_*.sys");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);

    static const ULONG64 TICKS_PER_SEC = 10000000;

    UINT removed = 0, locked = 0;
    do {
        char p[MAX_PATH];
        strcpy_s(p, MAX_PATH, tempDir);
        strcat_s(p, MAX_PATH, "\\");
        strcat_s(p, MAX_PATH, fd.cFileName);

        ULONG64 now64 = ((ULONG64)nowFt.dwHighDateTime << 32) | nowFt.dwLowDateTime;
        ULONG64 file64 = ((ULONG64)fd.ftLastWriteTime.dwHighDateTime << 32) |
                          fd.ftLastWriteTime.dwLowDateTime;
        ULONG64 ageSec = (now64 > file64) ? (now64 - file64) / TICKS_PER_SEC : 0;
        if (ageSec < REUSE_GRACE_SEC) {
            locked++;
            continue;
        }

        HANDLE h = CreateFileA(p, DELETE, 0, NULL, OPEN_EXISTING,
                               FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            removed++;
        } else {
            locked++;
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    LOGI("Stale temp drivers: removed %u, locked %u", removed, locked);
}

/* Write the embedded driver to a temp file with a restrictive DACL and
 * verify it on disk.  Returns TRUE and leaves the path in *path. */
static BOOL write_driver_temp(const char *path)
{
    /* SD and ACL must live in THIS frame: sa points into them and
     * CreateFileA below consumes them while they are alive. */
    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    BYTE aclBuf[512];   /* plenty: 2 ACEs need ~52 bytes */
    if (!build_restrictive_sa(&sa, &sd, (PACL)aclBuf, (DWORD)sizeof(aclBuf))) {
        LOGE("Failed to build restrictive DACL: %lu", GetLastError());
        return FALSE;
    }

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, &sa,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOGE("CreateFile (temp driver) failed: %lu path=%s", GetLastError(), path);
        return FALSE;
    }

    DWORD written;
    BOOL ok = WriteFile(hFile, g_driver_bin, g_driver_size, &written, NULL);
    CloseHandle(hFile);
    if (!ok || written != g_driver_size) {
        LOGE("WriteFile failed: ok=%d written=%lu expected=%lu", ok, written, g_driver_size);
        return FALSE;
    }
    if (!kdrv_verify_driver_file(path)) {
        LOGE("Post-write driver verification failed: %s", path);
        return FALSE;
    }
    LOGI("Driver written to %s (%lu bytes, ACL: SYSTEM+Administrators)", path, written);
    return TRUE;
}

/* Write the embedded driver (C byte array) to
 * %WINDIR%\Temp\sbie_unlock_<pid>.sys with a restrictive DACL and return
 * its path in outPath.  The pid-unique name avoids clashes with a
 * previous instance whose driver is still image-mapped in the kernel
 * (the mapped image locks the file until reboot). */
static BOOL extract_driver(char *outPath, ULONG pathCap)
{
    char winDir[MAX_PATH];
    DWORD winLen = GetWindowsDirectoryA(winDir, MAX_PATH);
    if (!winLen || winLen >= MAX_PATH) {
        LOGE("GetWindowsDirectoryA failed: %lu", GetLastError());
        return FALSE;
    }

    char tempDir[MAX_PATH];
    strcpy_s(tempDir, MAX_PATH, winDir);
    strcat_s(tempDir, MAX_PATH, "\\Temp");
    if (GetFileAttributesA(tempDir) == INVALID_FILE_ATTRIBUTES)
        CreateDirectoryA(tempDir, NULL);

    if (GetFileAttributesA(tempDir) == INVALID_FILE_ATTRIBUTES) {
        LOGE("Temp dir not usable: %s", tempDir);
        return FALSE;
    }

    cleanup_stale_temp_drivers(tempDir);

    char tempPath[MAX_PATH];
    wsprintfA(tempPath, "%s\\sbie_unlock_%lu.sys", tempDir, GetCurrentProcessId());
    if (write_driver_temp(tempPath)) {
        strcpy_s(outPath, pathCap, tempPath);
        return TRUE;
    }

    /* PID recycled + a previous run's driver from the same-named file is
     * still image-mapped: the file is locked by the kernel image section.
     * If the existing content is ours, reuse it. */
    if (kdrv_verify_driver_file(tempPath)) {
        LOGI("Temp driver locked by live instance, content verified - reusing");
        strcpy_s(outPath, pathCap, tempPath);
        return TRUE;
    }

    LOGE("Driver staging failed: %s", tempPath);
    return FALSE;
}

/* Steps 6-8 of the unlock: ensure a usable keypair (reuse the saved one
 * when the kernel is already patched, else generate), write its public
 * blob over the kernel key, and verify the write.  Returns 0 on success,
 * an ERR_* code on failure.  On failure *kp is left fully freed. */
static int patch_kernel_key(kdrv_t *drv, ULONG64 keyVa, BOOL alreadyPatched,
                            const char *keypairPath, ec_keypair_t *kp)
{
    if (alreadyPatched && ec_load_keypair(kp, keypairPath) == 0) {
        LOGI("Reusing saved keypair from keypair.dat");
    } else {
        if (alreadyPatched)
            LOGW("Keypair load failed (keypair.dat missing/corrupt?) - generating a fresh one");
        LOGI("Generating new ECDSA P-256 keypair");
        if (ec_gen_keypair(kp) != 0) {
            LOGE("ec_gen_keypair failed");
            return ERR_KEYGEN;
        }
        if (ec_save_keypair(kp, keypairPath) != 0) {
            LOGW("keypair.dat write failed - keypair will not survive a reboot");
        } else {
            LOGI("Keypair saved to keypair.dat");
        }
    }

    BYTE newBlob[BLOB_SIZE];
    if (ec_export_pub_blob(kp, newBlob) != 0) {
        LOGE("ec_export_pub_blob failed");
        return ERR_EXPORT;
    }
    LOGI("New public key blob generated (%d bytes)", BLOB_SIZE);

    if (kdrv_write(drv, keyVa, newBlob, BLOB_SIZE) != 0) {
        LOGE("kdrv_write failed at key VA");
        return ERR_WRITE_KEY;
    }
    LOGI("Public key written to kernel memory");

    BYTE verifyKey[BLOB_SIZE];
    if (kdrv_read(drv, keyVa, verifyKey, BLOB_SIZE) != 0 ||
        memcmp(verifyKey, newBlob, BLOB_SIZE) != 0) {
        LOGE("Write verification failed");
        return ERR_VERIFY;
    }
    LOGI("Write verified");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Main unlock thread                                                */
/* ------------------------------------------------------------------ */

static DWORD WINAPI unlock_thread(LPVOID param)
{
    (void)param;
    char sbieDir[MAX_PATH];
    char sbieDrvPath[MAX_PATH];
    char keypairPath[MAX_PATH];
    char backupDir[MAX_PATH];
    int err = 0;
    kdrv_t drv = {0};
    ec_keypair_t kp = {0};
    BOOL kp_valid = FALSE;
    BOOL attempt_started = FALSE;
    HANDLE hMutex = NULL;
    BOOL mutex_owned = FALSE;

    get_self_dir(sbieDir, MAX_PATH);
    log_init();

    LOGI("Sandboxie-Plus Unlocker v%s by %s", SBIE_UNLOCKER_VERSION, SBIE_UNLOCKER_AUTHOR);

    /* Diagnostic snapshot of driver-load blockers / interferers. Runs
     * before mutex and safe-mode checks so it is logged even when the
     * unlock itself is skipped. */
    sysguard_log_state();

    hMutex = CreateMutexA(NULL, FALSE, "Local\\sandboxie_unlocker_unlock");
    if (hMutex) {
        DWORD wait = WaitForSingleObject(hMutex, 0);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) {
            mutex_owned = TRUE;
        } else {
            LOGW("Another unlock attempt is already running, skipping");
            CloseHandle(hMutex);
            return 0;
        }
    } else {
        LOGW("CreateMutex failed: %lu", GetLastError());
        return 0;
    }

    if (!safety_begin_attempt()) {
        if (mutex_owned) ReleaseMutex(hMutex);
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }
    attempt_started = TRUE;

    strcpy_s(sbieDrvPath, MAX_PATH, sbieDir);
    strcat_s(sbieDrvPath, MAX_PATH, "\\SbieDrv.sys");
    if (GetFileAttributesA(sbieDrvPath) == INVALID_FILE_ATTRIBUTES) {
        LOGE("SbieDrv.sys not found in %s", sbieDir);
        err = ERR_SBIEDRV_MISSING;
        goto cleanup;
    }
    LOGI("SbieDir: %s", sbieDir);

    /* 1. Write driver to staging path (temp file) */
    char driverPath[MAX_PATH];
    if (!extract_driver(driverPath, MAX_PATH)) { err = ERR_STAGE; goto cleanup; }

    /* 2. Find SbieDrv.sys base in kernel (retry - driver may not be loaded yet) */
    ULONG imgSize = 0;
    ULONG64 sbieBase = 0;
    for (int attempt = 0; attempt < 60; attempt++) {
        sbieBase = kmod_find("sbiedrv", &imgSize);
        if (sbieBase) break;
        LOGW("SbieDrv.sys not in kernel yet, retry %d/60...", attempt + 1);
        Sleep(1000);
    }
    if (!sbieBase) { LOGE("SbieDrv.sys not found in kernel after 60 retries"); err = ERR_NOT_IN_KERNEL; goto cleanup; }
    LOGI("SbieDrv.sys kernel base: 0x%llX size: 0x%X", sbieBase, imgSize);

    /* 3. Find key RVA from PE on disk */
    ULONG keyRva = pe_find_key_rva(sbieDrvPath);
    if (!keyRva) { LOGE("ECDSA key not found in SbieDrv.sys on disk"); err = ERR_KEY_RVA; goto cleanup; }
    ULONG64 keyVa = sbieBase + keyRva;
    LOGI("Key RVA: 0x%X, kernel VA: 0x%llX", keyRva, keyVa);

    /* 4. Load kernel driver for R/W */
    int load_err = kdrv_load(&drv, driverPath);
    if (load_err != 0) { LOGE("kdrv_load failed: %d", load_err); err = ERR_KDRV_LOAD; goto cleanup; }
    LOGI("Kernel driver loaded");

    /* 5. Read & validate current key */
    BYTE currentKey[BLOB_SIZE];
    if (kdrv_read(&drv, keyVa, currentKey, BLOB_SIZE) != 0) {
        LOGE("kdrv_read failed at key VA");
        err = ERR_READ_KEY;
        goto cleanup;
    }
    if (currentKey[0] != 'E' || currentKey[1] != 'C' ||
        currentKey[2] != 'S' || currentKey[3] != '1') {
        LOGE("No ECS1 magic at key VA");
        err = ERR_BAD_MAGIC;
        goto cleanup;
    }
    BOOL alreadyPatched = (memcmp(currentKey, ORIGINAL_KEY, BLOB_SIZE) != 0);
    LOGI("Current key: %s", alreadyPatched ? "already patched" : "original");

    /* 6-8. Keypair + kernel patch + verify */
    strcpy_s(keypairPath, MAX_PATH, sbieDir);
    strcat_s(keypairPath, MAX_PATH, "\\keypair.dat");
    err = patch_kernel_key(&drv, keyVa, alreadyPatched, keypairPath, &kp);
    if (err) { ec_free_keypair(&kp); goto cleanup; }
    kp_valid = TRUE;

    /* 9. Unload driver (close handles only) */
    kdrv_unload(&drv);
    LOGI("Kernel driver unloaded");

    /* 10. Backup & re-sign .sig files */
    strcpy_s(backupDir, MAX_PATH, sbieDir);
    strcat_s(backupDir, MAX_PATH, "\\sig_backup");
    cert_backup_sigs(sbieDir, backupDir);
    LOGI(".sig backup done");

    /* 11. Write Certificate.dat.  A missing cert after a kernel patch means
     * SandMan still enforces the kill-timer - do NOT report success. */
    if (cert_write(sbieDir, &kp) != 0) {
        LOGE("cert_write failed");
        err = ERR_CERT;
        goto cleanup;
    }
    LOGI("Certificate.dat written");

    /* 12. Re-sign all .exe.sig files */
    LOGI("Re-signed %d .sig files", cert_resign_all(sbieDir, &kp));

    LOGI("Unlock complete!");
    safety_finish_success();
    attempt_started = FALSE;

cleanup:
    if (kp_valid) ec_free_keypair(&kp);
    /* Unload driver if still loaded (gotos from steps 5-8) */
    if (drv.hDev || drv.hSvc || drv.hScm) kdrv_unload(&drv);
    if (attempt_started) safety_finish_failure();
    if (mutex_owned) ReleaseMutex(hMutex);
    if (hMutex) CloseHandle(hMutex);
    if (err) LOGE("unlock failed: code %d", err);
    return err;
}

/* ------------------------------------------------------------------ */
/*  DllMain                                                           */
/* ------------------------------------------------------------------ */

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        load_real_version();
        HANDLE hThread = CreateThread(NULL, 0, unlock_thread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        /* DllMain(DLL_PROCESS_DETACH) is called on normal process exit
         * (ExitProcess) with reserved != NULL, and on explicit FreeLibrary
         * with reserved == NULL.  It is NOT called at all when the process
         * is killed via TerminateProcess or on BSOD.
         *
         * Therefore any DLL_PROCESS_DETACH means the current attempt did
         * not die abnormally.  Clear the active marker, but leave fail_count
         * untouched unless unlock_thread completed successfully. */
        if (InterlockedCompareExchange(&g_safety_attempt_owned, 0, 1) == 1)
            safety_clear_active_attempt();
    }
    return TRUE;
}
