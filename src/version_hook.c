/*
 * version_hook.c - DLL proxy for version.dll with full kernel unlock
 *
 * Loaded next to SandMan.exe before it initializes.  A background thread
 * stages the embedded driver (dbutil_2_3.sys) for kernel R/W, replaces
 * the ECDSA public key of SbieDrv.sys in kernel memory, and writes a
 * matching Certificate.dat plus re-signed .exe.sig files.  All 17
 * version.dll exports are forwarded to the real System32 version.dll.
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
#pragma warning(disable : 6553)
#include <windows.h>
#include <string.h>
#include <winreg.h>
#include "version.h"
#include "log.h"
#include "hostguard.h"

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
    if (!g_realVersion) LOGE("Failed to load real version.dll: %lu", GetLastError());
}

/* ------------------------------------------------------------------ */
/*  Export wrappers - correct signatures, forward to real version.dll */
/* ------------------------------------------------------------------ */

typedef BOOL(WINAPI *fn_GetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL(WINAPI *fn_GetFileVersionInfoW)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef BOOL(WINAPI *fn_GetFileVersionInfoExA)(DWORD, LPCSTR, BOOL, DWORD, LPVOID);
typedef BOOL(WINAPI *fn_GetFileVersionInfoExW)(DWORD, LPCWSTR, BOOL, DWORD, LPVOID);
typedef DWORD(WINAPI *fn_GetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
typedef DWORD(WINAPI *fn_GetFileVersionInfoSizeW)(LPCWSTR, LPDWORD);
typedef DWORD(WINAPI *fn_GetFileVersionInfoSizeExA)(DWORD, LPCSTR, LPDWORD);
typedef DWORD(WINAPI *fn_GetFileVersionInfoSizeExW)(DWORD, LPCWSTR, LPDWORD);
typedef BOOL(WINAPI *fn_GetFileVersionInfoByHandle)(DWORD, HANDLE, LPVOID);
typedef DWORD(WINAPI *fn_VerFindFileA)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
typedef DWORD(WINAPI *fn_VerFindFileW)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR,
                                       PUINT);
typedef DWORD(WINAPI *fn_VerInstallFileA)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR,
                                          PUINT);
typedef DWORD(WINAPI *fn_VerInstallFileW)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR,
                                          LPWSTR, PUINT);
typedef DWORD(WINAPI *fn_VerLanguageNameA)(DWORD, LPSTR, DWORD);
typedef DWORD(WINAPI *fn_VerLanguageNameW)(DWORD, LPWSTR, DWORD);
typedef BOOL(WINAPI *fn_VerQueryValueA)(LPCVOID, LPCSTR, LPVOID *, PUINT);
typedef BOOL(WINAPI *fn_VerQueryValueW)(LPCVOID, LPCWSTR, LPVOID *, PUINT);

#define RESOLVE(name, fn_type)                                                          \
    static fn_type real_##name = NULL;                                                  \
    if (!real_##name) {                                                                 \
        /* Retry the load on every unresolved call: a one-shot failure \
         * in DllMain must not leave all exports returning FALSE. */                \
        if (!g_realVersion) load_real_version();                                        \
        if (g_realVersion) real_##name = (fn_type)GetProcAddress(g_realVersion, #name); \
    }

__pragma(comment(linker, "/export:GetFileVersionInfoA=my_GetFileVersionInfoA")) BOOL WINAPI
    my_GetFileVersionInfoA(LPCSTR a, DWORD b, DWORD c, LPVOID d)
{
    RESOLVE(GetFileVersionInfoA, fn_GetFileVersionInfoA);
    if (real_GetFileVersionInfoA) return real_GetFileVersionInfoA(a, b, c, d);
    return FALSE;
}

__pragma(comment(linker, "/export:GetFileVersionInfoW=my_GetFileVersionInfoW")) BOOL WINAPI
    my_GetFileVersionInfoW(LPCWSTR a, DWORD b, DWORD c, LPVOID d)
{
    RESOLVE(GetFileVersionInfoW, fn_GetFileVersionInfoW);
    if (real_GetFileVersionInfoW) return real_GetFileVersionInfoW(a, b, c, d);
    return FALSE;
}

__pragma(comment(linker, "/export:GetFileVersionInfoExA=my_GetFileVersionInfoExA")) BOOL WINAPI
    my_GetFileVersionInfoExA(DWORD a, LPCSTR b, BOOL c, DWORD d, LPVOID e)
{
    RESOLVE(GetFileVersionInfoExA, fn_GetFileVersionInfoExA);
    if (real_GetFileVersionInfoExA) return real_GetFileVersionInfoExA(a, b, c, d, e);
    return FALSE;
}

__pragma(comment(linker, "/export:GetFileVersionInfoExW=my_GetFileVersionInfoExW")) BOOL WINAPI
    my_GetFileVersionInfoExW(DWORD a, LPCWSTR b, BOOL c, DWORD d, LPVOID e)
{
    RESOLVE(GetFileVersionInfoExW, fn_GetFileVersionInfoExW);
    if (real_GetFileVersionInfoExW) return real_GetFileVersionInfoExW(a, b, c, d, e);
    return FALSE;
}

__pragma(comment(linker, "/export:GetFileVersionInfoSizeA=my_GetFileVersionInfoSizeA")) DWORD WINAPI
    my_GetFileVersionInfoSizeA(LPCSTR a, LPDWORD b)
{
    RESOLVE(GetFileVersionInfoSizeA, fn_GetFileVersionInfoSizeA);
    if (real_GetFileVersionInfoSizeA) return real_GetFileVersionInfoSizeA(a, b);
    return 0;
}

__pragma(comment(linker, "/export:GetFileVersionInfoSizeW=my_GetFileVersionInfoSizeW")) DWORD WINAPI
    my_GetFileVersionInfoSizeW(LPCWSTR a, LPDWORD b)
{
    RESOLVE(GetFileVersionInfoSizeW, fn_GetFileVersionInfoSizeW);
    if (real_GetFileVersionInfoSizeW) return real_GetFileVersionInfoSizeW(a, b);
    return 0;
}

__pragma(comment(linker,
                 "/export:GetFileVersionInfoSizeExA=my_GetFileVersionInfoSizeExA")) DWORD WINAPI
    my_GetFileVersionInfoSizeExA(DWORD a, LPCSTR b, LPDWORD c)
{
    RESOLVE(GetFileVersionInfoSizeExA, fn_GetFileVersionInfoSizeExA);
    if (real_GetFileVersionInfoSizeExA) return real_GetFileVersionInfoSizeExA(a, b, c);
    return 0;
}

__pragma(comment(linker,
                 "/export:GetFileVersionInfoSizeExW=my_GetFileVersionInfoSizeExW")) DWORD WINAPI
    my_GetFileVersionInfoSizeExW(DWORD a, LPCWSTR b, LPDWORD c)
{
    RESOLVE(GetFileVersionInfoSizeExW, fn_GetFileVersionInfoSizeExW);
    if (real_GetFileVersionInfoSizeExW) return real_GetFileVersionInfoSizeExW(a, b, c);
    return 0;
}

__pragma(comment(linker,
                 "/export:GetFileVersionInfoByHandle=my_GetFileVersionInfoByHandle")) BOOL WINAPI
    my_GetFileVersionInfoByHandle(DWORD a, HANDLE b, LPVOID c)
{
    RESOLVE(GetFileVersionInfoByHandle, fn_GetFileVersionInfoByHandle);
    if (real_GetFileVersionInfoByHandle) return real_GetFileVersionInfoByHandle(a, b, c);
    return FALSE;
}

__pragma(comment(linker, "/export:VerFindFileA=my_VerFindFileA")) DWORD WINAPI
    my_VerFindFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPSTR e, PUINT f, LPSTR g, PUINT h)
{
    RESOLVE(VerFindFileA, fn_VerFindFileA);
    if (real_VerFindFileA) return real_VerFindFileA(a, b, c, d, e, f, g, h);
    return 0;
}

__pragma(comment(linker, "/export:VerFindFileW=my_VerFindFileW")) DWORD WINAPI
    my_VerFindFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPWSTR e, PUINT f, LPWSTR g, PUINT h)
{
    RESOLVE(VerFindFileW, fn_VerFindFileW);
    if (real_VerFindFileW) return real_VerFindFileW(a, b, c, d, e, f, g, h);
    return 0;
}

__pragma(comment(linker, "/export:VerInstallFileA=my_VerInstallFileA")) DWORD WINAPI
    my_VerInstallFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPCSTR e, LPCSTR f, LPSTR g, PUINT h)
{
    RESOLVE(VerInstallFileA, fn_VerInstallFileA);
    if (real_VerInstallFileA) return real_VerInstallFileA(a, b, c, d, e, f, g, h);
    return 0;
}

__pragma(comment(linker, "/export:VerInstallFileW=my_VerInstallFileW")) DWORD WINAPI
    my_VerInstallFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR e, LPCWSTR f, LPWSTR g,
                       PUINT h)
{
    RESOLVE(VerInstallFileW, fn_VerInstallFileW);
    if (real_VerInstallFileW) return real_VerInstallFileW(a, b, c, d, e, f, g, h);
    return 0;
}

__pragma(comment(linker, "/export:VerLanguageNameA=my_VerLanguageNameA")) DWORD WINAPI
    my_VerLanguageNameA(DWORD a, LPSTR b, DWORD c)
{
    RESOLVE(VerLanguageNameA, fn_VerLanguageNameA);
    if (real_VerLanguageNameA) return real_VerLanguageNameA(a, b, c);
    return 0;
}

__pragma(comment(linker, "/export:VerLanguageNameW=my_VerLanguageNameW")) DWORD WINAPI
    my_VerLanguageNameW(DWORD a, LPWSTR b, DWORD c)
{
    RESOLVE(VerLanguageNameW, fn_VerLanguageNameW);
    if (real_VerLanguageNameW) return real_VerLanguageNameW(a, b, c);
    return 0;
}

__pragma(comment(linker, "/export:VerQueryValueA=my_VerQueryValueA")) BOOL WINAPI
    my_VerQueryValueA(LPCVOID a, LPCSTR b, LPVOID *c, PUINT d)
{
    RESOLVE(VerQueryValueA, fn_VerQueryValueA);
    if (real_VerQueryValueA) return real_VerQueryValueA(a, b, c, d);
    return FALSE;
}

__pragma(comment(linker, "/export:VerQueryValueW=my_VerQueryValueW")) BOOL WINAPI
    my_VerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID *c, PUINT d)
{
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
#include "pagemap.h"
#include "kmod.h"
#include "pesearch.h"
#include "certgen.h"
#include "sysguard.h"
#include "safety.h"
#include "sbieapi.h"

/* Unlock error codes, in step order. */
enum {
    ERR_SBIEDRV_MISSING = 1,  /* SbieDrv.sys not found next to the DLL    */
    ERR_STAGE,                /* helper driver staging failed             */
    ERR_NOT_IN_KERNEL,        /* SbieDrv not in kernel module list        */
    ERR_KEY_RVA,              /* ECS1 key not found in SbieDrv.sys on disk */
    ERR_DRIVER_MISMATCH,      /* loaded driver is not the file on disk      */
    ERR_SIGS_NOT_PRESERVABLE, /* vendor .sig gone, removal would need repair */
    ERR_KDRV_LOAD,            /* helper driver load failed                */
    ERR_READ_KEY,             /* kernel read at key VA failed             */
    ERR_BAD_MAGIC,            /* no ECS1 magic at key VA                  */
    ERR_KEYGEN,               /* keypair generation failed                */
    ERR_EXPORT,               /* public blob export failed                */
    ERR_WRITE_KEY,            /* kernel write at key VA failed            */
    ERR_VERIFY,               /* write verification failed                */
    ERR_CERT,                 /* Certificate.dat write failed             */
    ERR_BUSY,                 /* another unlock attempt holds the mutex   */
    ERR_SAFE_MODE,            /* safe-mode lockout, no work done          */
};

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static void get_self_dir(char *out, ULONG cap)
{
    out[0] = 0;
    GetModuleFileNameA(g_self_module, out, cap);
    char *p = strrchr(out, '\\');
    if (p) *p = 0;
}

/* Set once this process has written Certificate.dat, so a failed attempt
 * removes a half-applied file.  A clean exit keeps the certificate: a
 * later SandMan start in the same boot needs it, and the first start
 * after a boot rewrites and reloads it before the UI. */
static BOOL g_cert_written = FALSE;

/* Remove Certificate.dat next to the DLL.  A missing absolute directory
 * would otherwise turn into "\Certificate.dat" (the drive root). */
static void delete_certificate_file(void)
{
    char path[MAX_PATH];
    get_self_dir(path, MAX_PATH);
    if (!path[0] || path[1] != ':') return;
    strcat_s(path, MAX_PATH, "\\Certificate.dat");
    DeleteFileA(path);
}

/* Boot identifier (SystemBootEnvironmentInformation, class 90): a fresh
 * GUID every boot, unaffected by sleep or clock changes.  The class is
 * undocumented and may be missing on older kernels, so the marker also
 * carries the computed boot time as a fallback. */
typedef struct {
    GUID boot_id;        /* zero when the class is unavailable */
    ULONGLONG boot_time; /* FILETIME of the boot, 100 ns */
} UNLOCK_MARK;

typedef struct {
    GUID boot_id;
    ULONG firmware_type;
} SYS_BOOT_ENV;

static BOOL get_boot_id(GUID *id)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    typedef LONG(NTAPI * qsi_fn)(ULONG, PVOID, ULONG, PULONG);
    qsi_fn qsi = ntdll ? (qsi_fn)(void *)GetProcAddress(ntdll, "NtQuerySystemInformation") : NULL;
    if (!qsi) return FALSE;

    BYTE buf[32]; /* the class returns a bigger struct than its GUID */
    memset(buf, 0, sizeof(buf));
    if (qsi(90 /* SystemBootEnvironmentInformation */, buf, sizeof(buf), NULL) < 0) return FALSE;
    memcpy(id, buf, sizeof(*id));
    return TRUE;
}

/* Wall-clock time of the boot, derived from the monotonic uptime.  Only
 * a fallback: a clock adjustment can make it drift, which costs one
 * extra elevation (never a wrong skip when the GUID is available). */
static ULONGLONG get_boot_time(void)
{
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    ULONGLONG now100 = ((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime;
    ULONGLONG up100 = GetTickCount64() * 10000ULL;
    return now100 > up100 ? now100 - up100 : 0;
}

/* Written after a successful unlock that the driver reloaded.  Its mere
 * presence is not enough: the boot identity must match this boot, so a
 * marker left by the previous boot asks for elevation again. */
static void mark_unlocked(const char *sbie_dir)
{
    UNLOCK_MARK mark;
    memset(&mark, 0, sizeof(mark));
    get_boot_id(&mark.boot_id);
    mark.boot_time = get_boot_time();

    char path[MAX_PATH];
    _snprintf_s(path, MAX_PATH, _TRUNCATE, "%s\\unlock.boot", sbie_dir);
    HANDLE hFile =
        CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(hFile, &mark, sizeof(mark), &written, NULL);
    CloseHandle(hFile);
}

/* Was the driver patched and the certificate reloaded in this boot?  A
 * missing marker, a marker from another boot, or a missing certificate
 * all mean "ask for elevation again". */
static BOOL unlocked_this_boot(const char *sbie_dir)
{
    char cert[MAX_PATH];
    _snprintf_s(cert, MAX_PATH, _TRUNCATE, "%s\\Certificate.dat", sbie_dir);
    if (GetFileAttributesA(cert) == INVALID_FILE_ATTRIBUTES) return FALSE;

    char path[MAX_PATH];
    _snprintf_s(path, MAX_PATH, _TRUNCATE, "%s\\unlock.boot", sbie_dir);
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    UNLOCK_MARK mark;
    DWORD got = 0;
    BOOL have_mark = ReadFile(hFile, &mark, sizeof(mark), &got, NULL) && got == sizeof(mark);
    CloseHandle(hFile);
    if (!have_mark) return FALSE;

    GUID current = {0};
    GUID zero = {0};
    if (get_boot_id(&current) && memcmp(&mark.boot_id, &zero, sizeof(GUID)) != 0)
        return memcmp(&mark.boot_id, &current, sizeof(GUID)) == 0;

    ULONGLONG now = get_boot_time();
    if (!mark.boot_time || !now) return FALSE;
    ULONGLONG diff = now > mark.boot_time ? now - mark.boot_time : mark.boot_time - now;
    return diff <= 10ULL * 1000 * 10000; /* 10 s */
}

/* SandMan.exe is asInvoker: started by a double-click it runs unelevated and
 * the hook cannot write the install directory, load the helper driver or
 * touch the kernel - it stays a transparent proxy.  Log that instead of
 * failing silently. */
static BOOL is_elevated(void)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return FALSE;
    TOKEN_ELEVATION te = {0};
    DWORD size = 0;
    BOOL elevated =
        GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &size) && te.TokenIsElevated;
    CloseHandle(hToken);
    return elevated;
}

/* Write the embedded driver to a temp file with a restrictive DACL and
 * verify it on disk.  Returns TRUE and leaves the path in *path. */
static BOOL write_driver_temp(const char *path)
{
    /* SD and ACL must live in THIS frame: sa points into them and
     * CreateFileA below consumes them while they are alive. */
    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    BYTE aclBuf[512]; /* plenty: 2 ACEs need ~52 bytes */
    if (!build_restrictive_sa(&sa, &sd, (PACL)aclBuf, (DWORD)sizeof(aclBuf))) {
        LOGE("Failed to build restrictive DACL: %lu", GetLastError());
        return FALSE;
    }

    /* CREATE_ALWAYS keeps the existing file's DACL - delete first
     * (same quirk as ec_save_keypair). */
    DeleteFileA(path);

    HANDLE hFile =
        CreateFileA(path, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOGE("CreateFile (temp driver) failed: %lu path=%s", GetLastError(), path);
        return FALSE;
    }

    DWORD written = 0;
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

/* Stage the embedded driver to %WINDIR%\Temp\sbie_unlock_<pid>.sys and
 * return its path.  The pid-unique name avoids clashes with a previous
 * instance whose mapped image still locks its staging file. */
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
    if (GetFileAttributesA(tempDir) == INVALID_FILE_ATTRIBUTES) CreateDirectoryA(tempDir, NULL);

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
 * an ERR_* code on failure.  On failure *kp is left in a state safe for
 * one ec_free_keypair call by the caller (the caller owns the free).
 * key_writable says whether the key's section is writable in the file on
 * disk (SbieDrv >= 1.18.7 keeps it read-only in .rdata - those pages are
 * written through a page alias). */
static int patch_kernel_key(kdrv_t *drv, ULONG64 keyVa, BOOL alreadyPatched,
                            const char *keypairPath, BOOL key_writable, ec_keypair_t *kp)
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

    /* Direct write when the key's section is writable in the file on disk
     * (SbieDrv <= 1.18.6), an alias write for the read-only .rdata of
     * 1.18.7+ - see pagemap.h.  The file is assumed to describe the loaded
     * image; a gross mismatch is caught earlier by the image-size and ECS1
     * checks, and the alias path re-reads the live PTE anyway. */
    int wr = key_writable ? kdrv_write(drv, keyVa, newBlob, BLOB_SIZE)
                          : kdrv_page_write(drv, keyVa, newBlob, BLOB_SIZE);
    if (wr != 0) {
        LOGE("key write failed at key VA 0x%llX (%s section, code %d)", keyVa,
             key_writable ? "writable" : "read-only", wr);
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
/*  Cross-attempt serialization                                       */
/* ------------------------------------------------------------------ */

/* One unlock at a time, across sessions too: the boot fast path and the
 * background thread must never run concurrently with another host's
 * attempt (fast user switching puts each SandMan in its own session). */
static HANDLE unlock_mutex_acquire(void)
{
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\sandboxie_unlocker_unlock");
    if (!hMutex) {
        LOGW("CreateMutex failed: %lu", GetLastError());
        return NULL;
    }
    DWORD wait = WaitForSingleObject(hMutex, 0);
    if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) return hMutex;
    LOGW("Another unlock attempt is already running, skipping");
    CloseHandle(hMutex);
    return NULL;
}

static void unlock_mutex_release(HANDLE hMutex)
{
    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }
}

/* ------------------------------------------------------------------ */
/*  Boot fast path (runs from DllMain, before SandMan initializes)    */
/* ------------------------------------------------------------------ */

/* The key RVA comes from SbieDrv.sys on disk, so the mapped module must be
 * that exact build: an installer that replaced the file without a reboot
 * leaves the old image in memory, where the key sits at a different RVA -
 * writing 72 bytes there corrupts whatever lives at that address.  The
 * loader maps the PE headers unchanged, so SizeOfImage and TimeDateStamp of
 * the mapped headers identify the build on their own. */
static BOOL driver_matches_file(kdrv_t *drv, ULONG64 base, const char *path)
{
    ULONG fileSize = 0, fileTs = 0;
    if (!pe_image_identity(path, &fileSize, &fileTs)) {
        LOGE("driver identity: cannot read PE headers of %s", path);
        return FALSE;
    }

    IMAGE_DOS_HEADER dos;
    if (kdrv_read(drv, base, &dos, sizeof(dos)) != 0 || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        LOGE("driver identity: no MZ at the loaded base 0x%llX", base);
        return FALSE;
    }
    if (dos.e_lfanew < 0 || (ULONG64)dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) > 0x1000) {
        LOGE("driver identity: e_lfanew 0x%lX outside the first page", dos.e_lfanew);
        return FALSE;
    }

    IMAGE_NT_HEADERS64 nt;
    if (kdrv_read(drv, base + (ULONG)dos.e_lfanew, &nt, sizeof(nt)) != 0 ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        LOGE("driver identity: no PE signature at the loaded base 0x%llX", base);
        return FALSE;
    }

    if (nt.OptionalHeader.SizeOfImage != fileSize || nt.FileHeader.TimeDateStamp != fileTs) {
        LOGE("driver identity mismatch: loaded ts=0x%lX size=0x%lX, file ts=0x%lX size=0x%lX",
             nt.FileHeader.TimeDateStamp, nt.OptionalHeader.SizeOfImage, fileTs, fileSize);
        LOGW("The installed SbieDrv.sys is not the running driver - reboot (or restart SbieSvc) "
             "and start SandMan again");
        return FALSE;
    }
    return TRUE;
}

/* Locate the ECDSA key in the loaded SbieDrv image and read its current
 * blob: find the module (the boot fast path gives the driver a few seconds,
 * the thread a minute), load the helper driver, check that the mapped image
 * is the file on disk, then read and validate the key.  Both unlock paths
 * share these steps; what differs between them is the policy around them.
 * Returns 0 or an ERR_* code; *drv is left for the caller to unload. */
static int locate_and_read_key(kdrv_t *drv, const char *tag, const char *helper_path,
                               const char *drv_path, int tries, ULONG64 *key_va, BOOL *writable,
                               BYTE *current)
{
    ULONG64 base = 0;
    for (int attempt = 0; attempt < tries; attempt++) {
        base = kmod_find("SbieDrv.sys");
        if (base) break;
        /* One line per second would bury the rest of the log. */
        if (attempt < 2 || attempt % 10 == 9)
            LOGW("%s: SbieDrv.sys not in kernel yet, retry %d/%d...", tag, attempt + 1, tries);
        Sleep(1000);
    }
    if (!base) {
        LOGE("%s: SbieDrv.sys not found in kernel after %d retries", tag, tries);
        return ERR_NOT_IN_KERNEL;
    }
    LOGI("%s: SbieDrv.sys kernel base: 0x%llX", tag, base);

    ULONG keyRva = pe_find_key_rva_ex(drv_path, writable);
    if (!keyRva) {
        LOGE("%s: ECDSA key not found in %s", tag, drv_path);
        return ERR_KEY_RVA;
    }
    LOGI("%s: key section %s", tag, *writable ? "writable" : "read-only (.rdata)");

    /* The file's own image size bounds the RVA; whether that file is the
     * loaded build is checked against the mapped headers below. */
    ULONG fileSize = 0;
    if (!pe_image_identity(drv_path, &fileSize, NULL) || (ULONG64)keyRva + BLOB_SIZE > fileSize) {
        LOGE("%s: key RVA 0x%X outside the file image (0x%X) - version mismatch", tag, keyRva,
             fileSize);
        return ERR_KEY_RVA;
    }
    *key_va = base + keyRva;
    LOGI("%s: key RVA 0x%X, kernel VA: 0x%llX", tag, keyRva, *key_va);

    if (kdrv_load(drv, helper_path) != 0) return ERR_KDRV_LOAD;
    if (!driver_matches_file(drv, base, drv_path)) return ERR_DRIVER_MISMATCH;

    if (kdrv_read(drv, *key_va, current, BLOB_SIZE) != 0) {
        LOGE("%s: kdrv_read failed at key VA 0x%llX", tag, *key_va);
        return ERR_READ_KEY;
    }
    if (current[0] != 'E' || current[1] != 'C' || current[2] != 'S' || current[3] != '1') {
        LOGE("%s: no ECS1 magic at key VA 0x%llX", tag, *key_va);
        return ERR_BAD_MAGIC;
    }
    return 0;
}

/* On every boot SbieDrv reloads with the vendor key from its file, and
 * it validates two things against that key long before the background
 * thread could have swapped it: Certificate.dat in DriverEntry, and the
 * connecting process's SandMan.exe.sig when SandMan attaches to the
 * driver API.  Both come back 0xC000A000 and SandMan shows its
 * "certificate/signature invalid" dialogs - the state the previous
 * session left on disk no longer matches the fresh kernel.
 *
 * This path runs before any SandMan code: an elevated host re-applies the
 * saved key and signs the files inline; an unelevated one leaves the work
 * to SandMan's own -assist instance, which the first connect starts.  It
 * must not LoadLibrary anything (loader lock): advapi32 is a
 * static import of SandMan, the public point is recovered from keypair.dat
 * without CNG (ec_pub_from_priv_file), and SbieDll stays with the elevated
 * instance and the background thread.  Best effort and bounded: every failure
 * logs and returns, the thread repeats the work when it can. */
#define FAST_SBIEDRV_TRIES 5

static void fast_patch_kernel_key(void)
{
    char sbieDir[MAX_PATH];
    get_self_dir(sbieDir, MAX_PATH);

    if (!is_sandman_process()) return; /* other hosts stay a proxy */

    if (!GetModuleHandleA("advapi32.dll")) {
        LOGW("fast path: advapi32 not loaded - leaving the work to the thread");
        return;
    }
    /* No elevation from here: SandMan itself starts an elevated -assist
     * instance when it finds SbieSvc/SbieDrv stopped, and that instance's
     * fast path does the unlock. */
    if (!is_elevated()) {
        if (unlocked_this_boot(sbieDir))
            LOGI("fast path: unlocked in this boot - nothing to do");
        else
            LOGI("fast path: unelevated - leaving elevation to SandMan's -assist");
        return;
    }
    if (!safety_unlock_allowed()) {
        LOGW("fast path: safe mode - skipped");
        return;
    }
    cert_migrate_backup(sbieDir, ORIGINAL_KEY);

    char sbieDrvPath[MAX_PATH];
    strcpy_s(sbieDrvPath, MAX_PATH, sbieDir);
    strcat_s(sbieDrvPath, MAX_PATH, "\\SbieDrv.sys");
    if (GetFileAttributesA(sbieDrvPath) == INVALID_FILE_ATTRIBUTES) return;

    char keypairPath[MAX_PATH];
    strcpy_s(keypairPath, MAX_PATH, sbieDir);
    strcat_s(keypairPath, MAX_PATH, "\\keypair.dat");
    BYTE pub[BLOB_SIZE];
    if (ec_pub_from_priv_file(keypairPath, pub) != 0) {
        LOGW("fast path: no usable keypair.dat - leaving the work to the thread");
        return;
    }

    HANDLE hMutex = unlock_mutex_acquire();
    if (!hMutex) return;
    BOOL attempt_started = safety_begin_attempt();
    if (!attempt_started) {
        unlock_mutex_release(hMutex);
        return;
    }

    int err = 0;
    kdrv_t drv = {0};

    char driverPath[MAX_PATH];
    if (!extract_driver(driverPath, MAX_PATH)) {
        err = ERR_STAGE;
        goto fast_out;
    }

    ULONG64 keyVa = 0;
    BOOL keyWritable = FALSE;
    BYTE currentKey[BLOB_SIZE];
    err = locate_and_read_key(&drv, "fast path", driverPath, sbieDrvPath, FAST_SBIEDRV_TRIES,
                              &keyVa, &keyWritable, currentKey);
    if (err == ERR_NOT_IN_KERNEL)
        LOGW("fast path: SbieDrv.sys not in kernel - leaving the work to the thread");
    if (err) goto fast_out;

    if (memcmp(currentKey, pub, BLOB_SIZE) == 0) {
        LOGI("fast path: kernel key already ours");
    } else {
        /* Patching the key without a restorable vendor signature would make
         * removal impossible without the installer - refuse instead. */
        if (!cert_vendor_sigs_preserved(sbieDir, ORIGINAL_KEY)) {
            err = ERR_SIGS_NOT_PRESERVABLE;
            goto fast_out;
        }
        int wr = keyWritable ? kdrv_write(&drv, keyVa, pub, BLOB_SIZE)
                             : kdrv_page_write(&drv, keyVa, pub, BLOB_SIZE);
        if (wr != 0) {
            LOGE("fast path: key write failed at 0x%llX (%s section, code %d)", keyVa,
                 keyWritable ? "writable" : "read-only", wr);
            err = ERR_WRITE_KEY;
            goto fast_out;
        }
        BYTE verifyKey[BLOB_SIZE];
        if (kdrv_read(&drv, keyVa, verifyKey, BLOB_SIZE) != 0 ||
            memcmp(verifyKey, pub, BLOB_SIZE) != 0) {
            LOGE("fast path: write verification failed");
            err = ERR_VERIFY;
            goto fast_out;
        }
        LOGI("fast path: kernel key patched before SandMan initialized");
    }

    /* Sign every executable for the key now in the kernel.  A vendor .sig
     * is moved to X.sig.vendor in the same step, so removal is a rename
     * back and no copy policy or marker can get in the way. */
    int unpreserved = 0;
    ec_keypair_t kp = {0};
    if (ec_load_keypair(&kp, keypairPath) == 0) {
        int signedCount = cert_sign_all(sbieDir, &kp, ORIGINAL_KEY, &unpreserved);
        LOGI("fast path: signed %d .sig file(s), vendor copies preserved", signedCount);
        ec_free_keypair(&kp);
    } else {
        LOGW("fast path: keypair.dat unreadable - .sig files left as they are");
    }
    if (unpreserved) LOGW("fast path: %d signature(s) have no vendor copy", unpreserved);

fast_out:
    kdrv_unload(&drv);
    if (err) {
        LOGW("fast path failed (code %d) - the background thread will retry", err);
        safety_finish_failure();
    } else {
        safety_fast_path_done();
    }
    unlock_mutex_release(hMutex);
}

/* ------------------------------------------------------------------ */
/*  Main unlock thread                                                */
/* ------------------------------------------------------------------ */

/* Full unlock: patch the kernel key, write Certificate.dat, re-sign the
 * .sig files and ask the driver to reload.  The background thread runs it
 * in an elevated host; an unelevated host gets the same work from
 * SandMan's elevated -assist instance.  Returns 0 or an ERR_* code. */
static int perform_unlock(const char *tag)
{
    char sbieDir[MAX_PATH];
    char sbieDrvPath[MAX_PATH];
    char keypairPath[MAX_PATH];

    int err = 0;
    kdrv_t drv = {0};
    ec_keypair_t kp = {0};
    BOOL kp_valid = FALSE;
    BOOL attempt_started = FALSE;
    HANDLE hMutex = NULL;

    get_self_dir(sbieDir, MAX_PATH);
    log_init();

    LOGI("Sandboxie-Plus Unlocker v%s by %s (%s)", SBIE_UNLOCKER_VERSION, SBIE_UNLOCKER_AUTHOR,
         tag);

    /* Logged even when the unlock is skipped (before mutex/safe-mode). */
    sysguard_log_state();

    /* Older hook builds kept sig_backup/ - turn the verified entries into
     * shadows before anything can depend on them. */
    cert_migrate_backup(sbieDir, ORIGINAL_KEY);

    hMutex = unlock_mutex_acquire();
    if (!hMutex) return ERR_BUSY;

    if (!safety_begin_attempt()) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return ERR_SAFE_MODE;
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
    if (!extract_driver(driverPath, MAX_PATH)) {
        err = ERR_STAGE;
        goto cleanup;
    }

    /* 2-5. Find the driver and its key, load the helper driver, check the
     * mapped image against the file on disk, read the current key. */
    ULONG64 keyVa = 0;
    BOOL keyWritable = FALSE;
    BYTE currentKey[BLOB_SIZE];
    err = locate_and_read_key(&drv, tag, driverPath, sbieDrvPath, 60, &keyVa, &keyWritable,
                              currentKey);
    if (err == ERR_NOT_IN_KERNEL)
        LOGW("If Sandboxie is installed but its driver will not load, Code Integrity "
             "refused it (SCM 577 / CI event 3004): run the Sandboxie installer once");
    if (err) goto cleanup;
    BOOL alreadyPatched = (memcmp(currentKey, ORIGINAL_KEY, BLOB_SIZE) != 0);
    LOGI("Current key: %s", alreadyPatched ? "already patched" : "original");

    /* 6-8. Keypair + kernel patch + verify */
    /* Removal must be able to put the vendor signatures back: patching a
     * driver whose signatures were already lost makes that impossible. */
    if (!alreadyPatched && !cert_vendor_sigs_preserved(sbieDir, ORIGINAL_KEY)) {
        err = ERR_SIGS_NOT_PRESERVABLE;
        goto cleanup;
    }
    strcpy_s(keypairPath, MAX_PATH, sbieDir);
    strcat_s(keypairPath, MAX_PATH, "\\keypair.dat");
    err = patch_kernel_key(&drv, keyVa, alreadyPatched, keypairPath, keyWritable, &kp);
    if (err) {
        ec_free_keypair(&kp);
        goto cleanup;
    }
    kp_valid = TRUE;

    /* 9. Unload driver (close handles only) */
    kdrv_unload(&drv);
    LOGI("Kernel driver unloaded");

    /* 10. Write Certificate.dat.  A missing cert after a kernel patch means
     * SandMan still enforces the kill-timer - do NOT report success. */
    if (cert_write(sbieDir, &kp) != 0) {
        LOGE("cert_write failed");
        err = ERR_CERT;
        goto cleanup;
    }
    g_cert_written = TRUE;
    LOGI("Certificate.dat written");

    /* 11. Sign every .exe.sig; a vendor one moves to X.sig.vendor first. */
    int unpreserved = 0;
    int signedCount = cert_sign_all(sbieDir, &kp, ORIGINAL_KEY, &unpreserved);
    if (signedCount)
        LOGI("Signed %d .sig files", signedCount);
    else
        LOGW("No .sig files signed - unexpected installation layout");
    if (unpreserved)
        LOGW("%d .sig file(s) have no vendor copy - removal would need the installer", unpreserved);

    /* 13. SbieDrv caches its certificate state from driver load time, so
     * the swapped key alone does not unlock anything: the driver has to
     * re-read Certificate.dat (the same call Sandboxie's About dialog
     * makes).  Without this the license only appears after a service
     * restart or a second SandMan start - the state is logged before and
     * after, so the log shows what the reload changed. */
    sbie_log_cert_state(sbieDir);
    if (sbie_reload_certificate(sbieDir) == 0) {
        LOGI("Driver asked to re-read the certificate");
        mark_unlocked(sbieDir);
    } else
        LOGW("Certificate not refreshed automatically - if Sandboxie still reports "
             "no license, restart the SbieSvc service once");
    sbie_log_cert_state(sbieDir);

    /* The certificate stays on disk for the whole session: SandMan reads
     * the file itself (certificate page / About), and a missing file shows
     * up as "no licence" even though the driver is already certified.
     * It is removed again when SandMan exits - see DLL_PROCESS_DETACH. */

    LOGI("Unlock complete!");
    safety_finish_success();
    attempt_started = FALSE;

cleanup:
    /* A half-applied session must not leave a certificate behind for the
     * next boot's DriverEntry to reject.  On success the file stays: the
     * session needs it (SandMan reads it) and Remove Hook deletes it. */
    if (g_cert_written && err) {
        delete_certificate_file();
        LOGW("Certificate.dat removed after the failed attempt");
    }
    if (kp_valid) ec_free_keypair(&kp);
    /* Unload driver if still loaded (gotos from the steps above). */
    kdrv_unload(&drv);
    if (attempt_started) safety_finish_failure();
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    if (err) LOGE("unlock failed: code %d", err);
    return err;
}

/* SandMan's background thread: an elevated host does the full job here;
 * an unelevated host leaves it to SandMan's -assist instance and only
 * notes that below. */
static DWORD WINAPI unlock_thread(LPVOID param)
{
    (void)param;
    char sbieDir[MAX_PATH];
    get_self_dir(sbieDir, MAX_PATH);
    log_init();

    /* The real version.dll is loaded here, not in DllMain: LoadLibrary
     * under the loader lock can deadlock.  Export stubs retry on their
     * own, so no caller ever sees an unresolved forward. */
    load_real_version();

    /* Only SandMan.exe performs the unlock; others skip silently. */
    if (!is_sandman_process()) {
        LOGI("Host process is not SandMan.exe - staying a transparent proxy");
        return 0;
    }

    if (!is_elevated()) {
        /* No custom elevation: SandMan's own -assist instance does the
         * privileged work.  Do not touch SbieDll here: SandMan treats a
         * pre-loaded SbieDll as "running sandboxed" (GetModuleHandleW
         * check in main.cpp) and would refuse to start. */
        LOGI("Host is NOT elevated - leaving the unlock to SandMan's -assist");
        return 0;
    }

    return (DWORD)perform_unlock("unlock");
}

/* ------------------------------------------------------------------ */
/*  Removal helper (called by unlock.bat)                             */
/* ------------------------------------------------------------------ */

/* Put the vendor signatures back and report through a one-line status
 * file, because a batch script cannot verify ECDSA.  Runs inside
 * rundll32.exe, where DllMain keeps the hook transparent. */
__pragma(comment(linker, "/export:RestoreVendorSigs=my_RestoreVendorSigs")) void CALLBACK
    my_RestoreVendorSigs(HWND hwnd, HINSTANCE inst, LPSTR cmdLine, int showCmd)
{
    (void)hwnd;
    (void)inst;
    (void)cmdLine;
    (void)showCmd;

    char dir[MAX_PATH];
    get_self_dir(dir, MAX_PATH);
    log_init();

    int failed = 0;
    int restored = cert_restore_vendor_sigs(dir, ORIGINAL_KEY, &failed);
    LOGI("restore: %d signature(s) put back, %d failed", restored, failed);

    char status[MAX_PATH];
    _snprintf_s(status, MAX_PATH, _TRUNCATE, "%s\\sig_restore.status", dir);
    HANDLE hFile =
        CreateFileA(status, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    char line[64];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE, "restored=%d failed=%d", restored, failed);
    DWORD written = 0;
    if (len > 0) WriteFile(hFile, line, (DWORD)len, &written, NULL);
    CloseHandle(hFile);
}

/* ------------------------------------------------------------------ */
/*  DllMain                                                           */
/* ------------------------------------------------------------------ */

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        g_self_module = hinst;
        /* The boot fast path runs here, synchronously: an elevated host
         * finishes the unlock before any SandMan code (the driver's
         * connect-time signature check included).  An unelevated host
         * leaves the elevation to SandMan's -assist instance.  No
         * LoadLibrary happens here - the real version.dll load stays in
         * the thread. */
        log_init();
        fast_patch_kernel_key();
        HANDLE hThread = CreateThread(NULL, 0, unlock_thread, NULL, 0, NULL);
        if (hThread)
            CloseHandle(hThread);
        else
            LOGE("CreateThread (unlock) failed: %lu", GetLastError());
    } else if (reason == DLL_PROCESS_DETACH) {
        /* DETACH does not run on TerminateProcess or BSOD, so reaching it
         * means the attempt did not die abnormally: clear the active
         * marker, leave fail_count to the unlock thread. */
        if (InterlockedCompareExchange(&g_safety_attempt_owned, 0, 1) == 1)
            safety_clear_active_attempt();

        /* Certificate.dat stays on disk.  The next start in this boot
         * needs it (the boot marker says the kernel is patched), and the
         * first start after a boot rewrites and reloads it before the UI.
         * Remove Hook deletes it. */
    }
    return TRUE;
}
