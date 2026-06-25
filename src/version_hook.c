/*
 * version_hook.c - DLL proxy for version.dll with full kernel unlock
 *
 * When placed next to SandMan.exe as version.dll, Windows loads this DLL
 * before SandMan initializes.  A background thread:
 *   1. Writes the embedded driver to an NTFS ADS (version.dll:driver)
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
 * Version: 1.0.0
 * Author:  HardTest
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
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
/*  Export wrappers — correct signatures, forward to real version.dll */
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

/* ------------------------------------------------------------------ */
/*  Crash safety — prevents BSOD boot loops                           */
/*                                                                    */
/*  Strategy: a counter in HKCU survives reboots.                     */
/*    DLL_PROCESS_ATTACH  → increment counter                         */
/*    unlock success      → log but don't reset (wait for clean exit) */
/*    DLL_PROCESS_DETACH  → reset counter to 0 (clean process exit)   */
/*                                                                    */
/*  If SandMan BSODs or is killed, DETACH never fires, so the         */
/*  counter stays high.  On the next boot, if counter >= CRASH_LIMIT, */
/*  we skip the unlock entirely and act as a transparent proxy.       */
/*  This breaks BSOD boot loops without requiring safe mode.          */
/*  User can reset via unlock.bat or by deleting the registry key.    */
/* ------------------------------------------------------------------ */

#define CRASH_REGKEY  "SOFTWARE\\sandboxie_unlocker"
#define CRASH_REGVAL  "crash_count"
#define CRASH_LIMIT   3

static DWORD crash_count_read(void)
{
    HKEY hKey;
    DWORD val = 0, type = 0, sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, CRASH_REGKEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, CRASH_REGVAL, NULL, &type, (LPBYTE)&val, &sz) == ERROR_SUCCESS
            && type == REG_DWORD && sz == sizeof(val)) {
            /* val is set */
        } else {
            val = 0;
        }
        RegCloseKey(hKey);
    }
    return val;
}

static void crash_count_set(DWORD val)
{
    HKEY hKey;
    DWORD disp = 0;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, CRASH_REGKEY, 0, NULL, 0,
                        KEY_WRITE, NULL, &hKey, &disp) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, CRASH_REGVAL, 0, REG_DWORD, (LPBYTE)&val, sizeof(val));
        RegCloseKey(hKey);
    }
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static void get_self_dir(char *out, ULONG cap)
{
    HMODULE hSelf = GetModuleHandleA("version.dll");
    GetModuleFileNameA(hSelf, out, cap);
    char *p = strrchr(out, '\\');
    if (p) *p = 0;
}

/* Write embedded driver (C byte array) to NTFS ADS of our DLL.
 * Path: C:\...\version.dll:driver — hidden from dir listings. */
static BOOL extract_driver(char *outPath, ULONG pathCap)
{
    HMODULE hSelf = GetModuleHandleA("version.dll");
    GetModuleFileNameA(hSelf, outPath, pathCap);
    strcat_s(outPath, pathCap, ":driver");

    HANDLE hFile = CreateFileA(outPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOGE("CreateFile (ADS) failed: %lu path=%s", GetLastError(), outPath);
        return FALSE;
    }

    DWORD written;
    BOOL ok = WriteFile(hFile, g_driver_bin, g_driver_size, &written, NULL);
    CloseHandle(hFile);
    if (!ok || written != g_driver_size) {
        LOGE("WriteFile failed: ok=%d written=%lu expected=%lu", ok, written, g_driver_size);
        return FALSE;
    }
    LOGI("Driver written to ADS (%lu bytes)", written);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Main unlock thread                                                */
/* ------------------------------------------------------------------ */

static DWORD WINAPI unlock_thread(LPVOID param)
{
    char sbieDir[MAX_PATH];
    char sbieDrvPath[MAX_PATH];
    char keypairPath[MAX_PATH];
    char backupDir[MAX_PATH];
    int err = 0;
    kdrv_t drv = {0};
    ec_keypair_t kp = {0};
    BOOL kp_valid = FALSE;

    get_self_dir(sbieDir, MAX_PATH);
    log_init();

    LOGI("Sandboxie-Plus Unlocker v%s by %s", SBIE_UNLOCKER_VERSION, SBIE_UNLOCKER_AUTHOR);

    /* Check crash counter — if too many abnormal exits, skip unlock */
    DWORD crashes = crash_count_read();
    if (crashes >= CRASH_LIMIT) {
        LOGW("SAFE MODE: crash count=%lu >= %d, skipping unlock", crashes, CRASH_LIMIT);
        LOGW("Reset via unlock.bat or delete HKCU\\%s", CRASH_REGKEY);
        return 0;
    }

    /* Increment crash counter (will be reset on clean DLL_PROCESS_DETACH) */
    crash_count_set(crashes + 1);
    LOGI("Crash count: %lu (will reset on clean exit)", crashes + 1);

    strcpy_s(sbieDrvPath, MAX_PATH, sbieDir);
    strcat_s(sbieDrvPath, MAX_PATH, "\\SbieDrv.sys");
    if (GetFileAttributesA(sbieDrvPath) == INVALID_FILE_ATTRIBUTES) {
        LOGE("SbieDrv.sys not found in %s", sbieDir);
        return 1;
    }
    LOGI("SbieDir: %s", sbieDir);

    /* 1. Write driver to NTFS ADS */
    char adsPath[MAX_PATH];
    if (!extract_driver(adsPath, MAX_PATH)) return 2;

    /* 2. Find SbieDrv.sys base in kernel (retry — driver may not be loaded yet) */
    ULONG imgSize = 0;
    ULONG64 sbieBase = 0;
    for (int attempt = 0; attempt < 60; attempt++) {
        sbieBase = kmod_find("sbiedrv", &imgSize);
        if (sbieBase) break;
        LOGW("SbieDrv.sys not in kernel yet, retry %d/60...", attempt + 1);
        Sleep(1000);
    }
    if (!sbieBase) { LOGE("SbieDrv.sys not found in kernel after 60 retries"); return 3; }
    LOGI("SbieDrv.sys kernel base: 0x%llX size: 0x%X", sbieBase, imgSize);

    /* 3. Find key RVA from PE on disk */
    ULONG keyRva = pe_find_key_rva(sbieDrvPath);
    if (!keyRva) { LOGE("ECDSA key not found in SbieDrv.sys on disk"); return 4; }
    ULONG64 keyVa = sbieBase + keyRva;
    LOGI("Key RVA: 0x%X, kernel VA: 0x%llX", keyRva, keyVa);

    /* 4. Load kernel driver for R/W */
    err = kdrv_load(&drv);
    if (err != 0) { LOGE("kdrv_load failed: %d", err); return 5; }
    LOGI("Kernel driver loaded");

    /* 5. Read & validate current key */
    BYTE currentKey[72];
    if (kdrv_read(&drv, keyVa, currentKey, 72) != 0) {
        LOGE("kdrv_read failed at key VA");
        err = 6;
        goto cleanup;
    }
    if (currentKey[0] != 'E' || currentKey[1] != 'C' ||
        currentKey[2] != 'S' || currentKey[3] != '1') {
        LOGE("No ECS1 magic at key VA");
        err = 7;
        goto cleanup;
    }
    BOOL alreadyPatched = (memcmp(currentKey, ORIGINAL_KEY, 72) != 0);
    LOGI("Current key: %s", alreadyPatched ? "already patched" : "original");

    /* 6. Load or generate keypair */
    strcpy_s(keypairPath, MAX_PATH, sbieDir);
    strcat_s(keypairPath, MAX_PATH, "\\keypair.dat");

    if (alreadyPatched && ec_load_keypair(&kp, keypairPath) == 0) {
        LOGI("Reusing saved keypair from keypair.dat");
    } else {
        LOGI("Generating new ECDSA P-256 keypair");
        if (ec_gen_keypair(&kp) != 0) {
            LOGE("ec_gen_keypair failed");
            err = 8;
            goto cleanup;
        }
        ec_save_keypair(&kp, keypairPath);
        LOGI("Keypair saved to keypair.dat");
    }
    kp_valid = TRUE;

    /* 7. Export & overwrite public key in kernel */
    BYTE newBlob[72];
    if (ec_export_pub_blob(&kp, newBlob) != 0) {
        LOGE("ec_export_pub_blob failed");
        err = 9;
        goto cleanup;
    }
    LOGI("New public key blob generated (72 bytes)");

    if (kdrv_write(&drv, keyVa, newBlob, 72) != 0) {
        LOGE("kdrv_write failed at key VA");
        err = 10;
        goto cleanup;
    }
    LOGI("Public key written to kernel memory");

    /* 8. Verify write */
    BYTE verifyKey[72];
    if (kdrv_read(&drv, keyVa, verifyKey, 72) != 0 ||
        memcmp(verifyKey, newBlob, 72) != 0) {
        LOGE("Write verification failed");
        err = 11;
        goto cleanup;
    }
    LOGI("Write verified");

    /* 9. Unload driver (close handles only) */
    kdrv_unload(&drv);
    LOGI("Kernel driver unloaded");

    /* 10. Backup & re-sign .sig files */
    strcpy_s(backupDir, MAX_PATH, sbieDir);
    strcat_s(backupDir, MAX_PATH, "\\sig_backup");
    cert_backup_sigs(sbieDir, backupDir);
    LOGI(".sig backup done");

    /* 11. Write Certificate.dat */
    if (cert_write(sbieDir, &kp) == 0)
        LOGI("Certificate.dat written");
    else
        LOGE("cert_write failed");

    /* 12. Re-sign all .exe.sig files */
    LOGI("Re-signed %d .sig files", cert_resign_all(sbieDir, &kp));

    LOGI("Unlock complete!");

cleanup:
    if (kp_valid) ec_free_keypair(&kp);
    /* Unload driver if still loaded (goto from steps 7-8) */
    if (drv.hDev) kdrv_unload(&drv);
    if (err) LOGE("unlock failed at step %d", err);
    return err;
}

/* ------------------------------------------------------------------ */
/*  DllMain                                                           */
/* ------------------------------------------------------------------ */

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        load_real_version();
        CreateThread(NULL, 0, unlock_thread, NULL, 0, NULL);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        /* Clean process exit (reserved == NULL) — reset crash counter.
         * If BSOD/kill (reserved != NULL), DETACH may still fire but
         * we don't reset — the counter stays high so the next boot
         * enters safe mode automatically. */
        if (reserved == NULL)
            crash_count_set(0);
    }
    return TRUE;
}
