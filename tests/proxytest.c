/*
 * proxytest.c - L4 integration test for the built dist\version.dll.
 *
 * Loads the proxy DLL into this (non-SandMan) process and verifies:
 *   1. All 17 version.dll exports are resolvable.
 *   2. Forwarding really works: a version-resource query round-trip
 *      (GetFileVersionInfoSize/GetFileVersionInfo/VerQueryValue) returns
 *      the DLL's own FileVersion string through the real version.dll.
 *   3. VerLanguageName forwards.
 *   4. The unlock thread's host filter: the log gains a
 *      "not SandMan.exe" line, and the host's safe-fail registry state
 *      under HKCU\SOFTWARE\sandboxie_unlocker is left untouched.
 *
 * Every call is dispatched through GetProcAddress on the PROXY handle -
 * the process never links version.lib, so an import-time load of the
 * real System32 version.dll cannot mask the proxy.
 *
 * Run from the repo root:  %TEMP%\sbie_proxytest.exe dist\version.dll
 * Exits non-zero on any failure.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "testfw.h"
#include "../src/version.h"

static const char *EXPORTS[] = {
    "GetFileVersionInfoA",        "GetFileVersionInfoW",
    "GetFileVersionInfoExA",      "GetFileVersionInfoExW",
    "GetFileVersionInfoSizeA",    "GetFileVersionInfoSizeW",
    "GetFileVersionInfoSizeExA",  "GetFileVersionInfoSizeExW",
    "GetFileVersionInfoByHandle",
    "VerFindFileA",               "VerFindFileW",
    "VerInstallFileA",            "VerInstallFileW",
    "VerLanguageNameA",           "VerLanguageNameW",
    "VerQueryValueA",             "VerQueryValueW",
};

typedef DWORD (WINAPI *fn_SizeA)(LPCSTR, LPDWORD);
typedef BOOL  (WINAPI *fn_InfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL  (WINAPI *fn_QueryA)(LPCVOID, LPCSTR, LPVOID *, PUINT);
typedef DWORD (WINAPI *fn_LangA)(DWORD, LPSTR, DWORD);

static char g_logPath[MAX_PATH];

/* Size of the proxy's log file before loading, 0 if absent. */
static DWORD log_size_before(void)
{
    HANDLE h = CreateFileA(g_logPath, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD size = GetFileSize(h, NULL);
    CloseHandle(h);
    return size == INVALID_FILE_SIZE ? 0 : size;
}

static BOOL log_has_marker_after(DWORD offset, const char *marker)
{
    HANDLE h = CreateFileA(g_logPath, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD size = GetFileSize(h, NULL);
    BOOL ok = FALSE;
    if (size != INVALID_FILE_SIZE && size > offset) {
        CHAR *buf = (CHAR *)HeapAlloc(GetProcessHeap(), 0, size - offset + 1);
        if (buf) {
            DWORD got = 0;
            SetFilePointer(h, offset, NULL, FILE_BEGIN);
            if (ReadFile(h, buf, size - offset, &got, NULL)) {
                buf[got] = 0;
                ok = strstr(buf, marker) != NULL;
            }
            HeapFree(GetProcessHeap(), 0, buf);
        }
    }
    CloseHandle(h);
    return ok;
}

static DWORD reg_attempt_active(void)
{
    DWORD v = 0xFFFFFFFF, sz = sizeof(v), type = 0;
    HKEY k;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\sandboxie_unlocker",
                      0, KEY_READ, &k) == ERROR_SUCCESS) {
        RegQueryValueExA(k, "attempt_active", NULL, &type,
                         (LPBYTE)&v, &sz);
        RegCloseKey(k);
    }
    return v;
}

int main(int argc, char **argv)
{
    TF_INIT(argc > 2 ? argv[2] : NULL);
    const char *dllPath = (argc > 1) ? argv[1] : "dist\\version.dll";

    TF_GROUP("proxy");

    /* Log path: next to the DLL under test. */
    _snprintf_s(g_logPath, sizeof(g_logPath), _TRUNCATE, "%s", dllPath);
    char *slash = strrchr(g_logPath, '\\');
    strcpy_s(slash ? slash + 1 : g_logPath, MAX_PATH, "version_hook.log");

    DWORD logBefore = log_size_before();
    DWORD activeBefore = reg_attempt_active();

    HMODULE h = LoadLibraryExA(dllPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    CHECK(h != NULL, "LoadLibraryEx(dist\\version.dll)");
    if (!h) { tf_summary(); return 1; }

    /* 1. All exports resolvable. */
    for (int i = 0; i < (int)(sizeof(EXPORTS)/sizeof(EXPORTS[0])); i++) {
        char name[96];
        _snprintf_s(name, sizeof(name), _TRUNCATE, "export %s", EXPORTS[i]);
        CHECK(GetProcAddress(h, EXPORTS[i]) != NULL, name);
    }

    DWORD handle = 0;
    char selfPath[MAX_PATH];
    GetModuleFileNameA(h, selfPath, MAX_PATH);

    /* 2. Forwarding round-trip on the DLL's own version resource.
     * All calls go through the proxy's exported pointers. */
    fn_SizeA pSize = (fn_SizeA)GetProcAddress(h, "GetFileVersionInfoSizeA");
    fn_InfoA pInfo = (fn_InfoA)GetProcAddress(h, "GetFileVersionInfoA");
    fn_QueryA pQuery = (fn_QueryA)GetProcAddress(h, "VerQueryValueA");
    CHECK(pSize != NULL && pInfo != NULL && pQuery != NULL,
          "forwarding core exports present");
    if (pSize && pInfo && pQuery) {
        DWORD sz = pSize(selfPath, &handle);
        CHECK(sz > 0 && sz <= 4096, "forwarded GetFileVersionInfoSizeA");
        if (sz > 0) {
            BYTE *block = (BYTE *)HeapAlloc(GetProcessHeap(), 0, sz);
            BOOL got = block != NULL && pInfo(selfPath, 0, sz, block);
            CHECK(got, "forwarded GetFileVersionInfoA");
            if (got) {
                char *ver = NULL;
                UINT verLen = 0;
                BOOL q = pQuery(block, "\\StringFileInfo\\040904b0\\FileVersion",
                                (LPVOID *)&ver, &verLen) && ver != NULL;
                CHECK(q, "forwarded VerQueryValueA");
                if (q) {
                    CHECK(strcmp(ver, SBIE_UNLOCKER_VERSION) == 0,
                          "FileVersion string == " SBIE_UNLOCKER_VERSION);
                }
            }
            HeapFree(GetProcessHeap(), 0, block);
        }
    }

    /* 3. VerLanguageName forwarding. */
    fn_LangA pLang = (fn_LangA)GetProcAddress(h, "VerLanguageNameA");
    CHECK(pLang != NULL, "VerLanguageNameA present");
    if (pLang) {
        char lang[64];
        DWORD langLen = pLang(0x0409, lang, sizeof(lang));
        CHECK(langLen > 0 && langLen < sizeof(lang) && lang[0] != 0,
              "forwarded VerLanguageNameA");
    }

    /* 3b. Failure hosts must degrade gracefully, not crash:
     *     - size of a missing file -> 0
     *     - VerQueryValue on an unknown path -> FALSE
     *     - GetFileVersionInfoByHandle: real version.dll has no such
     *       export, the wrapper returns FALSE without crashing. */
    if (pSize) {
        DWORD missing = pSize("Z:\\definitely\\missing.dll", &handle);
        CHECK(missing == 0, "forwarded size of missing file -> 0");
    }
    if (pInfo && pQuery) {
        BYTE block2[512];
        char *ver2 = NULL;
        UINT ver2Len = 0;
        if (pInfo(selfPath, 0, sizeof(block2), block2)) {
            CHECK(pQuery(block2, "\\NoSuchBlock", (LPVOID *)&ver2, &ver2Len) == FALSE,
                  "VerQueryValue rejects unknown path");
        }
    }
    {
        typedef BOOL (WINAPI *fn_ByHandle)(DWORD, HANDLE, LPVOID);
        fn_ByHandle pBH = (fn_ByHandle)GetProcAddress(h, "GetFileVersionInfoByHandle");
        CHECK(pBH != NULL, "ByHandle export present");
        if (pBH) {
            CHECK(pBH(0, NULL, NULL) == FALSE, "ByHandle degrades to FALSE");
        }
    }

    /* 4. Host filter: unlock skipped, log marker, registry untouched. */
    Sleep(800);
    CHECK(log_has_marker_after(logBefore, "not SandMan.exe"),
          "log gains non-SandMan filter line");
    DWORD activeAfter = reg_attempt_active();
    if (activeBefore == 0xFFFFFFFF)
        CHECK(activeAfter == 0xFFFFFFFF, "no safe-fail key created");
    else
        CHECK(activeAfter == activeBefore, "attempt_active untouched");

    FreeLibrary(h);
    return tf_summary();
}
