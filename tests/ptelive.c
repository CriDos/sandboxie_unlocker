/*
 * ptelive.c - admin-only live check of the read-only-page write path.
 *
 * Loads the embedded helper driver exactly like the unlocker does, locates
 * nt!MmPteBase, and exercises kdrv_page_write against a page this process
 * made read-only.  It touches only its own memory and Sandboxie is left
 * alone; the helper driver stays loaded until reboot, which is what a
 * normal unlock run leaves behind too.
 *
 * Build and run (elevated): _ptelive.bat
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "../src/fileio.h"
#include "../src/driver_bin.h"
#include "../src/kdrv.h"
#include "../src/pagemap.h"

static int fail(const char *what)
{
    printf("[FAIL] %s\n", what);
    return 1;
}

/* Stage the embedded driver in %WINDIR%\Temp and load it (same steps as
 * the unlocker, minus the restrictive DACL - this is a throwaway tool). */
static BOOL stage_and_load(kdrv_t *drv)
{
    char winDir[MAX_PATH] = {0};
    if (!GetWindowsDirectoryA(winDir, MAX_PATH)) return FALSE;

    char dir[MAX_PATH];
    _snprintf_s(dir, sizeof(dir), _TRUNCATE, "%s\\Temp", winDir);
    CreateDirectoryA(dir, NULL);

    char path[MAX_PATH];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\sbie_ptelive_%lu.sys", dir,
                GetCurrentProcessId());

    DeleteFileA(path);
    HANDLE h =
        CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("staging CreateFile failed: %lu\n", GetLastError());
        return FALSE;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(h, g_driver_bin, g_driver_size, &written, NULL) && written == g_driver_size;
    CloseHandle(h);
    if (!ok) {
        printf("staging WriteFile failed\n");
        return FALSE;
    }
    printf("staged %s (%lu bytes)\n", path, g_driver_size);

    int rc = kdrv_load(drv, path);
    if (rc != 0) {
        printf("kdrv_load failed: %d\n", rc);
        return FALSE;
    }
    printf("helper driver loaded (%s)\n", drv->hDev ? "device open" : "service only");
    return TRUE;
}

int main(void)
{
    printf("== sandboxie_unlocker PTE live check ==\n");

    BOOL elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION el = {0};
        DWORD got = 0;
        if (GetTokenInformation(token, TokenElevation, &el, sizeof(el), &got))
            elevated = el.TokenIsElevated != 0;
        CloseHandle(token);
    }
    if (!elevated) {
        printf("[FAIL] administrator rights required\n");
        return 1;
    }

    kdrv_t drv = {0};
    if (!stage_and_load(&drv)) return fail("stage/load helper driver");

    ULONG64 base = kdrv_pte_base(&drv);
    if (!base) {
        printf("[FAIL] PTE base not found/rejected - unlock would stop with a "
               "controlled error, no bugcheck\n");
        kdrv_unload(&drv);
        return 1;
    }
    printf("[PASS] PTE base located and validated: 0x%llX\n", base);

    /* 1. A writable page must take the direct path. */
    BYTE *rw = (BYTE *)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!rw) {
        kdrv_unload(&drv);
        return fail("VirtualAlloc (rw page)");
    }
    memcpy(rw, "AAAAAAAA", 8);
    static const char marker[] = "DIRECT!!";
    int rc = kdrv_page_write(&drv, (ULONG64)(ULONG_PTR)rw, marker, 8);
    if (rc != 0 || memcmp(rw, marker, 8) != 0) {
        VirtualFree(rw, 0, MEM_RELEASE);
        kdrv_unload(&drv);
        return fail("direct write to a writable page");
    }
    printf("[PASS] writable page: direct write\n");
    VirtualFree(rw, 0, MEM_RELEASE);

    /* 2. A read-only page must be written through the alias - this is the
     * exact operation that bugchecked SbieDrv 1.18.7's .rdata key page. */
    BYTE *ro = (BYTE *)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!ro) {
        kdrv_unload(&drv);
        return fail("VirtualAlloc (ro page)");
    }
    memset(ro, 'A', 0x1000);
    DWORD old = 0;
    if (!VirtualProtect(ro, 0x1000, PAGE_READONLY, &old)) {
        VirtualFree(ro, 0, MEM_RELEASE);
        kdrv_unload(&drv);
        return fail("VirtualProtect read-only");
    }

    static const char newkey[] = "ECDSA-KEY";
    rc = kdrv_page_write(&drv, (ULONG64)(ULONG_PTR)ro, newkey, 8);

    MEMORY_BASIC_INFORMATION mbi = {0};
    VirtualQuery(ro, &mbi, sizeof(mbi));
    BOOL still_ro = (mbi.Protect == PAGE_READONLY);
    BOOL patched = (memcmp(ro, newkey, 8) == 0);

    printf("%s read-only page write: rc=%d patched=%d protection still RO=%d\n",
           (rc == 0 && patched && still_ro) ? "[PASS]" : "[FAIL]", rc, patched, still_ro);
    if (rc != 0 || !patched || !still_ro) {
        printf("      (the same operation on SbieDrv's key page is what "
               "bugchecked 0xBE before this change)\n");
    }

    /* 3. Show that the alias path really was used: the page is still
     * read-only, so a plain user-mode store must fault. */
    BOOL user_store_faults = FALSE;
    __try {
        ro[0] = 'X';
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER
                                                                 : EXCEPTION_CONTINUE_SEARCH) {
        user_store_faults = TRUE;
    }
    printf("[%s] page stayed read-only for user code (store faulted: %d)\n",
           user_store_faults ? "PASS" : "WARN", user_store_faults);

    VirtualFree(ro, 0, MEM_RELEASE);
    kdrv_unload(&drv);
    printf("== done ==\n");
    return (rc == 0 && patched && still_ro) ? 0 : 1;
}
