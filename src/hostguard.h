/*
 * hostguard.h - host process gate for the unlock thread.
 *
 * The unlock must run only in SandMan.exe; any other process from the
 * Sandboxie directory that picks up version.dll stays a transparent
 * proxy.  The path predicate is separate so tests can cover matching
 * without launching renamed processes.
 */
#ifndef HOSTGUARD_H
#define HOSTGUARD_H

#include <windows.h>
#include <string.h>

static BOOL is_sandman_path(const char *exePath)
{
    const char *name = strrchr(exePath, '\\');
    name = name ? name + 1 : exePath;
    return _stricmp(name, "sandman.exe") == 0;
}

static BOOL is_sandman_process(void)
{
    char exePath[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, exePath, MAX_PATH);
    if (!n || n >= MAX_PATH) return FALSE;
    return is_sandman_path(exePath);
}

#endif /* HOSTGUARD_H */
