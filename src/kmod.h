/*
 * kmod.h - find a loaded kernel module base by its file name
 *
 * EnumDeviceDrivers is the documented way to list loaded images: it needs
 * no privileges and gives the same addresses as the module list, so the
 * hand-rolled RTL_PROCESS_MODULES parser (fixed 296-byte records, name
 * offsets, SeDebugPrivilege) is gone.  Where an image size is needed it is
 * read from the mapped PE headers at the point of use.
 */
#ifndef KMOD_H
#define KMOD_H

#include <windows.h>
#include <psapi.h>
#include <string.h>
#include "log.h"

/* Find a loaded module by its base file name (case-insensitive), e.g.
 * "SbieDrv.sys" or "ntoskrnl.exe".  Returns the image base, or 0. */
static ULONG64 kmod_find(const char *file_name)
{
    DWORD needed = 0;
    EnumDeviceDrivers(NULL, 0, &needed);
    if (!needed) {
        LOGE("kmod: EnumDeviceDrivers reported no drivers");
        return 0;
    }

    LPVOID *bases = (LPVOID *)HeapAlloc(GetProcessHeap(), 0, needed);
    if (!bases) return 0;
    if (!EnumDeviceDrivers(bases, needed, &needed)) {
        LOGE("kmod: EnumDeviceDrivers failed: %lu", GetLastError());
        HeapFree(GetProcessHeap(), 0, bases);
        return 0;
    }

    ULONG64 result = 0;
    DWORD count = needed / (DWORD)sizeof(bases[0]);
    for (DWORD i = 0; i < count; i++) {
        char name[MAX_PATH];
        if (!GetDeviceDriverBaseNameA(bases[i], name, sizeof(name))) continue;
        if (_stricmp(name, file_name) != 0) continue;
        result = (ULONG64)(ULONG_PTR)bases[i];
        break;
    }

    HeapFree(GetProcessHeap(), 0, bases);
    return result;
}

#endif /* KMOD_H */
