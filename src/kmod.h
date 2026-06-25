/*
 * kmod.h - find loaded kernel module base via NtQuerySystemInformation
 */
#ifndef KMOD_H
#define KMOD_H

#include <windows.h>
#include <winternl.h>

#define SystemModuleInformation 11

/* Enable SeDebugPrivilege so NtQuerySystemInformation returns full module list */
static void kmod_enable_debug_privilege(void)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return;
    LUID luid;
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        TOKEN_PRIVILEGES tp = { 1, { luid, SE_PRIVILEGE_ENABLED } };
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(hToken);
}

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT NameOffset;
    CHAR   Name[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

/* Find a loaded kernel module by case-insensitive substring match.
 * Returns image_base, or 0 on failure.  If out_size != NULL, writes
 * the module image size. */
static ULONG64 kmod_find(const char *name_lower, ULONG *out_size)
{
    static BOOL priv_enabled = FALSE;
    if (!priv_enabled) {
        kmod_enable_debug_privilege();
        priv_enabled = TRUE;
    }

    typedef NTSTATUS (NTAPI *pNtQSI)(ULONG, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;
    pNtQSI pNtQuerySystemInformation =
        (pNtQSI)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!pNtQuerySystemInformation) return 0;

    ULONG needed = 0;
    pNtQuerySystemInformation(SystemModuleInformation, NULL, 0, &needed);
    if (!needed) {
        LOGE("NtQuerySystemInformation returned needed=0");
        return 0;
    }

    ULONG bufSize = needed + 0x2000;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!buf) return 0;

    NTSTATUS st = pNtQuerySystemInformation(SystemModuleInformation, buf, bufSize, &needed);
    if (st < 0) {
        LOGE("NtQuerySystemInformation failed: 0x%lX", (unsigned long)st);
        HeapFree(GetProcessHeap(), 0, buf);
        return 0;
    }

    /* On x64, RTL_PROCESS_MODULES has 4 bytes of padding after
     * NumberOfModules before the first RTL_PROCESS_MODULE_INFORMATION.
     * We can't rely on the struct layout — parse manually. */
    ULONG count = *(ULONG *)buf;
    ULONG64 result = 0;

    /* Each entry is 296 bytes on x64:
     *   Section(8) MappedBase(8) ImageBase(8) ImageSize(4) Flags(4)
     *   LoadOrderIndex(2) InitOrderIndex(2) LoadCount(2) NameOffset(2)
     *   Name[256] */
    const ULONG ENTRY_SIZE = 296;
    BYTE *ptr = buf + 8;  /* skip count(4) + padding(4) */

    for (ULONG i = 0; i < count && ptr + ENTRY_SIZE <= buf + bufSize; i++) {
        ULONG64 imgBase = *(ULONG64 *)(ptr + 16);
        ULONG  imgSize  = *(ULONG  *)(ptr + 24);
        USHORT nameOff  = *(USHORT *)(ptr + 38);

        /* Name starts at ptr+40, full path like \SystemRoot\system32\... */
        char *name = (char *)(ptr + 40 + nameOff);
        char lower[256];
        ULONG j;
        for (j = 0; j < 255 && name[j]; j++)
            lower[j] = (char)tolower((unsigned char)name[j]);
        lower[j] = 0;

        if (strstr(lower, name_lower)) {
            result = imgBase;
            if (out_size) *out_size = imgSize;
            break;
        }

        ptr += ENTRY_SIZE;
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return result;
}

#endif /* KMOD_H */
