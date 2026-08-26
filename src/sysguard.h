/*
 * sysguard.h - OS security-state snapshot for the unlock log
 *
 * Logs, at unlock start, the raw registry state of mechanisms that can
 * block or interfere with loading the helper driver or with the kernel
 * patch: vulnerable driver blocklist (CI\Config), Smart App Control,
 * VBS/HVCI, Secure Boot, Driver Verifier, WDAC policy keys, and the
 * Windows build number.  Read-only, values as-is, no interpretation.
 */
#ifndef SYSGUARD_H
#define SYSGUARD_H

#include <windows.h>
#include <winreg.h>
#include <string.h>
#include "log.h"

#define SYSG_CI_CONFIG   "SYSTEM\\CurrentControlSet\\Control\\CI\\Config"
#define SYSG_CI_POLICY   "SYSTEM\\CurrentControlSet\\Control\\CI\\Policy"
#define SYSG_DEVICEGUARD "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"
#define SYSG_HVCI        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"
#define SYSG_SECUREBOOT  "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"
#define SYSG_MEMORY_MGMT "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"

/* Read a DWORD.  Returns 0 and sets *absent when the value or the key
 * is missing; other errors are logged and reported as absent too. */
static DWORD sysg_reg_dword(const char *key, const char *value, int *absent)
{
    DWORD v = 0, sz = sizeof(v);
    LSTATUS st = RegGetValueA(HKEY_LOCAL_MACHINE, key, value,
                              RRF_RT_REG_DWORD, NULL, &v, &sz);
    if (st == ERROR_SUCCESS) { *absent = 0; return v; }
    *absent = 1;
    if (!(st == ERROR_FILE_NOT_FOUND || st == ERROR_PATH_NOT_FOUND))
        LOGW("RegGetValue %s\\%s failed: 0x%lX (%lu)", key, value, (ULONG)st, (ULONG)st);
    return 0;
}

/* One raw DWORD line: "tag: name = value (hex)" or "= absent". */
static void sysg_line_dword(const char *tag, const char *key, const char *value)
{
    int absent = 0;
    DWORD v = sysg_reg_dword(key, value, &absent);
    if (absent)
        LOGI("%s: %s = absent", tag, value);
    else
        LOGI("%s: %s = %lu (0x%lX)", tag, value, v, v);
}

/* ------------------------------------------------------------------ */
/*  OS build                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR szCSDVersion[128];
} SYSG_OSVI;

typedef LONG (WINAPI *SYSG_RTLGETVERSION)(SYSG_OSVI *);

static const char *sysg_build_label(ULONG build)
{
    switch (build) {
    case 26100: return "24H2";
    case 22631: return "23H2";
    case 22621: return "22H2";
    case 22000: return "21H2";
    case 19045: return "10 22H2";
    case 19044: case 19043: return "10 21H2";
    case 19042: return "10 20H2";
    case 19041: return "10 2004";
    case 17763: return "10 1809";
    case 17134: return "10 1803";
    case 16299: return "10 1709";
    case 14393: return "10 1607";
    default:    return "";
    }
}

static void sysg_log_build(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    SYSG_RTLGETVERSION fn = ntdll ?
        (SYSG_RTLGETVERSION)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
    if (!fn) { LOGW("RtlGetVersion unavailable"); return; }

    SYSG_OSVI vi;
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (fn(&vi) != 0) { LOGW("RtlGetVersion failed"); return; }

    const char *label = sysg_build_label(vi.dwBuildNumber);
    if (label[0])
        LOGI("OS: %lu.%lu.%lu (%s)", vi.dwMajorVersion, vi.dwMinorVersion,
             vi.dwBuildNumber, label);
    else
        LOGI("OS: %lu.%lu.%lu", vi.dwMajorVersion, vi.dwMinorVersion,
             vi.dwBuildNumber);
}

/* ------------------------------------------------------------------ */
/*  CI\Config dump                                                    */
/* ------------------------------------------------------------------ */

static void sysg_log_ci_config(void)
{
    HKEY hKey;
    LSTATUS st = RegOpenKeyExA(HKEY_LOCAL_MACHINE, SYSG_CI_CONFIG, 0, KEY_READ, &hKey);
    if (st != ERROR_SUCCESS) {
        LOGW("CI\\Config open failed: 0x%lX (%lu)", (ULONG)st, (ULONG)st);
        return;
    }

    char name[128];
    BYTE data[1024];
    DWORD idx = 0;

    for (;;) {
        DWORD nameLen = sizeof(name), dataLen = sizeof(data), type = 0;
        st = RegEnumValueA(hKey, idx, name, &nameLen, NULL, &type, data, &dataLen);
        if (st == ERROR_NO_MORE_ITEMS) break;
        if (st == ERROR_MORE_DATA) { idx++; continue; }  /* oversized name/data: skip */
        if (st != ERROR_SUCCESS) { LOGW("CI\\Config enum failed: 0x%lX (%lu)", (ULONG)st, (ULONG)st); break; }
        if (nameLen >= sizeof(name)) nameLen = sizeof(name) - 1;
        name[nameLen] = 0;

        if (type == REG_DWORD && dataLen >= 4) {
            DWORD v = *(DWORD *)data;
            LOGI("CI.Config: %s = %lu (0x%lX)", name, v, v);
        } else if (type == REG_QWORD && dataLen >= 8) {
            ULONG64 q;
            memcpy(&q, data, sizeof(q));
            LOGI("CI.Config: %s = 0x%llX (QWORD)", name, q);
        } else if (type == REG_SZ || type == REG_EXPAND_SZ) {
            if (dataLen >= sizeof(data)) dataLen = sizeof(data) - 1;
            data[dataLen] = 0;
            LOGI("CI.Config: %s = \"%s\"", name, (char *)data);
        } else if (type == REG_BINARY) {
            char hex[100];
            ULONG n = (dataLen < 32) ? dataLen : 32;
            ULONG i, off = 0;
            for (i = 0; i < n && off < sizeof(hex) - 3; i++) {
                wsprintfA(hex + off, "%02X ", data[i]);
                off += 3;
            }
            LOGI("CI.Config: %s = <bin %lu bytes> %s", name, dataLen, hex);
        } else {
            LOGI("CI.Config: %s = <type %lu, %lu bytes>", name, type, dataLen);
        }
        idx++;
    }
    RegCloseKey(hKey);
}

/* ------------------------------------------------------------------ */
/*  Fixed checks                                                      */
/* ------------------------------------------------------------------ */

static void sysg_log_dwords(void)
{
    sysg_line_dword("CI.SAC", SYSG_CI_POLICY, "VerifiedAndReputablePolicyState");
    sysg_line_dword("VBS", SYSG_DEVICEGUARD, "EnableVirtualizationBasedSecurity");
    sysg_line_dword("VBS", SYSG_DEVICEGUARD, "RequirePlatformSecurityFeatures");
    sysg_line_dword("VBS", SYSG_DEVICEGUARD, "Locked");
    sysg_line_dword("HVCI", SYSG_HVCI, "Enabled");
    sysg_line_dword("HVCI", SYSG_HVCI, "Locked");
    sysg_line_dword("SecureBoot", SYSG_SECUREBOOT, "UEFISecureBootEnabled");
}

static void sysg_log_verifier(void)
{
    DWORD sz = 0;
    LSTATUS st = RegGetValueA(HKEY_LOCAL_MACHINE, SYSG_MEMORY_MGMT, "VerifyDrivers",
                              RRF_RT_REG_MULTI_SZ, NULL, NULL, &sz);
    if (st != ERROR_SUCCESS || sz == 0) {
        if (!(st == ERROR_FILE_NOT_FOUND || st == ERROR_PATH_NOT_FOUND))
            LOGW("RegGetValue VerifyDrivers failed: 0x%lX (%lu)", (ULONG)st, (ULONG)st);
        LOGI("Verifier: VerifyDrivers = none");
        return;
    }
    /* Bound the allocation: the value is diagnostic and the flat view is
     * capped at 950 chars anyway; a corrupted/hostile size must not turn
     * into a huge malloc (heap exhaustion in the locked-down context). */
    if (sz > 1024u * 1024u) sz = 1024u * 1024u;

    char *buf = (char *)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!buf) { LOGW("Verifier: alloc failed"); return; }

    DWORD got = sz;
    st = RegGetValueA(HKEY_LOCAL_MACHINE, SYSG_MEMORY_MGMT, "VerifyDrivers",
                      RRF_RT_REG_MULTI_SZ, NULL, buf, &got);
    if (st != ERROR_SUCCESS && st != ERROR_MORE_DATA) {
        LOGW("RegGetValue VerifyDrivers (data) failed: 0x%lX (%lu)", (ULONG)st, (ULONG)st);
        HeapFree(GetProcessHeap(), 0, buf);
        LOGI("Verifier: VerifyDrivers = none");
        return;
    }

    char flat[950];
    ULONG f = 0, i;
    int trunc = (st == ERROR_MORE_DATA) ? 1 : 0;
    for (i = 0; i + 1 < got; i++) {
        char c = buf[i];
        if (c == 0) {
            if (buf[i + 1] == 0) break;
            c = ' ';
        }
        if (f + 1 >= (ULONG)sizeof(flat)) { trunc = 1; break; }
        flat[f++] = c;
    }
    flat[f] = 0;
    HeapFree(GetProcessHeap(), 0, buf);

    if (!f && !trunc)
        LOGI("Verifier: VerifyDrivers = none");
    else
        LOGI("Verifier: VerifyDrivers = \"%s%s\"", flat, trunc ? "..." : "");
}

static void sysg_log_wdac(void)
{
    static const char *keys[] = {
        "SYSTEM\\CurrentControlSet\\Control\\CI\\CIPolicies",
        "SYSTEM\\CurrentControlSet\\Control\\CI\\ProtectedPolicies"
    };
    int k;
    for (k = 0; k < 2; k++) {
        HKEY hKey;
        LSTATUS st = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[k], 0, KEY_READ, &hKey);
        if (st != ERROR_SUCCESS) {
            LOGI("WDAC: %s = none (open err 0x%lX (%lu))", keys[k], (ULONG)st, (ULONG)st);
            continue;
        }

        char name[128];
        DWORD idx = 0, count = 0;
        char list[512];
        list[0] = 0;
        for (;;) {
            DWORD nameLen = sizeof(name);
            st = RegEnumKeyExA(hKey, idx, name, &nameLen, NULL, NULL, NULL, NULL);
            if (st == ERROR_NO_MORE_ITEMS) break;
            if (st == ERROR_MORE_DATA) { idx++; continue; }
            if (st != ERROR_SUCCESS) break;
            if (nameLen >= sizeof(name)) nameLen = sizeof(name) - 1;
            name[nameLen] = 0;
            count++;
            /* Bounded append: a pathological long name must not wipe the
             * accumulated list (strcat_s clears the dest on ERANGE). */
            if (count <= 8 && (ULONG)strlen(list) < (ULONG)sizeof(list) - 130) {
                if (list[0]) strcat_s(list, sizeof(list), " ");
                strcat_s(list, sizeof(list), name);
            }
            idx++;
        }
        RegCloseKey(hKey);

        LOGI("WDAC: %s = %u policy(ies)", keys[k], count);
        if (count && count <= 8)
            LOGI("WDAC:   %s", list);
    }
}

/* ------------------------------------------------------------------ */
/*  Entry point                                                       */
/* ------------------------------------------------------------------ */

static void sysguard_log_state(void)
{
    LOGI("---- OS security-state snapshot ----");
    sysg_log_build();
    sysg_log_ci_config();
    sysg_log_dwords();
    sysg_log_verifier();
    sysg_log_wdac();
    LOGI("---- end snapshot ----");
}

#endif /* SYSGUARD_H */