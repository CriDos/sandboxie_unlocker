/*
 * safety.h - crash-safe unlock state machine (prevents BSOD boot loops).
 *
 * HKCU holds attempt_active + fail_count: an attempt interrupted
 * (marker still set on the next run) bumps fail_count, controlled
 * errors clear the marker, success resets both.  After CRASH_LIMIT
 * failures the DLL stays a transparent proxy until reset.
 *
 * Extracted from version_hook.c so the state machine is unit-testable.
 */
#ifndef SAFETY_H
#define SAFETY_H

#include <windows.h>
#include "log.h"

#define SAFETY_REGKEY          "SOFTWARE\\sandboxie_unlocker"
#define SAFETY_REG_FAIL_COUNT  "fail_count"
#define SAFETY_REG_ACTIVE      "attempt_active"
#define CRASH_LIMIT            3

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

#endif /* SAFETY_H */
