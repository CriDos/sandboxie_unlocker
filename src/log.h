/*
 * log.h - simple file logger for the unlock thread
 *
 * Writes to version_hook.log next to the DLL.
 * All modules include this and use LOGI / LOGE / LOGW macros.
 */
#ifndef LOG_H
#define LOG_H

#include <windows.h>
#include <stdio.h>

static char g_log_path[MAX_PATH] = {0};

static void log_init(void)
{
    if (g_log_path[0]) return;
    HMODULE hSelf = GetModuleHandleA("version.dll");
    GetModuleFileNameA(hSelf, g_log_path, MAX_PATH);
    char *p = strrchr(g_log_path, '\\');
    if (p) {
        strcpy_s(p + 1, MAX_PATH - (p + 1 - g_log_path), "version_hook.log");
    } else {
        strcpy_s(g_log_path, MAX_PATH, "version_hook.log");
    }
}

static void log_write(const char *level, const char *fmt, ...)
{
    log_init();

    HANDLE hFile = CreateFileA(g_log_path, FILE_APPEND_DATA, FILE_SHARE_READ,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    /* Timestamp */
    SYSTEMTIME st;
    GetLocalTime(&st);
    char ts[32];
    wsprintfA(ts, "%02d:%02d:%02d.%03d ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    /* Level prefix */
    char prefix[16];
    wsprintfA(prefix, "[%s] ", level);

    /* Message */
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt, args);
    va_end(args);

    /* Full line */
    char line[1200];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE, "%s%s%s\r\n", ts, prefix, msg);
    if (len < 0) len = 0;

    DWORD written;
    if (len > 0) WriteFile(hFile, line, (DWORD)len, &written, NULL);
    CloseHandle(hFile);
}

#define LOGI(...) log_write("INFO",  __VA_ARGS__)
#define LOGE(...) log_write("ERROR", __VA_ARGS__)
#define LOGW(...) log_write("WARN",  __VA_ARGS__)

#endif /* LOG_H */
