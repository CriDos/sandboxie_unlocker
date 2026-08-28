/*
 * fileio.h - file helpers: read a whole file, stale staging cleanup
 */
#ifndef FILEIO_H
#define FILEIO_H

#include <windows.h>
#include "log.h"

/* Read the whole file into a single HeapAlloc buffer.  Returns TRUE on
 * success and leaves the buffer in *out with its size in *out_size
 * (free with HeapFree(GetProcessHeap(), 0, *out)).  Returns FALSE with
 * *out = NULL on any error, empty file, or size above max_size. */
static BOOL read_file_all(const char *path, BYTE **out, DWORD *out_size, DWORD max_size)
{
    *out = NULL;
    *out_size = 0;

    HANDLE hFile = CreateFileA(path, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0 || size > max_size) {
        CloseHandle(hFile);
        return FALSE;
    }

    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf) { CloseHandle(hFile); return FALSE; }

    DWORD got = 0;
    BOOL ok = ReadFile(hFile, buf, size, &got, NULL) && got == size;
    CloseHandle(hFile);
    if (!ok) { HeapFree(GetProcessHeap(), 0, buf); return FALSE; }

    *out = buf;
    *out_size = size;
    return TRUE;
}

/* Remove sbie_unlock_*.sys leftovers.  Deletion opens each file with
 * DELETE access and share mode 0, so files held by a staging writer or
 * a kernel image section fail to open and are skipped (retried after
 * reboot).  Files younger than REUSE_GRACE_SEC may belong to an instance
 * that has not loaded its driver yet - leave them alone. */
#define REUSE_GRACE_SEC 30

static void cleanup_stale_temp_drivers(const char *tempDir)
{
    char pattern[MAX_PATH];
    strcpy_s(pattern, MAX_PATH, tempDir);
    strcat_s(pattern, MAX_PATH, "\\sbie_unlock_*.sys");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);

    static const ULONG64 TICKS_PER_SEC = 10000000;

    UINT removed = 0, locked = 0;
    do {
        char p[MAX_PATH];
        strcpy_s(p, MAX_PATH, tempDir);
        strcat_s(p, MAX_PATH, "\\");
        strcat_s(p, MAX_PATH, fd.cFileName);

        ULONG64 now64 = ((ULONG64)nowFt.dwHighDateTime << 32) | nowFt.dwLowDateTime;
        ULONG64 file64 = ((ULONG64)fd.ftLastWriteTime.dwHighDateTime << 32) |
                          fd.ftLastWriteTime.dwLowDateTime;
        ULONG64 ageSec = (now64 > file64) ? (now64 - file64) / TICKS_PER_SEC : 0;
        if (ageSec < REUSE_GRACE_SEC) {
            locked++;
            continue;
        }

        HANDLE h = CreateFileA(p, DELETE, 0, NULL, OPEN_EXISTING,
                               FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            removed++;
        } else {
            locked++;
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    LOGI("Stale temp drivers: removed %u, locked %u", removed, locked);
}

#endif /* FILEIO_H */
