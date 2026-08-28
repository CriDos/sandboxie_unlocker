/*
 * fileio.h - read a whole file into a heap buffer
 */
#ifndef FILEIO_H
#define FILEIO_H

#include <windows.h>

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

#endif /* FILEIO_H */
