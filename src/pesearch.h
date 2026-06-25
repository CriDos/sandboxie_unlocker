/*
 * pesearch.h - find the RVA of KphpTrustedPublicKey by parsing SbieDrv.sys
 *
 * Searches for the 72-byte ECS1 public key blob in the PE file on disk
 * and converts the file offset to an RVA using section mapping.
 */
#ifndef PESEARCH_H
#define PESEARCH_H

#include <windows.h>

/* The original KphpTrustedPublicKey[72] from verify.c */
static const BYTE ORIGINAL_KEY[72] = {
    0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00,
    0x05, 0x7A, 0x12, 0x5A, 0xF8, 0x54, 0x01, 0x42,
    0xDB, 0x19, 0x87, 0xFC, 0xC4, 0xE3, 0xD3, 0x8D,
    0x46, 0x7B, 0x74, 0x01, 0x12, 0xFC, 0x78, 0xEB,
    0xEF, 0x7F, 0xF6, 0xAF, 0x4D, 0x9A, 0x3A, 0xF6,
    0x64, 0x90, 0xDB, 0xE3, 0x48, 0xAB, 0x3E, 0xA7,
    0x2F, 0xC1, 0x18, 0x32, 0xBD, 0x23, 0x02, 0x9D,
    0x3F, 0xF3, 0x27, 0x86, 0x71, 0x45, 0x26, 0x14,
    0x14, 0xF5, 0x19, 0xAA, 0x2D, 0xEE, 0x50, 0x10,
};

/* ECS1 magic + keysize=0x20 pattern (for already-patched binaries) */
static const BYTE ECS1_PATTERN[8] = {
    0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00,
};

/* Convert a file offset to RVA using PE section mapping.
 * Returns RVA or 0 on failure. */
static ULONG pe_offset_to_rva(const BYTE *pe_data, DWORD file_offset)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)pe_data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(pe_data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD rawStart = sec[i].PointerToRawData;
        DWORD rawEnd   = rawStart + sec[i].SizeOfRawData;
        if (file_offset >= rawStart && file_offset < rawEnd) {
            return sec[i].VirtualAddress + (file_offset - rawStart);
        }
    }
    return 0;
}

/* Find the RVA of the ECDSA key in SbieDrv.sys on disk.
 * Returns RVA or 0 on failure. */
static ULONG pe_find_key_rva(const char *driver_path)
{
    HANDLE hFile = CreateFileA(driver_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return 0;
    }

    BYTE *data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (!data) { CloseHandle(hFile); return 0; }

    DWORD bytesRead;
    if (!ReadFile(hFile, data, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        HeapFree(GetProcessHeap(), 0, data);
        CloseHandle(hFile);
        return 0;
    }
    CloseHandle(hFile);

    /* Search for original key first */
    DWORD offset = 0;
    for (DWORD i = 0; i + 72 <= fileSize; i++) {
        if (memcmp(data + i, ORIGINAL_KEY, 72) == 0) {
            offset = i;
            break;
        }
    }

    /* If not found, search for any ECS1 pattern */
    if (offset == 0) {
        for (DWORD i = 0; i + 8 <= fileSize; i++) {
            if (memcmp(data + i, ECS1_PATTERN, 8) == 0) {
                offset = i;
                break;
            }
        }
    }

    ULONG rva = 0;
    if (offset)
        rva = pe_offset_to_rva(data, offset);

    HeapFree(GetProcessHeap(), 0, data);
    return rva;
}

#endif /* PESEARCH_H */
