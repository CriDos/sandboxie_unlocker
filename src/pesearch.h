/*
 * pesearch.h - find the RVA of KphpTrustedPublicKey by parsing SbieDrv.sys
 *
 * Searches for the 72-byte ECS1 public key blob in the PE file on disk
 * and converts the file offset to an RVA using section mapping.
 */
#ifndef PESEARCH_H
#define PESEARCH_H

#include <windows.h>
#include "fileio.h"

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
 * Returns RVA or 0 on failure.  All header fields are bounds-checked
 * against data_size - the file must not be trusted. */
static ULONG pe_offset_to_rva(const BYTE *pe_data, DWORD data_size, DWORD file_offset)
{
    if (data_size < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) return 0;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)pe_data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (dos->e_lfanew < 0 ||
        (DWORD)dos->e_lfanew > data_size - sizeof(IMAGE_NT_HEADERS64)) return 0;

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(pe_data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD secTableOff = dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    DWORD secTableSize = (DWORD)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (secTableOff > data_size || secTableSize > data_size - secTableOff) return 0;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD rawStart = sec[i].PointerToRawData;
        DWORD rawEnd   = rawStart + sec[i].SizeOfRawData;
        if (rawEnd < rawStart) continue;  /* overflow guard */
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
    BYTE *data = NULL;
    DWORD fileSize = 0;
    if (!read_file_all(driver_path, &data, &fileSize, 16 * 1024 * 1024))
        return 0;

    /* Single pass.  Prefer an exact ORIGINAL_KEY match anywhere in the
     * file (unpatched driver); fall back to the first ECS1 magic (a
     * patched driver holds our key there instead). */
    DWORD origOffset = 0, magicOffset = 0;
    for (DWORD i = 0; i + 8 <= fileSize; i++) {
        if (!magicOffset && memcmp(data + i, ECS1_PATTERN, 8) == 0)
            magicOffset = i;
        if (i + 72 <= fileSize && memcmp(data + i, ORIGINAL_KEY, 72) == 0) {
            origOffset = i;
            break;
        }
    }
    DWORD offset = origOffset ? origOffset : magicOffset;

    ULONG rva = 0;
    if (offset)
        rva = pe_offset_to_rva(data, fileSize, offset);

    HeapFree(GetProcessHeap(), 0, data);
    return rva;
}

#endif /* PESEARCH_H */
