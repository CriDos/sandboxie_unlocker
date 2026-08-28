/*
 * ecrypto.h - ECDSA P-256 via Windows CNG (bcrypt.dll)
 *
 * Generates a keypair, exports the public key as a 72-byte BCRYPT
 * ECCPUBLIC_BLOB, and signs SHA-256 hashes in raw R||S format (64 bytes).
 * No external dependencies - uses only bcrypt.dll.
 */
#ifndef ECRYPTO_H
#define ECRYPTO_H

#include <windows.h>
#include <bcrypt.h>
#include "log.h"
#include "fileio.h"

#define BLOB_SIZE       72
#define SIG_SIZE        64           /* raw R||S */

typedef struct {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
} ec_keypair_t;

/* Generate a fresh ECDSA P-256 keypair. Returns 0 on success. */
static int ec_gen_keypair(ec_keypair_t *kp)
{
    NTSTATUS st;
    st = BCryptOpenAlgorithmProvider(&kp->hAlg, L"ECDSA_P256", NULL, 0);
    if (st) return 1;
    st = BCryptGenerateKeyPair(kp->hAlg, &kp->hKey, 256, 0);
    if (st) { BCryptCloseAlgorithmProvider(kp->hAlg, 0); kp->hAlg = NULL; return 2; }
    st = BCryptFinalizeKeyPair(kp->hKey, 0);
    if (st) { BCryptDestroyKey(kp->hKey); kp->hKey = NULL; BCryptCloseAlgorithmProvider(kp->hAlg, 0); kp->hAlg = NULL; return 3; }
    return 0;
}

/* Export the public key as a 72-byte BCRYPT blob. Returns 0 on success. */
static int ec_export_pub_blob(const ec_keypair_t *kp, BYTE *out)
{
    ULONG exported = 0;
    NTSTATUS st = BCryptExportKey(kp->hKey, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                  out, BLOB_SIZE, &exported, 0);
    return (st == 0 && exported == BLOB_SIZE) ? 0 : 1;
}

/* Sign a pre-computed SHA-256 hash (32 bytes). Produces raw R||S (64 bytes).
 * Returns 0 on success. */
static int ec_sign_hash(const ec_keypair_t *kp, const BYTE *hash32, BYTE *out)
{
    BYTE sig[128];
    ULONG sig_len = sizeof(sig);
    NTSTATUS st = BCryptSignHash(kp->hKey, NULL, (PUCHAR)hash32, 32,
                                 sig, sig_len, &sig_len, 0);
    if (st) return 1;
    if (sig_len != SIG_SIZE) return 2;
    memcpy(out, sig, SIG_SIZE);
    return 0;
}

/* Base64 encode (standard, no line breaks). */
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int ec_base64_encode(const BYTE *src, ULONG src_len, char *dst, ULONG dst_cap)
{
    ULONG needed = ((src_len + 2) / 3) * 4 + 1;
    if (dst_cap < needed) return 1;

    ULONG i, j = 0;
    for (i = 0; i + 2 < src_len; i += 3) {
        DWORD n = (src[i] << 16) | (src[i+1] << 8) | src[i+2];
        dst[j++] = B64[(n >> 18) & 63];
        dst[j++] = B64[(n >> 12) & 63];
        dst[j++] = B64[(n >> 6) & 63];
        dst[j++] = B64[n & 63];
    }
    ULONG rem = src_len - i;
    if (rem == 1) {
        DWORD n = src[i] << 16;
        dst[j++] = B64[(n >> 18) & 63];
        dst[j++] = B64[(n >> 12) & 63];
        dst[j++] = '=';
        dst[j++] = '=';
    } else if (rem == 2) {
        DWORD n = (src[i] << 16) | (src[i+1] << 8);
        dst[j++] = B64[(n >> 18) & 63];
        dst[j++] = B64[(n >> 12) & 63];
        dst[j++] = B64[(n >> 6) & 63];
        dst[j++] = '=';
    }
    dst[j] = 0;
    return 0;
}

/* Free keypair resources. */
static void ec_free_keypair(ec_keypair_t *kp)
{
    if (kp->hKey) { BCryptDestroyKey(kp->hKey); kp->hKey = NULL; }
    if (kp->hAlg) { BCryptCloseAlgorithmProvider(kp->hAlg, 0); kp->hAlg = NULL; }
}

/* Restrictive DACL (SYSTEM + Administrators) for keypair.dat and the
 * staged driver file.  *sd and *acl must live in the CALLER's frame: sa
 * points into them and is consumed by CreateFileA after the return. */
static BOOL build_restrictive_sa(SECURITY_ATTRIBUTES *sa,
                                 SECURITY_DESCRIPTOR *sd, PACL acl, DWORD aclLen)
{
    BYTE sysSid[SECURITY_MAX_SID_SIZE], admSid[SECURITY_MAX_SID_SIZE];
    DWORD sysLen = sizeof(sysSid), admLen = sizeof(admSid);

    if (!InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION))
        return FALSE;
    if (!InitializeAcl(acl, aclLen, ACL_REVISION))
        return FALSE;
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, sysSid, &sysLen) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admSid, &admLen))
        return FALSE;
    if (!AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, sysSid) ||
        !AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, admSid))
        return FALSE;
    if (!SetSecurityDescriptorDacl(sd, TRUE, acl, FALSE))
        return FALSE;

    sa->nLength = sizeof(*sa);
    sa->lpSecurityDescriptor = sd;
    sa->bInheritHandle = FALSE;
    return TRUE;
}

/* Save keypair to a file (raw BCRYPT_ECCPRIVATE_BLOB) for reuse. */
static int ec_save_keypair(const ec_keypair_t *kp, const char *path)
{
    ULONG blob_len = 0;
    NTSTATUS st = BCryptExportKey(kp->hKey, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                  NULL, 0, &blob_len, 0);
    if (st) return 1;

    BYTE *blob = (BYTE *)HeapAlloc(GetProcessHeap(), 0, blob_len);
    if (!blob) return 2;

    st = BCryptExportKey(kp->hKey, NULL, BCRYPT_ECCPRIVATE_BLOB,
                         blob, blob_len, &blob_len, 0);
    if (st) { HeapFree(GetProcessHeap(), 0, blob); return 3; }

    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    BYTE aclBuf[512];   /* plenty: 2 ACEs need ~52 bytes */
    BOOL hasSa = build_restrictive_sa(&sa, &sd, (PACL)aclBuf, (DWORD)sizeof(aclBuf));
    /* CREATE_ALWAYS keeps the existing file's DACL - delete first so a
     * wide-open ACL is never silently preserved. */
    if (hasSa && !DeleteFileA(path) && GetLastError() != ERROR_FILE_NOT_FOUND)
        LOGW("keypair.dat: old file delete failed: %lu", GetLastError());
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, hasSa ? &sa : NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        if (hasSa) LOGW("keypair.dat: restrictive DACL failed on create: %lu", GetLastError());
        HeapFree(GetProcessHeap(), 0, blob);
        return 4;
    }

    DWORD written;
    BOOL ok = WriteFile(hFile, blob, blob_len, &written, NULL);
    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, blob);
    return (ok && written == blob_len) ? 0 : 5;
}

/* Load keypair from a previously saved private key blob. */
static int ec_load_keypair(ec_keypair_t *kp, const char *path)
{
    BYTE *blob = NULL;
    DWORD fileSize = 0;
    /* A P-256 private blob is ~104 bytes; anything beyond a few KB is
     * corrupt or hostile - reject before allocating. */
    if (!read_file_all(path, &blob, &fileSize, 4096)) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
            LOGW("keypair load: %s is admin-locked (non-elevated host?)", path);
        else
            LOGW("keypair load: read failed: %lu", err);
        return 1;
    }

    NTSTATUS st = BCryptOpenAlgorithmProvider(&kp->hAlg, L"ECDSA_P256", NULL, 0);
    if (st) { HeapFree(GetProcessHeap(), 0, blob); return 2; }

    st = BCryptImportKeyPair(kp->hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB,
                             &kp->hKey, blob, fileSize, 0);
    HeapFree(GetProcessHeap(), 0, blob);
    if (st) { BCryptCloseAlgorithmProvider(kp->hAlg, 0); kp->hAlg = NULL; return 3; }

    return 0;
}

#endif /* ECRYPTO_H */
