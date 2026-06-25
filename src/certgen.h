/*
 * certgen.h - Certificate.dat generation and .sig re-signing
 *
 * Builds a UTF-8 Certificate.dat with an ECDSA P-256 signature that
 * the driver's KphValidateCertificate will accept.  Also re-signs
 * all .exe.sig files in the Sandboxie directory with our key.
 */
#ifndef CERTGEN_H
#define CERTGEN_H

#include <windows.h>
#include "log.h"
#include "ecrypto.h"

/* Certificate tags that produce:
 *   type  = eCertEternal (4)
 *   level = eCertMaxLevel (7)
 *   opts  = opt_sec + opt_enc + opt_net + opt_desk
 *   expiration = -1 (never expires)
 */
static const char *CERT_TAGS[] = {
    "NAME: HardTest",
    "DATE: 25.06.2026",
    "TYPE: ETERNAL",
    "SOFTWARE: Sandboxie-Plus",
    "OPTIONS: SBOX,EBOX,NETI,DESK",
    NULL
};

/* SHA-256 a file. Returns 0 on success, writes 32 bytes into out. */
static int sha256_file(const char *path, BYTE *out)
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, L"SHA256", NULL, 0)) return 2;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 3;
    }

    BYTE buf[65536];
    DWORD bytesRead;
    while (ReadFile(hFile, buf, sizeof(buf), &bytesRead, NULL) && bytesRead > 0)
        BCryptHashData(hHash, buf, bytesRead, 0);

    BCryptFinishHash(hHash, out, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    return 0;
}

/* SHA-256 of name:value pairs from CERT_TAGS (excludes SIGNATURE).
 * Matches verify.c's hashing: hash(utf8(name)) then hash(utf8(value)). */
static void cert_hash_body(BYTE *out32)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, L"SHA256", NULL, 0)) { memset(out32, 0, 32); return; }
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        memset(out32, 0, 32);
        return;
    }

    for (int i = 0; CERT_TAGS[i]; i++) {
        const char *colon = strchr(CERT_TAGS[i], ':');
        if (!colon) continue;
        const char *name = CERT_TAGS[i];
        const char *value = colon + 1;
        while (*name == ' ') name++;
        while (*value == ' ') value++;
        BCryptHashData(hHash, (PUCHAR)name, (ULONG)(colon - name), 0);
        BCryptHashData(hHash, (PUCHAR)value, (ULONG)strlen(value), 0);
    }

    BCryptFinishHash(hHash, out32, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

/* Write Certificate.dat to sbie_dir. Returns 0 on success. */
static int cert_write(const char *sbie_dir, const ec_keypair_t *kp)
{
    BYTE hash[32];
    cert_hash_body(hash);

    BYTE sig[64];
    int r = ec_sign_hash(kp, hash, sig);
    if (r) { LOGE("ec_sign_hash failed: %d", r); return 1; }

    char sig_b64[256];
    r = ec_base64_encode(sig, 64, sig_b64, sizeof(sig_b64));
    if (r) { LOGE("ec_base64_encode failed: %d", r); return 2; }

    char content[2048];
    content[0] = 0;
    for (int i = 0; CERT_TAGS[i]; i++) {
        strcat_s(content, sizeof(content), CERT_TAGS[i]);
        strcat_s(content, sizeof(content), "\n");
    }
    strcat_s(content, sizeof(content), "SIGNATURE: ");
    strcat_s(content, sizeof(content), sig_b64);
    strcat_s(content, sizeof(content), "\n");

    char path[MAX_PATH];
    strcpy_s(path, MAX_PATH, sbie_dir);
    strcat_s(path, MAX_PATH, "\\Certificate.dat");

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOGE("CreateFile failed: %lu path=%s", GetLastError(), path);
        return 3;
    }

    DWORD written;
    BOOL ok = WriteFile(hFile, content, (DWORD)strlen(content), &written, NULL);
    CloseHandle(hFile);
    if (!ok) { LOGE("WriteFile failed: %lu", GetLastError()); return 4; }
    return 0;
}

/* Re-sign a single .exe.sig file.  .sig = 64-byte raw ECDSA of SHA-256(exe). */
static int cert_resign_one(const char *exe_path, const char *sig_path,
                           const ec_keypair_t *kp)
{
    BYTE hash[32];
    if (sha256_file(exe_path, hash) != 0) return 1;

    BYTE sig[64];
    if (ec_sign_hash(kp, hash, sig) != 0) return 2;

    HANDLE hSig = CreateFileA(sig_path, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSig == INVALID_HANDLE_VALUE) return 3;

    DWORD written;
    BOOL ok = WriteFile(hSig, sig, 64, &written, NULL);
    CloseHandle(hSig);
    return ok ? 0 : 4;
}

/* Backup original .sig files (only if backup doesn't exist yet). */
static void cert_backup_sigs(const char *sbie_dir, const char *backup_dir)
{
    char test[MAX_PATH];
    strcpy_s(test, MAX_PATH, backup_dir);
    strcat_s(test, MAX_PATH, "\\SandMan.exe.sig");
    if (GetFileAttributesA(test) != INVALID_FILE_ATTRIBUTES)
        return;  /* backup already exists */

    CreateDirectoryA(backup_dir, NULL);

    char pattern[MAX_PATH];
    strcpy_s(pattern, MAX_PATH, sbie_dir);
    strcat_s(pattern, MAX_PATH, "\\*.exe.sig");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        char src[MAX_PATH], dst[MAX_PATH];
        strcpy_s(src, MAX_PATH, sbie_dir);
        strcat_s(src, MAX_PATH, "\\");
        strcat_s(src, MAX_PATH, fd.cFileName);
        strcpy_s(dst, MAX_PATH, backup_dir);
        strcat_s(dst, MAX_PATH, "\\");
        strcat_s(dst, MAX_PATH, fd.cFileName);
        CopyFileA(src, dst, FALSE);
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

/* Re-sign all .exe.sig files in the Sandboxie directory. */
static int cert_resign_all(const char *sbie_dir, const ec_keypair_t *kp)
{
    char pattern[MAX_PATH];
    strcpy_s(pattern, MAX_PATH, sbie_dir);
    strcat_s(pattern, MAX_PATH, "\\*.exe.sig");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    int count = 0;
    do {
        char sigPath[MAX_PATH], exePath[MAX_PATH];
        strcpy_s(sigPath, MAX_PATH, sbie_dir);
        strcat_s(sigPath, MAX_PATH, "\\");
        strcat_s(sigPath, MAX_PATH, fd.cFileName);

        strcpy_s(exePath, MAX_PATH, sbie_dir);
        strcat_s(exePath, MAX_PATH, "\\");
        size_t nameLen = strlen(fd.cFileName);
        if (nameLen > 4)
            strncat_s(exePath, MAX_PATH, fd.cFileName, nameLen - 4);

        if (GetFileAttributesA(exePath) != INVALID_FILE_ATTRIBUTES)
            if (cert_resign_one(exePath, sigPath, kp) == 0)
                count++;
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return count;
}

#endif /* CERTGEN_H */
