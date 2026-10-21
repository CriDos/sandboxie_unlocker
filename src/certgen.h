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
#include "fileio.h"
#include "pesearch.h"

/* Certificate tags that produce:
 *   type  = eCertEternal (4)
 *   level = eCertMaxLevel (7)
 *   opts  = opt_sec + opt_enc + opt_net + opt_desk
 *   expiration = -1 (never expires)
 */
static const char *CERT_TAGS[] = {"NAME: HardTest",
                                  "DATE: 25.06.2026",
                                  "TYPE: ETERNAL",
                                  "SOFTWARE: Sandboxie-Plus",
                                  "OPTIONS: SBOX,EBOX,NETI,DESK",
                                  NULL};

/* SHA-256 a file. Returns 0 on success, writes 32 bytes into out. */
static int sha256_file(const char *path, BYTE *out)
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOGE("sha256_file: open failed: %lu path=%s", GetLastError(), path);
        return 1;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, L"SHA256", NULL, 0)) {
        CloseHandle(hFile);
        return 2;
    }
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return 3;
    }

    /* 64KB on the unlock thread's stack would be reckless; the file
     * hashing is single-threaded, so a static buffer is safe. */
    static BYTE buf[65536];
    DWORD bytesRead;
    BOOL readOk = TRUE;
    BOOL hashOk = TRUE;
    DWORD readErr = 0;
    NTSTATUS hashSt = 0;
    for (;;) {
        if (!ReadFile(hFile, buf, sizeof(buf), &bytesRead, NULL)) {
            readOk = FALSE;
            readErr = GetLastError(); /* capture now - BCrypt/CloseHandle calls below clobber it */
            break;
        }
        if (bytesRead == 0) break;
        hashSt = BCryptHashData(hHash, buf, bytesRead, 0);
        if (hashSt) {
            hashOk = FALSE;
            break;
        }
    }

    NTSTATUS finSt = BCryptFinishHash(hHash, out, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    /* An unfed hash still finishes cleanly, so each failure class keeps
     * its own diagnosis: finish, hash feed, then file read. */
    if (finSt) {
        LOGE("sha256_file: BCryptFinishHash failed: 0x%lX", (unsigned long)finSt);
        return 6;
    }
    if (!hashOk) {
        LOGE("sha256_file: BCryptHashData failed: 0x%lX", (unsigned long)hashSt);
        return 6;
    }
    if (!readOk) {
        LOGE("sha256_file: ReadFile failed: %lu path=%s", readErr, path);
        return 5;
    }
    return 0;
}

/* SHA-256 of name:value pairs from CERT_TAGS (excludes SIGNATURE).
 * Matches verify.c's hashing: hash(utf8(name)) then hash(utf8(value)).
 * Returns 0 on success; on failure out32 is zeroed. */
static int cert_hash_body(BYTE *out32)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, L"SHA256", NULL, 0)) {
        memset(out32, 0, 32);
        return 1;
    }
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        memset(out32, 0, 32);
        return 2;
    }

    int r = 0;
    for (int i = 0; CERT_TAGS[i]; i++) {
        const char *colon = strchr(CERT_TAGS[i], ':');
        if (!colon) continue;
        const char *name = CERT_TAGS[i];
        const char *value = colon + 1;
        while (*name == ' ') name++;
        while (*value == ' ') value++;
        if (BCryptHashData(hHash, (PUCHAR)name, (ULONG)(colon - name), 0) ||
            BCryptHashData(hHash, (PUCHAR)value, (ULONG)strlen(value), 0)) {
            r = 3;
            break;
        }
    }

    if (!r && BCryptFinishHash(hHash, out32, 32, 0)) r = 4;

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (r) memset(out32, 0, 32);
    return r;
}

/* Write Certificate.dat to sbie_dir. Returns 0 on success. */
static int cert_write(const char *sbie_dir, const ec_keypair_t *kp)
{
    BYTE hash[32];
    if (cert_hash_body(hash)) {
        LOGE("cert_hash_body failed");
        return 5;
    }

    BYTE sig[64];
    int r = ec_sign_hash(kp, hash, sig);
    if (r) {
        LOGE("ec_sign_hash failed: %d", r);
        return 1;
    }

    char sig_b64[256];
    r = ec_base64_encode(sig, 64, sig_b64, sizeof(sig_b64));
    if (r) {
        LOGE("ec_base64_encode failed: %d", r);
        return 2;
    }

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

    HANDLE hFile =
        CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOGE("CreateFile failed: %lu path=%s", GetLastError(), path);
        return 3;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, content, (DWORD)strlen(content), &written, NULL);
    DWORD werr = GetLastError(); /* capture before CloseHandle clobbers it */
    CloseHandle(hFile);
    if (!ok || written != (DWORD)strlen(content)) {
        LOGE("cert_write: WriteFile failed: %lu written=%lu", werr, written);
        return 4;
    }
    return 0;
}

/* Does *sig_path* hold the vendor signature for *exe_path*, verified with
 * *trusted_pub*?  Returns 1 (valid), 0 (not this key) or -1 (unreadable). */
static int cert_sig_is_vendor(const char *exe_path, const char *sig_path, const BYTE *trusted_pub)
{
    BYTE hash[32];
    if (sha256_file(exe_path, hash) != 0) return -1;

    BYTE *sig = NULL;
    DWORD sigSize = 0;
    if (!read_file_all(sig_path, &sig, &sigSize, 4096) || sigSize != SIG_SIZE) {
        if (sig) HeapFree(GetProcessHeap(), 0, sig);
        return -1;
    }

    int ok = (ec_verify_pub(trusted_pub, hash, sig) == 0) ? 1 : 0;
    HeapFree(GetProcessHeap(), 0, sig);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Vendor signature shadows                                          */
/* ------------------------------------------------------------------ */

/* The vendor .sig is never overwritten: ReplaceFile swaps our signature in
 * and moves the vendor one to X.sig.vendor, so removal is a rename back.
 * No copy policy, no marker, no backup directory - nothing to poison, and
 * nothing that depends on the order the files happen to be seen in. */
#define SHADOW_SUFFIX ".vendor"

static void sig_join(char *out, const char *dir, const char *name)
{ _snprintf_s(out, MAX_PATH, _TRUNCATE, "%s\\%s", dir, name); }

/* Cut *suffix_len* characters off *path*; "" when nothing would remain. */
static void sig_strip(char *path, size_t suffix_len)
{
    size_t len = strlen(path);
    if (len > suffix_len)
        path[len - suffix_len] = 0;
    else
        path[0] = 0;
}

/* "X.exe.sig" in *dir* -> "X.exe"; "" when the name is too short. */
static void sig_exe_path(char *out, const char *dir, const char *sig_name)
{
    sig_join(out, dir, sig_name);
    sig_strip(out, 4);
}

/* Vendor shadow of a .sig path: "X.exe.sig" -> "X.exe.sig.vendor". */
static void sig_shadow_path(char *out, const char *sig_path)
{ _snprintf_s(out, MAX_PATH, _TRUNCATE, "%s" SHADOW_SUFFIX, sig_path); }

/* Replace *path* with *data* in one step; the previous file ends up at
 * *backup* (NULL to drop it).  Returns 0 on success. */
static int replace_with_data(const char *path, const BYTE *data, DWORD size, const char *backup)
{
    char tmp[MAX_PATH];
    _snprintf_s(tmp, MAX_PATH, _TRUNCATE, "%s.tmp", path);

    HANDLE hFile =
        CreateFileA(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOGE("sig: cannot create %s: %lu", tmp, GetLastError());
        return 1;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(hFile, data, size, &written, NULL);
    DWORD werr = GetLastError();
    CloseHandle(hFile);
    if (!ok || written != size) {
        LOGE("sig: cannot write %s: %lu", tmp, werr);
        DeleteFileA(tmp);
        return 2;
    }

    if (ReplaceFileA(path, tmp, backup, REPLACEFILE_IGNORE_MERGE_ERRORS, NULL, NULL)) return 0;

    LOGE("sig: cannot replace %s: %lu", path, GetLastError());
    DeleteFileA(tmp);
    return 3;
}

/* Sign *exe_path* into *sig_path*, moving a vendor signature aside first.
 * Returns 0 when our signature is in place and the vendor one is
 * restorable; 4 when the vendor signature is gone and must not be touched
 * (leaving the file alone beats replacing it with something unremovable). */
static int sign_with_shadow(const char *exe_path, const char *sig_path, const ec_keypair_t *kp,
                            const BYTE *trusted_pub)
{
    char shadow[MAX_PATH];
    sig_shadow_path(shadow, sig_path);

    BYTE hash[32];
    if (sha256_file(exe_path, hash) != 0) return 1;

    BYTE sig[SIG_SIZE];
    if (ec_sign_hash(kp, hash, sig) != 0) {
        LOGE("sig: signing failed: %s", exe_path);
        return 2;
    }

    if (cert_sig_is_vendor(exe_path, sig_path, trusted_pub) == 1)
        return replace_with_data(sig_path, sig, SIG_SIZE, shadow) == 0 ? 0 : 3;

    /* Already re-signed (or foreign): the vendor bytes, if any, live in the
     * shadow.  Without a verified shadow they are gone for good. */
    if (cert_sig_is_vendor(exe_path, shadow, trusted_pub) != 1) {
        LOGE("sig: no restorable vendor signature for %s", sig_path);
        return 4;
    }
    return replace_with_data(sig_path, sig, SIG_SIZE, NULL) == 0 ? 0 : 5;
}

/* Sign every executable in the directory.  *unpreserved counts files whose
 * vendor signature is already gone (they are left untouched). */
static int cert_sign_all(const char *sbie_dir, const ec_keypair_t *kp, const BYTE *trusted_pub,
                         int *unpreserved)
{
    char pattern[MAX_PATH];
    sig_join(pattern, sbie_dir, "*.exe.sig");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    int signed_count = 0;
    do {
        char exe[MAX_PATH], sig[MAX_PATH];
        sig_join(sig, sbie_dir, fd.cFileName);
        sig_exe_path(exe, sbie_dir, fd.cFileName);
        if (!exe[0]) continue;

        if (GetFileAttributesA(exe) == INVALID_FILE_ATTRIBUTES) {
            LOGW("sig: exe missing for %s - skipped", fd.cFileName);
            continue;
        }

        int r = sign_with_shadow(exe, sig, kp, trusted_pub);
        if (r == 0) {
            signed_count++;
        } else {
            LOGW("sig: FAILED for %s (code %d)", fd.cFileName, r);
            if (r == 4 && unpreserved) (*unpreserved)++;
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return signed_count;
}

/* True when every executable can be returned to its vendor signature: the
 * installed .sig still verifies, or a verified shadow is in place.  Called
 * before the first kernel write - this is what makes removal safe. */
static BOOL cert_vendor_sigs_preserved(const char *sbie_dir, const BYTE *trusted_pub)
{
    char pattern[MAX_PATH];
    sig_join(pattern, sbie_dir, "*.exe.sig");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return TRUE; /* nothing to restore */

    BOOL ok = TRUE;
    do {
        char exe[MAX_PATH], sig[MAX_PATH], shadow[MAX_PATH];
        sig_join(sig, sbie_dir, fd.cFileName);
        sig_exe_path(exe, sbie_dir, fd.cFileName);
        if (!exe[0] || GetFileAttributesA(exe) == INVALID_FILE_ATTRIBUTES) continue;

        if (cert_sig_is_vendor(exe, sig, trusted_pub) == 1) continue;

        sig_shadow_path(shadow, sig);
        if (cert_sig_is_vendor(exe, shadow, trusted_pub) == 1) continue;

        LOGE("sig: vendor signature for %s is gone and no shadow exists", fd.cFileName);
        ok = FALSE;
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return ok;
}

/* Put every verified shadow back.  Returns the number restored; *failed
 * counts shadows that did not verify (kept, never deleted). */
static int cert_restore_vendor_sigs(const char *sbie_dir, const BYTE *trusted_pub, int *failed)
{
    if (failed) *failed = 0;

    char pattern[MAX_PATH];
    sig_join(pattern, sbie_dir, "*.sig" SHADOW_SUFFIX);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    int restored = 0;
    do {
        char shadow[MAX_PATH], sig[MAX_PATH], exe[MAX_PATH];
        sig_join(shadow, sbie_dir, fd.cFileName);
        strcpy_s(sig, MAX_PATH, shadow);
        sig_strip(sig, strlen(SHADOW_SUFFIX));
        strcpy_s(exe, MAX_PATH, sig);
        sig_strip(exe, 4);
        if (!exe[0]) continue;

        if (cert_sig_is_vendor(exe, shadow, trusted_pub) != 1) {
            LOGE("restore: %s does not verify - left in place", fd.cFileName);
            if (failed) (*failed)++;
            continue;
        }
        if (!MoveFileExA(shadow, sig, MOVEFILE_REPLACE_EXISTING)) {
            LOGE("restore: cannot put %s back: %lu", fd.cFileName, GetLastError());
            if (failed) (*failed)++;
            continue;
        }
        restored++;
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return restored;
}

/* Older builds kept the vendor files in sig_backup/.  Move the verified
 * ones into shadows once, so their removal path keeps working. */
static void cert_migrate_backup(const char *sbie_dir, const BYTE *trusted_pub)
{
    char bdir[MAX_PATH], marker[MAX_PATH];
    sig_join(bdir, sbie_dir, "sig_backup");
    sig_join(marker, bdir, "verified");
    if (GetFileAttributesA(marker) == INVALID_FILE_ATTRIBUTES) return;

    char pattern[MAX_PATH];
    sig_join(pattern, bdir, "*.sig");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    int moved = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            char src[MAX_PATH], exe[MAX_PATH], shadow[MAX_PATH], sig[MAX_PATH];
            sig_join(src, bdir, fd.cFileName);
            sig_exe_path(exe, sbie_dir, fd.cFileName);
            if (!exe[0] || GetFileAttributesA(exe) == INVALID_FILE_ATTRIBUTES) continue;
            if (cert_sig_is_vendor(exe, src, trusted_pub) != 1) continue;

            sig_join(sig, sbie_dir, fd.cFileName);
            sig_shadow_path(shadow, sig);
            if (GetFileAttributesA(shadow) != INVALID_FILE_ATTRIBUTES) continue;
            if (MoveFileExA(src, shadow, 0)) moved++;
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    if (moved) LOGI("sig: migrated %d verified backup file(s) to shadows", moved);
    DeleteFileA(marker);
    RemoveDirectoryA(bdir); /* only when empty - leftovers are harmless */
}

#endif /* CERTGEN_H */
