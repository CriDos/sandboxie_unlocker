/*
 * selftest.c - L1/L2 test suite: unit + filesystem tests.
 *
 * Groups:
 *   base64     RFC 4648 vectors + capacity guard
 *   crypto     ECDSA P-256 sign/verify round-trip via CNG, negatives
 *   persist    keypair persistence: private-blob roundtrip, file
 *              roundtrip (admin-DACL aware), junk/missing rejection
 *   cethash    certificate body hash determinism
 *   pe         offset->RVA mapping on a real PE file + negatives
 *   pefixture  synthetic SbieDrv-like PE: original key, patched
 *              (ECS1 fallback), multi-magic first-match, no key
 *   fileio     read_file_all edge cases
 *   stale      stale staging cleanup: age grace, locks, pattern
 *   cert       Certificate.dat layout
 *   sec        restrictive DACL read-back behavior vs elevation
 *
 * No kernel access, no Sandboxie interaction - safe to run anywhere.
 * Run from the repo root; argv[1] is a PE file for the mapping tests
 * (default dist\version.dll), argv[2] an optional group filter.
 *
 * Build: _tests.bat
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#include "testfw.h"
#include "../src/fileio.h"
#include "../src/ecrypto.h"
#include "../src/pesearch.h"
#include "../src/certgen.h"
#include "../src/safety.h"
#include "../src/hostguard.h"
#include "../src/kmod.h"
#include "../src/driver_bin.h"
#include "../src/kdrv.h"

/* CHECK plus early return from a void test function on failure. */
#define CHECKV(cond, name)                                       \
    do {                                                         \
        int _c = (int)!!(cond);                                  \
        CHECK(_c, name);                                         \
        if (!_c) return;                                         \
    } while (0)

/* ---------------- helpers ---------------- */

static BOOL write_file_simple(const char *path, const BYTE *data, DWORD size)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written = 0;
    BOOL ok = WriteFile(h, data, size, &written, NULL) && written == size;
    CloseHandle(h);
    return ok;
}

static BOOL exists(const char *path)
{
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static void temp_path(char *out, size_t cap, const char *leaf)
{
    char dir[MAX_PATH];
    GetTempPathA(MAX_PATH, dir);
    _snprintf_s(out, cap, _TRUNCATE, "%s%s", dir, leaf);
}

/* ---------------- base64 ---------------- */

static void test_base64(void)
{
    TF_GROUP("base64");
    static const struct { const char *in; const char *want; } V[] = {
        { "",       ""         },
        { "f",      "Zg=="     },
        { "fo",     "Zm8="     },
        { "foo",    "Zm9v"     },
        { "foob",   "Zm9vYg==" },
        { "fooba",  "Zm9vYmE=" },
        { "foobar", "Zm9vYmFy" },
    };
    for (int i = 0; i < (int)(sizeof(V)/sizeof(V[0])); i++) {
        char out[64];
        int r = ec_base64_encode((const BYTE *)V[i].in,
                                 (ULONG)strlen(V[i].in), out, sizeof(out));
        char name[96];
        _snprintf_s(name, sizeof(name), _TRUNCATE, "encode '%s'", V[i].in);
        CHECK(r == 0 && strcmp(out, V[i].want) == 0, name);
    }
    char tiny[8];
    CHECK(ec_base64_encode((const BYTE *)"foobar", 6, tiny, sizeof(tiny)) != 0,
          "dst_cap guard");
    /* Exact-fit boundary: 64 bytes need exactly 89 chars incl. NUL. */
    BYTE sig64[64] = { 0 };
    char fit[89];
    CHECK(ec_base64_encode(sig64, sizeof(sig64), fit, sizeof(fit)) == 0 &&
          strlen(fit) == 88, "exact-fit buffer accepted");
    CHECK(ec_base64_encode(sig64, sizeof(sig64), fit, sizeof(fit) - 1) != 0,
          "one byte short rejected");
}

/* ---------------- independent CNG verifier ---------------- */

static BCRYPT_KEY_HANDLE vk_import(const BYTE *pub)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE k = NULL;
    if (BCryptOpenAlgorithmProvider(&alg, L"ECDSA_P256", NULL, 0) == 0) {
        BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &k,
                            (BYTE *)pub, BLOB_SIZE, 0);
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return k;
}

static BOOL verify_with_pub(const BYTE *pub, const BYTE *hash, const BYTE *sig)
{
    BCRYPT_KEY_HANDLE k = vk_import(pub);
    if (!k) return FALSE;
    NTSTATUS st = BCryptVerifySignature(k, NULL, (PUCHAR)hash, 32,
                                        (PUCHAR)sig, SIG_SIZE, 0);
    BCryptDestroyKey(k);
    return st == 0;
}

/* ---------------- crypto ---------------- */

static void test_crypto(void)
{
    TF_GROUP("crypto");
    ec_keypair_t kp = { 0 };
    CHECKV(ec_gen_keypair(&kp) == 0, "ec_gen_keypair");

    BYTE pub[BLOB_SIZE];
    CHECKV(ec_export_pub_blob(&kp, pub) == 0, "ec_export_pub_blob");
    CHECK(pub[0] == 'E' && pub[1] == 'C' && pub[2] == 'S' && pub[3] == '1' &&
          pub[4] == 0x20 && pub[5] == 0 && pub[6] == 0 && pub[7] == 0,
          "pub blob ECS1 magic + keysize");

    BYTE hash[32];
    CHECKV(cert_hash_body(hash) == 0, "cert_hash_body");

    BYTE sig[64];
    CHECKV(ec_sign_hash(&kp, hash, sig) == 0, "ec_sign_hash");
    CHECK(verify_with_pub(pub, hash, sig), "verify valid signature");

    BYTE bad[64];
    memcpy(bad, sig, sizeof(bad));
    bad[10] ^= 0x40;
    CHECK(!verify_with_pub(pub, hash, bad), "rejects corrupted signature");

    BYTE other[32];
    memcpy(other, hash, sizeof(other));
    other[0] ^= 1;
    CHECK(!verify_with_pub(pub, other, sig), "rejects different hash");

    /* Zeroed keypair must fail export, not crash. */
    ec_keypair_t dead = { 0 };
    BYTE blob[BLOB_SIZE];
    CHECK(ec_export_pub_blob(&dead, blob) != 0, "export on zeroed keypair fails");

    ec_free_keypair(&kp);
}

/* ---------------- keypair persistence ---------------- */

static void test_persist(void)
{
    TF_GROUP("persist");
    ec_keypair_t kp = { 0 };
    CHECKV(ec_gen_keypair(&kp) == 0, "ec_gen_keypair");

    BYTE pub[BLOB_SIZE];
    CHECKV(ec_export_pub_blob(&kp, pub) == 0, "ec_export_pub_blob");

    BYTE hash[32];
    CHECKV(cert_hash_body(hash) == 0, "cert_hash_body");

    /* In-memory private blob round-trip: export, destroy, re-import. */
    ULONG privLen = 0;
    CHECKV(BCryptExportKey(kp.hKey, NULL, BCRYPT_ECCPRIVATE_BLOB,
                           NULL, 0, &privLen, 0) == 0, "private blob size query");
    BYTE *priv = (BYTE *)HeapAlloc(GetProcessHeap(), 0, privLen);
    CHECKV(priv != NULL &&
           BCryptExportKey(kp.hKey, NULL, BCRYPT_ECCPRIVATE_BLOB,
                           priv, privLen, &privLen, 0) == 0, "private blob export");

    char path[MAX_PATH];
    temp_path(path, sizeof(path), "sbie_selftest_keypair.dat");
    CHECKV(ec_save_keypair(&kp, path) == 0, "ec_save_keypair");
    ec_free_keypair(&kp);

    ec_keypair_t kp2 = { 0 };
    CHECKV(BCryptOpenAlgorithmProvider(&kp2.hAlg, L"ECDSA_P256", NULL, 0) == 0 &&
           BCryptImportKeyPair(kp2.hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB,
                               &kp2.hKey, priv, privLen, 0) == 0,
           "private blob import");
    HeapFree(GetProcessHeap(), 0, priv);
    BYTE sig2[64];
    CHECKV(ec_sign_hash(&kp2, hash, sig2) == 0, "sign after blob reload");
    CHECK(verify_with_pub(pub, hash, sig2),
          "blob reload verifies vs original pub");
    ec_free_keypair(&kp2);

    /* File round-trip: the saved file carries an admin-only DACL, so a
     * non-elevated token cannot read it back (security property). */
    ec_keypair_t kp3 = { 0 };
    if (ec_load_keypair(&kp3, path) == 0) {
        BYTE sig3[64];
        CHECK(ec_sign_hash(&kp3, hash, sig3) == 0, "sign after file reload");
        CHECK(verify_with_pub(pub, hash, sig3), "file roundtrip verifies");
        ec_free_keypair(&kp3);
    } else {
        BYTE *probe = NULL; DWORD psize = 0;
        if (read_file_all(path, &probe, &psize, 4096)) {
            HeapFree(GetProcessHeap(), 0, probe);
            CHECK(FALSE, "file roundtrip (readable but import failed)");
        } else {
            CHECK(!tf_is_elevated(), "unreadable keypair implies non-elevated");
            SKIP_TEST("file roundtrip", "admin-locked DACL, non-elevated token");
        }
    }
    DeleteFileA(path);

    /* Junk and missing files must be rejected, not crash. */
    FILE *f = fopen(path, "wb");
    if (f) { for (int i = 0; i < 100; i++) fputc(0xAA, f); fclose(f); }
    ec_keypair_t kp4 = { 0 };
    CHECK(ec_load_keypair(&kp4, path) != 0, "junk keypair rejected");
    DeleteFileA(path);

    char missing[MAX_PATH];
    temp_path(missing, sizeof(missing), "sbie_selftest_no_such.dat");
    ec_keypair_t kp5 = { 0 };
    CHECK(ec_load_keypair(&kp5, missing) != 0, "missing keypair rejected");

    /* A PUBLIC blob (what the kernel holds) is not a private key:
     * importing it through the private-blob path must fail.  `pub`
     * was exported at the top of this test. */
    char pubPath[MAX_PATH];
    temp_path(pubPath, sizeof(pubPath), "sbie_selftest_pub.dat");
    if (write_file_simple(pubPath, pub, BLOB_SIZE)) {
        ec_keypair_t kp6 = { 0 };
        CHECK(ec_load_keypair(&kp6, pubPath) != 0, "public blob rejected as private");
        DeleteFileA(pubPath);
    }
}

/* ---------------- cert hash ---------------- */

static void test_cert_hash(void)
{
    TF_GROUP("cethash");
    BYTE h1[32], h2[32];
    CHECK(cert_hash_body(h1) == 0 && cert_hash_body(h2) == 0,
          "cert_hash_body twice");
    CHECK(memcmp(h1, h2, 32) == 0, "cert hash deterministic");
}

/* ---------------- PE mapping on a real file ---------------- */

static void test_pe_real(const char *pePath)
{
    TF_GROUP("pe");
    BYTE *data = NULL;
    DWORD size = 0;
    if (!read_file_all(pePath, &data, &size, 16 * 1024 * 1024)) {
        SKIP_TEST("real PE mapping", "PE file unavailable");
        return;
    }

    /* Independent minimal section walk. */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)data;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(data + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    int checked = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData < 64) continue;
        DWORD off = sec[i].PointerToRawData + 32;
        DWORD rva = pe_offset_to_rva(data, size, off);
        char name[96];
        _snprintf_s(name, sizeof(name), _TRUNCATE,
                    "rva mapping section '%.8s'", (const char *)sec[i].Name);
        CHECK(rva == sec[i].VirtualAddress + 32, name);
        checked++;
    }
    CHECK(checked > 0, "at least one mapped section");

    CHECK(pe_offset_to_rva(data, size, size + 16) == 0, "offset past EOF -> 0");
    CHECK(pe_offset_to_rva(data, 4, 0) == 0, "truncated buffer -> 0");

    HeapFree(GetProcessHeap(), 0, data);
}

/* ---------------- synthetic PE fixture ---------------- */

/*
 * Layout of the crafted image (single .data section):
 *   0x000 DOS header (e_lfanew = 0x40)
 *   0x040 NT headers64 + one section header
 *   0x200 section raw data start, VirtualAddress = 0x1000, 0x400 bytes
 *
 * Variants (headers rebuilt before each):
 *   A "original": ORIGINAL_KEY at raw 0x280   -> RVA 0x1080
 *   B "patched":  ECS1 magic only at 0x300    -> RVA 0x1100
 *   C "multi":    ECS1 magics at 0x240, 0x300 -> first, 0x1040
 *   D "empty":    no key material             -> 0
 *   E "bogus":    ECS1 at 0x280, e_lfanew far out -> 0
 *   F "truncated": ORIGINAL_KEY cut to 64 at 0x580 -> magic fallback, 0x1380
 */
static void pe_fixture_headers(BYTE *buf)
{
    /* Full clear: every variant must start clean, or key material from
     * the previous variant wins the exact-match scan. */
    memset(buf, 0, 0x1000);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(buf + 0x40);
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x40;
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = 0x8664;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    /* IMAGE_FIRST_SECTION reads FileHeader.SizeOfOptionalHeader at
     * expansion time - only valid AFTER that field is filled in.
     * (Computing it earlier silently aimed the section header into
     * the optional header and cost a debugging session.) */
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    memcpy(sec->Name, ".data", 6);
    sec->VirtualAddress = 0x1000;
    sec->SizeOfRawData = 0x400;
    sec->PointerToRawData = 0x200;
}

static void test_pe_fixture(void)
{
    TF_GROUP("pefixture");
    static BYTE buf[0x1000];
    char path[MAX_PATH];
    temp_path(path, sizeof(path), "sbie_selftest_fixture.sys");

    /* A: unpatched driver - exact ORIGINAL_KEY wins over the magic. */
    pe_fixture_headers(buf);
    memcpy(buf + 0x280, ORIGINAL_KEY, sizeof(ORIGINAL_KEY));
    CHECKV(write_file_simple(path, buf, sizeof(buf)), "fixture A write");
    CHECK(pe_find_key_rva(path) == 0x1080, "fixture A: ORIGINAL_KEY RVA");

    /* B: patched driver - no ORIGINAL_KEY, single ECS1 magic fallback. */
    pe_fixture_headers(buf);
    memcpy(buf + 0x300, ECS1_PATTERN, sizeof(ECS1_PATTERN));
    CHECKV(write_file_simple(path, buf, sizeof(buf)), "fixture B write");
    CHECK(pe_find_key_rva(path) == 0x1100, "fixture B: ECS1 fallback RVA");

    /* C: several magics - first one in file order wins. */
    pe_fixture_headers(buf);
    memcpy(buf + 0x240, ECS1_PATTERN, sizeof(ECS1_PATTERN));
    memcpy(buf + 0x300, ECS1_PATTERN, sizeof(ECS1_PATTERN));
    CHECKV(write_file_simple(path, buf, sizeof(buf)), "fixture C write");
    CHECK(pe_find_key_rva(path) == 0x1040, "fixture C: first magic wins");

    /* D: no key material at all. */
    pe_fixture_headers(buf);
    CHECKV(write_file_simple(path, buf, sizeof(buf)), "fixture D write");
    CHECK(pe_find_key_rva(path) == 0, "fixture D: no key -> 0");

    /* E: bogus e_lfanew with key material present - the offset is found
     * but the mapping must bail out, not crash. */
    pe_fixture_headers(buf);
    ((IMAGE_DOS_HEADER *)buf)->e_lfanew = 0x7FFFFFFF;
    memcpy(buf + 0x280, ECS1_PATTERN, sizeof(ECS1_PATTERN));
    CHECKV(write_file_simple(path, buf, sizeof(buf)), "fixture E write");
    CHECK(pe_find_key_rva(path) == 0, "fixture E: bogus e_lfanew -> 0");

    /* F: ORIGINAL_KEY truncated to 64 bytes - the exact 72-byte match
     * can never fire, the ECS1 fallback must still find the magic
     * inside the partial key. */
    pe_fixture_headers(buf);
    DWORD truncOff = 0x580;   /* 0x580 + 64 = 0x5C0, inside the section */
    memcpy(buf + truncOff, ORIGINAL_KEY, sizeof(ORIGINAL_KEY) - 8);
    CHECKV(write_file_simple(path, buf, sizeof(buf)), "fixture F write");
    CHECK(pe_find_key_rva(path) == 0x1000 + (truncOff - 0x200),
          "fixture F: truncated key falls back to magic");

    DeleteFileA(path);
}

/* ---------------- fileio ---------------- */

static void test_fileio(void)
{
    TF_GROUP("fileio");
    BYTE *data = NULL;
    DWORD size = 0;

    char missing[MAX_PATH];
    temp_path(missing, sizeof(missing), "sbie_selftest_missing.bin");
    CHECK(!read_file_all(missing, &data, &size, 1024) && data == NULL,
          "missing file -> FALSE");

    char empty[MAX_PATH];
    temp_path(empty, sizeof(empty), "sbie_selftest_empty.bin");
    if (write_file_simple(empty, (const BYTE *)"", 0)) {
        CHECK(!read_file_all(empty, &data, &size, 1024), "empty file -> FALSE");
        DeleteFileA(empty);
    }

    const BYTE payload[16] = "0123456789abcdef";
    char small[MAX_PATH];
    temp_path(small, sizeof(small), "sbie_selftest_small.bin");
    CHECKV(write_file_simple(small, payload, sizeof(payload)), "write 16B");
    CHECK(read_file_all(small, &data, &size, 1024) &&
          size == sizeof(payload) &&
          memcmp(data, payload, sizeof(payload)) == 0, "read back 16B");
    HeapFree(GetProcessHeap(), 0, data);
    data = NULL;
    CHECK(!read_file_all(small, &data, &size, 8) && data == NULL,
          "size above cap -> FALSE");
    DeleteFileA(small);
}

/* ---------------- stale staging cleanup ---------------- */

static void backdate(const char *path, ULONG64 seconds)
{
    HANDLE h = CreateFileA(path, FILE_WRITE_ATTRIBUTES, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER now, past;
    GetSystemTimeAsFileTime((FILETIME *)&now);
    past.QuadPart = now.QuadPart - seconds * 10000000ULL;
    SetFileTime(h, NULL, NULL, (const FILETIME *)&past);
    CloseHandle(h);
}

static void touch(const char *path)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

static void test_stale(void)
{
    TF_GROUP("stale");
    char dir[MAX_PATH];
    GetTempPathA(MAX_PATH, dir);
    strcat_s(dir, MAX_PATH, "sbie_selftest_stale");
    CreateDirectoryA(dir, NULL);

    char young[MAX_PATH], old[MAX_PATH], lockedOld[MAX_PATH], other[MAX_PATH];
    _snprintf_s(young,     sizeof(young),     _TRUNCATE, "%s\\sbie_unlock_young.sys",  dir);
    _snprintf_s(old,       sizeof(old),       _TRUNCATE, "%s\\sbie_unlock_old.sys",    dir);
    _snprintf_s(lockedOld, sizeof(lockedOld), _TRUNCATE, "%s\\sbie_unlock_locked.sys", dir);
    _snprintf_s(other,     sizeof(other),     _TRUNCATE, "%s\\sbie_unlock_keep.dll",   dir);

    touch(young);
    touch(old);       backdate(old, 120);
    touch(lockedOld); backdate(lockedOld, 120);
    touch(other);

    HANDLE held = CreateFileA(lockedOld, GENERIC_READ, 0, NULL,
                              OPEN_EXISTING, 0, NULL);
    CHECK(held != INVALID_HANDLE_VALUE, "test setup: lock held");

    cleanup_stale_temp_drivers(dir);

    CHECK(exists(young),     "keeps young file (grace)");
    CHECK(!exists(old),      "deletes old unlocked file");
    CHECK(exists(lockedOld), "skips old locked file");
    CHECK(exists(other),     "leaves non-.sys files");

    if (held != INVALID_HANDLE_VALUE) CloseHandle(held);
    DeleteFileA(young);
    DeleteFileA(lockedOld);
    DeleteFileA(other);
    RemoveDirectoryA(dir);
}

/* ---------------- certificate layout ---------------- */

static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static BOOL b64_decode(const char *src, BYTE *dst, DWORD dst_cap, DWORD *out_len)
{
    DWORD acc = 0, n = 0;
    int bits = 0;
    for (const char *p = src; *p && *p != '\n' && *p != '\r'; p++) {
        if (*p == '=') break;
        int v = b64_value(*p);
        if (v < 0) return FALSE;
        acc = (acc << 6) | (DWORD)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= dst_cap) return FALSE;
            dst[n++] = (BYTE)((acc >> bits) & 0xFF);
        }
    }
    *out_len = n;
    return TRUE;
}

static void test_cert(void)
{
    TF_GROUP("cert");
    ec_keypair_t kp = { 0 };
    CHECKV(ec_gen_keypair(&kp) == 0, "keygen");

    /* Export the public blob up front: the file's SIGNATURE must verify
     * against it.  ECDSA signing is randomized - two signatures of the
     * same hash differ, so the file signature is verified, not diffed. */
    BYTE pub[BLOB_SIZE];
    CHECKV(ec_export_pub_blob(&kp, pub) == 0, "ec_export_pub_blob");

    char dir[MAX_PATH];
    GetTempPathA(MAX_PATH, dir);
    CHECKV(cert_write(dir, &kp) == 0, "cert_write");
    CHECK(cert_write("Z:\\definitely_missing_dir_xyz", &kp) != 0,
          "cert_write fails on unwritable dir");

    char path[MAX_PATH];
    _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\Certificate.dat", dir);
    BYTE *data = NULL; DWORD size = 0;
    if (!read_file_all(path, &data, &size, 64 * 1024)) {
        CHECK(FALSE, "Certificate.dat readable");
        ec_free_keypair(&kp);
        DeleteFileA(path);
        return;
    }
    CHECK(TRUE, "Certificate.dat readable");
    CHECK(size > 64 && data[size - 1] == '\n', "ends with newline");
    CHECK(memcmp(data, "NAME: ", 6) == 0, "starts with NAME tag");
    CHECK(strstr((char *)data, "TYPE: ETERNAL\n") != NULL, "TYPE: ETERNAL present");
    CHECK(strstr((char *)data, "SIGNATURE: ") != NULL, "SIGNATURE present");

    /* Deep check: decode the file's SIGNATURE and verify it against the
     * body hash recomputed from the same tags. */
    BYTE hash[32];
    CHECK(cert_hash_body(hash) == 0, "recompute body hash");
    char *line = strstr((char *)data, "SIGNATURE: ");
    CHECK(line != NULL, "SIGNATURE line parse");
    if (line) {
        BYTE fileSig[64];
        DWORD fileSigLen = 0;
        CHECK(b64_decode(line + 11, fileSig, sizeof(fileSig), &fileSigLen) &&
              fileSigLen == SIG_SIZE, "signature decodes to 64 bytes");
        CHECK(verify_with_pub(pub, hash, fileSig),
              "file signature verifies against key");
    }

    HeapFree(GetProcessHeap(), 0, data);
    ec_free_keypair(&kp);
    DeleteFileA(path);
}

/* ---------------- restrictive DACL vs elevation ---------------- */

static void test_sec(void)
{
    TF_GROUP("sec");
    char path[MAX_PATH];
    temp_path(path, sizeof(path), "sbie_selftest_dacl.bin");

    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    BYTE acl[512];
    CHECKV(build_restrictive_sa(&sa, &sd, (PACL)acl, sizeof(acl)),
           "build_restrictive_sa");

    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, &sa,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECKV(h != INVALID_HANDLE_VALUE, "create with restrictive DACL");
    const BYTE payload[8] = "SECDATA";
    DWORD written = 0;
    WriteFile(h, payload, sizeof(payload), &written, NULL);
    CloseHandle(h);

    HANDLE r = CreateFileA(path, GENERIC_READ, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (tf_is_elevated()) {
        CHECK(r != INVALID_HANDLE_VALUE, "elevated token reads back");
    } else {
        CHECK(r == INVALID_HANDLE_VALUE &&
              GetLastError() == ERROR_ACCESS_DENIED,
              "non-elevated token denied");
    }
    if (r != INVALID_HANDLE_VALUE) CloseHandle(r);
    DeleteFileA(path);
}

/* ---------------- safe-fail state machine ---------------- */

static void safety_reset_key(void)
{
    /* The key belongs to the unlocker alone (unlock.bat deletes it the
     * same way on Remove Hook / Reset). */
    RegDeleteKeyA(HKEY_CURRENT_USER, SAFETY_REGKEY);
}

static DWORD safety_reg_value(const char *name)
{
    return safety_read_dword(name, 0xFFFFFFFF);
}

static void test_safety(void)
{
    TF_GROUP("safety");
    safety_reset_key();

    /* Fresh begin arms the attempt. */
    CHECKV(safety_begin_attempt() == TRUE, "fresh begin succeeds");
    CHECK(safety_reg_value(SAFETY_REG_ACTIVE) == 1, "begin sets attempt_active");
    CHECK(g_safety_attempt_owned == 1, "begin owns the attempt");

    /* Simulated crash: marker left set, next begin counts a failure. */
    CHECK(safety_begin_attempt() == TRUE, "begin after crash succeeds");
    CHECK(safety_reg_value(SAFETY_REG_FAIL_COUNT) == 1, "crash bumps fail_count");

    /* Controlled failure: clears the marker, keeps the counter. */
    safety_finish_failure();
    CHECK(safety_reg_value(SAFETY_REG_ACTIVE) == 0, "failure clears marker");
    CHECK(safety_reg_value(SAFETY_REG_FAIL_COUNT) == 1, "failure keeps counter");
    CHECK(g_safety_attempt_owned == 0, "failure releases the attempt");

    /* Success: full reset. */
    CHECKV(safety_begin_attempt() == TRUE, "begin after failure succeeds");
    safety_finish_success();
    CHECK(safety_reg_value(SAFETY_REG_FAIL_COUNT) == 0, "success resets counter");
    CHECK(safety_reg_value(SAFETY_REG_ACTIVE) == 0, "success clears marker");

    /* Three interrupted attempts in a row -> safe mode.  Each begin
     * counts the PREVIOUS armed attempt, so the counter reaches the
     * limit one begin later than the naive reading. */
    CHECK(safety_begin_attempt() == TRUE, "interrupted run 1 begins");
    CHECK(safety_reg_value(SAFETY_REG_FAIL_COUNT) == 0, "run 1 not counted yet");
    CHECK(safety_begin_attempt() == TRUE, "interrupted run 2 begins");
    CHECK(safety_reg_value(SAFETY_REG_FAIL_COUNT) == 1, "run 1 counted");
    CHECK(safety_begin_attempt() == TRUE, "interrupted run 3 begins");
    CHECK(safety_reg_value(SAFETY_REG_FAIL_COUNT) == 2, "run 2 counted");
    CHECK(safety_begin_attempt() == FALSE, "run 4 hits safe mode");
    CHECK(safety_reg_value(SAFETY_REG_FAIL_COUNT) == 3, "run 3 counted, limit reached");
    CHECK(safety_begin_attempt() == FALSE, "still locked out");

    /* Clearing the marker alone must not re-arm a locked-out DLL. */
    safety_clear_active_attempt();
    CHECK(safety_begin_attempt() == FALSE, "clear alone does not re-arm");

    /* Recovery: success resets everything. */
    safety_finish_success();
    CHECK(safety_begin_attempt() == TRUE, "post-reset begin succeeds");
    safety_finish_success();
    safety_reset_key();
}

/* ---------------- host filter predicate ---------------- */

static void test_host(void)
{
    TF_GROUP("host");
    CHECK(is_sandman_path("C:\\Program Files\\Sandboxie-Plus\\SandMan.exe") == TRUE,
          "full path matches");
    CHECK(is_sandman_path("c:\\x\\sandman.EXE") == TRUE, "case-insensitive match");
    CHECK(is_sandman_path("SandMan.exe") == TRUE, "bare name matches");
    CHECK(is_sandman_path("C:\\x\\SandMan2.exe") == FALSE, "prefix mismatch rejected");
    CHECK(is_sandman_path("C:\\x\\SbieSvc.exe") == FALSE, "other host rejected");
    CHECK(is_sandman_path("") == FALSE, "empty path rejected");
    CHECK(is_sandman_process() == FALSE, "test exe is not SandMan");
}

/* ---------------- staged driver verification ---------------- */

static void test_kdrv_verify(void)
{
    TF_GROUP("kdrv");
    char path[MAX_PATH];
    temp_path(path, sizeof(path), "sbie_selftest_stage.sys");

    CHECKV(write_file_simple(path, g_driver_bin, g_driver_size),
           "stage driver bytes");
    CHECK(kdrv_verify_driver_file(path) == TRUE, "exact embedded bytes verify");

    /* One flipped byte must fail verification (swap-race guard). */
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    CHECKV(h != INVALID_HANDLE_VALUE, "reopen staged file");
    BYTE flip = g_driver_bin[64] ^ 0xFF;
    DWORD w = 0;
    SetFilePointer(h, 64, NULL, FILE_BEGIN);
    WriteFile(h, &flip, 1, &w, NULL);
    CloseHandle(h);
    CHECK(kdrv_verify_driver_file(path) == FALSE, "corrupted byte rejected");

    /* Truncated file rejected. */
    CHECKV(write_file_simple(path, g_driver_bin, g_driver_size - 1),
           "truncate stage file");
    CHECK(kdrv_verify_driver_file(path) == FALSE, "truncated file rejected");
    DeleteFileA(path);
}

/* ---------------- kernel module lookup (user-mode API smoke) ---------------- */

static void test_kmod(void)
{
    TF_GROUP("kmod");
    ULONG size = 0;
    ULONG64 base = kmod_find("ntoskrnl", &size);
    /* Non-elevated tokens may receive a list with every ImageBase
     * zeroed (observed on recent builds) - the product only runs
     * elevated, so the hard check is elevation-gated. */
    if (!tf_is_elevated() && base == 0) {
        SKIP_TEST("ntoskrnl lookup", "module bases zeroed for non-elevated token");
    } else {
        CHECK(base != 0, "ntoskrnl found in kernel module list");
        CHECK(size > 0x100000, "module image size sane");
    }
    CHECK(kmod_find("definitely_not_a_kernel_module_xyz", NULL) == 0,
          "absent module -> 0");
}

/* ---------------- logger ---------------- */

static DWORD file_size(const char *path)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD size = GetFileSize(h, NULL);
    CloseHandle(h);
    return size == INVALID_FILE_SIZE ? 0 : size;
}

static void test_log(void)
{
    TF_GROUP("log");
    char logp[MAX_PATH];
    GetModuleFileNameA(NULL, logp, MAX_PATH);
    char *slash = strrchr(logp, '\\');
    strcpy_s(slash ? slash + 1 : logp, MAX_PATH, "version_hook.log");

    DWORD before = file_size(logp);
    LOGI("selftest marker %u", GetTickCount());
    CHECK(file_size(logp) > before, "log line appended");

    /* A message far beyond the 1024-byte buffer must truncate, not
     * corrupt the file or crash. */
    static char big[4000];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = 0;
    DWORD mid = file_size(logp);
    LOGW("%s", big);
    CHECK(file_size(logp) > mid, "oversized message truncated safely");
}

int main(int argc, char **argv)
{
    TF_INIT(argc > 2 ? argv[2] : NULL);
    const char *pePath = (argc > 1) ? argv[1] : "dist\\version.dll";

    printf("== sandboxie_unlocker selftest ==\n");
    test_base64();
    test_crypto();
    test_persist();
    test_cert_hash();
    test_pe_real(pePath);
    test_pe_fixture();
    test_fileio();
    test_stale();
    test_cert();
    test_sec();
    test_safety();
    test_host();
    test_kdrv_verify();
    test_kmod();
    test_log();
    return tf_summary();
}
