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
 *              (ECS1 fallback), multi-magic first-match, no key,
 *              writable vs read-only section reporting
 *   fileio     read_file_all edge cases
 *   stale      stale staging cleanup: age grace, locks, pattern
 *   cert       Certificate.dat layout
 *   sec        restrictive DACL read-back behavior vs elevation
 *   safety     safe-fail state machine (interrupted attempts, safe mode)
 *   host       SandMan host predicate
 *   kdrv       staged helper driver content verification
 *   pte        PTE alias math + self-map base vote scan
 *   sigshadow  vendor .sig shadows (move aside / restore / gate)
 *   sbieapi    SbieDll-backed calls fail cleanly without Sandboxie
 *   kmod       kernel module lookup smoke
 *   log        logger append + truncation
 *
 * No kernel access, no Sandboxie interaction - safe to run anywhere.
 * Run from the repo root; argv[1] is a PE file for the mapping tests
 * (default dist\version.dll), argv[2] an optional group filter.
 *
 * Build: _tests.bat
 */
#define WIN32_LEAN_AND_MEAN
/* C6553 is SDK-header SAL noise for RegOpenKeyExA(..., 0, ...); suppress it
 * before the includes, same as the DLL does. */
#pragma warning(disable : 6553)
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
#include "../src/pagemap.h"
#include "../src/sbieapi.h"

/* CHECK plus early return from a void test function on failure. */
#define CHECKV(cond, name)      \
    do {                        \
        int _c = (int)!!(cond); \
        CHECK(_c, name);        \
        if (!_c) return;        \
    } while (0)

/* ---------------- helpers ---------------- */

static BOOL write_file_simple(const char *path, const BYTE *data, DWORD size)
{
    HANDLE h =
        CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written = 0;
    BOOL ok = WriteFile(h, data, size, &written, NULL) && written == size;
    CloseHandle(h);
    return ok;
}

static BOOL exists(const char *path)
{ return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES; }

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
    static const struct {
        const char *in;
        const char *want;
    } V[] = {
        {"", ""},
        {"f", "Zg=="},
        {"fo", "Zm8="},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="},
        {"fooba", "Zm9vYmE="},
        {"foobar", "Zm9vYmFy"},
    };
    for (int i = 0; i < (int)(sizeof(V) / sizeof(V[0])); i++) {
        char out[64];
        int r = ec_base64_encode((const BYTE *)V[i].in, (ULONG)strlen(V[i].in), out, sizeof(out));
        char name[96];
        _snprintf_s(name, sizeof(name), _TRUNCATE, "encode '%s'", V[i].in);
        CHECK(r == 0 && strcmp(out, V[i].want) == 0, name);
    }
    char tiny[8];
    CHECK(ec_base64_encode((const BYTE *)"foobar", 6, tiny, sizeof(tiny)) != 0, "dst_cap guard");
    /* Exact-fit boundary: 64 bytes need exactly 89 chars incl. NUL. */
    BYTE sig64[64] = {0};
    char fit[89];
    CHECK(ec_base64_encode(sig64, sizeof(sig64), fit, sizeof(fit)) == 0 && strlen(fit) == 88,
          "exact-fit buffer accepted");
    CHECK(ec_base64_encode(sig64, sizeof(sig64), fit, sizeof(fit) - 1) != 0,
          "one byte short rejected");
}

/* ---------------- independent CNG verifier ---------------- */

static BCRYPT_KEY_HANDLE vk_import(const BYTE *pub)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE k = NULL;
    if (BCryptOpenAlgorithmProvider(&alg, L"ECDSA_P256", NULL, 0) == 0) {
        (void)BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &k, (BYTE *)pub, BLOB_SIZE, 0);
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return k;
}

static BOOL verify_with_pub(const BYTE *pub, const BYTE *hash, const BYTE *sig)
{
    BCRYPT_KEY_HANDLE k = vk_import(pub);
    if (!k) return FALSE;
    NTSTATUS st = BCryptVerifySignature(k, NULL, (PUCHAR)hash, 32, (PUCHAR)sig, SIG_SIZE, 0);
    BCryptDestroyKey(k);
    return st == 0;
}

/* ---------------- crypto ---------------- */

static void test_crypto(void)
{
    TF_GROUP("crypto");
    ec_keypair_t kp = {0};
    CHECKV(ec_gen_keypair(&kp) == 0, "ec_gen_keypair");

    BYTE pub[BLOB_SIZE];
    CHECKV(ec_export_pub_blob(&kp, pub) == 0, "ec_export_pub_blob");
    CHECK(pub[0] == 'E' && pub[1] == 'C' && pub[2] == 'S' && pub[3] == '1' && pub[4] == 0x20 &&
              pub[5] == 0 && pub[6] == 0 && pub[7] == 0,
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
    ec_keypair_t dead = {0};
    BYTE blob[BLOB_SIZE];
    CHECK(ec_export_pub_blob(&dead, blob) != 0, "export on zeroed keypair fails");

    ec_free_keypair(&kp);
}

/* ---------------- keypair persistence ---------------- */

static void test_persist(void)
{
    TF_GROUP("persist");
    ec_keypair_t kp = {0};
    CHECKV(ec_gen_keypair(&kp) == 0, "ec_gen_keypair");
    CHECKV(kp.hKey != NULL, "keypair handle");

    BYTE pub[BLOB_SIZE];
    CHECKV(ec_export_pub_blob(&kp, pub) == 0, "ec_export_pub_blob");

    BYTE hash[32];
    CHECKV(cert_hash_body(hash) == 0, "cert_hash_body");

    /* In-memory private blob round-trip: export, destroy, re-import. */
    ULONG privLen = 0;
    CHECKV(BCryptExportKey(kp.hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &privLen, 0) == 0,
           "private blob size query");
    BYTE *priv = (BYTE *)HeapAlloc(GetProcessHeap(), 0, privLen);
    CHECKV(priv != NULL && BCryptExportKey(kp.hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, priv, privLen,
                                           &privLen, 0) == 0,
           "private blob export");

    char path[MAX_PATH];
    temp_path(path, sizeof(path), "sbie_selftest_keypair.dat");
    CHECKV(ec_save_keypair(&kp, path) == 0, "ec_save_keypair");
    ec_free_keypair(&kp);

    ec_keypair_t kp2 = {0};
    CHECKV(BCryptOpenAlgorithmProvider(&kp2.hAlg, L"ECDSA_P256", NULL, 0) == 0 &&
               BCryptImportKeyPair(kp2.hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB, &kp2.hKey, priv, privLen,
                                   0) == 0,
           "private blob import");
    HeapFree(GetProcessHeap(), 0, priv);
    BYTE sig2[64];
    CHECKV(ec_sign_hash(&kp2, hash, sig2) == 0, "sign after blob reload");
    CHECK(verify_with_pub(pub, hash, sig2), "blob reload verifies vs original pub");
    ec_free_keypair(&kp2);

    /* File round-trip: the saved file carries an admin-only DACL, so a
     * non-elevated token cannot read it back (security property). */
    ec_keypair_t kp3 = {0};
    if (ec_load_keypair(&kp3, path) == 0) {
        BYTE sig3[64];
        CHECK(ec_sign_hash(&kp3, hash, sig3) == 0, "sign after file reload");
        CHECK(verify_with_pub(pub, hash, sig3), "file roundtrip verifies");
        ec_free_keypair(&kp3);
    } else {
        BYTE *probe = NULL;
        DWORD psize = 0;
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
    if (f) {
        for (int i = 0; i < 100; i++) fputc(0xAA, f);
        fclose(f);
    }
    ec_keypair_t kp4 = {0};
    CHECK(ec_load_keypair(&kp4, path) != 0, "junk keypair rejected");
    DeleteFileA(path);

    char missing[MAX_PATH];
    temp_path(missing, sizeof(missing), "sbie_selftest_no_such.dat");
    ec_keypair_t kp5 = {0};
    CHECK(ec_load_keypair(&kp5, missing) != 0, "missing keypair rejected");

    /* A PUBLIC blob (what the kernel holds) is not a private key:
     * importing it through the private-blob path must fail.  `pub`
     * was exported at the top of this test. */
    char pubPath[MAX_PATH];
    temp_path(pubPath, sizeof(pubPath), "sbie_selftest_pub.dat");
    if (write_file_simple(pubPath, pub, BLOB_SIZE)) {
        ec_keypair_t kp6 = {0};
        CHECK(ec_load_keypair(&kp6, pubPath) != 0, "public blob rejected as private");
        DeleteFileA(pubPath);
    }
}

/* ---------------- boot fast path: public blob from a saved private blob ---
 *
 * The fast path runs under the loader lock and must not pull in CNG, so
 * the kernel key is recovered from keypair.dat as raw bytes. */

static void test_fast_pub(void)
{
    TF_GROUP("fastpub");
    ec_keypair_t kp = {0};
    CHECKV(ec_gen_keypair(&kp) == 0, "ec_gen_keypair");
    CHECKV(kp.hKey != NULL, "keypair handle");

    BYTE pub[BLOB_SIZE];
    CHECKV(ec_export_pub_blob(&kp, pub) == 0, "ec_export_pub_blob");

    ULONG privLen = 0;
    CHECKV(BCryptExportKey(kp.hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &privLen, 0) == 0,
           "private blob size query");
    BYTE priv[128];
    CHECKV(privLen <= sizeof(priv) && BCryptExportKey(kp.hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, priv,
                                                      sizeof(priv), &privLen, 0) == 0,
           "private blob export");
    CHECKV(privLen == 104, "P-256 private blob is 104 bytes");
    CHECK(memcmp(priv, "ECS2", 4) == 0, "private blob magic is ECS2");
    ec_free_keypair(&kp);

    BYTE recovered[BLOB_SIZE];
    CHECKV(ec_pub_from_priv_data(priv, privLen, recovered) == 0, "public blob recovered");
    CHECK(memcmp(recovered, pub, BLOB_SIZE) == 0, "recovered blob == exported public");

    /* Truncated, wrong-magic and wrong-cbKey blobs must be rejected. */
    CHECK(ec_pub_from_priv_data(priv, privLen - 1, recovered) != 0, "short blob rejected");
    BYTE bad[104];
    memcpy(bad, priv, sizeof(bad));
    bad[0] = 'X';
    CHECK(ec_pub_from_priv_data(bad, sizeof(bad), recovered) != 0, "wrong magic rejected");
    memcpy(bad, priv, sizeof(bad));
    bad[4] = 0x21;
    CHECK(ec_pub_from_priv_data(bad, sizeof(bad), recovered) != 0, "wrong cbKey rejected");
    CHECK(ec_pub_from_priv_data(pub, BLOB_SIZE, recovered) != 0, "public blob rejected as private");

    /* File variant: a saved keypair round-trips, junk does not. */
    char path[MAX_PATH];
    temp_path(path, sizeof(path), "sbie_selftest_fastpub.dat");
    CHECKV(write_file_simple(path, priv, privLen), "keypair fixture written");
    CHECKV(ec_pub_from_priv_file(path, recovered) == 0, "public blob from file");
    CHECK(memcmp(recovered, pub, BLOB_SIZE) == 0, "file blob == exported public");
    DeleteFileA(path);

    BYTE junk[100];
    memset(junk, 0xAA, sizeof(junk));
    CHECKV(write_file_simple(path, junk, sizeof(junk)), "junk fixture written");
    CHECK(ec_pub_from_priv_file(path, recovered) != 0, "junk file rejected");
    DeleteFileA(path);

    char missing[MAX_PATH];
    temp_path(missing, sizeof(missing), "sbie_selftest_no_such_fastpub.dat");
    CHECK(ec_pub_from_priv_file(missing, recovered) != 0, "missing file rejected");
}

/* ---------------- cert hash ---------------- */

static void test_cert_hash(void)
{
    TF_GROUP("cethash");
    BYTE h1[32] = {0}, h2[32] = {0};
    CHECK(cert_hash_body(h1) == 0 && cert_hash_body(h2) == 0, "cert_hash_body twice");
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
        _snprintf_s(name, sizeof(name), _TRUNCATE, "rva mapping section '%.8s'",
                    (const char *)sec[i].Name);
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
    /* Identity fields: pe_image_identity compares exactly these with the
     * mapped image (SizeOfImage) and the build stamp (TimeDateStamp). */
    nt->OptionalHeader.SizeOfImage = 0x4000;
    nt->FileHeader.TimeDateStamp = 0x5F5E1000;
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
    BOOL writable = FALSE;
    CHECK(pe_find_key_rva_ex(path, &writable) == 0x1080 && writable == FALSE,
          "fixture A: ORIGINAL_KEY RVA (read-only section)");
    pe_fixture_headers(buf);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION((IMAGE_NT_HEADERS64 *)(buf + 0x40));
    sec->Characteristics = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;
    memcpy(buf + 0x280, ORIGINAL_KEY, sizeof(ORIGINAL_KEY));
    CHECKV(write_file_simple(path, buf, sizeof(buf)), "fixture A-write write");
    writable = FALSE;
    CHECK(pe_find_key_rva_ex(path, &writable) == 0x1080 && writable == TRUE,
          "fixture A/writable: writable section reported");
    CHECK(pe_find_key_rva(path) == 0x1080, "fixture A: wrapper keeps the RVA");

    /* Identity: the same headers the driver check compares against. */
    ULONG idSize = 0, idTs = 0;
    CHECKV(pe_image_identity(path, &idSize, &idTs), "identity: PE headers read");
    CHECK(idSize == 0x4000 && idTs == 0x5F5E1000, "identity: SizeOfImage + timestamp");
    CHECKV(write_file_simple(path, (const BYTE *)"not a PE", 8), "identity: junk write");
    CHECK(!pe_image_identity(path, NULL, NULL), "identity: non-PE rejected");
    CHECK(!pe_image_identity("Z:\\no_such_dir\\SbieDrv.sys", NULL, NULL),
          "identity: missing file rejected");

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
    DWORD truncOff = 0x580; /* 0x580 + 64 = 0x5C0, inside the section */
    memcpy(buf + truncOff, ORIGINAL_KEY, sizeof(ORIGINAL_KEY) - 8);
    CHECKV(write_file_simple(path, buf, sizeof(buf)), "fixture F write");
    CHECK(pe_find_key_rva(path) == 0x1000 + (truncOff - 0x200),
          "fixture F: truncated key falls back to magic");

    /* G: key blob crossing a section boundary.  The section holding the
     * first byte is read-only, the tail lands in a writable one: writing
     * through the reported permission would hit the read-only half and
     * bugcheck, so the finder must refuse instead of returning half a
     * truth. */
    pe_fixture_headers(buf);
    {
        IMAGE_NT_HEADERS64 *nt2 = (IMAGE_NT_HEADERS64 *)(buf + 0x40);
        nt2->FileHeader.NumberOfSections = 2;
        IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt2);
        memcpy(s[0].Name, ".rdata", 7);
        s[0].VirtualAddress = 0x1000;
        s[0].SizeOfRawData = 0x400;
        s[0].PointerToRawData = 0x200; /* raw 0x200..0x5FF */
        s[0].Characteristics = IMAGE_SCN_MEM_READ;
        memcpy(s[1].Name, ".data", 6);
        s[1].VirtualAddress = 0x2000;
        s[1].SizeOfRawData = 0x400;
        s[1].PointerToRawData = 0x600; /* raw 0x600..0x9FF */
        s[1].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        memcpy(buf + 0x5D0, ORIGINAL_KEY, sizeof(ORIGINAL_KEY)); /* crosses 0x600 */
    }
    CHECKV(write_file_simple(path, buf, sizeof(buf)), "fixture G write");
    CHECK(pe_find_key_rva(path) == 0, "fixture G: blob across sections -> 0");

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
    CHECK(!read_file_all(missing, &data, &size, 1024) && data == NULL, "missing file -> FALSE");

    char empty[MAX_PATH];
    temp_path(empty, sizeof(empty), "sbie_selftest_empty.bin");
    if (write_file_simple(empty, (const BYTE *)"", 0)) {
        CHECK(!read_file_all(empty, &data, &size, 1024), "empty file -> FALSE");
        DeleteFileA(empty);
    }

    BYTE payload[16];
    memcpy(payload, "0123456789abcdef", sizeof(payload));
    char tiny[MAX_PATH];
    temp_path(tiny, sizeof(tiny), "sbie_selftest_small.bin");
    CHECKV(write_file_simple(tiny, payload, sizeof(payload)), "write 16B");
    CHECK(read_file_all(tiny, &data, &size, 1024) && size == sizeof(payload) &&
              memcmp(data, payload, sizeof(payload)) == 0,
          "read back 16B");
    HeapFree(GetProcessHeap(), 0, data);
    data = NULL;
    CHECK(!read_file_all(tiny, &data, &size, 8) && data == NULL, "size above cap -> FALSE");
    DeleteFileA(tiny);
}

/* ---------------- stale staging cleanup ---------------- */

static void backdate(const char *path, ULONG64 seconds)
{
    HANDLE h = CreateFileA(path, FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER now, past;
    GetSystemTimeAsFileTime((FILETIME *)&now);
    past.QuadPart = now.QuadPart - seconds * 10000000ULL;
    SetFileTime(h, NULL, NULL, (const FILETIME *)&past);
    CloseHandle(h);
}

static void touch(const char *path)
{
    HANDLE h =
        CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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
    _snprintf_s(young, sizeof(young), _TRUNCATE, "%s\\sbie_unlock_young.sys", dir);
    _snprintf_s(old, sizeof(old), _TRUNCATE, "%s\\sbie_unlock_old.sys", dir);
    _snprintf_s(lockedOld, sizeof(lockedOld), _TRUNCATE, "%s\\sbie_unlock_locked.sys", dir);
    _snprintf_s(other, sizeof(other), _TRUNCATE, "%s\\sbie_unlock_keep.dll", dir);

    touch(young);
    touch(old);
    backdate(old, 120);
    touch(lockedOld);
    backdate(lockedOld, 120);
    touch(other);

    HANDLE held = CreateFileA(lockedOld, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(held != INVALID_HANDLE_VALUE, "test setup: lock held");

    cleanup_stale_temp_drivers(dir);

    CHECK(exists(young), "keeps young file (grace)");
    CHECK(!exists(old), "deletes old unlocked file");
    CHECK(exists(lockedOld), "skips old locked file");
    CHECK(exists(other), "leaves non-.sys files");

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
    ec_keypair_t kp = {0};
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
    BYTE *data = NULL;
    DWORD size = 0;
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
    const char *line = strstr((char *)data, "SIGNATURE: ");
    CHECK(line != NULL, "SIGNATURE line parse");
    if (line) {
        BYTE fileSig[64];
        DWORD fileSigLen = 0;
        CHECK(b64_decode(line + 11, fileSig, sizeof(fileSig), &fileSigLen) &&
                  fileSigLen == SIG_SIZE,
              "signature decodes to 64 bytes");
        CHECK(verify_with_pub(pub, hash, fileSig), "file signature verifies against key");
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
    CHECKV(build_restrictive_sa(&sa, &sd, (PACL)acl, sizeof(acl)), "build_restrictive_sa");

    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECKV(h != INVALID_HANDLE_VALUE, "create with restrictive DACL");
    const BYTE payload[8] = "SECDATA";
    DWORD written = 0;
    WriteFile(h, payload, sizeof(payload), &written, NULL);
    CloseHandle(h);

    HANDLE r = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (tf_is_elevated()) {
        CHECK(r != INVALID_HANDLE_VALUE, "elevated token reads back");
    } else {
        CHECK(r == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED,
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
{ return safety_read_dword(name, 0xFFFFFFFF); }

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

    CHECKV(write_file_simple(path, g_driver_bin, g_driver_size), "stage driver bytes");
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
    CHECKV(write_file_simple(path, g_driver_bin, g_driver_size - 1), "truncate stage file");
    CHECK(kdrv_verify_driver_file(path) == FALSE, "truncated file rejected");
    DeleteFileA(path);
}

/* ---------------- PTE alias math (writes into read-only pages) ---------------- */

static void test_pte(void)
{
    TF_GROUP("pte");

    /* Machine-dependent: 4-level paging, or refused on LA57 systems. */
    if (!kdrv_pte_supported())
        SKIP_TEST("4-level paging", "LA57 host - PTE alias unsupported by design");
    else
        CHECK(kdrv_pte_supported(), "4-level paging");

    /* Fixed pre-RS1 base doubles as the arithmetic fixture. */
    const ULONG64 PTE_BASE = 0xFFFFF68000000000ULL;

    CHECK(kdrv_pte_va(PTE_BASE, 0) == PTE_BASE, "page 0 PTE");
    CHECK(kdrv_pte_va(PTE_BASE, 0x1000) == PTE_BASE + 8, "consecutive pages are 8 bytes apart");

    /* Real key VA from the 0xBE dump (SbieDrv base + RVA 0x330C0): only the
     * low 36 bits of (va >> 12) are indices, the canonical sign extension
     * above them must not leak into the address. */
    ULONG64 kernel_va = 0xFFFFF8065E5130C0ULL;
    ULONG64 pte = kdrv_pte_va(PTE_BASE, kernel_va);
    CHECK(pte >= PTE_BASE && pte < PTE_BASE + 0x8000000000ULL,
          "kernel VA PTE stays in the self-map window");
    CHECK((pte & 7) == 0, "PTE address is 8-byte aligned");
    CHECK(pte == kdrv_pte_va(PTE_BASE, kernel_va & 0x0000FFFFFFFFFFFFULL),
          "sign extension of the VA is ignored");

    /* Alias entry built from the read-only .rdata PTE captured in the dump. */
    ULONG64 src = 0x8900001089a35021ULL;
    ULONG64 alias = kdrv_alias_pte(src);
    CHECK((src & 0x2) == 0, "dump PTE fixture is read-only");
    CHECK((alias & 0x000FFFFFFFFFF000ULL) == (src & 0x000FFFFFFFFFF000ULL),
          "alias keeps the physical frame");
    CHECK((alias & 0x1) != 0 && (alias & 0x2) != 0, "alias is present and writable");
    CHECK((alias & 0x4) == 0, "alias stays supervisor (SMAP)");
    CHECK(alias & 0x8000000000000000ULL, "alias is non-executable");
    CHECK((alias & ~0x000FFFFFFFFFF000ULL) == 0x8000000000000003ULL,
          "alias carries no flags from the source PTE");

    /* Self-map base shape. */
    CHECK(kdrv_is_pte_base(0xFFFFF88000000000ULL), "real base from the dump accepted");
    CHECK(kdrv_is_pte_base(0xFFFFF68000000000ULL), "pre-RS1 fixed base accepted");
    CHECK(!kdrv_is_pte_base(0), "zero rejected");
    CHECK(!kdrv_is_pte_base(0xFFFFF88000000001ULL), "low bits rejected");
    CHECK(!kdrv_is_pte_base(0xFFFFF88000001000ULL), "page offset rejected");
    CHECK(!kdrv_is_pte_base(0x0000F88000000000ULL), "user-half value rejected");

    /* PTE arithmetic votes for the global it is applied to.  Addresses are
     * the live 24H2 ones (.text 0x504E31 -> nt!MmPteBase at 0xFC44C8). */
    kdrv_pte_target_t targets[KDRV_MAX_PTE_TARGETS];
    int target_count = 0;
    const ULONG64 storage = 0xFFFFF80000FC44C8ULL;
    const ULONG64 code_va = 0xFFFFF80000504E31ULL;
    INT32 disp = (INT32)(storage - (code_va + 7));
    BYTE code[64];

    memset(code, 0x90, sizeof(code));
    code[0] = 0x48;
    code[1] = 0x8B;
    code[2] = 0x05; /* mov rax, [rip+disp] */
    memcpy(code + 3, &disp, sizeof(disp));
    code[7] = 0x48;
    code[8] = 0xC1;
    code[9] = 0xEB;
    code[10] = 0x09; /* shr rbx,9 */
    kdrv_rank_refs(code, sizeof(code), code_va, targets, &target_count);
    CHECK(target_count == 1 && targets[0].target == storage && targets[0].refs == 1,
          "live 24H2 reference votes for MmPteBase");

    kdrv_rank_refs(code, sizeof(code), code_va, targets, &target_count);
    CHECK(target_count == 1 && targets[0].refs == 2, "repeated reference adds a vote");

    memset(code, 0x90, sizeof(code));
    code[0] = 0x4C;
    code[1] = 0x8B;
    code[2] = 0x0D; /* mov r9, [rip+disp] */
    memcpy(code + 3, &disp, sizeof(disp));
    code[7] = 0x48;
    code[8] = 0xC1;
    code[9] = 0xEA;
    code[10] = 0x09; /* shr rdx,9 */
    target_count = 0;
    kdrv_rank_refs(code, sizeof(code), code_va, targets, &target_count);
    CHECK(target_count == 1 && targets[0].target == storage, "another register is scored");

    memset(code, 0x90, sizeof(code));
    code[0] = 0x48;
    code[1] = 0x8B;
    code[2] = 0x05; /* plain load, no PTE math */
    memcpy(code + 3, &disp, sizeof(disp));
    code[7] = 0x48;
    code[8] = 0x8B;
    code[9] = 0xCB;
    target_count = 0;
    kdrv_rank_refs(code, sizeof(code), code_va, targets, &target_count);
    CHECK(target_count == 0, "a global without PTE arithmetic gets no vote");

    memset(code, 0x90, sizeof(code));
    code[0] = 0x48;
    code[1] = 0x8B;
    code[2] = 0x05; /* mov rax, [rip+disp] */
    memcpy(code + 3, &disp, sizeof(disp));
    code[7] = 0x48;
    code[8] = 0x8D;
    code[9] = 0x1C;
    code[10] = 0xDD;
    code[11] = 0;
    code[12] = 0;
    code[13] = 0;
    code[14] = 0; /* lea rbx,[rbx*8] */
    target_count = 0;
    kdrv_rank_refs(code, sizeof(code), code_va, targets, &target_count);
    CHECK(target_count == 1 && targets[0].target == storage, "lea *8 spelling scores");

    /* The section table offset must include e_lfanew.  ntoskrnl's 0x118 is
     * a multiple of 40, so an omitted e_lfanew still lands on real section
     * headers 7 entries late - this exact bug shipped and only showed up
     * when the arithmetic was checked against the header by hand. */
    IMAGE_DOS_HEADER tdos;
    IMAGE_NT_HEADERS64 tnt;
    memset(&tdos, 0, sizeof(tdos));
    memset(&tnt, 0, sizeof(tnt));
    tnt.FileHeader.SizeOfOptionalHeader = 0xF0;
    tdos.e_lfanew = 0x118;
    CHECK(kdrv_section_table_off(&tdos, &tnt) == 0x118 + 24 + 0xF0,
          "section table offset includes e_lfanew (ntoskrnl layout)");
    tdos.e_lfanew = 0xF8;
    CHECK(kdrv_section_table_off(&tdos, &tnt) == 0xF8 + 24 + 0xF0,
          "section table offset follows e_lfanew");

    /* Only live sections may be read: a global in the zero-filled tail of a
     * section counts, a discarded INIT section never does. */
    IMAGE_SECTION_HEADER secs[2];
    memset(secs, 0, sizeof(secs));
    secs[0].VirtualAddress = 0x1000;
    secs[0].Misc.VirtualSize = 0x2000; /* raw data ends at 0x2000 */
    secs[0].SizeOfRawData = 0x1000;
    secs[0].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
    secs[1].VirtualAddress = 0x5000;
    secs[1].Misc.VirtualSize = 0x1000;
    secs[1].SizeOfRawData = 0x1000;
    secs[1].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE;
    const ULONG64 img2 = 0xFFFFF80000000000ULL;
    const ULONG64 img2_size = 0x10000ULL;

    CHECK(kdrv_target_mapped(secs, 2, img2, img2_size, img2 + 0x1800),
          "a global in the uninitialised tail is readable");
    CHECK(!kdrv_target_mapped(secs, 2, img2, img2_size, img2 + 0x5800),
          "a discarded section is not readable");
    CHECK(!kdrv_target_mapped(secs, 2, img2, img2_size, img2 + 0x9000),
          "an address outside every section is rejected");
}

/* ---------------- vendor signature shadows ---------------- */

static void test_sigshadow(void)
{
    TF_GROUP("sigshadow");

    /* "Vendor" key (stands in for the baked ORIGINAL_KEY, whose private
     * half nobody has) and "our" re-signing key. */
    ec_keypair_t vendor = {0}, ours = {0};
    BYTE vendorPub[BLOB_SIZE], ourPub[BLOB_SIZE];
    CHECKV(ec_gen_keypair(&vendor) == 0 && ec_export_pub_blob(&vendor, vendorPub) == 0,
           "vendor keypair");
    CHECKV(ec_gen_keypair(&ours) == 0 && ec_export_pub_blob(&ours, ourPub) == 0, "our keypair");

    char dir[MAX_PATH], exe[MAX_PATH], sig[MAX_PATH], shadow[MAX_PATH];
    temp_path(dir, sizeof(dir), "sbie_selftest_sigshadow");
    temp_path(exe, sizeof(exe), "sbie_selftest_sigshadow\\App.exe");
    temp_path(sig, sizeof(sig), "sbie_selftest_sigshadow\\App.exe.sig");
    temp_path(shadow, sizeof(shadow), "sbie_selftest_sigshadow\\App.exe.sig.vendor");

    CHECKV(CreateDirectoryA(dir, NULL) || GetLastError() == ERROR_ALREADY_EXISTS,
           "create fixture dir");
    /* Leftovers from an aborted run must not fake a signature. */
    DeleteFileA(sig);
    DeleteFileA(shadow);
    CHECKV(write_file_simple(exe, (const BYTE *)"fake executable payload", 24),
           "write fixture exe");

    BYTE hash[32];
    CHECKV(sha256_file(exe, hash) == 0, "hash fixture exe");
    BYTE vendorSig[SIG_SIZE], ourSig[SIG_SIZE];
    CHECKV(ec_sign_hash(&vendor, hash, vendorSig) == 0, "sign with vendor key");
    CHECKV(ec_sign_hash(&ours, hash, ourSig) == 0, "sign with our key");

    CHECK(cert_sig_is_vendor(exe, sig, vendorPub) == -1, "missing .sig is unreadable");

    /* 1. Stock install: the vendor signature moves aside, ours lands. */
    CHECKV(write_file_simple(sig, vendorSig, sizeof(vendorSig)), "write vendor .sig");
    CHECK(cert_sig_is_vendor(exe, sig, vendorPub) == 1, "vendor .sig recognized");
    CHECK(cert_vendor_sigs_preserved(dir, vendorPub), "stock install is removable");
    int unp = 0;
    CHECK(cert_sign_all(dir, &ours, vendorPub, &unp) == 1 && unp == 0, "signed one file");
    CHECK(cert_sig_is_vendor(exe, shadow, vendorPub) == 1, "vendor signature kept as a shadow");
    CHECK(cert_sig_is_vendor(exe, sig, ourPub) == 1, "installed .sig is ours");

    /* 2. Already signed: the shadow is untouched and the gate stays open. */
    CHECKV(write_file_simple(sig, ourSig, sizeof(ourSig)), "rewrite our .sig");
    CHECK(cert_vendor_sigs_preserved(dir, vendorPub), "shadow keeps the install removable");
    unp = 0;
    CHECK(cert_sign_all(dir, &ours, vendorPub, &unp) == 1 && unp == 0, "re-sign with a shadow");
    CHECK(cert_sig_is_vendor(exe, shadow, vendorPub) == 1, "shadow still holds the vendor file");

    /* 3. Shadow lost: nothing may be overwritten and the gate closes. */
    CHECKV(DeleteFileA(shadow), "drop the shadow");
    CHECK(!cert_vendor_sigs_preserved(dir, vendorPub), "lost vendor signature closes the gate");
    unp = 0;
    CHECK(cert_sign_all(dir, &ours, vendorPub, &unp) == 0 && unp == 1,
          "unpreservable file is left alone");
    CHECK(cert_sig_is_vendor(exe, sig, ourPub) == 1, "the file was not touched");

    /* 4. Restore puts the vendor file back and removes the shadow. */
    CHECKV(write_file_simple(shadow, vendorSig, sizeof(vendorSig)), "restore fixture shadow");
    int failed = 0;
    CHECK(cert_restore_vendor_sigs(dir, vendorPub, &failed) == 1 && failed == 0,
          "restored one signature");
    CHECK(cert_sig_is_vendor(exe, sig, vendorPub) == 1, "restored .sig is the vendor file");
    CHECK(!exists(shadow), "shadow removed after restore");

    /* 5. A shadow that does not verify is kept and reported. */
    CHECKV(write_file_simple(shadow, ourSig, sizeof(ourSig)), "write a bad shadow");
    failed = 0;
    CHECK(cert_restore_vendor_sigs(dir, vendorPub, &failed) == 0 && failed == 1,
          "bad shadow reported");
    CHECK(exists(shadow), "bad shadow kept for a later repair");
    CHECKV(DeleteFileA(shadow), "drop the bad shadow");

    /* 6. The older sig_backup/ directory is migrated into shadows. */
    char bdir[MAX_PATH], bfile[MAX_PATH], marker[MAX_PATH];
    temp_path(bdir, sizeof(bdir), "sbie_selftest_sigshadow\\sig_backup");
    temp_path(bfile, sizeof(bfile), "sbie_selftest_sigshadow\\sig_backup\\App.exe.sig");
    temp_path(marker, sizeof(marker), "sbie_selftest_sigshadow\\sig_backup\\verified");
    CHECKV(CreateDirectoryA(bdir, NULL) || GetLastError() == ERROR_ALREADY_EXISTS,
           "create backup dir");
    CHECKV(write_file_simple(bfile, vendorSig, sizeof(vendorSig)), "write backup file");
    CHECKV(write_file_simple(marker, (const BYTE *)"x", 1), "write marker");
    cert_migrate_backup(dir, vendorPub);
    CHECK(cert_sig_is_vendor(exe, shadow, vendorPub) == 1, "backup migrated into a shadow");
    CHECK(!exists(marker), "marker consumed by the migration");

    DeleteFileA(sig);
    DeleteFileA(shadow);
    DeleteFileA(exe);
    DeleteFileA(bfile);
    RemoveDirectoryA(bdir);
    RemoveDirectoryA(dir);
    ec_free_keypair(&vendor);
    ec_free_keypair(&ours);
}

/* ---------------- SbieDll-backed driver calls ---------------- */

static void test_sbieapi(const char *dllPath)
{
    TF_GROUP("sbieapi");

    /* No Sandboxie directory at all: clean failure, no crash. */
    CHECK(sbie_reload_certificate("C:\\sbie_selftest_missing_dir_xyz") != 0,
          "missing SbieDll -> clean failure");
    sbie_log_cert_state("C:\\sbie_selftest_missing_dir_xyz");
    CHECK(TRUE, "state query on a missing install does not crash");

    /* A real DLL without the SbieApi_ exports must also fail cleanly. */
    char dir[MAX_PATH], dll[MAX_PATH], dllLog[MAX_PATH];
    temp_path(dir, sizeof(dir), "sbie_selftest_sbiedir");
    temp_path(dll, sizeof(dll), "sbie_selftest_sbiedir\\SbieDll.dll");
    temp_path(dllLog, sizeof(dllLog), "sbie_selftest_sbiedir\\version_hook.log");
    CreateDirectoryA(dir, NULL);
    CHECKV(CopyFileA(dllPath, dll, FALSE) || GetLastError() == ERROR_FILE_EXISTS,
           "stage a stand-in SbieDll");
    CHECK(sbie_reload_certificate(dir) != 0, "DLL without the export -> clean failure");
    sbie_log_cert_state(dir);
    CHECK(TRUE, "state query on a foreign DLL does not crash");

    DeleteFileA(dllLog);
    DeleteFileA(dll);
    RemoveDirectoryA(dir);
}

/* ---------------- kernel module lookup (user-mode API smoke) ---------------- */

static void test_kmod(void)
{
    TF_GROUP("kmod");
    ULONG64 base = kmod_find("ntoskrnl.exe");
    /* An unelevated token can receive every ImageBase zeroed (seen on
     * 24H2), so the lookup is asserted only when elevated - the product
     * only calls it from the elevated helper. */
    if (!tf_is_elevated() && base == 0) {
        SKIP_TEST("ntoskrnl lookup", "driver bases are zeroed for an unelevated token");
    } else {
        CHECK(base != 0, "ntoskrnl.exe found in the driver list");
        CHECK(kmod_find("NTOSKRNL.EXE") == base, "name match is case-insensitive");
    }
    CHECK(kmod_find("definitely_not_a_kernel_module_xyz") == 0, "absent module -> 0");
}

/* ---------------- logger ---------------- */

static DWORD file_size(const char *path)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, 0, NULL);
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
    LOGI("selftest marker %llu", (unsigned long long)GetTickCount64());
    CHECK(file_size(logp) > before, "log line appended");

    /* A message far beyond the 1024-byte buffer must truncate, not
     * corrupt the file or crash. */
    static char big[4000];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = 0;
    DWORD mid = file_size(logp);
    LOGW("%s", big);
    CHECK(file_size(logp) > mid, "oversized message truncated safely");

    /* A full log rotates to .old.log once per process instead of growing
     * without bound. */
    char oldp[MAX_PATH];
    strcpy_s(oldp, MAX_PATH, logp);
    char *dot = strrchr(oldp, '.');
    if (dot) strcpy_s(dot, MAX_PATH - (dot - oldp), ".old.log");
    DeleteFileA(oldp);

    HANDLE h =
        CreateFileA(logp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != INVALID_HANDLE_VALUE, "rotate fixture created");
    if (h != INVALID_HANDLE_VALUE) {
        static char chunk[65536];
        memset(chunk, 'z', sizeof(chunk));
        DWORD written;
        for (int i = 0; i < 17; i++) /* 1 MB + 64 KB: over the cap */
            WriteFile(h, chunk, sizeof(chunk), &written, NULL);
        CloseHandle(h);
    }
    strcpy_s(g_log_path, MAX_PATH, logp);
    log_rotate();
    CHECK(file_size(logp) == 0, "full log moved away");
    CHECK(file_size(oldp) > LOG_MAX_BYTES, "previous log kept as .old.log");
    DeleteFileA(oldp);
}

int main(int argc, char **argv)
{
    TF_INIT(argc > 2 ? argv[2] : NULL);
    const char *pePath = (argc > 1) ? argv[1] : "dist\\version.dll";

    printf("== sandboxie_unlocker selftest ==\n");
    test_base64();
    test_crypto();
    test_persist();
    test_fast_pub();
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
    test_pte();
    test_sigshadow();
    test_sbieapi(pePath);
    test_kmod();
    test_log();
    return tf_summary();
}
