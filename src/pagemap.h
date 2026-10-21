/*
 * pagemap.h - writing kernel pages that are mapped read-only
 *
 * SbieDrv >= 1.18.7 declares KphpTrustedPublicKey const, which puts the key
 * into .rdata - mapped read-only.  The helper driver memmove has no SEH, so
 * a direct write there bugchecks the box (0xBE).  Such pages are written
 * through a writable alias of the same physical frame; the page tables
 * self-map at a base Windows randomizes per boot, which is found in the
 * loaded image and validated before it is used.
 */
#ifndef PAGEMAP_H
#define PAGEMAP_H

#include <windows.h>
#include "log.h"
#include "kdrv.h"
#include "kmod.h"

/* 4-level x64 paging self-maps the page tables, so the PTE of *va*
 * sits at base + 8 * (packed indices); only the low 36 bits of
 * (va >> 12) are indices, the bits above are the canonical sign
 * extension and must be masked off. */
#define KDRV_VA_INDEX_MASK 0xFFFFFFFFFULL

/* The self-map base is set at boot and kept in a kernel global; every
 * PTE address is computed from it.  The global is found by how the code
 * uses it, not by a byte pattern: getting from an address to its PTE is
 * always `>> 12, * 8` in some spelling, so a reference to a global that is
 * followed by shr 9 / shl 3 / lea *8 is a vote for that global.  The
 * busiest global that holds a self-map shaped value is the base.
 *
 * shortcut: a kernel that stops doing PTE arithmetic on the global makes
 * the lookup find nothing and the unlock stop with a controlled error - it
 * never guesses a base.  Upgrade if the log starts saying that. */
#define KDRV_MAX_PTE_TARGETS 64

typedef struct {
    ULONG64 target; /* global that the code turns into a PTE address */
    int refs;
} kdrv_pte_target_t;

/* Is *v* shaped like a 4-level self-map base (kernel-half PML4 entry,
 * everything below it zero)? */
static BOOL kdrv_is_pte_base(ULONG64 v)
{
    ULONG64 idx = (v >> 39) & 0x1FF;
    return (v & KDRV_VA_INDEX_MASK) == 0 && (v >> 48) == 0xFFFF && idx >= 0x100 && idx <= 0x1FF;
}

/* VA of the PTE that maps *va*. */
static ULONG64 kdrv_pte_va(ULONG64 pte_base, ULONG64 va)
{ return pte_base + ((va >> 12) & KDRV_VA_INDEX_MASK) * 8; }

/* Alias PTE for the frame described by *src_pte*: present, writable,
 * supervisor (US=0 keeps SMAP out of the way for the kernel-mode store)
 * and non-executable.  Windows' per-PTE software bits are dropped. */
static ULONG64 kdrv_alias_pte(ULONG64 src_pte)
{ return (src_pte & 0x000FFFFFFFFFF000ULL) | 0x1ULL | 0x2ULL | 0x8000000000000000ULL; }

/* Opcodes that can address a global through [rip + disp32]. */
static BOOL kdrv_is_mem_op(BYTE op)
{
    switch (op) {
    case 0x01:
    case 0x03:
    case 0x09:
    case 0x0B:
    case 0x21:
    case 0x23:
    case 0x29:
    case 0x2B:
    case 0x31:
    case 0x33:
    case 0x39:
    case 0x3B:
    case 0x63:
    case 0x85:
    case 0x89:
    case 0x8B:
    case 0x8D:
    case 0x8F:
    case 0xC7:
    case 0xFF:
        return TRUE;
    }
    return FALSE;
}

/* Does this short window turn an address into a PTE address?  shr r,9 (the
 * 4-level index) and its shl r,3 / lea r,[r*8+..] spellings count. */
static BOOL kdrv_pte_arith(const BYTE *p, ULONG len)
{
    for (ULONG i = 0; i + 4 <= len; i++) {
        BYTE rex = p[i];
        if (rex != 0x48 && rex != 0x49 && rex != 0x4C && rex != 0x4D) continue;
        if (p[i + 1] == 0xC1) {
            BYTE modrm = p[i + 2];
            if ((modrm & 0xF8) == 0xE8 && p[i + 3] == 9) /* shr r,9 */
                return TRUE;
            if ((modrm & 0xF8) == 0xE0 && p[i + 3] == 3) /* shl r,3 */
                return TRUE;
        } else if (p[i + 1] == 0x8D && (p[i + 2] & 0xC7) == 0x04 && (p[i + 3] >> 6) == 3) {
            return TRUE; /* lea r,[r*8+..] */
        }
    }
    return FALSE;
}

/* Record one reference to *target*, keeping the busiest globals. */
static void kdrv_target_vote(kdrv_pte_target_t *t, int *count, ULONG64 target)
{
    int k = 0;
    while (k < *count && t[k].target != target) k++;

    if (k == *count) {
        if (*count < KDRV_MAX_PTE_TARGETS) {
            (*count)++;
        } else {
            /* Table full: drop a single-hit entry, never a busy one. */
            k = 0;
            for (int i = 1; i < *count; i++) {
                if (t[i].refs < t[k].refs) k = i;
            }
            if (t[k].refs > 1) return;
        }
        t[k].target = target;
        t[k].refs = 0;
    }
    t[k].refs++;
}

/* Count PTE-arithmetic references to globals in one code chunk. */
static void kdrv_rank_refs(const BYTE *code, ULONG len, ULONG64 va, kdrv_pte_target_t *t,
                           int *count)
{
    if (len < 8) return;

    for (ULONG i = 0; i + 8 <= len; i++) {
        BYTE b = code[i];
        if (b != 0x48 && b != 0x49 && b != 0x4C && b != 0x4D) continue;
        if (!kdrv_is_mem_op(code[i + 1]) || (code[i + 2] & 0xC7) != 0x05) continue;

        ULONG after = len - (i + 7);
        if (after > 32) after = 32;
        if (!kdrv_pte_arith(code + i + 7, after)) continue;

        INT32 disp;
        memcpy(&disp, code + i + 3, sizeof(disp));
        kdrv_target_vote(t, count, va + i + 7 + (ULONG64)(LONG64)disp);
    }
}

typedef void (*kdrv_chunk_fn)(const BYTE *buf, ULONG len, ULONG64 va, void *ctx);

/* Read one section in chunks and hand each chunk to *fn*.  Stops on a read
 * error instead of walking into unmapped space. */
static void kdrv_walk_sections(kdrv_t *d, const IMAGE_SECTION_HEADER *sec, ULONG sec_count,
                               ULONG64 img_base, ULONG64 img_size, BOOL want_exec, BYTE *buf,
                               ULONG chunk, ULONG overlap, kdrv_chunk_fn fn, void *ctx)
{
    for (ULONG s = 0; s < sec_count; s++) {
        if (!!(sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) != want_exec) continue;
        if (!sec[s].SizeOfRawData) continue;
        /* Discarded sections (INIT) may already be unmapped - reading
         * them would fault the un-SEH'd helper driver. */
        if (sec[s].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) continue;

        ULONG64 sec_base = img_base + sec[s].VirtualAddress;
        if (sec_base < img_base || sec_base >= img_base + img_size)
            continue; /* bogus section header must not steer the reads */
        /* Never read padding past the mapping: the raw size can exceed
         * the virtual size and the image end. */
        ULONG span = sec[s].SizeOfRawData;
        if (sec[s].Misc.VirtualSize && span > sec[s].Misc.VirtualSize)
            span = sec[s].Misc.VirtualSize;
        if (sec_base + span > img_base + img_size) span = (ULONG)(img_base + img_size - sec_base);

        ULONG left = span;
        ULONG64 off = 0;
        while (left) {
            ULONG take = (left > chunk) ? chunk : left;
            if (kdrv_read(d, sec_base + off, buf, take) != 0) {
                LOGW("kdrv: section read failed at 0x%llX", sec_base + off);
                break;
            }
            fn(buf, take, sec_base + off, ctx);
            left -= take;
            if (!left) break;
            off += (take > overlap) ? take - overlap : take;
        }
    }
}

/* Does *va* fall inside a section that is still mapped?  Only such an
 * address may be read: a reference into a discarded INIT section would
 * fault the driver.  The whole virtual size counts - globals live in the
 * zero-filled tail of .data too, past the raw data. */
static BOOL kdrv_target_mapped(const IMAGE_SECTION_HEADER *sec, ULONG sec_count, ULONG64 img_base,
                               ULONG64 img_size, ULONG64 va)
{
    for (ULONG s = 0; s < sec_count; s++) {
        if (sec[s].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) continue;
        ULONG span = sec[s].Misc.VirtualSize;
        if (span < sec[s].SizeOfRawData) span = sec[s].SizeOfRawData;
        if (!span) continue;
        ULONG64 start = img_base + sec[s].VirtualAddress;
        if (start < img_base || start >= img_base + img_size) continue;
        if (start + span > img_base + img_size) span = (ULONG)(img_base + img_size - start);
        if (va >= start && va < start + span) return TRUE;
    }
    return FALSE;
}

typedef struct {
    kdrv_pte_target_t *targets;
    int count;
} kdrv_rank_ctx_t;

static void kdrv_chunk_rank(const BYTE *buf, ULONG len, ULONG64 va, void *ctx)
{
    kdrv_rank_ctx_t *c = (kdrv_rank_ctx_t *)ctx;
    kdrv_rank_refs(buf, len, va, c->targets, &c->count);
}

/* Offset of the section table inside a PE image.  The NT headers start at
 * e_lfanew, so that offset must be part of the sum: leaving it out reads
 * the DOS stub as section headers, which only "works" while e_lfanew
 * happens to be a multiple of sizeof(IMAGE_SECTION_HEADER) (= 40). */
static ULONG kdrv_section_table_off(const IMAGE_DOS_HEADER *dos, const IMAGE_NT_HEADERS64 *nt)
{
    return dos->e_lfanew + 4 + (ULONG)sizeof(IMAGE_FILE_HEADER) +
           nt->FileHeader.SizeOfOptionalHeader;
}

/* Read the self-map base out of the loaded ntoskrnl image.  Returns the
 * base or 0; a failure is reported and leaves the unlock a controlled
 * error, never a fault in the helper driver. */
static ULONG64 kdrv_locate_pte_base(kdrv_t *d)
{
    ULONG64 img_base = kmod_find("ntoskrnl.exe");
    if (!img_base) {
        LOGE("kdrv_locate_pte_base: ntoskrnl.exe not found in the driver list");
        return 0;
    }

    /* Section table of the *loaded* image (its headers are mapped). */
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    if (kdrv_read(d, img_base, &dos, sizeof(dos)) != 0 || dos.e_lfanew < 0 ||
        dos.e_lfanew >= 0x1000 || /* NT headers live in the first page */
        kdrv_read(d, img_base + dos.e_lfanew, &nt, sizeof(nt)) != 0) {
        LOGE("kdrv_locate_pte_base: PE headers unreadable");
        return 0;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || nt.Signature != IMAGE_NT_SIGNATURE) {
        LOGE("kdrv_locate_pte_base: bad PE headers");
        return 0;
    }
    ULONG img_size = nt.OptionalHeader.SizeOfImage;
    if (!img_size) {
        LOGE("kdrv_locate_pte_base: image size is zero");
        return 0;
    }

    IMAGE_SECTION_HEADER sec[64];
    ULONG sec_count = nt.FileHeader.NumberOfSections;
    if (!sec_count || sec_count > 64) {
        LOGE("kdrv_locate_pte_base: implausible section count %lu", sec_count);
        return 0;
    }
    ULONG sec_off = kdrv_section_table_off(&dos, &nt);
    if (sec_off + sec_count * (ULONG)sizeof(sec[0]) > 0x1000 ||
        kdrv_read(d, img_base + sec_off, sec, sec_count * sizeof(sec[0])) != 0) {
        LOGE("kdrv_locate_pte_base: section table unreadable");
        return 0;
    }

    const ULONG CHUNK = 512 * 1024;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, CHUNK);
    if (!buf) {
        LOGE("kdrv_locate_pte_base: alloc failed");
        return 0;
    }

    kdrv_pte_target_t targets[KDRV_MAX_PTE_TARGETS];
    kdrv_rank_ctx_t ctx = {targets, 0};
    kdrv_walk_sections(d, sec, sec_count, img_base, img_size, TRUE, buf, CHUNK, 8, kdrv_chunk_rank,
                       &ctx);
    HeapFree(GetProcessHeap(), 0, buf);

    if (!ctx.count) {
        LOGE("kdrv_locate_pte_base: no PTE arithmetic on a global in the code");
        return 0;
    }

    /* Busiest global first; the first one holding a self-map shaped value
     * is the base.  A mis-decoded reference costs one safe read, nothing
     * more - the value shape decides, and a non-match is skipped. */
    ULONG64 base = 0;
    ULONG64 base_va = 0;
    int base_refs = 0;
    for (int rank = 0; rank < ctx.count && !base; rank++) {
        int best = rank;
        for (int i = rank + 1; i < ctx.count; i++) {
            if (targets[i].refs > targets[best].refs) best = i;
        }
        kdrv_pte_target_t t = targets[best];
        targets[best] = targets[rank];
        targets[rank] = t;

        if (!kdrv_target_mapped(sec, sec_count, img_base, img_size, t.target)) {
            LOGW("kdrv_locate_pte_base: target 0x%llX (RVA 0x%llX) is outside a live section",
                 t.target, t.target - img_base);
            continue;
        }
        ULONG64 v = 0;
        if (kdrv_read(d, t.target, &v, sizeof(v)) != 0) {
            LOGW("kdrv_locate_pte_base: target 0x%llX unreadable", t.target);
            continue;
        }
        LOGI("PTE-arithmetic global at RVA 0x%llX: %d reference(s), value 0x%llX",
             t.target - img_base, t.refs, v);
        if (kdrv_is_pte_base(v)) {
            base = v;
            base_va = t.target;
            base_refs = t.refs;
        }
    }

    if (!base) {
        LOGE("kdrv_locate_pte_base: no self-map shaped value among %d target(s)", ctx.count);
        return 0;
    }
    LOGI("nt!MmPteBase at RVA 0x%llX = 0x%llX (%d reference(s))", base_va - img_base, base,
         base_refs);
    return base;
}

/* Validate a candidate base against a page this process owns: its PTE
 * must be a present, writable, user entry.  A wrong base cannot pass
 * this, and the check runs before any write - so a bad base ends as a
 * controlled failure, not as corrupt memory. */
static BOOL kdrv_validate_pte_base(kdrv_t *d, ULONG64 base)
{
    BYTE *probe = (BYTE *)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!probe) {
        /* An unvalidated base must not be used: refuse instead. */
        LOGE("kdrv_validate_pte_base: probe alloc failed: %lu", GetLastError());
        return FALSE;
    }

    *(volatile BYTE *)probe = 1; /* fault the page in */
    ULONG64 probe_pte = 0;
    BOOL ok = kdrv_read(d, kdrv_pte_va(base, (ULONG64)(ULONG_PTR)probe), &probe_pte,
                        sizeof(probe_pte)) == 0 &&
              (probe_pte & 0x1) && (probe_pte & 0x2) && (probe_pte & 0x4) &&
              (probe_pte & 0x000FFFFFFFFFF000ULL); /* a real frame, not junk */
    if (ok)
        LOGI("PTE base 0x%llX validated against an owned page", base);
    else
        LOGE("kdrv_validate_pte_base: base 0x%llX failed validation "
             "(own page PTE 0x%llX)",
             base, probe_pte);

    VirtualFree(probe, 0, MEM_RELEASE);
    return ok;
}

/* The page-table base, or 0 when this OS cannot be handled: 5-level
 * paging (LA57) uses another layout, and guessing a base would fault
 * the un-SEH'd helper driver into a bugcheck. */
static BOOL kdrv_pte_supported(void)
{
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    return (ULONG64)(ULONG_PTR)si.lpMaximumApplicationAddress <= 0x00007FFFFFFEFFFFULL;
}

/* Pre-RS1 kernels (every Windows before 10 1607) have no nt!MmPteBase
 * to find: their self-map base is the fixed classic constant.  Newer
 * builds must never fall back to it - there it is unmapped and reading
 * a PTE through it would bugcheck the box. */
#define KDRV_PTE_BASE_FIXED 0xFFFFF68000000000ULL
#define KDRV_OS_RS1_BUILD 14393

static ULONG64 kdrv_pte_base_fixed(void)
{
    typedef LONG(WINAPI * fn_getver)(RTL_OSVERSIONINFOW *);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    fn_getver getver = ntdll ? (fn_getver)(void *)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
    if (!getver) return 0;

    RTL_OSVERSIONINFOW vi;
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (getver(&vi) != 0) return 0;

    if (vi.dwMajorVersion > 10) return 0;
    if (vi.dwMajorVersion == 10 && vi.dwBuildNumber >= KDRV_OS_RS1_BUILD) return 0;

    LOGI("Pre-RS1 kernel (build %lu.%lu.%lu): fixed self-map base", vi.dwMajorVersion,
         vi.dwMinorVersion, vi.dwBuildNumber);
    return KDRV_PTE_BASE_FIXED;
}

static ULONG64 kdrv_pte_base(kdrv_t *d)
{
    if (!kdrv_pte_supported()) {
        LOGE("kdrv: 5-level paging detected, no PTE alias - unlock unsupported here");
        return 0;
    }

    ULONG64 base = kdrv_locate_pte_base(d);
    if (!base) base = kdrv_pte_base_fixed();
    if (!base) {
        LOGE("kdrv: no page-table base found - unlock unsupported on this kernel");
        return 0;
    }
    return kdrv_validate_pte_base(d, base) ? base : 0;
}

/* Write *size* bytes to kernel VA *va*, which may live in a read-only
 * image section.  A writable page takes the direct path; a read-only
 * page is written through a fresh alias of its physical frame, so the
 * store never touches a read-only mapping (a stale read-only TLB entry
 * on the original VA would fault again).  Every failure is detected
 * before any store, so a read-only page can never reach the driver's
 * un-SEH'd memmove.  Returns 0 on success. */
static int kdrv_page_write(kdrv_t *d, ULONG64 va, const void *data, ULONG size)
{
    if ((va & 0xFFF) + size > 0x1000) {
        LOGE("kdrv_page_write: %lu bytes at 0x%llX cross a page boundary", size, va);
        return 1;
    }

    ULONG64 pte_base = kdrv_pte_base(d);
    if (!pte_base) return 1;

    ULONG64 target_pte = 0;
    ULONG64 pte_va = kdrv_pte_va(pte_base, va);
    if (kdrv_read(d, pte_va, &target_pte, sizeof(target_pte)) != 0) {
        LOGE("kdrv_page_write: PTE read failed at 0x%llX", pte_va);
        return 2;
    }
    if (!(target_pte & 0x1) || (target_pte & 0x80)) {
        LOGE("kdrv_page_write: no 4K present mapping for 0x%llX (PTE 0x%llX)", va, target_pte);
        return 3;
    }
    if (target_pte & 0x2) {
        LOGI("Target page is writable - direct write");
        return kdrv_write(d, va, data, size);
    }

    /* Three committed pages, never touched by user code: their PTE page
     * is materialised by touching the neighbour that shares the 2MB
     * region, and the alias page itself stays out of the TLB.  The 2MB
     * boundary can cross at most one of the two neighbour boundaries. */
    BYTE *pages = (BYTE *)VirtualAlloc(NULL, 3 * 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pages) {
        LOGE("kdrv_page_write: VirtualAlloc failed: %lu", GetLastError());
        return 4;
    }

    BYTE *alias = pages + 0x1000;
    BYTE *anchor = ((ULONG_PTR)alias >> 21) == ((ULONG_PTR)pages >> 21) ? pages : pages + 0x2000;
    if (((ULONG_PTR)alias >> 21) != ((ULONG_PTR)anchor >> 21)) {
        /* Cannot happen: contiguous pages, one 2MB boundary at most. */
        VirtualFree(pages, 0, MEM_RELEASE);
        LOGE("kdrv_page_write: no neighbour page in the alias 2MB region");
        return 5;
    }
    *(volatile BYTE *)anchor = 0; /* materialise the PTE page, not the alias */

    ULONG64 alias_va = (ULONG64)(ULONG_PTR)alias;
    ULONG64 alias_pte_va = kdrv_pte_va(pte_base, alias_va);
    ULONG64 saved_pte = 0;
    int rc = 0;
    BOOL restored = TRUE;

    if (kdrv_read(d, alias_pte_va, &saved_pte, sizeof(saved_pte)) != 0) {
        LOGE("kdrv_page_write: alias PTE read failed at 0x%llX", alias_pte_va);
        rc = 6;
        goto out;
    }

    ULONG64 alias_pte = kdrv_alias_pte(target_pte);
    if (kdrv_write(d, alias_pte_va, &alias_pte, sizeof(alias_pte)) != 0) {
        LOGE("kdrv_page_write: alias PTE write failed at 0x%llX", alias_pte_va);
        rc = 7;
        goto out;
    }

    LOGI("Target page is read-only - writing via page alias 0x%llX", alias_va);
    if (kdrv_write(d, alias_va + (va & 0xFFF), data, size) != 0) {
        LOGE("kdrv_page_write: alias write failed");
        rc = 8;
    }

    /* The alias mapping must not outlive this call. */
    if (kdrv_write(d, alias_pte_va, &saved_pte, sizeof(saved_pte)) != 0) {
        LOGE("kdrv_page_write: alias PTE restore failed at 0x%llX", alias_pte_va);
        restored = FALSE;
        if (!rc) rc = 9;
    }

out:
    /* Freeing the pages while their PTE still points at the target frame
     * would hand that frame back to the allocator - leak them instead. */
    if (restored)
        VirtualFree(pages, 0, MEM_RELEASE);
    else
        LOGW("kdrv_page_write: alias PTE left in place, pages leaked on purpose");
    return rc;
}

#endif /* PAGEMAP_H */
