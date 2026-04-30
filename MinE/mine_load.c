/*
 * mine_load.c
 */

#include "mine_load.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

 /* ─── ELF structs ─────────────────────────────────────────────────────────── */

#pragma pack(push, 1)
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type; uint16_t e_machine; uint32_t e_version;
    uint32_t e_entry; uint32_t e_phoff; uint32_t e_shoff;
    uint32_t e_flags; uint16_t e_ehsize; uint16_t e_phentsize;
    uint16_t e_phnum; uint16_t e_shentsize; uint16_t e_shnum; uint16_t e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type; uint16_t e_machine; uint32_t e_version;
    uint64_t e_entry; uint64_t e_phoff; uint64_t e_shoff;
    uint32_t e_flags; uint16_t e_ehsize; uint16_t e_phentsize;
    uint16_t e_phnum; uint16_t e_shentsize; uint16_t e_shnum; uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type; uint32_t p_offset;
    uint32_t p_vaddr; uint32_t p_paddr;
    uint32_t p_filesz; uint32_t p_memsz;
    uint32_t p_flags; uint32_t p_align;
} Elf32_Phdr;

typedef struct {
    uint32_t p_type; uint32_t p_flags;
    uint64_t p_offset; uint64_t p_vaddr; uint64_t p_paddr;
    uint64_t p_filesz; uint64_t p_memsz; uint64_t p_align;
} Elf64_Phdr;
#pragma pack(pop)

/* ─── Constants ───────────────────────────────────────────────────────────── */

#define PT_LOAD  1
#define PF_X     0x1
#define PF_W     0x2
#define PF_R     0x4

#define PAGE_SZ   0x1000ULL
#define PG_DOWN(x) ((x) & ~(PAGE_SZ - 1))
#define PG_UP(x)   (((x) + PAGE_SZ - 1) & ~(PAGE_SZ - 1))

/* ─── Unified segment ─────────────────────────────────────────────────────── */

typedef struct {
    uint64_t offset;
    uint64_t vaddr;
    uint64_t filesz;
    uint64_t memsz;
    uint32_t flags;
} Seg;

/* ─── prot flags ──────────────────────────────────────────────────────────── */

static DWORD elf_prot(uint32_t f)
{
    int r = !!(f & PF_R), w = !!(f & PF_W), x = !!(f & PF_X);
    if (x && w) return PAGE_EXECUTE_READWRITE;
    if (x && r) return PAGE_EXECUTE_READ;
    if (x)      return PAGE_EXECUTE;
    if (w)      return PAGE_READWRITE;
    if (r)      return PAGE_READONLY;
    return PAGE_NOACCESS;
}

/* ─── File helpers ────────────────────────────────────────────────────────── */

static bool fread_at(HANDLE fh, uint64_t off, void* buf, DWORD n)
{
    LARGE_INTEGER li; memset(&li, 0, sizeof(li)); li.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(fh, li, NULL, FILE_BEGIN)) return false;
    DWORD got = 0;
    return ReadFile(fh, buf, n, &got, NULL) && got == n;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MineLoad
 * ═══════════════════════════════════════════════════════════════════════════ */

bool MineLoad(LPCSTR path, uint8_t bits, MineImage* out)
{
    memset(out, 0, sizeof(*out));
    out->bits = bits;

    /* ── open ── */
    HANDLE fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[MinE-Error] Cannot open '%s'  err=%lu\n", path, GetLastError());
        return false;
    }

    /* ── read ELF header ── */
    uint8_t hbuf[64] = { 0 };
    DWORD   got = 0;
    if (!ReadFile(fh, hbuf, sizeof(hbuf), &got, NULL) || got < 16) {
        fprintf(stderr, "[MinE-Error] Failed to read ELF header\n");
        CloseHandle(fh);
        return false;
    }

    uint16_t e_type = 0; uint64_t e_entry = 0, e_phoff = 0; uint16_t e_phnum = 0, e_phentsize = 0;

    if (bits == 64) {
        Elf64_Ehdr* h = (Elf64_Ehdr*)hbuf;
        e_type = h->e_type; e_entry = h->e_entry;
        e_phoff = h->e_phoff; e_phnum = h->e_phnum; e_phentsize = h->e_phentsize;
    }
    else {
        Elf32_Ehdr* h = (Elf32_Ehdr*)hbuf;
        e_type = h->e_type; e_entry = h->e_entry;
        e_phoff = h->e_phoff; e_phnum = h->e_phnum; e_phentsize = h->e_phentsize;
    }

    /* ── read all program headers into a buffer ── */
    uint32_t ph_total = (uint32_t)e_phnum * e_phentsize;
    uint8_t* phbuf = (uint8_t*)malloc(ph_total);
    if (!phbuf) { CloseHandle(fh); return false; }

    if (!fread_at(fh, e_phoff, phbuf, ph_total)) {
        fprintf(stderr, "[MinE-Error] Cannot read program headers\n");
        free(phbuf); CloseHandle(fh); return false;
    }

    /* ── pass 1: VA range ── */
    uint64_t va_min = UINT64_MAX, va_max = 0;
    uint16_t load_count = 0;

    for (uint16_t i = 0; i < e_phnum; i++) {
        uint32_t p_type; uint64_t p_vaddr, p_memsz;
        if (bits == 64) {
            Elf64_Phdr* p = (Elf64_Phdr*)(phbuf + i * e_phentsize);
            p_type = p->p_type; p_vaddr = p->p_vaddr; p_memsz = p->p_memsz;
        }
        else {
            Elf32_Phdr* p = (Elf32_Phdr*)(phbuf + i * e_phentsize);
            p_type = p->p_type; p_vaddr = p->p_vaddr; p_memsz = p->p_memsz;
        }
        if (p_type != PT_LOAD || p_memsz == 0) continue;
        if (PG_DOWN(p_vaddr) < va_min) va_min = PG_DOWN(p_vaddr);
        if (PG_UP(p_vaddr + p_memsz) > va_max) va_max = PG_UP(p_vaddr + p_memsz);
        load_count++;
    }

    if (load_count == 0) {
        fprintf(stderr, "[MinE-Error] No PT_LOAD segments\n");
        free(phbuf); CloseHandle(fh); return false;
    }

    uint64_t img_size = va_max - va_min;
    printf("[MinE] Image VA range: 0x%llX - 0x%llX  (size 0x%llX, %u segments)\n",
        (unsigned long long)va_min, (unsigned long long)va_max,
        (unsigned long long)img_size, load_count);

    /* ── reserve the ENTIRE image as one MEM_RESERVE block ──
     *
     *  This is the critical fix for error 487.
     *  We reserve all VA space upfront so every segment can be committed
     *  inside the same reserved region without conflicts.
     *
     *  ET_EXEC: try the linked VA first; fall back to OS-chosen if occupied.
     *  ET_DYN:  always let the OS pick (load_bias != 0).
     */
    LPVOID hint = (e_type == 2 /* ET_EXEC */) ? (LPVOID)va_min : NULL;

    LPVOID base_region = VirtualAlloc(hint, (SIZE_T)img_size,
        MEM_RESERVE, PAGE_NOACCESS);

    if (!base_region && e_type == 2) {
        /* Fixed VA busy — fall back to OS choice (treat as PIE) */
        fprintf(stderr, "[MinE] Linked VA 0x%llX busy, letting OS pick\n",
            (unsigned long long)va_min);
        base_region = VirtualAlloc(NULL, (SIZE_T)img_size,
            MEM_RESERVE, PAGE_NOACCESS);
    }

    if (!base_region) {
        fprintf(stderr, "[MinE-Error] MEM_RESERVE failed  err=%lu\n", GetLastError());
        free(phbuf); CloseHandle(fh); return false;
    }

    uint64_t load_bias = (uint64_t)base_region - va_min;
    printf("[MinE] Reserved 0x%llX bytes at 0x%llX  bias=0x%llX\n",
        (unsigned long long)img_size,
        (unsigned long long)base_region,
        (unsigned long long)load_bias);

    /* ── pass 2: commit + populate each PT_LOAD inside the reserved region ── */
    bool ok = true;

    for (uint16_t i = 0; i < e_phnum && ok; i++) {
        Seg s = { 0 }; uint32_t p_type;

        if (bits == 64) {
            Elf64_Phdr* p = (Elf64_Phdr*)(phbuf + i * e_phentsize);
            p_type = p->p_type;
            s.offset = p->p_offset; s.vaddr = p->p_vaddr;
            s.filesz = p->p_filesz; s.memsz = p->p_memsz; s.flags = p->p_flags;
        }
        else {
            Elf32_Phdr* p = (Elf32_Phdr*)(phbuf + i * e_phentsize);
            p_type = p->p_type;
            s.offset = p->p_offset; s.vaddr = p->p_vaddr;
            s.filesz = p->p_filesz; s.memsz = p->p_memsz; s.flags = p->p_flags;
        }

        if (p_type != PT_LOAD || s.memsz == 0) continue;

        uint64_t seg_va = PG_DOWN(s.vaddr) + load_bias;
        uint64_t seg_size = PG_UP(s.vaddr + s.memsz) - PG_DOWN(s.vaddr);

        printf("[MinE]   PT_LOAD  va=0x%llX  filesz=0x%llX  memsz=0x%llX  %c%c%c\n",
            (unsigned long long)(s.vaddr + load_bias),
            (unsigned long long)s.filesz,
            (unsigned long long)s.memsz,
            (s.flags & PF_R) ? 'R' : '-',
            (s.flags & PF_W) ? 'W' : '-',
            (s.flags & PF_X) ? 'X' : '-');

        /* commit pages inside the already-reserved region */
        LPVOID seg_region = VirtualAlloc((LPVOID)seg_va, (SIZE_T)seg_size,
            MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!seg_region) {
            fprintf(stderr, "[MinE-Error] MEM_COMMIT failed at 0x%llX  err=%lu\n",
                (unsigned long long)seg_va, GetLastError());
            ok = false; break;
        }

        /* zero the whole committed range (.bss covered automatically) */
        memset(seg_region, 0, (size_t)seg_size);

        /* copy file image at the right page offset */
        if (s.filesz > 0) {
            uint8_t* dest = (uint8_t*)seg_region + (s.vaddr - PG_DOWN(s.vaddr));
            if (!fread_at(fh, s.offset, dest, (DWORD)s.filesz)) {
                fprintf(stderr, "[MinE-Error] ReadFile failed for segment\n");
                ok = false; break;
            }
        }

        /* apply real page protection */
        DWORD old_prot;
        VirtualProtect(seg_region, (SIZE_T)seg_size, elf_prot(s.flags), &old_prot);
    }

    if (!ok) {
        VirtualFree(base_region, 0, MEM_RELEASE);
        free(phbuf); CloseHandle(fh);
        return false;
    }

    out->base = (uint64_t)base_region;
    out->load_bias = load_bias;
    out->entry = e_entry + load_bias;
    /* phdr_va: program headers are inside the first PT_LOAD segment.
     * The ELF spec says PT_PHDR gives the VA; if absent, use phoff
     * adjusted by the load bias (correct for PIE, 0 for ET_EXEC). */
    out->phdr_va = e_phoff + load_bias;
    out->phnum = e_phnum;

    printf("[MinE] Loaded OK  base=0x%llX  entry=0x%llX\n",
        (unsigned long long)out->base,
        (unsigned long long)out->entry);

    free(phbuf);
    CloseHandle(fh);
 
    return true;
}