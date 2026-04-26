#define _CRT_SECURE_NO_WARNINGS

#include "mine.h"
#include "mine_load.h"
#include "mine_stack.h"
#include "mine_VEH.h"
#include "mine_trace.h"
#include "mine_dynamic.h"
#include "jump.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* ─── ELF identity ────────────────────────────────────────────────────────── */

#define EI_MAG0     0
#define EI_MAG1     1
#define EI_MAG2     2
#define EI_MAG3     3
#define EI_CLASS    4
#define EI_DATA     5
#define EI_VERSION  6

#define ELFMAG0     0x7Fu
#define ELFMAG1     'E'
#define ELFMAG2     'L'
#define ELFMAG3     'F'
#define ELFCLASS32  1
#define ELFCLASS64  2
#define ELFDATA2LSB 1
#define ET_EXEC     2
#define ET_DYN      3
#define EM_386      3
#define EM_X86_64   62

#pragma pack(push, 1)
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;    uint16_t e_machine; uint32_t e_version;
    uint32_t e_entry;   uint32_t e_phoff;   uint32_t e_shoff;
    uint32_t e_flags;   uint16_t e_ehsize;  uint16_t e_phentsize;
    uint16_t e_phnum;   uint16_t e_shentsize; uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;    uint16_t e_machine; uint32_t e_version;
    uint64_t e_entry;   uint64_t e_phoff;   uint64_t e_shoff;
    uint32_t e_flags;   uint16_t e_ehsize;  uint16_t e_phentsize;
    uint16_t e_phnum;   uint16_t e_shentsize; uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;
#pragma pack(pop)

typedef struct {
    uint8_t  bits;
    uint16_t type;
    uint16_t machine;
    uint64_t entry;
    uint16_t phnum;
} ElfInfo;

static ElfInfo g_elf;

/* ─── helpers ─────────────────────────────────────────────────────────────── */

static bool read_bytes(LPCSTR path, void* buf, DWORD n)
{
    HANDLE fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz;
    GetFileSizeEx(fh, &sz);
    if (sz.QuadPart < (LONGLONG)n) { CloseHandle(fh); return false; }

    DWORD got = 0;
    BOOL  ok = ReadFile(fh, buf, n, &got, NULL);
    CloseHandle(fh);
    return ok && got == n;
}

static void print_magic_hint(const uint8_t* b)
{
    if (b[0] == 'M' && b[1] == 'Z')
        fprintf(stderr, "[MinE-Error] Binary is not ELF! (Windows PE detected)\n");
    else if (b[0] == 0xCE || b[0] == 0xCF)
        fprintf(stderr, "[MinE-Error] Binary is not ELF! (Mach-O detected)\n");
    else if (b[0] == '#' && b[1] == '!')
        fprintf(stderr, "[MinE-Error] Binary is not ELF! (shell script detected)\n");
    else
        fprintf(stderr, "[MinE-Error] Binary is not ELF! "
            "(magic: %02X %02X %02X %02X)\n",
            b[0], b[1], b[2], b[3]);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CheckApp
 * ═══════════════════════════════════════════════════════════════════════════ */

bool CheckApp(LPCSTR path)
{
    uint8_t buf[64];
    if (!read_bytes(path, buf, sizeof(buf))) {
        fprintf(stderr, "[MinE-Error] Cannot open or file too small: '%s'\n", path);
        return false;
    }

    /* magic */
    if (buf[EI_MAG0] != ELFMAG0 || buf[EI_MAG1] != ELFMAG1 ||
        buf[EI_MAG2] != ELFMAG2 || buf[EI_MAG3] != ELFMAG3) {
        print_magic_hint(buf);
        return false;
    }

    /* endian */
    if (buf[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "[MinE-Error] Binary is not ELF! (big-endian not supported)\n");
        return false;
    }

    /* version */
    if (buf[EI_VERSION] != 1) {
        fprintf(stderr, "[MinE-Error] Binary is not ELF! "
            "(unknown ELF version %u)\n", buf[EI_VERSION]);
        return false;
    }

    uint8_t  cls = buf[EI_CLASS];
    uint16_t type = 0, machine = 0;
    uint64_t entry = 0;
    uint16_t phnum = 0;

    if (cls == ELFCLASS64) {
        Elf64_Ehdr* h = (Elf64_Ehdr*)buf;
        type = h->e_type; machine = h->e_machine;
        entry = h->e_entry; phnum = h->e_phnum;
        if (machine != EM_X86_64) {
            fprintf(stderr, "[MinE-Error] ELF64 e_machine=%u, need x86-64(62)\n", machine);
            return false;
        }
    }
    else if (cls == ELFCLASS32) {
        Elf32_Ehdr* h = (Elf32_Ehdr*)buf;
        type = h->e_type; machine = h->e_machine;
        entry = h->e_entry; phnum = h->e_phnum;
        if (machine != EM_386) {
            fprintf(stderr, "[MinE-Error] ELF32 e_machine=%u, need x86(3)\n", machine);
            return false;
        }
    }
    else {
        fprintf(stderr, "[MinE-Error] Unknown EI_CLASS=%u\n", cls);
        return false;
    }

    if (type != ET_EXEC && type != ET_DYN) {
        fprintf(stderr, "[MinE-Error] e_type=%u, need ET_EXEC or ET_DYN\n", type);
        return false;
    }

    g_elf.bits = (cls == ELFCLASS64) ? 64 : 32;
    g_elf.type = type;
    g_elf.machine = machine;
    g_elf.entry = entry;
    g_elf.phnum = phnum;
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MineRun — full pipeline
 * ═══════════════════════════════════════════════════════════════════════════ */

void MineRun(LPCSTR path)
{
    /* ── init tracer (checks MINE_TRACE env var) ── */
    MineTraceInit();

    printf("[MinE] Starting '%s'\n", path);
    printf("[MinE] Class : ELF%u  Arch : %s  Type : %s\n",
        g_elf.bits,
        g_elf.machine == EM_X86_64 ? "x86-64" : "x86",
        g_elf.type == ET_EXEC ? "ET_EXEC" : "ET_DYN");

    if (g_trace_enabled)
        printf("[MinE] Syscall tracing ON  (MINE_TRACE set)\n");

    /* ── 1. Map PT_LOAD segments ── */
    MineImage img;
    if (!MineLoad(path, g_elf.bits, &img)) {
        fprintf(stderr, "[MinE-Error] Load failed\n");
        return;
    }

    /* ── 2. Apply GOT/PLT relocations (dynamic linking) ── */
    if (!MineDynLink(path, &img)) {
        fprintf(stderr, "[MinE-Error] Dynamic link failed\n");
        return;
    }

    /* ── 3. Install VEH syscall trap ── */
    if (!MineVEHInstall()) return;

    /* ── 4. Allocate guest stack ── */
    MineStack stk;
    if (!MineStackAlloc(&stk)) {
        MineVEHRemove();
        return;
    }

    /* ── 5. Build initial stack layout ── */
    extern char** environ;
    const char* argv[] = { path, NULL };
    uint64_t rsp = MineStackBuild(stk.stack_top, 1, argv,
        (const char**)environ, &img);

    if (!rsp) {
        fprintf(stderr, "[MinE-Error] Stack build failed\n");
        MineVEHRemove();
        return;
    }

    printf("[MinE] Entry : 0x%llX   RSP : 0x%llX\n",
        (unsigned long long)img.entry,
        (unsigned long long)rsp);
    
    printf("[MinE] Executing \n");
    fflush(stdout);
    fflush(stderr);

    /* ── 6. Jump — does not return ── */
    MineJump(img.entry, rsp);
}