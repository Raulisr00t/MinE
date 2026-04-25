#include "mine.h"
#include "mine_load.h"
#include "mine_stack.h"
#include "mine_VEH.h"
#include "jump.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

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

#pragma pack(pop)

typedef struct {
    uint8_t  bits;
    uint16_t type;
    uint16_t machine;
    uint64_t entry;
    uint16_t phnum;
} ElfInfo;

static ElfInfo g_elf;

static bool read_bytes(LPCSTR path, void* buf, DWORD n)
{
    HANDLE fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (fh == INVALID_HANDLE_VALUE) 
        return false;
    
    LARGE_INTEGER sz; GetFileSizeEx(fh, &sz);

    if (sz.QuadPart < (LONGLONG)n) { 
        CloseHandle(fh); 
        return false; 
    }

    DWORD got = 0;
    BOOL ok = ReadFile(fh, buf, n, &got, NULL);
    
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
        fprintf(stderr, "[MinE-Error] Binary is not ELF! (magic: %02X %02X %02X %02X)\n",
            b[0], b[1], b[2], b[3]);
}

bool CheckApp(LPCSTR path)
{
    uint8_t buf[64];
    if (!read_bytes(path, buf, sizeof(buf))) {
        fprintf(stderr, "[MinE-Error] Cannot open or file too small: '%s'\n", path);
        return false;
    }

    if (buf[EI_MAG0] != ELFMAG0 || buf[EI_MAG1] != ELFMAG1 ||
        buf[EI_MAG2] != ELFMAG2 || buf[EI_MAG3] != ELFMAG3) {
        print_magic_hint(buf); return false;
    }

    if (buf[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "[MinE-Error] Binary is not ELF! (big-endian not supported)\n");
        return false;
    }

    if (buf[EI_VERSION] != 1) {
        fprintf(stderr, "[MinE-Error] Binary is not ELF! (unknown ELF version %u)\n",
            buf[EI_VERSION]);
        return false;
    }

    uint8_t  cls = buf[EI_CLASS];
    uint16_t type, machine;

    uint64_t entry;
    uint16_t phnum;

    if (cls == ELFCLASS64) {
        Elf64_Ehdr* h = (Elf64_Ehdr*)buf;

        type = h->e_type; machine = h->e_machine; entry = h->e_entry; phnum = h->e_phnum;

        if (machine != EM_X86_64) {
            fprintf(stderr, "[MinE-Error] Binary is not ELF! (ELF64 e_machine=%u, need 62)\n", machine);
            return false;
        }
    }

    else if (cls == ELFCLASS32) {
        Elf32_Ehdr* h = (Elf32_Ehdr*)buf;
        type = h->e_type; machine = h->e_machine; entry = h->e_entry; phnum = h->e_phnum;
    
        if (machine != EM_386) {
            fprintf(stderr, "[MinE-Error] Binary is not ELF! (ELF32 e_machine=%u, need 3)\n", machine);
            return false;
        }
    }

    else {
        fprintf(stderr, "[MinE-Error] Binary is not ELF! (unknown EI_CLASS=%u)\n", cls);
        return false;
    }

    if (type != ET_EXEC && type != ET_DYN) {
        fprintf(stderr, "[MinE-Error] Binary is not ELF! (e_type=%u)\n", type);
        return false;
    }

    g_elf.bits = cls == ELFCLASS64 ? 64 : 32; g_elf.type = type;
    g_elf.machine = machine; g_elf.entry = entry; g_elf.phnum = phnum;
    
    return true;
}

void MineRun(LPCSTR path)
{
    printf("[MinE] Starting to Execute'%s'\n\n", path);
    printf("[MinE] Class : ELF%u  Arch : %s  Type : %s\n",
        g_elf.bits,
        g_elf.machine == EM_X86_64 ? "x86-64" : "x86",
        g_elf.type == ET_EXEC ? "ET_EXEC" : "ET_DYN");

    MineImage img;
    
    if (!MineLoad(path, g_elf.bits, &img)) {
        fprintf(stderr, "[MinE-Error] Load failed\n");
        return;
    }

    if (!MineVEHInstall()) return;

    MineStack stk;
    if (!MineStackAlloc(&stk)) return;

    const char* argv[] = { path, NULL };
    extern char** environ;               

    uint64_t rsp = MineStackBuild(stk.stack_top, 1, argv,
        (const char**)environ, &img);

    if (!rsp) {
        fprintf(stderr, "[MinE-Error] Stack build failed\n");
        MineVEHRemove();
        return;
    }

    printf("[MinE] Jumping to entry 0x%llX \n",
        (unsigned long long)img.entry);
    fflush(stdout);

    MineJump(img.entry, rsp);
}