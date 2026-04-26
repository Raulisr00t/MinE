#define _CRT_SECURE_NO_WARNINGS
#include "mine_dynamic.h"

#include <Windows.h>
#include <io.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "mine_thunk.h"

/* ─── ELF64 structs ───────────────────────────────────────────────────────── */

#pragma pack(push,1)
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type, e_machine; uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum;
    uint16_t e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} Elf64_Phdr;

typedef struct { int64_t d_tag; uint64_t d_val; } Elf64_Dyn;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} Elf64_Rela;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info, st_other;
    uint16_t st_shndx;
    uint64_t st_value, st_size;
} Elf64_Sym;
#pragma pack(pop)

/* ─── ELF dynamic tag constants (from ELF spec) ───────────────────────────── */

#define PT_DYNAMIC    2

#define DT_NULL       0
#define DT_NEEDED     1
#define DT_PLTRELSZ   2   /* size in bytes of PLT reloc table               */
#define DT_PLTGOT     3
#define DT_STRTAB     5
#define DT_SYMTAB     6
#define DT_RELA       7   /* address of .rela.dyn                           */
#define DT_RELASZ     8   /* size in bytes of .rela.dyn                     */
#define DT_RELAENT    9
#define DT_STRSZ      10
#define DT_SYMENT     11
#define DT_INIT       12
#define DT_FINI       13
#define DT_PLTREL     20  /* type of PLT relocs: DT_RELA=7 or DT_REL=17    */
#define DT_JMPREL     23  /* address of PLT reloc table (.rela.plt)         */
#define DT_INIT_ARRAY     25
#define DT_FINI_ARRAY     26
#define DT_INIT_ARRAYSZ   27
#define DT_FINI_ARRAYSZ   28
#define DT_GNU_HASH       0x6ffffef5
#define DT_VERSYM         0x6ffffff0
#define DT_RELACOUNT      0x6ffffff9
#define DT_FLAGS_1        0x6ffffffb
#define DT_VERNEED        0x6ffffffe
#define DT_VERNEEDNUM     0x6fffffff

/* relocation types */
#define R_X86_64_NONE      0
#define R_X86_64_64        1
#define R_X86_64_RELATIVE  8
#define R_X86_64_GLOB_DAT  6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_IRELATIVE 37

#define ELF64_R_SYM(i)   ((uint32_t)((i) >> 32))
#define ELF64_R_TYPE(i)  ((uint32_t)((i) & 0xFFFFFFFFULL))

/* ─── libc stubs ──────────────────────────────────────────────────────────── */

static void stub_noop(void) { }
static void stub_exit(int c) { ExitProcess((UINT)c); }

static int stub_write(int fd, const void* buf, size_t n)
{
    HANDLE h;
    switch (fd) {
    case 1:  h = GetStdHandle(STD_OUTPUT_HANDLE); break;
    case 2:  h = GetStdHandle(STD_ERROR_HANDLE);  break;
    default: {
        intptr_t r = _get_osfhandle(fd);
        h = (r == -1) ? INVALID_HANDLE_VALUE : (HANDLE)r;
        break;
    }
    }
    if (!h || h == INVALID_HANDLE_VALUE) return -1;
    DWORD w = 0;
    WriteFile(h, buf, (DWORD)n, &w, NULL);
    return (int)w;
}

static int stub_puts(const char* s)
{
    stub_write(1, s, strlen(s));
    stub_write(1, "\n", 1);
    return 0;
}

static int stub_printf(const char* fmt, ...)
{
    char buf[4096];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) stub_write(1, buf, (size_t)n);
    return n;
}

static int    stub_fflush(void* f) { (void)f; return 0; }
static void   stub_abort(void) { ExitProcess(134); }
static void   stub_stack_chk(void) { stub_write(2, "stack smash\n", 12); ExitProcess(127); }
static int* stub_errno_loc(void) { static int e = 0; return &e; }

/* ─── stub table ──────────────────────────────────────────────────────────── */

typedef struct { const char* name; void* fn; } SymStub;

static const SymStub s_stubs[] = {
    {"exit",                         (void*)stub_exit},
    {"_exit",                        (void*)stub_exit},
    {"abort",                        (void*)stub_abort},
    {"write",                        (void*)stub_write},
    {"puts",                         (void*)stub_puts},
    {"printf",                       (void*)stub_printf},
    {"fprintf",                      (void*)stub_printf},
    {"vprintf",                      (void*)vprintf},
    {"vfprintf",                     (void*)vfprintf},
    {"sprintf",                      (void*)sprintf},
    {"snprintf",                     (void*)snprintf},
    {"vsprintf",                     (void*)vsprintf},
    {"vsnprintf",                    (void*)vsnprintf},
    {"malloc",                       (void*)malloc},
    {"free",                         (void*)free},
    {"calloc",                       (void*)calloc},
    {"realloc",                      (void*)realloc},
    {"memcpy",                       (void*)memcpy},
    {"memmove",                      (void*)memmove},
    {"memset",                       (void*)memset},
    {"memcmp",                       (void*)memcmp},
    {"strlen",                       (void*)strlen},
    {"strcmp",                       (void*)strcmp},
    {"strncmp",                      (void*)strncmp},
    {"strcpy",                       (void*)strcpy},
    {"strncpy",                      (void*)strncpy},
    {"strcat",                       (void*)strcat},
    {"strncat",                      (void*)strncat},
    {"strchr",                       (void*)strchr},
    {"strrchr",                      (void*)strrchr},
    {"strstr",                       (void*)strstr},
    {"atoi",                         (void*)atoi},
    {"atol",                         (void*)atol},
    {"strtol",                       (void*)strtol},
    {"strtoul",                      (void*)strtoul},
    {"strtod",                       (void*)strtod},
    {"fflush",                       (void*)stub_fflush},
    {"__errno_location",             (void*)stub_errno_loc},
    {"__stack_chk_fail",             (void*)stub_stack_chk},
    {"__cxa_finalize",               (void*)stub_noop},
    {"__cxa_atexit",                 (void*)stub_noop},
    /* optional GCC/linker hooks — always safe to stub out */
    {"_ITM_deregisterTMCloneTable",  (void*)stub_noop},
    {"_ITM_registerTMCloneTable",    (void*)stub_noop},
    {"__gmon_start__",               (void*)stub_noop},
    {"_Jv_RegisterClasses",          (void*)stub_noop},
    {NULL, NULL}
};

static void* find_stub(const char* name)
{
    for (int i = 0; s_stubs[i].name; i++) {
        if (strcmp(s_stubs[i].name, name) == 0) {
            /* wrap in a Linux->Windows ABI thunk */
            return MineThunkFor(s_stubs[i].fn);
        }
    }
    return NULL;
}

/* ─── __libc_start_main ───────────────────────────────────────────────────── */

typedef int (*main_fn_t)(int, char**, char**);
static char** g_envp = NULL;

static int stub_libc_start_main(
    main_fn_t main_fn, int argc, char** argv,
    void* init, void* fini, void* rtld_fini, void* stack_end)
{
    (void)rtld_fini; (void)stack_end;
    if (init) ((void(*)(void))init)();
    int ret = main_fn(argc, argv, g_envp);
    if (fini) ((void(*)(void))fini)();
    ExitProcess((UINT)ret);
    return 0;
}

/* ─── file helper ─────────────────────────────────────────────────────────── */

static bool fread_at(HANDLE fh, uint64_t off, void* buf, DWORD n)
{
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(fh, li, NULL, FILE_BEGIN)) return false;
    DWORD got = 0;
    return ReadFile(fh, buf, n, &got, NULL) && (got == n);
}

/* ─── apply one relocation ────────────────────────────────────────────────── */

static void apply_rela(const Elf64_Rela* r, uint64_t bias,
    const Elf64_Sym* symtab, const char* strtab)
{
    uint32_t type = ELF64_R_TYPE(r->r_info);
    uint32_t sym_idx = ELF64_R_SYM(r->r_info);

    uint64_t* target = (uint64_t*)(uintptr_t)(r->r_offset + bias);
    uint64_t  S = 0;
    int64_t   A = r->r_addend;

    /* ── resolve symbol ── */
    if (sym_idx && symtab && strtab) {
        const Elf64_Sym* sym = &symtab[sym_idx];
        const char* name = strtab + sym->st_name;

        /* defined locally in the binary */
        if (sym->st_value)
            S = sym->st_value + bias;

        /* undefined — look in our stub table */
        if (!S && name && *name) {
            if (strcmp(name, "__libc_start_main") == 0)
                S = (uint64_t)(uintptr_t)MineThunkFor((void*)stub_libc_start_main);
            else {
                void* stub = find_stub(name);
                if (stub)
                    S = (uint64_t)(uintptr_t)stub;
                else
                    fprintf(stderr, "[MinE-Dyn] Unresolved: %s\n", name);
            }
        }

        if (type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT)
            fprintf(stderr, "[MinE-Dyn]   %-32s -> 0x%016llX\n",
                name, (unsigned long long)S);
    }

    /* ── patch GOT entry ── */
    DWORD old = 0;
    VirtualProtect(target, 8, PAGE_EXECUTE_READWRITE, &old);

    switch (type) {
    case R_X86_64_NONE:      break;
    case R_X86_64_RELATIVE:  *target = (uint64_t)((int64_t)bias + A); break;
    case R_X86_64_64:        *target = S + (uint64_t)A;               break;
    case R_X86_64_GLOB_DAT:
    case R_X86_64_JUMP_SLOT: *target = S;                             break;
    case R_X86_64_IRELATIVE:
    {
        typedef uint64_t(*ifunc_t)(void);
        ifunc_t fn = (ifunc_t)(uintptr_t)((uint64_t)((int64_t)bias + A));
        __try { *target = fn(); }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            fprintf(stderr, "[MinE-Dyn] IRELATIVE faulted\n");
        }
    }
    break;
    default:
        fprintf(stderr, "[MinE-Dyn] Unknown reloc type %u\n", type);
        break;
    }

    VirtualProtect(target, 8, old, &old);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MineDynLink
 * ═══════════════════════════════════════════════════════════════════════════ */

bool MineDynLink(const char* path, MineImage* img)
{
    g_envp = (char**)_environ;
    MineThunkInit();

    HANDLE fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return false;

    /* ── ELF header ── */
    Elf64_Ehdr ehdr;
    memset(&ehdr, 0, sizeof(ehdr));
    if (!fread_at(fh, 0, &ehdr, (DWORD)sizeof(ehdr))) { CloseHandle(fh); return false; }

    /* ── program headers ── */
    DWORD      ph_bytes = (DWORD)ehdr.e_phnum * (DWORD)ehdr.e_phentsize;
    Elf64_Phdr* phdrs = (Elf64_Phdr*)calloc(1, (size_t)ph_bytes + 8);
    if (!phdrs) { CloseHandle(fh); return false; }
    if (!fread_at(fh, ehdr.e_phoff, phdrs, ph_bytes))
    {
        free(phdrs); CloseHandle(fh); return false;
    }
    CloseHandle(fh);

    /* ── find PT_DYNAMIC ── */
    uint64_t dyn_va = 0;
    for (int i = 0; i < (int)ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn_va = phdrs[i].p_vaddr + img->load_bias;
            break;
        }
    }
    free(phdrs);

    if (!dyn_va) {
        printf("[MinE-Dyn] Static binary — no relocations needed\n");
        return true;
    }

    /*
     * For a PIE: DT_* address fields hold linked VAs (based at 0).
     * Real address = d_val + load_bias.
     * Guard against double-bias: if already within mapped image, use as-is.
     */
#define BIAS_ADDR(v) \
    (((v) >= img->base && (v) < img->base + 0x800000ULL) \
     ? (v) : (v) + img->load_bias)

    Elf64_Dyn* dyn = (Elf64_Dyn*)(uintptr_t)dyn_va;
    uint64_t   strtab = 0, symtab = 0;
    uint64_t   rela = 0, relasz = 0;
    uint64_t   jmprel = 0, pltrelsz = 0;  /* DT_JMPREL + DT_PLTRELSZ(=2) */
    uint64_t   init_fn = 0, fini_fn = 0;
    uint64_t   init_arr = 0, init_arr_sz = 0;
    uint64_t   fini_arr = 0, fini_arr_sz = 0;

    for (Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        switch ((uint64_t)d->d_tag) {
        case DT_STRTAB:       strtab = BIAS_ADDR(d->d_val); break;
        case DT_SYMTAB:       symtab = BIAS_ADDR(d->d_val); break;
        case DT_RELA:         rela = BIAS_ADDR(d->d_val); break;
        case DT_RELASZ:       relasz = d->d_val;            break;
        case DT_JMPREL:       jmprel = BIAS_ADDR(d->d_val); break;
        case DT_PLTRELSZ:     pltrelsz = d->d_val;            break; /* = 2 */
        case DT_INIT:         init_fn = BIAS_ADDR(d->d_val); break;
        case DT_FINI:         fini_fn = BIAS_ADDR(d->d_val); break;
        case DT_INIT_ARRAY:   init_arr = BIAS_ADDR(d->d_val); break;
        case DT_INIT_ARRAYSZ: init_arr_sz = d->d_val;            break;
        case DT_FINI_ARRAY:   fini_arr = BIAS_ADDR(d->d_val); break;
        case DT_FINI_ARRAYSZ: fini_arr_sz = d->d_val;            break;
        default: break;
        }
    }

    /* print DT_NEEDED */
    if (strtab) {
        for (Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++)
            if (d->d_tag == DT_NEEDED)
                printf("[MinE-Dyn] Requires: %s\n",
                    (const char*)(uintptr_t)(strtab + d->d_val));
    }

    fprintf(stderr,
        "[MinE-Dyn] strtab=0x%llX symtab=0x%llX\n"
        "[MinE-Dyn] rela=0x%llX sz=%llu  plt=0x%llX sz=%llu\n",
        (unsigned long long)strtab, (unsigned long long)symtab,
        (unsigned long long)rela, (unsigned long long)relasz,
        (unsigned long long)jmprel, (unsigned long long)pltrelsz);

    const Elf64_Sym* sym_table = symtab ? (const Elf64_Sym*)(uintptr_t)symtab : NULL;
    const char* str_table = strtab ? (const char*)(uintptr_t)strtab : NULL;

    /* ── .rela.dyn ── */
    if (rela && relasz) {
        uint64_t n = relasz / sizeof(Elf64_Rela);
        printf("[MinE-Dyn] .rela.dyn  %llu relocations\n", (unsigned long long)n);
        Elf64_Rela* rels = (Elf64_Rela*)(uintptr_t)rela;
        for (uint64_t i = 0; i < n; i++)
            apply_rela(&rels[i], img->load_bias, sym_table, str_table);
    }

    /* ── .rela.plt ── */
    if (jmprel && pltrelsz) {
        uint64_t n = pltrelsz / sizeof(Elf64_Rela);
        printf("[MinE-Dyn] .rela.plt  %llu relocations\n", (unsigned long long)n);
        Elf64_Rela* rels = (Elf64_Rela*)(uintptr_t)jmprel;
        for (uint64_t i = 0; i < n; i++)
            apply_rela(&rels[i], img->load_bias, sym_table, str_table);
    }

    /* ── DT_INIT ── */
    if (init_fn) {
        printf("[MinE-Dyn] Calling DT_INIT @ 0x%llX\n", (unsigned long long)init_fn);
        __try { ((void(*)(void))(uintptr_t)init_fn)(); }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            fprintf(stderr, "[MinE-Dyn] DT_INIT faulted\n");
        }
    }

    /* ── INIT_ARRAY ── */
    if (init_arr && init_arr_sz) {
        uint64_t n = init_arr_sz / sizeof(uint64_t);
        uint64_t* arr = (uint64_t*)(uintptr_t)init_arr;
        
        for (uint64_t i = 0; i < n; i++) {
            if (arr[i] && arr[i] != (uint64_t)-1) {
                __try { ((void(*)(void))(uintptr_t)arr[i])(); }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
            }
        }
    }

    printf("[MinE-Dyn] Dynamic linking complete\n");
 
    return true;
}