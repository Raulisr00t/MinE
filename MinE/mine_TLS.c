#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include "mine_tls.h"
#include "mine_dynamic.h"

#include <Windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <wincrypt.h>
#include <ntstatus.h>

/*
 * x86-64 TLS variant II layout (glibc/musl):
 *
 *   [TLS data block (tls_memsz bytes)] [MineTCB]
 *                                       ^ FS points here
 *
 *   FS:[0x00]  self        pointer to this struct
 *   FS:[0x08]  dtv         dynamic thread vector
 *   FS:[0x28]  stack_guard stack canary value
 *   FS:[0x30]  ptr_guard   pointer guard
 *
 * Local-exec TLS access uses negative FS offsets: fs:[-X]
 * __tls_get_addr uses DTV[module] + offset
 */

#pragma pack(push, 1)
typedef struct {
    uint64_t self;          /* 0x00 */
    uint64_t dtv;           /* 0x08 */
    uint64_t reserved1;     /* 0x10 */
    uint64_t reserved2;     /* 0x18 */
    uint64_t reserved3;     /* 0x20 */
    uint64_t stack_guard;   /* 0x28 */
    uint64_t ptr_guard;     /* 0x30 */
    uint64_t reserved4;     /* 0x38 */
    uint8_t  pad[0x100 - 0x40];
} MineTCB;
#pragma pack(pop)

static MineTCB* g_tcb = NULL;
static uint64_t g_fs_base = 0;
static uint8_t* g_tls_block = NULL;
static uint64_t g_tls_size = 0;
static void*    g_alloc_base = NULL;

/* Try wrfsbase - available on Windows 10+ when CR4.FSGSBASE=1 */
static bool try_wrfsbase(uint64_t base)
{
    __try {
        _writefsbase_u64(base);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

/* Fallback: NtSetInformationThread */
typedef NTSTATUS(NTAPI* NtSetInfoThread_t)(HANDLE, ULONG, PVOID, ULONG);

static bool try_nt_set_fs(uint64_t base)
{
    static NtSetInfoThread_t fn = NULL;
    if (!fn) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
            fn = (NtSetInfoThread_t)GetProcAddress(ntdll, "NtSetInformationThread");
    }
    if (!fn) return false;

    NTSTATUS st = fn(GetCurrentThread(), 0x11, &base, (ULONG)sizeof(base));
    if (st >= 0) return true;
    st = fn(GetCurrentThread(), 0x31, &base, (ULONG)sizeof(base));
    return st >= 0;
}

bool MineTLSInit(const MineImage* img)
{
    uint64_t tls_memsz = img->tls_memsz;
    uint64_t tls_filesz = img->tls_filesz;
    uint64_t tls_align = img->tls_align;
    if (tls_align < 16) tls_align = 16;

    /* Round TLS size up to alignment */
    uint64_t aligned_tls = 0;
    if (tls_memsz > 0)
        aligned_tls = (tls_memsz + tls_align - 1) & ~(tls_align - 1);

    /*
     * Allocate one contiguous block: [TLS data][MineTCB]
     * FS points to the MineTCB portion.
     * Local-exec TLS vars use negative FS offsets into the TLS data region.
     */
    uint64_t total = aligned_tls + sizeof(MineTCB);
    g_alloc_base = VirtualAlloc(NULL, (SIZE_T)(total + 4096),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_alloc_base) {
        fprintf(stderr, "[MinE-TLS] Failed to allocate TLS+TCB block\n");
        return false;
    }
    memset(g_alloc_base, 0, (size_t)total);

    g_tls_block = (uint8_t*)g_alloc_base;
    g_tls_size = aligned_tls;
    g_tcb = (MineTCB*)(g_tls_block + aligned_tls);

    /* Copy TLS template data from the loaded image */
    if (tls_filesz > 0 && img->tls_vaddr) {
        memcpy(g_tls_block, (void*)(uintptr_t)img->tls_vaddr, (size_t)tls_filesz);
        printf("[MinE-TLS] Copied %llu bytes of TLS template data\n",
            (unsigned long long)tls_filesz);
    }

    /* FS:[0x00] = self-pointer */
    g_tcb->self = (uint64_t)(uintptr_t)g_tcb;

    /* FS:[0x28] = stack canary */
    HCRYPTPROV cp = 0;
    if (CryptAcquireContextA(&cp, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(cp, 8, (BYTE*)&g_tcb->stack_guard);
        CryptReleaseContext(cp, 0);
    }
    else {
        g_tcb->stack_guard = 0xDEADBEEFCAFEBABEULL;
    }

    /* FS:[0x30] = pointer guard */
    g_tcb->ptr_guard = g_tcb->stack_guard ^ 0x5A5A5A5A5A5A5A5AULL;

    g_fs_base = (uint64_t)(uintptr_t)g_tcb;

    bool ok = false;

    if (try_wrfsbase(g_fs_base)) {
        printf("[MinE-TLS] FS base set via wrfsbase @ 0x%llX  canary=0x%llX  tls_size=%llu\n",
            (unsigned long long)g_fs_base,
            (unsigned long long)g_tcb->stack_guard,
            (unsigned long long)aligned_tls);
        MineDynSetGuestFS(g_fs_base);
        ok = true;
    }
    else if (try_nt_set_fs(g_fs_base)) {
        printf("[MinE-TLS] FS base set via NtSetInformationThread @ 0x%llX  tls_size=%llu\n",
            (unsigned long long)g_fs_base,
            (unsigned long long)aligned_tls);
        MineDynSetGuestFS(g_fs_base);
        ok = true;
    }
    else {
        fprintf(stderr,
            "[MinE-TLS] WARNING: Cannot set FS base (no FSGSBASE support).\n"
            "           Stack canary checks WILL fail for glibc binaries.\n"
            "           Try running as Administrator or on Windows 10 1903+.\n");
        ok = false;
    }

    return ok;
}

uint64_t MineTLSBase(void) { return g_fs_base; }
uint8_t* MineTLSGetBlock(void) { return g_tls_block; }
uint64_t MineTLSGetSize(void) { return g_tls_size; }
