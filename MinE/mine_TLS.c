#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include "mine_tls.h"

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
 * Minimal Thread Control Block (TCB) layout expected by glibc/musl x86-64:
 *
 *   FS:[0x00]  self        pointer to this struct (required by glibc)
 *   FS:[0x08]  dtv         dynamic thread vector   (NULL is OK for static TLS)
 *   FS:[0x10]  unused
 *   FS:[0x18]  unused
 *   FS:[0x20]  unused
 *   FS:[0x28]  stack_guard stack canary value      (MUST be non-zero)
 *   FS:[0x30]  ptr_guard   pointer guard
 *   ...
 *
 * We allocate a page-aligned block, fill the canary, and point FS at it.
 */

#pragma pack(push, 1)
typedef struct {
    uint64_t self;          /* 0x00 — must point to this struct             */
    uint64_t dtv;           /* 0x08                                         */
    uint64_t reserved1;     /* 0x10                                         */
    uint64_t reserved2;     /* 0x18                                         */
    uint64_t reserved3;     /* 0x20                                         */
    uint64_t stack_guard;   /* 0x28 — stack canary                          */
    uint64_t ptr_guard;     /* 0x30 — pointer guard                         */
    uint64_t reserved4;     /* 0x38                                         */
    /* padding to 64 bytes */
    uint8_t  pad[0x100 - 0x40];
} MineTCB;
#pragma pack(pop)

static MineTCB* g_tcb = NULL;
static uint64_t g_fs_base = 0;

/* Try wrfsbase — available on Windows 10+ when CR4.FSGSBASE=1 */
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

/* Fallback: NtSetInformationThread with undocumented ThreadLocalStoragePointer=0x11 */
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

    /* class 0x11 = ThreadWow64Context on some builds, try both 0x11 and 0x31 */
    NTSTATUS st = fn(GetCurrentThread(), 0x11, &base, (ULONG)sizeof(base));
    if (st >= 0) return true;
    st = fn(GetCurrentThread(), 0x31, &base, (ULONG)sizeof(base));
    return st >= 0;
}

bool MineTLSInit(void)
{
    /* allocate 4 KB aligned TCB */
    g_tcb = (MineTCB*)_aligned_malloc(sizeof(MineTCB), 64);
    if (!g_tcb) {
        fprintf(stderr, "[MinE-TLS] Failed to allocate TCB\n");
        return false;
    }
    memset(g_tcb, 0, sizeof(MineTCB));

    /* FS:[0x00] must be a self-pointer */
    g_tcb->self = (uint64_t)(uintptr_t)g_tcb;

    /* FS:[0x28] = stack canary — use a random value from Win32 */
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

    /* try to actually set FS base */
    bool ok = false;

    if (try_wrfsbase(g_fs_base)) {
        printf("[MinE-TLS] FS base set via wrfsbase @ 0x%llX  canary=0x%llX\n",
            (unsigned long long)g_fs_base,
            (unsigned long long)g_tcb->stack_guard);
        ok = true;
    }
    else if (try_nt_set_fs(g_fs_base)) {
        printf("[MinE-TLS] FS base set via NtSetInformationThread @ 0x%llX\n",
            (unsigned long long)g_fs_base);
        ok = true;
    }
    else {
        /*
         * Can't set FS base in user mode on this build.
         * Patch the canary value Windows already put in FS:[0x28] into our TCB
         * so the check passes even with the wrong FS base.
         * Windows puts its own cookie at GS:[0x28] on x64 (not FS).
         * FS on Windows x64 = TEB; FS:[0x28] = 0 typically (unused field).
         *
         * Best we can do: hook the VEH to intercept FS-prefix faults.
         * For now, report the limitation.
         */
        fprintf(stderr,
            "[MinE-TLS] WARNING: Cannot set FS base (no FSGSBASE support).\n"
            "           Stack canary checks WILL fail for glibc binaries.\n"
            "           Try running as Administrator or on Windows 10 1903+.\n");
        ok = false;
    }

    return ok;
}

uint64_t MineTLSBase(void) { return g_fs_base; }