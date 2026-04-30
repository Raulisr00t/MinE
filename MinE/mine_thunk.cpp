#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include "mine_thunk.h"
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*
 * Each thunk is 16 bytes:
 *   48 B8 <win_fn 8 bytes>   mov rax, win_fn        10 bytes
 *   E9 <rel32>               jmp MineLinuxToWinFS    5 bytes
 *   90                       nop                     1 byte
 *
 * MineLinuxToWinFS (mine_ABI.asm):
 *   Saves guest FS, shuffles Linux->Win ABI (6 args), calls rax, restores FS.
 *
 * NO DEDUPLICATION — every MineThunkFor call with a unique win_fn gets its
 * own thunk slot. This avoids the bug where two different stub_* functions
 * that happen to have adjacent code addresses were incorrectly sharing thunks.
 */

#define MAX_THUNKS  1024
#define THUNK_BYTES 16

static uint8_t* g_pool = NULL;
static int      g_count = 0;

static uint8_t* alloc_near(void* target, size_t size)
{
    uint64_t base = (uint64_t)(uintptr_t)target;
    for (int64_t delta = 0x10000; delta < 0x70000000LL; delta += 0x10000) {
        for (int sign = -1; sign <= 1; sign += 2) {
            uint64_t addr = base + (uint64_t)(delta * sign);
            uint8_t* p = (uint8_t*)VirtualAlloc(
                (LPVOID)(uintptr_t)addr, size,
                MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (p) return p;
        }
    }
    return NULL;
}

void MineThunkInit(void)
{
    size_t sz = (size_t)MAX_THUNKS * THUNK_BYTES;
    void* shim = (void*)MineLinuxToWinFS;

    g_pool = shim ? alloc_near(shim, sz) : NULL;
    if (!g_pool)
        g_pool = (uint8_t*)VirtualAlloc(NULL, sz,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (g_pool)
        printf("[MinE-Thunk] Pool @ 0x%llX  (shim @ 0x%llX)\n",
            (unsigned long long)(uintptr_t)g_pool,
            (unsigned long long)(uintptr_t)MineLinuxToWinFS);
    else
        fprintf(stderr, "[MinE-Thunk] FATAL: cannot allocate thunk pool\n");
}

void* MineThunkFor(void* win_fn)
{
    if (!win_fn || !g_pool) return win_fn;

    if (g_count >= MAX_THUNKS) {
        fprintf(stderr, "[MinE-Thunk] Pool full (%d), using raw ptr\n", MAX_THUNKS);
        return win_fn;
    }

    uint8_t* t = g_pool + (size_t)g_count * THUNK_BYTES;
    uint64_t  fn64 = (uint64_t)(uintptr_t)win_fn;
    uint64_t  shim64 = (uint64_t)(uintptr_t)MineLinuxToWinFS;

    /* mov rax, imm64 */
    t[0] = 0x48; t[1] = 0xB8;
    memcpy(t + 2, &fn64, 8);

    /* Try rel32 jmp to MineLinuxToWinFS */
    uint8_t* after_jmp = t + 10 + 5;
    int64_t  rel64 = (int64_t)shim64 - (int64_t)(uintptr_t)after_jmp;

    if (rel64 >= -0x7FFFFFFFLL && rel64 <= 0x7FFFFFFFLL) {
        /* rel32 jmp — fits in one slot */
        int32_t rel32 = (int32_t)rel64;
        t[10] = 0xE9;
        memcpy(t + 11, &rel32, 4);
        t[15] = 0x90;
        g_count++;
    }
    else {
        /* abs64 jump — needs 2 slots (32 bytes) */
        if (g_count + 1 >= MAX_THUNKS) {
            fprintf(stderr, "[MinE-Thunk] Pool full for abs64 thunk\n");
            return win_fn;
        }
        /*
         * Slot 0 (t+0..t+15):
         *   48 B8 <win_fn>       mov rax, win_fn      10b
         *   49 BB <shim>         mov r11, shim        (needs t+10..t+19) — crosses slot!
         *
         * Use a different layout that fits:
         * Both slots together = 32 bytes:
         *   [0]  48 B8 <fn 8b>          mov rax, fn          10b
         *   [10] 49 BB <shim 8b>        mov r11, shim        10b
         *   [20] 41 FF E3               jmp r11               3b
         *   [23] 90 * 9                 nop pad               9b
         */
        uint8_t* blk = t;   /* 32 bytes = 2 slots */
        /* mov rax, fn */
        blk[0] = 0x48; blk[1] = 0xB8; memcpy(blk + 2, &fn64, 8);
        /* mov r11, shim */
        blk[10] = 0x49; blk[11] = 0xBB; memcpy(blk + 12, &shim64, 8);
        /* jmp r11 */
        blk[20] = 0x41; blk[21] = 0xFF; blk[22] = 0xE3;
        /* nop pad */
        memset(blk + 23, 0x90, 9);

        g_count += 2;
    }

    return (void*)t;
}