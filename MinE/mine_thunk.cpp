#define _CRT_SECURE_NO_WARNINGS
#include "mine_thunk.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAX_THUNKS  256
#define THUNK_BYTES 16   /* bytes per thunk */

static uint8_t* g_pool = NULL;
static int      g_count = 0;

extern void MineLinuxToWin(void);

/* Try to VirtualAlloc within +-2 GB of MineLinuxToWin so rel32 jmp works */
static uint8_t* alloc_near(void* target, size_t size)
{
    uint64_t base = (uint64_t)(uintptr_t)target;
    /* search upward then downward in 64 KB steps */
    for (int64_t delta = 0x10000; delta < 0x70000000LL; delta += 0x10000) {
        for (int sign = -1; sign <= 1; sign += 2) {
            uint64_t try_addr = base + (uint64_t)(delta * sign);
            uint8_t* p = (uint8_t*)VirtualAlloc(
                (LPVOID)(uintptr_t)try_addr, size,
                MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (p) return p;
        }
    }
    return NULL;
}

void MineThunkInit(void)
{
    size_t pool_size = (size_t)MAX_THUNKS * THUNK_BYTES;

    /* try to get pool near MineLinuxToWin so rel32 jmp reaches */
    g_pool = alloc_near((void*)MineLinuxToWin, pool_size);
    if (!g_pool) {
        /* fallback: anywhere */
        g_pool = (uint8_t*)VirtualAlloc(NULL, pool_size,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }

    if (g_pool)
        printf("[MinE-Thunk] Pool @ 0x%llX  (shim @ 0x%llX)\n",
            (unsigned long long)(uintptr_t)g_pool,
            (unsigned long long)(uintptr_t)MineLinuxToWin);
    else
        fprintf(stderr, "[MinE-Thunk] Alloc failed!\n");
}

/*
 * Each thunk (16 bytes):
 *   48 B8 <win_fn 8 bytes>   mov rax, <win_fn>    ; 10 bytes
 *   E9 <rel32>               jmp MineLinuxToWin   ;  5 bytes
 *   90                       nop                  ;  1 byte
 *
 * MineLinuxToWin receives:
 *   RAX = Windows function to call
 *   RDI/RSI/RDX/RCX/R8/R9 = Linux arguments
 * It shuffles to Windows ABI and calls RAX.
 */
void* MineThunkFor(void* win_fn)
{
    if (!win_fn) return NULL;
    if (!g_pool || g_count >= MAX_THUNKS) return win_fn;

    uint8_t* t = g_pool + (size_t)g_count * THUNK_BYTES;
    g_count++;

    /* mov rax, imm64 */
    t[0] = 0x48; t[1] = 0xB8;
    uint64_t fn64 = (uint64_t)(uintptr_t)win_fn;
    memcpy(t + 2, &fn64, 8);

    /* jmp rel32 to MineLinuxToWin */
    uint8_t* after_jmp = t + 10 + 5;
    int64_t  rel64 = (int64_t)(uintptr_t)MineLinuxToWin
        - (int64_t)(uintptr_t)after_jmp;

    if (rel64 < -0x7FFFFFFFLL || rel64 > 0x7FFFFFFFLL) {
        /* still too far — embed a full 64-bit jump sequence (12 bytes) */
        /* Reuse thunk space: mov r11,imm64 + jmp r11 = 12 bytes, fits in 16 */
        /*   49 BB <imm64>   mov r11, MineLinuxToWin   10 bytes
         *   41 FF E3        jmp r11                    3 bytes
         *   -- but RAX must carry win_fn, so put win_fn before MineLinuxToWin addr:
         * Layout:
         *   48 B8 <win_fn>          mov rax, win_fn          10 bytes
         *   49 BB <MineLinuxToWin>  mov r11, MineLinuxToWin  !! needs 20 total
         *
         * Won't fit. Use a two-thunk approach: put MineLinuxToWin address in pool+1.
         * For now print warning and return raw ptr with wrong ABI.
         */
        fprintf(stderr,
            "[MinE-Thunk] WARNING: MineLinuxToWin too far (rel=%lld). "
            "ABI mismatch for this stub.\n", (long long)rel64);
        g_count--;  /* reclaim */
        return win_fn;
    }

    int32_t rel32 = (int32_t)rel64;
    t[10] = 0xE9;
    memcpy(t + 11, &rel32, 4);
    t[15] = 0x90;

    return (void*)t;
}