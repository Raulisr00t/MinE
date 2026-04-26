/*
 * mine_thunk.h
 *
 * Every function we give to the guest must be called with Linux x86-64 ABI
 * (args in RDI, RSI, RDX, RCX, R8, R9) but our stubs are Windows __cdecl
 * (args in RCX, RDX, R8, R9).
 *
 * MineLinuxToWin (in mine_abi.asm) fixes this:
 *   set RAX = Windows fn ptr, then call MineLinuxToWin
 *
 * MAKE_THUNK generates a naked per-symbol wrapper:
 *   <name>_thunk:  mov rax, <win_fn>  ;  jmp MineLinuxToWin
 */

#ifndef MINE_THUNK_H
#define MINE_THUNK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    /* defined in mine_abi.asm */
    void MineLinuxToWin(void);

    /*
     * A thunk is a small heap-allocated code blob:
     *   48 B8 <imm64>   mov rax, <win_fn>
     *   FF E0           jmp rax  (to MineLinuxToWin... wait, we need a call not jmp)
     *
     * Actually simpler: since we control the stub, make a trampoline per function
     * that does the arg shuffle inline. We generate them dynamically.
     *
     * Thunk layout (14 bytes):
     *   48 B8 xx xx xx xx xx xx xx xx   mov rax, <win_fn_ptr>   (10 bytes)
     *   E9 xx xx xx xx                  jmp MineLinuxToWin      (5 bytes)
     *   -- total: 15 bytes, pad to 16
     */

    typedef struct {
        uint8_t code[16];
    } MineThunk;

    /* Allocate executable memory for thunks and generate one per stub */
    void  MineThunkInit(void);

    /* Given a Windows function pointer, return a Linux-ABI-compatible thunk ptr */
    void* MineThunkFor(void* win_fn);

#ifdef __cplusplus
}
#endif

#endif /* MINE_THUNK_H */