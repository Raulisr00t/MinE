#ifndef SYSCALL_TRANSLATE_H
#define SYSCALL_TRANSLATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    uint64_t MineSyscall(uint64_t nr,
        uint64_t a1, uint64_t a2, uint64_t a3,
        uint64_t a4, uint64_t a5, uint64_t a6);

    /*
     * g_mine_fs_base: the FS base address set by the guest via arch_prctl(ARCH_SET_FS).
     * Also declared in mine_ABI.asm (.DATA section) so MineJump can read it.
     * syscall_translate.c updates this whenever arch_prctl(ARCH_SET_FS) is called.
     */
    extern uint64_t g_mine_fs_base;

#ifdef __cplusplus
}
#endif

#endif /* SYSCALL_TRANSLATE_H */