#ifndef SYSCALL_TRANSLATE_H
#define SYSCALL_TRANSLATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    uint64_t MineSyscall(uint64_t nr,
        uint64_t a1, uint64_t a2, uint64_t a3,
        uint64_t a4, uint64_t a5, uint64_t a6);

#ifdef __cplusplus
}
#endif

#endif 