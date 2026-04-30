#ifndef MINE_STACK_H
#define MINE_STACK_H

#include "mine_load.h"
#include <stdint.h>
#include <stdbool.h>

#include <bcrypt.h>
#include <wincrypt.h>
#include <ntstatus.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MINE_STACK_SIZE  (8 * 1024 * 1024)

    typedef struct {
        uint64_t stack_top;
        uint64_t rsp;
    } MineStack;

    bool     MineStackAlloc(MineStack* out);
    uint64_t MineStackBuild(uint64_t stack_top,
        int argc, const char** argv, const char** envp,
        const MineImage* img);

#ifdef __cplusplus
}
#endif

#endif