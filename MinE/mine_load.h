#ifndef MINE_LOAD_H
#define MINE_LOAD_H

#include <Windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        uint64_t base;
        uint64_t load_bias;
        uint64_t entry;
        uint64_t phdr_va;
        uint16_t phnum;
        uint8_t  bits;
    } MineImage;

    bool MineLoad(LPCSTR path, uint8_t bits, MineImage* out);

#ifdef __cplusplus
}
#endif

#endif