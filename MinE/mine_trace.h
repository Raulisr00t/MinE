#ifndef MINE_TRACE_H
#define MINE_TRACE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

    void MineTraceInit(void);

    void MineTraceEnter(uint64_t nr, uint64_t a1, uint64_t a2, uint64_t a3,
        uint64_t a4, uint64_t a5, uint64_t a6);
    void MineTraceExit(uint64_t nr, uint64_t result);

    extern bool g_trace_enabled;

#ifdef __cplusplus
}
#endif

#endif 