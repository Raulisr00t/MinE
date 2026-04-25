#include "mine_VEH.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

static PVOID g_veh = NULL;

static LONG WINAPI VEHHandler(EXCEPTION_POINTERS* ep)
{
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    CONTEXT* ctx = ep->ContextRecord;

    if (er->ExceptionCode != STATUS_ILLEGAL_INSTRUCTION &&
        er->ExceptionCode != 0xC0000096UL)
        return EXCEPTION_CONTINUE_SEARCH;

    __try {
        uint8_t* rip = (uint8_t*)ctx->Rip;
        if (rip[0] != 0x0F || rip[1] != 0x05)
            return EXCEPTION_CONTINUE_SEARCH;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    ctx->Rax = MineSyscall(ctx->Rax,
        ctx->Rdi, ctx->Rsi, ctx->Rdx,
        ctx->R10, ctx->R8, ctx->R9);
    ctx->Rip += 2;
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool MineVEHInstall(void)
{
    g_veh = AddVectoredExceptionHandler(1, VEHHandler);
    if (!g_veh) {
        fprintf(stderr, "[MinE-Error] AddVectoredExceptionHandler failed  err=%lu\n",
            GetLastError());
        return false;
    }

    printf("[MinE] VEH installed syscall trap active\n");
    
    return true;
}

void MineVEHRemove(void)
{
    if (g_veh) {                              
        RemoveVectoredExceptionHandler(g_veh);
        g_veh = NULL;
    }
}