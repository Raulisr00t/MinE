#include "mine_VEH.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

static PVOID g_veh = NULL;

static void report_crash(EXCEPTION_POINTERS* ep)
{
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    CONTEXT* ctx = ep->ContextRecord;

    fprintf(stderr,
        "\n[MinE] !! CRASH  code=0x%08lX  RIP=0x%016llX\n"
        "         RAX=0x%016llX  RBX=0x%016llX\n"
        "         RCX=0x%016llX  RDX=0x%016llX\n"
        "         RSI=0x%016llX  RDI=0x%016llX\n"
        "         RSP=0x%016llX  RBP=0x%016llX\n"
        "         R8 =0x%016llX  R9 =0x%016llX\n"
        "         R10=0x%016llX  R11=0x%016llX\n",
        er->ExceptionCode,
        (unsigned long long)ctx->Rip,
        (unsigned long long)ctx->Rax, (unsigned long long)ctx->Rbx,
        (unsigned long long)ctx->Rcx, (unsigned long long)ctx->Rdx,
        (unsigned long long)ctx->Rsi, (unsigned long long)ctx->Rdi,
        (unsigned long long)ctx->Rsp, (unsigned long long)ctx->Rbp,
        (unsigned long long)ctx->R8, (unsigned long long)ctx->R9,
        (unsigned long long)ctx->R10, (unsigned long long)ctx->R11);

    fprintf(stderr, "         RIP bytes: ");
    __try {
        uint8_t* rip = (uint8_t*)ctx->Rip;
        for (int i = 0; i < 16; i++)
            fprintf(stderr, "%02X ", rip[i]);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "<unreadable>");
    }
    fprintf(stderr, "\n");
    fflush(stderr);
}

static LONG WINAPI VEHHandler(EXCEPTION_POINTERS* ep)
{
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    CONTEXT* ctx = ep->ContextRecord;

    if (er->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION ||
        er->ExceptionCode == 0xC0000096UL)
    {
        __try {
            uint8_t* rip = (uint8_t*)ctx->Rip;
            
            if (rip[0] == 0x0F && rip[1] == 0x05) {
                ctx->Rax = MineSyscall(ctx->Rax,
                    ctx->Rdi, ctx->Rsi, ctx->Rdx,
                    ctx->R10, ctx->R8, ctx->R9);
                ctx->Rip += 2;
            
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        fprintf(stderr, "\n[MinE] SIGSEGV — guest accessed 0x%016llX (%s)\n",
            (unsigned long long)er->ExceptionInformation[1],
            er->ExceptionInformation[0] ? "write" : "read");
        report_crash(ep);
        ExitProcess(139);
    }

    if (er->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) {
        fprintf(stderr, "\n[MinE] SIGILL — illegal instruction\n");
        report_crash(ep);
        ExitProcess(132);
    }

    if (er->ExceptionCode == EXCEPTION_STACK_OVERFLOW) {
        fprintf(stderr, "\n[MinE] Stack overflow at RIP=0x%016llX\n",
            (unsigned long long)ctx->Rip);
        ExitProcess(139);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

bool MineVEHInstall(void)
{
    g_veh = AddVectoredExceptionHandler(1, VEHHandler);
    if (!g_veh) {
        fprintf(stderr, "[MinE-Error] AddVectoredExceptionHandler failed err=%lu\n",
            GetLastError());
        return false;
    }
    printf("[MinE] VEH installed — syscall trap active\n");
    return true;
}

void MineVEHRemove(void)
{
    if (g_veh) {
        RemoveVectoredExceptionHandler(g_veh);
        g_veh = NULL;
    }
}