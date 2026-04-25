#include "jump.h"
#include <Windows.h>
#include <stdio.h>

#if defined(_MSC_VER)
                                            
extern void MineJump(uint64_t entry, uint64_t rsp);

#elif defined(__GNUC__)

__attribute__((naked))
void MineJump(uint64_t entry, uint64_t rsp)
{
    __asm__ volatile (
        "mov  %rdx, %rsp\n"     
        "xor  %rbp, %rbp\n"     
        "xor  %rbx, %rbx\n"
        "xor  %r12, %r12\n"
        "xor  %r13, %r13\n"
        "xor  %r14, %r14\n"
        "xor  %r15, %r15\n"
        "xor  %rsi, %rsi\n"
        "xor  %rdi, %rdi\n"
        "xor  %rdx, %rdx\n"
        "xor  %rax, %rax\n"
        "jmp  *%rcx\n"          
        );
}

#endif 