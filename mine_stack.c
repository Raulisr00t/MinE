#define _CRT_SECURE_NO_WARNINGS
#include "mine_stack.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#define AT_NULL     0
#define AT_PHDR     3
#define AT_PHENT    4
#define AT_PHNUM    5
#define AT_PAGESZ   6
#define AT_BASE     7
#define AT_FLAGS    8
#define AT_ENTRY    9
#define AT_UID      11
#define AT_EUID     12
#define AT_GID      13
#define AT_EGID     14
#define AT_CLKTCK   17
#define AT_PLATFORM 15
#define AT_HWCAP    16
#define AT_SECURE   23
#define AT_RANDOM   25
#define AT_HWCAP2   26
#define AT_EXECFN   31

static uint8_t* sp;

static void push_u64(uint64_t v)
{
    sp -= 8;
    memcpy(sp, &v, 8);
}

static uint64_t push_str(const char* s)
{
    size_t len = strlen(s) + 1;
    sp -= len;
    memcpy(sp, s, len);
    return (uint64_t)sp;
}

static void push_auxv(uint64_t type, uint64_t val)
{
    push_u64(val);
    push_u64(type);
}

static uint64_t push_random(void)
{
    sp -= 16;
    HCRYPTPROV p = 0;  

    if (CryptAcquireContextA(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(p, 16, sp);
        CryptReleaseContext(p, 0);
    }
    else {
        memset(sp, 0xAB, 16);
    }
    return (uint64_t)sp;
}

bool MineStackAlloc(MineStack* out)
{
    SIZE_T total = (SIZE_T)MINE_STACK_SIZE + (SIZE_T)0x1000;

    void* region = VirtualAlloc(NULL, total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!region) {
        fprintf(stderr, "[MinE-Error] Stack alloc failed  err=%lu\n", GetLastError());
        return false;
    }

    DWORD old;
    VirtualProtect(region, 0x1000, PAGE_NOACCESS, &old);

    out->stack_top = (uint64_t)region + (uint64_t)total;
    out->rsp = 0;

    printf("[MinE] Stack  0x%llX - 0x%llX  (%u MiB)\n",
        (unsigned long long)((uint64_t)region + 0x1000),
        (unsigned long long)out->stack_top,
        (unsigned)(MINE_STACK_SIZE / (1024 * 1024)));

    return true;
}

uint64_t MineStackBuild(uint64_t stack_top,
    int argc, const char** argv, const char** envp,
    const MineImage* img)
{
    sp = (uint8_t*)stack_top;
    sp = (uint8_t*)((uintptr_t)sp & ~(uintptr_t)7);

    int envc = 0;
    if (envp) while (envp[envc]) envc++;

    uint64_t* env_ptrs = (uint64_t*)malloc(((size_t)envc + 1) * sizeof(uint64_t));

    for (int i = envc - 1; i >= 0; i--)
        env_ptrs[i] = push_str(envp[i]);
    env_ptrs[envc] = 0;

    uint64_t* arg_ptrs = (uint64_t*)malloc(((size_t)argc + 1) * sizeof(uint64_t));

    for (int i = argc - 1; i >= 0; i--)
        arg_ptrs[i] = push_str(argv[i]);
    arg_ptrs[argc] = 0;

    uint64_t platform_addr = push_str("x86_64");
    uint64_t random_addr = push_random();
    uint64_t execfn_addr = push_str(argv[0]);

    sp = (uint8_t*)((uintptr_t)sp & ~(uintptr_t)15);

    push_auxv(AT_NULL, 0);
    push_auxv(AT_EXECFN, execfn_addr);
    push_auxv(AT_RANDOM, random_addr);
    push_auxv(AT_PLATFORM, platform_addr);
    push_auxv(AT_HWCAP2, 0);
    push_auxv(AT_HWCAP, 0x078bfbff);
    push_auxv(AT_SECURE, 0);
    push_auxv(AT_CLKTCK, 100);
    push_auxv(AT_EGID, 1000);
    push_auxv(AT_GID, 1000);
    push_auxv(AT_EUID, 1000);
    push_auxv(AT_UID, 1000);
    push_auxv(AT_FLAGS, 0);
    push_auxv(AT_BASE, 0);
    push_auxv(AT_ENTRY, img->entry);
    push_auxv(AT_PAGESZ, 0x1000);
    push_auxv(AT_PHNUM, img->phnum);
    push_auxv(AT_PHENT, (img->bits == 64) ? 56 : 32);
    push_auxv(AT_PHDR, img->phdr_va);

    push_u64(0);
    for (int i = envc - 1; i >= 0; i--)
        push_u64(env_ptrs[i]);

    push_u64(0);
    for (int i = argc - 1; i >= 0; i--)
        push_u64(arg_ptrs[i]);

    push_u64((uint64_t)argc);

    free(arg_ptrs);
    free(env_ptrs);

    uint64_t rsp = (uint64_t)sp;
    if (rsp & 15) rsp &= ~(uint64_t)15;

    printf("[MinE] Stack RSP=0x%llX  argc=%d  envc=%d\n",
        (unsigned long long)rsp, argc, envc);
    return rsp;
}