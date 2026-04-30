#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include "mine_trace.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

bool g_trace_enabled = false;

static const struct { uint64_t nr; const char* name; } s_names[] = {
    {0,"read"},{1,"write"},{2,"open"},{3,"close"},
    {4,"stat"},{5,"fstat"},{6,"lstat"},{8,"lseek"},
    {9,"mmap"},{10,"mprotect"},{11,"munmap"},{12,"brk"},
    {13,"rt_sigaction"},{14,"rt_sigprocmask"},{15,"rt_sigreturn"},
    {16,"ioctl"},{17,"pread64"},{20,"writev"},{21,"access"},
    {22,"pipe"},{24,"sched_yield"},{25,"mremap"},
    {32,"dup"},{33,"dup2"},{35,"nanosleep"},{39,"getpid"},
    {41,"socket"},{42,"connect"},{43,"accept"},
    {56,"clone"},{57,"fork"},{59,"execve"},
    {60,"exit"},{61,"wait4"},{62,"kill"},
    {63,"uname"},{72,"fcntl"},{79,"getcwd"},{80,"chdir"},
    {83,"mkdir"},{87,"unlink"},{89,"readlink"},
    {96,"gettimeofday"},{97,"getrlimit"},
    {102,"getuid"},{104,"getgid"},{107,"geteuid"},{108,"getegid"},
    {110,"getppid"},{111,"getpgrp"},{112,"setsid"},
    {131,"sigaltstack"},{158,"arch_prctl"},{186,"gettid"},
    {202,"futex"},{217,"getdents64"},{218,"set_tid_address"},
    {228,"clock_gettime"},{229,"clock_getres"},{231,"exit_group"},
    {257,"openat"},{262,"newfstatat"},{273,"set_robust_list"},
    {302,"prlimit64"},{318,"getrandom"},
};

static const char* nr_name(uint64_t nr)
{
    for (int i = 0; i < (int)(sizeof(s_names) / sizeof(s_names[0])); i++)
        if (s_names[i].nr == nr) return s_names[i].name;
    return "???";
}

void MineTraceInit(void)
{
    /* enable if env var set OR always flush so output isn't lost on crash */
    g_trace_enabled = (getenv("MINE_TRACE") != NULL);

    /* always line-buffer stderr so we see output before a crash */
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void MineTraceEnter(uint64_t nr,
    uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6)
{
    if (!g_trace_enabled) return;
    
    fprintf(stderr, "[sys] %-18s (%llx %llx %llx %llx %llx %llx) --> ",
        nr_name(nr),
        (unsigned long long)a1, (unsigned long long)a2,
        (unsigned long long)a3, (unsigned long long)a4,
        (unsigned long long)a5, (unsigned long long)a6);
}

void MineTraceExit(uint64_t nr, uint64_t result)
{
    if (!g_trace_enabled) return;
    
    int64_t s = (int64_t)result;
    
    if (s < 0 && s >= -4095)
        fprintf(stderr, "ERR %lld\n", (long long)s);
 
    else
        fprintf(stderr, "= 0x%llx\n", (unsigned long long)result);
}