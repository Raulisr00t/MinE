#define _CRT_SECURE_NO_WARNINGS
#include "mine_trace.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

bool g_trace_enabled = false;

// syscall name table 

static const struct { uint64_t nr; const char* name; } s_names[] = {
    {0,"read"},{1,"write"},{2,"open"},{3,"close"},
    {4,"stat"},{5,"fstat"},{6,"lstat"},{8,"lseek"},
    {9,"mmap"},{10,"mprotect"},{11,"munmap"},{12,"brk"},
    {13,"rt_sigaction"},{14,"rt_sigprocmask"},{15,"rt_sigreturn"},
    {16,"ioctl"},{17,"pread64"},{20,"writev"},{21,"access"},
    {22,"pipe"},{24,"sched_yield"},{25,"mremap"},
    {32,"dup"},{33,"dup2"},{35,"nanosleep"},{39,"getpid"},
    {41,"socket"},{42,"connect"},{43,"accept"},{44,"sendto"},
    {45,"recvfrom"},{49,"bind"},{50,"listen"},
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
    {318,"getrandom"},
};

static const char* nr_name(uint64_t nr)
{
    for (int i = 0; i < (int)(sizeof(s_names) / sizeof(s_names[0])); i++)
        if (s_names[i].nr == nr) return s_names[i].name;
    return "???";
}

#define COL_RESET  7
#define COL_NR     11  
#define COL_ARG    8   
#define COL_OK     10  
#define COL_ERR    12  

static void set_col(WORD c)
{
    SetConsoleTextAttribute(GetStdHandle(STD_ERROR_HANDLE), c);
}

/* ─── public API ──────────────────────────────────────────────────────────── */

void MineTraceInit(void)
{
    g_trace_enabled = (getenv("MINE_TRACE") != NULL);
}

void MineTraceEnter(uint64_t nr,
    uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6)
{
    if (!g_trace_enabled) return;

    set_col(COL_NR);
    fprintf(stderr, "[sys] %-20s", nr_name(nr));
    set_col(COL_ARG);
    fprintf(stderr, " (%llx, %llx, %llx, %llx, %llx, %llx)",
        (unsigned long long)a1, (unsigned long long)a2,
        (unsigned long long)a3, (unsigned long long)a4,
        (unsigned long long)a5, (unsigned long long)a6);
    set_col(COL_RESET);
}

void MineTraceExit(uint64_t nr, uint64_t result)
{
    if (!g_trace_enabled) return;

    int64_t s = (int64_t)result;
    /* Linux: -1 to -4095 are errors */
    if (s < 0 && s >= -4095) {
        set_col(COL_ERR);
        fprintf(stderr, " = %lld (err)\n", (long long)s);
    }

    else {
        set_col(COL_OK);
        fprintf(stderr, " = %llx\n", (unsigned long long)result);
    }
    
    set_col(COL_RESET);
}