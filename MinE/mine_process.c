#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include "mine_process.h"
#include "mine_thread.h"
#include "mine_vfs.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <io.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * exec — re-invoke MinE.exe with the target ELF binary
 *
 * We can't do a true Unix exec (replace process image) on Windows, so we
 * CreateProcess a new MinE.exe instance with the ELF path as argument,
 * wait for it, and return its exit code. The caller typically does
 * fork()+exec(), but since fork() returns -1 (or a fake pid), programs
 * that use system() or posix_spawn() patterns work through here.
 * ═══════════════════════════════════════════════════════════════════════════ */

static char g_mine_exe_path[MAX_PATH] = {0};

static void find_mine_exe(void)
{
    if (g_mine_exe_path[0]) return;
    GetModuleFileNameA(NULL, g_mine_exe_path, MAX_PATH);
}

int64_t MineExecve(const char* path, char* const argv[], char* const envp[])
{
    if (!path || !path[0]) return -2; /* ENOENT */

    find_mine_exe();

    int virt_type = VFS_REAL;
    const char* win_path = MineVFSTranslate(path, &virt_type);
    const char* use_path = win_path ? win_path : path;

    /* Build command line: MinE.exe <elf_path> [args...] */
    char cmdline[32768];
    int pos = snprintf(cmdline, sizeof(cmdline), "\"%s\" \"%s\"", g_mine_exe_path, use_path);

    if (argv) {
        for (int i = 1; argv[i] && pos < (int)sizeof(cmdline) - 256; i++) {
            pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " \"%s\"", argv[i]);
        }
    }

    /* Build environment block if provided */
    char* env_block = NULL;
    if (envp) {
        size_t total = 0;
        for (int i = 0; envp[i]; i++)
            total += strlen(envp[i]) + 1;
        total++;
        env_block = (char*)calloc(1, total);
        if (env_block) {
            char* p = env_block;
            for (int i = 0; envp[i]; i++) {
                size_t len = strlen(envp[i]);
                memcpy(p, envp[i], len);
                p += len + 1;
            }
        }
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.dwFlags = STARTF_USESTDHANDLES;
    memset(&pi, 0, sizeof(pi));

    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                             0, env_block, NULL, &si, &pi);
    free(env_block);

    if (!ok) return -2; /* ENOENT */

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    ExitProcess(exit_code);
    return 0; /* not reached */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * waitpid
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_CHILDREN 64
static struct { HANDLE hProcess; DWORD pid; bool used; } g_children[MAX_CHILDREN];

void MineRegisterChild(HANDLE hProcess, DWORD pid)
{
    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (!g_children[i].used) {
            g_children[i].hProcess = hProcess;
            g_children[i].pid = pid;
            g_children[i].used = true;
            return;
        }
    }
}

int64_t MineWaitpid(int pid, int* status, int options)
{
    /* WNOHANG = 1 */
    bool nohang = (options & 1) != 0;

    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (!g_children[i].used) continue;
        if (pid > 0 && (int)g_children[i].pid != pid) continue;
        if (pid == -1 || pid == 0 || (int)g_children[i].pid == pid) {
            DWORD wait_ms = nohang ? 0 : INFINITE;
            DWORD result = WaitForSingleObject(g_children[i].hProcess, wait_ms);
            if (result == WAIT_TIMEOUT) return 0;

            DWORD exit_code = 0;
            GetExitCodeProcess(g_children[i].hProcess, &exit_code);
            CloseHandle(g_children[i].hProcess);
            DWORD child_pid = g_children[i].pid;
            g_children[i].used = false;

            /* Linux status: exited normally = (code << 8) */
            if (status) *status = (int)(exit_code << 8);
            return (int64_t)child_pid;
        }
    }

    return -10; /* ECHILD */
}

int64_t MineFork(void)
{
    return -38; /* ENOSYS — true fork isn't possible on Windows */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * epoll emulation — backed by poll
 *
 * We maintain a table of epoll instances, each with a list of watched fds.
 * epoll_wait translates to our MinePoll implementation.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

#define EPOLLIN      0x001
#define EPOLLOUT     0x004
#define EPOLLERR     0x008
#define EPOLLHUP     0x010
#define EPOLLET      0x80000000U
#define EPOLLONESHOT 0x40000000U

#pragma pack(push, 1)
typedef struct {
    uint32_t events;
    union {
        void*    ptr;
        int      fd;
        uint32_t u32;
        uint64_t u64;
    } data;
} Linux_epoll_event;
#pragma pack(pop)

#define MAX_EPOLL_INSTANCES 16
#define MAX_EPOLL_FDS 256

typedef struct {
    int      fd;
    uint32_t events;
    uint64_t data;
    bool     used;
} EpollEntry;

typedef struct {
    bool       used;
    int        epfd;
    EpollEntry entries[MAX_EPOLL_FDS];
    int        count;
} EpollInstance;

static EpollInstance g_epoll[MAX_EPOLL_INSTANCES];
static int g_epoll_next_fd = 1000;

int64_t MineEpollCreate(int flags)
{
    (void)flags;
    for (int i = 0; i < MAX_EPOLL_INSTANCES; i++) {
        if (!g_epoll[i].used) {
            g_epoll[i].used = true;
            g_epoll[i].epfd = g_epoll_next_fd++;
            g_epoll[i].count = 0;
            memset(g_epoll[i].entries, 0, sizeof(g_epoll[i].entries));
            return g_epoll[i].epfd;
        }
    }
    return -24; /* EMFILE */
}

static EpollInstance* find_epoll(int epfd)
{
    for (int i = 0; i < MAX_EPOLL_INSTANCES; i++)
        if (g_epoll[i].used && g_epoll[i].epfd == epfd)
            return &g_epoll[i];
    return NULL;
}

int64_t MineEpollCtl(int epfd, int op, int fd, void* event)
{
    EpollInstance* ep = find_epoll(epfd);
    if (!ep) return -9; /* EBADF */

    Linux_epoll_event* ev = (Linux_epoll_event*)event;

    switch (op) {
    case EPOLL_CTL_ADD:
        if (!ev) return -22;
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (!ep->entries[i].used) {
                ep->entries[i].fd = fd;
                ep->entries[i].events = ev->events;
                ep->entries[i].data = ev->data.u64;
                ep->entries[i].used = true;
                ep->count++;
                return 0;
            }
        }
        return -28; /* ENOSPC */

    case EPOLL_CTL_MOD:
        if (!ev) return -22;
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (ep->entries[i].used && ep->entries[i].fd == fd) {
                ep->entries[i].events = ev->events;
                ep->entries[i].data = ev->data.u64;
                return 0;
            }
        }
        return -2; /* ENOENT */

    case EPOLL_CTL_DEL:
        for (int i = 0; i < MAX_EPOLL_FDS; i++) {
            if (ep->entries[i].used && ep->entries[i].fd == fd) {
                ep->entries[i].used = false;
                ep->count--;
                return 0;
            }
        }
        return -2; /* ENOENT */
    }
    return -22;
}

int64_t MineEpollWait(int epfd, void* events, int maxevents, int timeout)
{
    EpollInstance* ep = find_epoll(epfd);
    if (!ep) return -9;

    Linux_epoll_event* out = (Linux_epoll_event*)events;
    if (!out || maxevents <= 0) return -22;

    /* Build pollfd array from our registered fds */
    typedef struct { int32_t fd; int16_t events; int16_t revents; } pfd_t;

    int n = 0;
    for (int i = 0; i < MAX_EPOLL_FDS && n < ep->count; i++)
        if (ep->entries[i].used) n++;

    if (n == 0) {
        if (timeout > 0) Sleep((DWORD)timeout);
        return 0;
    }

    pfd_t* pfds = (pfd_t*)calloc(n, sizeof(pfd_t));
    int*   idx_map = (int*)calloc(n, sizeof(int));
    if (!pfds || !idx_map) { free(pfds); free(idx_map); return -12; }

    int k = 0;
    for (int i = 0; i < MAX_EPOLL_FDS && k < n; i++) {
        if (!ep->entries[i].used) continue;
        pfds[k].fd = ep->entries[i].fd;
        pfds[k].events = 0;
        if (ep->entries[i].events & EPOLLIN)  pfds[k].events |= 0x0001;
        if (ep->entries[i].events & EPOLLOUT) pfds[k].events |= 0x0004;
        pfds[k].revents = 0;
        idx_map[k] = i;
        k++;
    }

    int64_t ret = MinePoll(pfds, (uint32_t)n, timeout);

    int ready = 0;
    for (int j = 0; j < n && ready < maxevents; j++) {
        if (pfds[j].revents == 0) continue;
        int ei = idx_map[j];
        out[ready].events = 0;
        if (pfds[j].revents & 0x0001) out[ready].events |= EPOLLIN;
        if (pfds[j].revents & 0x0004) out[ready].events |= EPOLLOUT;
        if (pfds[j].revents & 0x0008) out[ready].events |= EPOLLERR;
        if (pfds[j].revents & 0x0010) out[ready].events |= EPOLLHUP;
        out[ready].data.u64 = ep->entries[ei].data;
        ready++;
    }

    free(pfds);
    free(idx_map);
    return (int64_t)ready;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * timerfd emulation
 *
 * We create a pipe pair. A background thread sleeps for the interval
 * and writes a uint64_t counter to the write end. The read end fd is
 * returned so it's pollable.
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    int64_t tv_sec;
    int64_t tv_nsec;
} Mine_timespec;

typedef struct {
    Mine_timespec it_interval;
    Mine_timespec it_value;
} Mine_itimerspec;

#define MAX_TIMERFDS 16

typedef struct {
    bool    used;
    int     fd_read;
    int     fd_write;
    HANDLE  thread;
    bool    stop;
    Mine_itimerspec spec;
    CRITICAL_SECTION lock;
} TimerfdEntry;

static TimerfdEntry g_timerfds[MAX_TIMERFDS];

static DWORD ts_to_ms(const Mine_timespec* ts)
{
    if (ts->tv_sec == 0 && ts->tv_nsec == 0) return 0;
    return (DWORD)(ts->tv_sec * 1000 + ts->tv_nsec / 1000000);
}

static DWORD WINAPI timerfd_thread(LPVOID param)
{
    TimerfdEntry* te = (TimerfdEntry*)param;

    DWORD initial = ts_to_ms(&te->spec.it_value);
    if (initial == 0) return 0;

    Sleep(initial);
    if (te->stop) return 0;

    uint64_t count = 1;
    HANDLE h = (HANDLE)_get_osfhandle(te->fd_write);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, &count, sizeof(count), &w, NULL);
    }

    DWORD interval = ts_to_ms(&te->spec.it_interval);
    while (interval > 0 && !te->stop) {
        Sleep(interval);
        if (te->stop) break;
        count = 1;
        if (h != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            WriteFile(h, &count, sizeof(count), &w, NULL);
        }
    }
    return 0;
}

int64_t MineTimerfdCreate(int clockid, int flags)
{
    (void)clockid; (void)flags;
    for (int i = 0; i < MAX_TIMERFDS; i++) {
        if (!g_timerfds[i].used) {
            int fds[2];
            if (MineVFSPipe(fds, 0) < 0) return -24; /* EMFILE */
            g_timerfds[i].used = true;
            g_timerfds[i].fd_read = fds[0];
            g_timerfds[i].fd_write = fds[1];
            g_timerfds[i].thread = NULL;
            g_timerfds[i].stop = false;
            memset(&g_timerfds[i].spec, 0, sizeof(Mine_itimerspec));
            InitializeCriticalSection(&g_timerfds[i].lock);
            return fds[0];
        }
    }
    return -24;
}

static TimerfdEntry* find_timerfd(int fd)
{
    for (int i = 0; i < MAX_TIMERFDS; i++)
        if (g_timerfds[i].used && g_timerfds[i].fd_read == fd)
            return &g_timerfds[i];
    return NULL;
}

int64_t MineTimerfdSettime(int fd, int flags, const void* new_value, void* old_value)
{
    (void)flags;
    TimerfdEntry* te = find_timerfd(fd);
    if (!te) return -9; /* EBADF */

    if (old_value) memcpy(old_value, &te->spec, sizeof(Mine_itimerspec));

    if (te->thread) {
        te->stop = true;
        WaitForSingleObject(te->thread, 1000);
        CloseHandle(te->thread);
        te->thread = NULL;
    }

    if (new_value) {
        memcpy(&te->spec, new_value, sizeof(Mine_itimerspec));
        te->stop = false;
        DWORD tid;
        te->thread = CreateThread(NULL, 0, timerfd_thread, te, 0, &tid);
    }
    return 0;
}

int64_t MineTimerfdGettime(int fd, void* curr_value)
{
    TimerfdEntry* te = find_timerfd(fd);
    if (!te) return -9;
    if (curr_value) memcpy(curr_value, &te->spec, sizeof(Mine_itimerspec));
    return 0;
}
