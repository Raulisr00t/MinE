#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include "mine_thread.h"
#include "mine_dynamic.h"
#include "mine_tls.h"
#include "mine_vfs.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <intrin.h>
#include <io.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Futex — backed by WaitOnAddress / WakeByAddress (Win8+)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef BOOL (WINAPI *WaitOnAddress_t)(volatile void*, void*, SIZE_T, DWORD);
typedef void (WINAPI *WakeByAddressSingle_t)(void*);
typedef void (WINAPI *WakeByAddressAll_t)(void*);

static WaitOnAddress_t      pWaitOnAddress = NULL;
static WakeByAddressSingle_t pWakeByAddressSingle = NULL;
static WakeByAddressAll_t   pWakeByAddressAll = NULL;
static LONG g_futex_init = 0;

static void futex_init(void)
{
    if (InterlockedCompareExchange(&g_futex_init, 1, 0) == 0) {
        HMODULE k = GetModuleHandleA("api-ms-win-core-synch-l1-2-0.dll");
        if (!k) k = GetModuleHandleA("kernel32.dll");
        if (k) {
            pWaitOnAddress = (WaitOnAddress_t)GetProcAddress(k, "WaitOnAddress");
            pWakeByAddressSingle = (WakeByAddressSingle_t)GetProcAddress(k, "WakeByAddressSingle");
            pWakeByAddressAll = (WakeByAddressAll_t)GetProcAddress(k, "WakeByAddressAll");
        }
    }
}

int64_t MineFutex(uint32_t* uaddr, int op, uint32_t val,
                  const void* timeout, uint32_t* uaddr2, uint32_t val3)
{
    (void)uaddr2; (void)val3;
    futex_init();

    int cmd = op & FUTEX_CMD_MASK;

    switch (cmd) {
    case FUTEX_WAIT:
    case FUTEX_WAIT_BITSET: {
        if (!pWaitOnAddress) {
            Sleep(0);
            return 0;
        }
        uint32_t current = *(volatile uint32_t*)uaddr;
        if (current != val)
            return -11; /* EAGAIN */

        DWORD ms = INFINITE;
        if (timeout) {
            typedef struct { int64_t tv_sec; int64_t tv_nsec; } ts_t;
            const ts_t* ts = (const ts_t*)timeout;
            ms = (DWORD)(ts->tv_sec * 1000 + ts->tv_nsec / 1000000);
            if (ms == 0 && ts->tv_nsec > 0) ms = 1;
        }

        BOOL ok = pWaitOnAddress((volatile void*)uaddr, &val, sizeof(uint32_t), ms);
        if (!ok) {
            if (GetLastError() == ERROR_TIMEOUT)
                return -110; /* ETIMEDOUT */
        }
        return 0;
    }
    case FUTEX_WAKE:
    case FUTEX_WAKE_BITSET: {
        if (!pWakeByAddressSingle || !pWakeByAddressAll)
            return 0;
        if (val == 1)
            pWakeByAddressSingle(uaddr);
        else if (val > 1)
            pWakeByAddressAll(uaddr);
        return (int64_t)val;
    }
    case FUTEX_REQUEUE:
    case FUTEX_CMP_REQUEUE:
        if (pWakeByAddressAll) pWakeByAddressAll(uaddr);
        return 0;
    case FUTEX_WAKE_OP:
        if (pWakeByAddressAll) {
            pWakeByAddressAll(uaddr);
            if (uaddr2) pWakeByAddressAll(uaddr2);
        }
        return 0;
    default:
        return 0;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Pthreads — backed by Windows threads + CriticalSection + ConditionVariable
 * ═══════════════════════════════════════════════════════════════════════════ */

extern void MineWinToLinux(void);

typedef struct {
    uint64_t start_fn;
    uint64_t arg;
    void*    retval;
} ThreadCtx;

static DWORD WINAPI thread_entry(LPVOID param)
{
    ThreadCtx* ctx = (ThreadCtx*)param;
    uint64_t fn = ctx->start_fn;
    uint64_t arg = ctx->arg;

    MineTLSInitThread();

    uint64_t guest_fs = MineGetGuestFS();
    if (guest_fs) {
        __try { _writefsbase_u64(guest_fs); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    typedef void* (*win_fn_t)(void*, uint64_t, uint64_t, uint64_t);
    void* ret = NULL;
    __try {
        ret = ((win_fn_t)MineWinToLinux)((void*)(uintptr_t)fn, arg, 0, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[MinE-Thread] Thread function faulted\n");
    }

    ctx->retval = ret;
    return 0;
}

int MineThreadCreate(MineThread* t, const void* attr,
                     uint64_t fn, uint64_t arg)
{
    (void)attr;
    if (!t) return 22; /* EINVAL */

    ThreadCtx* ctx = (ThreadCtx*)calloc(1, sizeof(ThreadCtx));
    if (!ctx) return 12; /* ENOMEM */
    ctx->start_fn = fn;
    ctx->arg = arg;
    ctx->retval = NULL;

    DWORD tid = 0;
    HANDLE h = CreateThread(NULL, 0, thread_entry, ctx, 0, &tid);
    if (!h) { free(ctx); return 11; /* EAGAIN */ }

    t->handle = h;
    t->tid = tid;
    return 0;
}

int MineThreadJoin(MineThread t, void** retval)
{
    if (!t.handle) return 22;
    WaitForSingleObject((HANDLE)t.handle, INFINITE);
    if (retval) *retval = NULL;
    CloseHandle((HANDLE)t.handle);
    return 0;
}

int MineThreadDetach(MineThread t)
{
    if (t.handle) CloseHandle((HANDLE)t.handle);
    return 0;
}

/* ── Mutex (CRITICAL_SECTION) ────────────────────────────────────────────── */

int MineMutexInit(MineMutex* m, const void* attr)
{
    (void)attr;
    if (!m) return 22;
    CRITICAL_SECTION* cs = (CRITICAL_SECTION*)calloc(1, sizeof(CRITICAL_SECTION));
    if (!cs) return 12;
    InitializeCriticalSection(cs);
    m->cs = cs;
    return 0;
}

int MineMutexLock(MineMutex* m)
{
    if (!m || !m->cs) return 22;
    EnterCriticalSection((CRITICAL_SECTION*)m->cs);
    return 0;
}

int MineMutexTrylock(MineMutex* m)
{
    if (!m || !m->cs) return 22;
    return TryEnterCriticalSection((CRITICAL_SECTION*)m->cs) ? 0 : 16; /* EBUSY */
}

int MineMutexUnlock(MineMutex* m)
{
    if (!m || !m->cs) return 22;
    LeaveCriticalSection((CRITICAL_SECTION*)m->cs);
    return 0;
}

int MineMutexDestroy(MineMutex* m)
{
    if (!m || !m->cs) return 0;
    DeleteCriticalSection((CRITICAL_SECTION*)m->cs);
    free(m->cs);
    m->cs = NULL;
    return 0;
}

/* ── Condition variable ──────────────────────────────────────────────────── */

int MineCondInit(MineCond* c, const void* attr)
{
    (void)attr;
    if (!c) return 22;
    CONDITION_VARIABLE* cv = (CONDITION_VARIABLE*)calloc(1, sizeof(CONDITION_VARIABLE));
    if (!cv) return 12;
    InitializeConditionVariable(cv);
    c->cv = cv;
    return 0;
}

int MineCondWait(MineCond* c, MineMutex* m)
{
    if (!c || !c->cv || !m || !m->cs) return 22;
    SleepConditionVariableCS((CONDITION_VARIABLE*)c->cv,
                             (CRITICAL_SECTION*)m->cs, INFINITE);
    return 0;
}

int MineCondTimedwait(MineCond* c, MineMutex* m, const void* abstime)
{
    if (!c || !c->cv || !m || !m->cs) return 22;
    DWORD ms = INFINITE;
    if (abstime) {
        typedef struct { int64_t tv_sec; int64_t tv_nsec; } ts_t;
        const ts_t* ts = (const ts_t*)abstime;
        LARGE_INTEGER freq, cnt;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&cnt);
        double now = (double)cnt.QuadPart / (double)freq.QuadPart;
        double target = (double)ts->tv_sec + (double)ts->tv_nsec / 1e9;
        double diff = target - now;
        ms = diff > 0 ? (DWORD)(diff * 1000.0) : 0;
    }
    if (!SleepConditionVariableCS((CONDITION_VARIABLE*)c->cv,
                                  (CRITICAL_SECTION*)m->cs, ms))
        return 110; /* ETIMEDOUT */
    return 0;
}

int MineCondSignal(MineCond* c)
{
    if (!c || !c->cv) return 22;
    WakeConditionVariable((CONDITION_VARIABLE*)c->cv);
    return 0;
}

int MineCondBroadcast(MineCond* c)
{
    if (!c || !c->cv) return 22;
    WakeAllConditionVariable((CONDITION_VARIABLE*)c->cv);
    return 0;
}

int MineCondDestroy(MineCond* c)
{
    if (!c || !c->cv) return 0;
    free(c->cv);
    c->cv = NULL;
    return 0;
}

/* ── RWLock (SRWLOCK) ────────────────────────────────────────────────────── */

int MineRWLockInit(MineRWLock* rw, const void* attr)
{
    (void)attr;
    if (!rw) return 22;
    SRWLOCK* srw = (SRWLOCK*)calloc(1, sizeof(SRWLOCK));
    if (!srw) return 12;
    InitializeSRWLock(srw);
    rw->srw = srw;
    return 0;
}

int MineRWLockRdlock(MineRWLock* rw)
{
    if (!rw || !rw->srw) return 22;
    AcquireSRWLockShared((SRWLOCK*)rw->srw);
    return 0;
}

int MineRWLockWrlock(MineRWLock* rw)
{
    if (!rw || !rw->srw) return 22;
    AcquireSRWLockExclusive((SRWLOCK*)rw->srw);
    return 0;
}

int MineRWLockUnlock(MineRWLock* rw)
{
    if (!rw || !rw->srw) return 22;
    __try { ReleaseSRWLockExclusive((SRWLOCK*)rw->srw); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        __try { ReleaseSRWLockShared((SRWLOCK*)rw->srw); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    return 0;
}

int MineRWLockDestroy(MineRWLock* rw)
{
    if (!rw || !rw->srw) return 0;
    free(rw->srw);
    rw->srw = NULL;
    return 0;
}

/* ── TLS keys (Windows TLS slots) ────────────────────────────────────────── */

#define MAX_TLS_DTORS 64
static void (*g_tls_dtors[MAX_TLS_DTORS])(void*);
static DWORD g_tls_keys[MAX_TLS_DTORS];
static LONG  g_tls_count = 0;

uint32_t MineTlsCreate(void (*dtor)(void*))
{
    DWORD key = TlsAlloc();
    if (key == TLS_OUT_OF_INDEXES) return (uint32_t)-1;

    LONG idx = InterlockedIncrement(&g_tls_count) - 1;
    if (idx < MAX_TLS_DTORS) {
        g_tls_keys[idx] = key;
        g_tls_dtors[idx] = dtor;
    }
    return key;
}

void* MineTlsGet(uint32_t key)
{
    return TlsGetValue((DWORD)key);
}

int MineTlsSet(uint32_t key, const void* val)
{
    return TlsSetValue((DWORD)key, (LPVOID)val) ? 0 : 22;
}

/* ── pthread_once ────────────────────────────────────────────────────────── */

int MineOnce(void* once_control, void (*init_routine)(void))
{
    volatile LONG* flag = (volatile LONG*)once_control;
    if (InterlockedCompareExchange(flag, 1, 0) == 0) {
        init_routine();
        InterlockedExchange(flag, 2);
    } else {
        while (*flag == 1)
            SwitchToThread();
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Poll / Select
 * ═══════════════════════════════════════════════════════════════════════════ */

#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

#pragma pack(push, 1)
typedef struct {
    int32_t  fd;
    int16_t  events;
    int16_t  revents;
} Linux_pollfd;
#pragma pack(pop)

#define LINUX_POLLIN    0x0001
#define LINUX_POLLPRI   0x0002
#define LINUX_POLLOUT   0x0004
#define LINUX_POLLERR   0x0008
#define LINUX_POLLHUP   0x0010
#define LINUX_POLLNVAL  0x0020

static HANDLE fd_to_handle_poll(int fd)
{
    switch (fd) {
    case 0: return GetStdHandle(STD_INPUT_HANDLE);
    case 1: return GetStdHandle(STD_OUTPUT_HANDLE);
    case 2: return GetStdHandle(STD_ERROR_HANDLE);
    default: { intptr_t h = _get_osfhandle(fd); return (h == -1) ? NULL : (HANDLE)h; }
    }
}

int64_t MinePoll(void* fds_ptr, uint32_t nfds, int timeout_ms)
{
    Linux_pollfd* fds = (Linux_pollfd*)fds_ptr;
    if (!fds || nfds == 0) {
        if (timeout_ms > 0) Sleep((DWORD)timeout_ms);
        return 0;
    }

    WSAPOLLFD* wfds = (WSAPOLLFD*)calloc(nfds, sizeof(WSAPOLLFD));
    if (!wfds) return -12;

    bool any_socket = false;
    for (uint32_t i = 0; i < nfds; i++) {
        fds[i].revents = 0;
        if (fds[i].fd < 0) { wfds[i].fd = INVALID_SOCKET; continue; }

        intptr_t h = _get_osfhandle(fds[i].fd);
        if (h == -1) {
            fds[i].revents = LINUX_POLLNVAL;
            wfds[i].fd = INVALID_SOCKET;
            continue;
        }

        wfds[i].fd = (SOCKET)h;
        wfds[i].events = 0;
        if (fds[i].events & LINUX_POLLIN)  wfds[i].events |= POLLRDNORM;
        if (fds[i].events & LINUX_POLLOUT) wfds[i].events |= POLLWRNORM;
        if (fds[i].events & LINUX_POLLPRI) wfds[i].events |= POLLRDBAND;
        any_socket = true;
    }

    int ready = 0;

    if (any_socket) {
        ready = WSAPoll(wfds, nfds, timeout_ms);
        if (ready == SOCKET_ERROR) {
            /* Not sockets — handle as console/pipe fds */
            for (uint32_t i = 0; i < nfds; i++) {
                if (fds[i].fd < 0) continue;
                if (fds[i].fd <= 2 && (fds[i].events & LINUX_POLLIN)) {
                    HANDLE h = fd_to_handle_poll(fds[i].fd);
                    if (h) {
                        DWORD avail = 0;
                        if (PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL) && avail > 0)
                            fds[i].revents |= LINUX_POLLIN;
                        else if (fds[i].fd == 0)
                            fds[i].revents |= LINUX_POLLIN;
                    }
                }
                if (fds[i].events & LINUX_POLLOUT)
                    fds[i].revents |= LINUX_POLLOUT;
            }
            ready = 0;
            for (uint32_t i = 0; i < nfds; i++)
                if (fds[i].revents) ready++;
            free(wfds);
            return ready;
        }
    } else {
        if (timeout_ms > 0) Sleep((DWORD)timeout_ms);
        for (uint32_t i = 0; i < nfds; i++) {
            if (fds[i].fd < 0) continue;
            if (fds[i].events & LINUX_POLLOUT)
                fds[i].revents |= LINUX_POLLOUT;
            if (fds[i].events & LINUX_POLLIN) {
                HANDLE h = fd_to_handle_poll(fds[i].fd);
                if (h) {
                    DWORD avail = 0;
                    if (PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL) && avail > 0)
                        fds[i].revents |= LINUX_POLLIN;
                }
            }
        }
        ready = 0;
        for (uint32_t i = 0; i < nfds; i++)
            if (fds[i].revents) ready++;
        free(wfds);
        return ready;
    }

    for (uint32_t i = 0; i < nfds; i++) {
        if (fds[i].fd < 0) continue;
        if (wfds[i].revents & (POLLRDNORM | POLLIN))  fds[i].revents |= LINUX_POLLIN;
        if (wfds[i].revents & (POLLWRNORM | POLLOUT))  fds[i].revents |= LINUX_POLLOUT;
        if (wfds[i].revents & POLLERR)                 fds[i].revents |= LINUX_POLLERR;
        if (wfds[i].revents & POLLHUP)                 fds[i].revents |= LINUX_POLLHUP;
    }

    free(wfds);
    return (int64_t)ready;
}

int64_t MineSelect(int nfds, void* readfds, void* writefds,
                   void* exceptfds, void* timeout)
{
    typedef struct { int64_t tv_sec; int64_t tv_usec; } Linux_timeval;

    struct timeval tv_win;
    struct timeval* ptv = NULL;
    if (timeout) {
        Linux_timeval* ltv = (Linux_timeval*)timeout;
        tv_win.tv_sec = (long)ltv->tv_sec;
        tv_win.tv_usec = (long)ltv->tv_usec;
        ptv = &tv_win;
    }

    fd_set r, w, e;
    FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&e);

    /* Linux fd_sets are bitmaps. For now just handle small fd counts. */
    typedef struct { unsigned long fds_bits[16]; } linux_fd_set;

    int max_fd = nfds < 64 ? nfds : 64;

    if (readfds) {
        linux_fd_set* lfs = (linux_fd_set*)readfds;
        for (int fd = 0; fd < max_fd; fd++) {
            if (lfs->fds_bits[fd / 32] & (1UL << (fd % 32))) {
                intptr_t h = (fd <= 2) ? (intptr_t)fd_to_handle_poll(fd) : _get_osfhandle(fd);
                if (h != -1) FD_SET((SOCKET)h, &r);
            }
        }
    }
    if (writefds) {
        linux_fd_set* lfs = (linux_fd_set*)writefds;
        for (int fd = 0; fd < max_fd; fd++) {
            if (lfs->fds_bits[fd / 32] & (1UL << (fd % 32))) {
                intptr_t h = (fd <= 2) ? (intptr_t)fd_to_handle_poll(fd) : _get_osfhandle(fd);
                if (h != -1) FD_SET((SOCKET)h, &w);
            }
        }
    }

    int ret = select(0, readfds ? &r : NULL, writefds ? &w : NULL,
                     exceptfds ? &e : NULL, ptv);
    if (ret == SOCKET_ERROR) {
        if (ptv) {
            DWORD ms = (DWORD)(ptv->tv_sec * 1000 + ptv->tv_usec / 1000);
            Sleep(ms);
        }
        return 0;
    }
    return (int64_t)ret;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Directory operations — opendir / readdir / closedir
 * ═══════════════════════════════════════════════════════════════════════════ */

struct MineDIR {
    HANDLE      hFind;
    bool        started;
    bool        finished;
    MineDirent  entry;
    char        pattern[MAX_PATH];
};

MineDIR* MineOpendir(const char* path)
{
    if (!path) return NULL;

    int virt_type = VFS_REAL;
    const char* win_path = MineVFSTranslate(path, &virt_type);
    const char* use = win_path ? win_path : path;

    char pattern[MAX_PATH];
    size_t len = strlen(use);
    if (len + 3 >= MAX_PATH) return NULL;
    memcpy(pattern, use, len);
    if (len > 0 && use[len-1] != '\\' && use[len-1] != '/') {
        pattern[len] = '\\';
        len++;
    }
    pattern[len] = '*';
    pattern[len+1] = '\0';

    for (size_t i = 0; i < len + 1; i++)
        if (pattern[i] == '/') pattern[i] = '\\';

    MineDIR* d = (MineDIR*)calloc(1, sizeof(MineDIR));
    if (!d) return NULL;

    strcpy(d->pattern, pattern);
    d->hFind = INVALID_HANDLE_VALUE;
    d->started = false;
    d->finished = false;
    return d;
}

MineDirent* MineReaddir(MineDIR* dir)
{
    if (!dir || dir->finished) return NULL;

    WIN32_FIND_DATAA fdata;
    memset(&fdata, 0, sizeof(fdata));

    if (!dir->started) {
        dir->hFind = FindFirstFileA(dir->pattern, &fdata);
        if (dir->hFind == INVALID_HANDLE_VALUE) {
            dir->finished = true;
            return NULL;
        }
        dir->started = true;
    } else {
        if (!FindNextFileA(dir->hFind, &fdata)) {
            dir->finished = true;
            return NULL;
        }
    }

    memset(&dir->entry, 0, sizeof(dir->entry));
    dir->entry.d_ino = 1;
    dir->entry.d_off = 0;
    dir->entry.d_reclen = sizeof(MineDirent);
    dir->entry.d_type = (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 4 : 8;
    strncpy(dir->entry.d_name, fdata.cFileName, sizeof(dir->entry.d_name) - 1);

    return &dir->entry;
}

int MineClosedir(MineDIR* dir)
{
    if (!dir) return -1;
    if (dir->hFind != INVALID_HANDLE_VALUE)
        FindClose(dir->hFind);
    free(dir);
    return 0;
}
