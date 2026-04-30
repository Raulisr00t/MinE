#define _CRT_SECURE_NO_WARNINGS
#define WIN32_NO_STATUS
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#undef WIN32_NO_STATUS
/* ntstatus.h must come AFTER undef WIN32_NO_STATUS so its STATUS_* defines
   don't conflict with the ones windows.h already pulled in */
#include "syscall_translate.h"
#include "mine_dynamic.h"
#include "mine_trace.h"
#include <io.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <wincrypt.h>
#include <intrin.h>

#pragma comment(lib, "ws2_32.lib")

   /* ─── Linux syscall numbers ───────────────────────────────────────────────── */
#define SYS_read              0
#define SYS_write             1
#define SYS_open              2
#define SYS_close             3
#define SYS_stat              4
#define SYS_fstat             5
#define SYS_lstat             6
#define SYS_poll              7
#define SYS_lseek             8
#define SYS_mmap              9
#define SYS_mprotect          10
#define SYS_munmap            11
#define SYS_brk               12
#define SYS_rt_sigaction      13
#define SYS_rt_sigprocmask    14
#define SYS_rt_sigreturn      15
#define SYS_ioctl             16
#define SYS_writev            20
#define SYS_access            21
#define SYS_pipe              22
#define SYS_select            23
#define SYS_sched_yield       24
#define SYS_msync             26
#define SYS_mincore           27
#define SYS_madvise           28
#define SYS_dup               32
#define SYS_dup2              33
#define SYS_nanosleep         35
#define SYS_getpid            39
#define SYS_sendfile          40
#define SYS_socket            41
#define SYS_connect           42
#define SYS_accept            43
#define SYS_sendto            44
#define SYS_recvfrom          45
#define SYS_sendmsg           46
#define SYS_recvmsg           47
#define SYS_shutdown          48
#define SYS_bind              49
#define SYS_listen            50
#define SYS_getsockname       51
#define SYS_getpeername       52
#define SYS_setsockopt        54
#define SYS_getsockopt        55
#define SYS_exit              60
#define SYS_uname             63
#define SYS_fcntl             72
#define SYS_ftruncate         77
#define SYS_getcwd            79
#define SYS_chdir             80
#define SYS_rename            82
#define SYS_mkdir             83
#define SYS_rmdir             84
#define SYS_unlink            87
#define SYS_readlink          89
#define SYS_chmod             90
#define SYS_fchmod            91
#define SYS_chown             92
#define SYS_fchown            93
#define SYS_lchown            94
#define SYS_umask             95
#define SYS_gettimeofday      96
#define SYS_getrlimit         97
#define SYS_getrusage         98
#define SYS_sysinfo           99
#define SYS_times             100
#define SYS_getuid            102
#define SYS_getgid            104
#define SYS_setuid            105
#define SYS_setgid            106
#define SYS_geteuid           107
#define SYS_getegid           108
#define SYS_getppid           110
#define SYS_getpgrp           111
#define SYS_getgroups         115
#define SYS_setgroups         116
#define SYS_sigaltstack       131
#define SYS_prctl             157
#define SYS_arch_prctl        158
#define SYS_gettid            186
#define SYS_futex             202
#define SYS_getdents64        217
#define SYS_set_tid_address   218
#define SYS_clock_gettime     228
#define SYS_clock_getres      229
#define SYS_exit_group        231
#define SYS_openat            257
#define SYS_set_robust_list   273
#define SYS_get_robust_list   274
#define SYS_pipe2             293
#define SYS_prlimit64         302
#define SYS_getrandom         318
#define SYS_capget            125
#define SYS_capset            126
#define SYS_rt_sigsuspend     130
#define SYS_mlock             149
#define SYS_munlock           150
#define SYS_mlockall          151
#define SYS_munlockall        152
#define SYS_settimeofday      164

/* ─── Linux errno ─────────────────────────────────────────────────────────── */
#define LINUX_EPERM      1
#define LINUX_ENOENT     2
#define LINUX_EIO        5
#define LINUX_EBADF      9
#define LINUX_ENOMEM     12
#define LINUX_EACCES     13
#define LINUX_EFAULT     14
#define LINUX_EEXIST     17
#define LINUX_EINVAL     22
#define LINUX_EMFILE     24
#define LINUX_ENOTTY     25
#define LINUX_ENOSPC     28
#define LINUX_ENOSYS     38
#define LINUX_ENOTSOCK   88
#define LINUX_EMSGSIZE   90
#define LINUX_EOPNOTSUPP 95
#define LINUX_EAFNOSUPPORT 97
#define LINUX_EADDRINUSE 98
#define LINUX_ECONNRESET 104
#define LINUX_EISCONN    106
#define LINUX_ENOTCONN   107
#define LINUX_ETIMEDOUT  110
#define LINUX_ECONNREFUSED 111
#define LINUX_EHOSTUNREACH 113
#define LINUX_EALREADY   114
#define LINUX_EINPROGRESS 115

/* ─── mmap/prot ───────────────────────────────────────────────────────────── */
#define LINUX_PROT_NONE  0x0
#define LINUX_PROT_READ  0x1
#define LINUX_PROT_WRITE 0x2
#define LINUX_PROT_EXEC  0x4
#define LINUX_MAP_ANON   0x20
#define LINUX_MAP_FIXED  0x10

/* ─── arch_prctl ──────────────────────────────────────────────────────────── */
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_SET_GS 0x1001
#define ARCH_GET_GS 0x1004

/* ─── Linux structs ───────────────────────────────────────────────────────── */
typedef struct {
    uint64_t st_dev; uint64_t st_ino; uint64_t st_nlink;
    uint32_t st_mode; uint32_t st_uid; uint32_t st_gid; uint32_t __pad;
    uint64_t st_rdev; int64_t st_size;
    int64_t st_blksize; int64_t st_blocks;
    uint64_t st_atime; uint64_t st_atime_ns;
    uint64_t st_mtime; uint64_t st_mtime_ns;
    uint64_t st_ctime; uint64_t st_ctime_ns;
    int64_t __unused[3];
} Linux_stat;

typedef struct { int64_t tv_sec; int64_t tv_nsec; } Linux_timespec;
typedef struct { int64_t tv_sec; int64_t tv_usec; } Linux_timeval;
typedef struct { uint64_t iov_base; uint64_t iov_len; } Linux_iovec;
typedef struct { uint64_t rlim_cur; uint64_t rlim_max; } Linux_rlimit;

typedef struct {
    uint64_t msg_name; uint32_t msg_namelen; uint32_t _pad0;
    uint64_t msg_iov; uint64_t msg_iovlen;
    uint64_t msg_control; uint64_t msg_controllen;
    int32_t msg_flags; uint32_t _pad1;
} Linux_msghdr;

/* ─── State ───────────────────────────────────────────────────────────────── */
static uint64_t g_fs_base = 0;
static uint64_t g_tid_addr = 0;
static uint64_t g_robust_list = 0;

static bool    g_wsa_init = false;
static WSADATA g_wsa;
static void ensure_wsa(void)
{
    if (!g_wsa_init) {
        memset(&g_wsa, 0, sizeof(g_wsa));
        if (WSAStartup(MAKEWORD(2, 2), &g_wsa) == 0)
            g_wsa_init = true;
    }
}

/* ─── Error helpers ───────────────────────────────────────────────────────── */
static int64_t winerr(void)
{
    switch (GetLastError()) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:    return -(int64_t)LINUX_ENOENT;
    case ERROR_ACCESS_DENIED:     return -(int64_t)LINUX_EACCES;
    case ERROR_INVALID_HANDLE:    return -(int64_t)LINUX_EBADF;
    case ERROR_NOT_ENOUGH_MEMORY: return -(int64_t)LINUX_ENOMEM;
    case ERROR_ALREADY_EXISTS:    return -(int64_t)LINUX_EEXIST;
    case ERROR_DISK_FULL:         return -(int64_t)LINUX_ENOSPC;
    default:                      return -(int64_t)LINUX_EIO;
    }
}

static int64_t wsaerr(void)
{
    switch (WSAGetLastError()) {
    case WSAECONNREFUSED:  return -(int64_t)LINUX_ECONNREFUSED;
    case WSAETIMEDOUT:     return -(int64_t)LINUX_ETIMEDOUT;
    case WSAEHOSTUNREACH:  return -(int64_t)LINUX_EHOSTUNREACH;
    case WSAENETUNREACH:   return -(int64_t)LINUX_EHOSTUNREACH;
    case WSAEADDRINUSE:    return -(int64_t)LINUX_EADDRINUSE;
    case WSAENOTCONN:      return -(int64_t)LINUX_ENOTCONN;
    case WSAEISCONN:       return -(int64_t)LINUX_EISCONN;
    case WSAENOTSOCK:      return -(int64_t)LINUX_ENOTSOCK;
    case WSAEINVAL:        return -(int64_t)LINUX_EINVAL;
    case WSAEINPROGRESS:   return -(int64_t)LINUX_EINPROGRESS;
    case WSAEALREADY:      return -(int64_t)LINUX_EALREADY;
    case WSAEMSGSIZE:      return -(int64_t)LINUX_EMSGSIZE;
    case WSAEOPNOTSUPP:    return -(int64_t)LINUX_EOPNOTSUPP;
    case WSAEAFNOSUPPORT:  return -(int64_t)LINUX_EAFNOSUPPORT;
    case WSAEACCES:        return -(int64_t)LINUX_EACCES;
    default:               return -(int64_t)LINUX_EIO;
    }
}

static DWORD linux_prot_to_win(uint32_t p)
{
    int r = !!(p & LINUX_PROT_READ), w = !!(p & LINUX_PROT_WRITE), x = !!(p & LINUX_PROT_EXEC);
    if (x && w) return PAGE_EXECUTE_READWRITE;
    if (x && r) return PAGE_EXECUTE_READ;
    if (x)    return PAGE_EXECUTE;
    if (w)    return PAGE_READWRITE;
    if (r)    return PAGE_READONLY;
    return PAGE_NOACCESS;
}

/* ─── File helpers ────────────────────────────────────────────────────────── */
static uint64_t filetime_to_unix(FILETIME ft)
{
    ULARGE_INTEGER ul = { 0 };
    ul.LowPart = ft.dwLowDateTime; ul.HighPart = ft.dwHighDateTime;
    return (ul.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

static HANDLE fd_to_handle(int fd)
{
    switch (fd) {
    case 0: return GetStdHandle(STD_INPUT_HANDLE);
    case 1: return GetStdHandle(STD_OUTPUT_HANDLE);
    case 2: return GetStdHandle(STD_ERROR_HANDLE);
    default: { intptr_t h = _get_osfhandle(fd); return (h == -1) ? NULL : (HANDLE)h; }
    }
}

/* ─── I/O ─────────────────────────────────────────────────────────────────── */
static int64_t sys_read(int fd, void* buf, uint64_t count)
{
    HANDLE h = fd_to_handle(fd); if (!h) return -(int64_t)LINUX_EBADF;
    DWORD got = 0; if (!ReadFile(h, buf, (DWORD)count, &got, NULL)) return -(int64_t)LINUX_EIO;
    return (int64_t)got;
}

static int64_t sys_write(int fd, const void* buf, uint64_t count)
{
    HANDLE h = fd_to_handle(fd); if (!h) return -(int64_t)LINUX_EBADF;
    DWORD w = 0; if (!WriteFile(h, buf, (DWORD)count, &w, NULL)) return -(int64_t)LINUX_EIO;
    return (int64_t)w;
}

static int64_t sys_writev(int fd, const Linux_iovec* iov, int iovcnt)
{
    int64_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        int64_t n = sys_write(fd, (void*)(uintptr_t)iov[i].iov_base, iov[i].iov_len);
        if (n < 0) return total ? total : n;
        total += n;
    }
    return total;
}

static int64_t sys_open_internal(const char* path, int flags, int mode)
{
    (void)mode;
    DWORD access = GENERIC_READ, create = OPEN_EXISTING;
    if ((flags & 3) == 1) access = GENERIC_WRITE;
    if ((flags & 3) == 2) access = GENERIC_READ | GENERIC_WRITE;
    if (flags & 0x40)  create = OPEN_ALWAYS;
    if (flags & 0x200) create = CREATE_ALWAYS;
    if (flags & 0x800) create = TRUNCATE_EXISTING;
    HANDLE h = CreateFileA(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, create, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return winerr();
    int fd = _open_osfhandle((intptr_t)h, 0);
    if (fd < 0) { CloseHandle(h); return -(int64_t)LINUX_EIO; }
    return fd;
}

static int64_t sys_open(const char* path, int flags, int mode) { return sys_open_internal(path, flags, mode); }
static int64_t sys_openat(int d, const char* path, int flags, int mode) { (void)d; return sys_open_internal(path, flags, mode); }
static int64_t sys_close(int fd) { if (fd <= 2) return 0; return _close(fd) == 0 ? 0 : -(int64_t)LINUX_EBADF; }

static void fill_stat(Linux_stat* st, DWORD attr, uint64_t size)
{
    memset(st, 0, sizeof(*st));
    st->st_dev = 1; st->st_ino = 1; st->st_nlink = 1;
    st->st_uid = 1000; st->st_gid = 1000; st->st_blksize = 4096;
    if (attr & FILE_ATTRIBUTE_DIRECTORY) { st->st_mode = 0040755; st->st_size = 4096; }
    else { st->st_mode = 0100644; st->st_size = (int64_t)size; }
    st->st_blocks = (st->st_size + 511) / 512;
    FILETIME ft; memset(&ft, 0, sizeof(ft)); GetSystemTimeAsFileTime(&ft);
    uint64_t t = filetime_to_unix(ft);
    st->st_atime = st->st_mtime = st->st_ctime = t;
}

static int64_t sys_fstat(int fd, Linux_stat* st)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE || !h) {
        memset(st, 0, sizeof(*st)); st->st_mode = 0020666; st->st_nlink = 1; st->st_blksize = 4096;
        return 0;
    }
    BY_HANDLE_FILE_INFORMATION info; memset(&info, 0, sizeof(info));
    if (!GetFileInformationByHandle(h, &info)) return winerr();
    ULARGE_INTEGER sz = { 0 }; sz.LowPart = info.nFileSizeLow; sz.HighPart = info.nFileSizeHigh;
    fill_stat(st, info.dwFileAttributes, sz.QuadPart);
    st->st_ino = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
    return 0;
}

static int64_t sys_stat(const char* path, Linux_stat* st)
{
    WIN32_FILE_ATTRIBUTE_DATA fa; memset(&fa, 0, sizeof(fa));
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fa)) return winerr();
    ULARGE_INTEGER sz = { 0 }; sz.LowPart = fa.nFileSizeLow; sz.HighPart = fa.nFileSizeHigh;
    fill_stat(st, fa.dwFileAttributes, sz.QuadPart); return 0;
}

static int64_t sys_lseek(int fd, int64_t off, int whence)
{
    int64_t r = _lseeki64(fd, off, whence); return r < 0 ? -(int64_t)LINUX_EIO : r;
}

static int64_t sys_access(const char* path, int mode)
{
    (void)mode; return GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES ? -(int64_t)LINUX_ENOENT : 0;
}

static int64_t sys_getcwd(char* buf, uint64_t size)
{
    char tmp[4096]; if (!GetCurrentDirectoryA(sizeof(tmp), tmp)) return winerr();
    for (char* p = tmp; *p; p++) if (*p == '\\') *p = '/';
    size_t len = strlen(tmp); if (len + 1 > size) return -(int64_t)LINUX_EINVAL;
    memcpy(buf, tmp, len + 1); return (int64_t)(uintptr_t)buf;
}

static int64_t sys_fcntl(int fd, int cmd, uint64_t arg)
{
 (void)fd; (void)arg; switch (cmd) { case 1:case 2:case 3:case 4:case 7:return 0; } return -(int64_t)LINUX_EINVAL;
}

static int64_t sys_ftruncate(int fd, int64_t len)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd); if (h == INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;
    LARGE_INTEGER li = { 0 }; li.QuadPart = len;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) return -(int64_t)LINUX_EIO;
    return SetEndOfFile(h) ? 0 : -(int64_t)LINUX_EIO;
}

/* ─── Memory ──────────────────────────────────────────────────────────────── */
static int64_t sys_mmap(uint64_t hint, uint64_t len, uint32_t prot,
    uint32_t flags, int fd, uint64_t off)
{
    uint64_t alen = (len + 0xFFFULL) & ~0xFFFULL;
    DWORD wprot = linux_prot_to_win(prot);
    LPVOID addr = (flags & LINUX_MAP_FIXED) ? (LPVOID)(uintptr_t)hint : NULL;
    LPVOID p = VirtualAlloc(addr, (SIZE_T)alen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p && (flags & LINUX_MAP_FIXED)) return -(int64_t)LINUX_ENOMEM;
    if (!p) p = VirtualAlloc(NULL, (SIZE_T)alen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) return -(int64_t)LINUX_ENOMEM;
    if (fd >= 0 && !(flags & LINUX_MAP_ANON)) {
        HANDLE fh = (HANDLE)_get_osfhandle(fd);
        if (fh != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER li = { 0 }; li.QuadPart = (LONGLONG)off;
            SetFilePointerEx(fh, li, NULL, FILE_BEGIN);
            DWORD got = 0;
            if (!ReadFile(fh, p, (DWORD)alen, &got, NULL)) { /* partial ok */ }
        }
    }
    else { memset(p, 0, (size_t)alen); }
    if (wprot && wprot != PAGE_READWRITE) { DWORD old = 0; VirtualProtect(p, (SIZE_T)alen, wprot, &old); }
    return (int64_t)(uintptr_t)p;
}

static int64_t sys_munmap(uint64_t addr, uint64_t len)
{
    uint64_t alen = (len + 0xFFFULL) & ~0xFFFULL;
    VirtualFree((LPVOID)(uintptr_t)addr, (SIZE_T)alen, MEM_DECOMMIT);
    VirtualFree((LPVOID)(uintptr_t)addr, 0, MEM_RELEASE);
    return 0;
}

static int64_t sys_mprotect(uint64_t addr, uint64_t len, uint32_t prot)
{
    DWORD old = 0; return VirtualProtect((LPVOID)(uintptr_t)addr, (SIZE_T)len, linux_prot_to_win(prot), &old) ? 0 : -(int64_t)LINUX_EINVAL;
}

static int64_t sys_brk(uint64_t req)
{
    static uint64_t brk_cur = 0, brk_end = 0;
    if (!brk_cur) {
        LPVOID r = VirtualAlloc(NULL, (SIZE_T)(256ULL * 1024 * 1024), MEM_RESERVE, PAGE_NOACCESS);
        if (!r) return -(int64_t)LINUX_ENOMEM;
        brk_cur = brk_end = (uint64_t)(uintptr_t)r;
    }
    if (req == 0) return (int64_t)brk_cur;
    if (req > brk_cur) {
        uint64_t need = (req - brk_end + 0xFFFULL) & ~0xFFFULL;
        if (!VirtualAlloc((LPVOID)(uintptr_t)brk_end, (SIZE_T)need, MEM_COMMIT, PAGE_READWRITE))
            return (int64_t)brk_cur;
        brk_end += need;
    }
    brk_cur = req; return (int64_t)brk_cur;
}

/* ─── Time ────────────────────────────────────────────────────────────────── */
static int64_t sys_clock_gettime(int clk, Linux_timespec* ts)
{
    (void)clk;
    LARGE_INTEGER freq = { 0 }, cnt = { 0 };
    QueryPerformanceFrequency(&freq); QueryPerformanceCounter(&cnt);
    uint64_t ns = freq.QuadPart > 0 ? (uint64_t)((double)cnt.QuadPart / (double)freq.QuadPart * 1e9) : 0ULL;
    ts->tv_sec = (int64_t)(ns / 1000000000ULL); ts->tv_nsec = (int64_t)(ns % 1000000000ULL);
    return 0;
}

static int64_t sys_clock_getres(int clk, Linux_timespec* ts)
{
    (void)clk; if (!ts) return 0;
    LARGE_INTEGER freq = { 0 };
    QueryPerformanceFrequency(&freq);
    ts->tv_sec = 0; ts->tv_nsec = freq.QuadPart > 0 ? (int64_t)(1000000000LL / freq.QuadPart) : 1;
    return 0;
}

static int64_t sys_gettimeofday(Linux_timeval* tv, void* tz)
{
    (void)tz; if (!tv) return 0;
    FILETIME ft; memset(&ft, 0, sizeof(ft)); GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ul = { 0 };
    ul.LowPart = ft.dwLowDateTime; ul.HighPart = ft.dwHighDateTime;
    uint64_t us = (ul.QuadPart - 116444736000000000ULL) / 10ULL;
    tv->tv_sec = (int64_t)(us / 1000000ULL); tv->tv_usec = (int64_t)(us % 1000000ULL);
    return 0;
}

static int64_t sys_nanosleep(const Linux_timespec* req, Linux_timespec* rem)
{
    if (!req) return -(int64_t)LINUX_EFAULT;
    DWORD ms = (DWORD)((uint64_t)req->tv_sec * 1000ULL + (uint64_t)req->tv_nsec / 1000000ULL);
    Sleep(ms); if (rem) { rem->tv_sec = 0; rem->tv_nsec = 0; } return 0;
}

/* ─── Identity ────────────────────────────────────────────────────────────── */
static int64_t sys_uname(uint8_t* buf)
{
    memset(buf, 0, 6 * 65);
    strcpy((char*)buf + 0 * 65, "Linux"); strcpy((char*)buf + 1 * 65, "mine");
    strcpy((char*)buf + 2 * 65, "5.15.0-mine"); strcpy((char*)buf + 3 * 65, "#1 MinE");
    strcpy((char*)buf + 4 * 65, "x86_64"); return 0;
}

static int64_t sys_getrlimit(uint32_t resource, Linux_rlimit* rl)
{
    if (!rl) return -(int64_t)LINUX_EFAULT;
    switch (resource) {
    case 3: rl->rlim_cur = 8ULL * 1024 * 1024; rl->rlim_max = 8ULL * 1024 * 1024; break;
    case 7: rl->rlim_cur = 1024;            rl->rlim_max = 4096;           break;
    default: rl->rlim_cur = (uint64_t)-1;  rl->rlim_max = (uint64_t)-1;   break;
    }
    return 0;
}

static int64_t sys_getrandom(void* buf, uint64_t count, uint32_t flags)
{
    (void)flags; HCRYPTPROV p = 0;
    if (!CryptAcquireContextA(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return -(int64_t)LINUX_EIO;
    CryptGenRandom(p, (DWORD)count, (BYTE*)buf); CryptReleaseContext(p, 0);
    return (int64_t)count;
}

/* ─── arch_prctl ──────────────────────────────────────────────────────────── */
static int64_t sys_arch_prctl(uint64_t code, uint64_t addr)
{
    switch (code) {
    case ARCH_SET_FS:
        g_fs_base = addr;
        /*
         * KEY FIX: store the guest FS in mine_dynamic.c's g_saved_guest_fs
         * so call_linux_fn3() and MineJump can restore it before guest code runs.
         * This is the single source of truth for the guest TLS base.
         */
        MineDynSetGuestFS(addr);
        __try { _writefsbase_u64(addr); }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            fprintf(stderr, "[MinE] WARNING: wrfsbase failed\n");
        }
        return 0;
    case ARCH_GET_FS:
        __try { g_fs_base = _readfsbase_u64(); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (addr) *(uint64_t*)(uintptr_t)addr = g_fs_base;
        return 0;
    case ARCH_SET_GS: return 0;
    case ARCH_GET_GS: if (addr) *(uint64_t*)(uintptr_t)addr = 0; return 0;
    default: return -(int64_t)LINUX_EINVAL;
    }
}

/* ─── Sockets ─────────────────────────────────────────────────────────────── */
static int64_t sys_socket(int domain, int type, int protocol)
{
    ensure_wsa(); int wtype = type & 0xF;
    SOCKET s = socket(domain, wtype, protocol);
    if (s == INVALID_SOCKET) return wsaerr();
    int fd = _open_osfhandle((intptr_t)s, 0);
    if (fd < 0) { closesocket(s); return -(int64_t)LINUX_EMFILE; }
    return fd;
}

static int64_t sys_bind(int fd, const void* addr, uint32_t addrlen)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;
    return bind(s, (const struct sockaddr*)addr, (int)addrlen) == SOCKET_ERROR ? wsaerr() : 0;
}

static int64_t sys_connect(int fd, const void* addr, uint32_t addrlen)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;
    if (connect(s, (const struct sockaddr*)addr, (int)addrlen) == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS) return -(int64_t)LINUX_EINPROGRESS;
        return wsaerr();
    }
    return 0;
}

static int64_t sys_accept(int fd, void* addr, uint32_t* addrlen)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;
    int alen = addrlen ? (int)*addrlen : 0;
    SOCKET ns = accept(s, addr ? (struct sockaddr*)addr : NULL, addrlen ? &alen : NULL);
    if (ns == INVALID_SOCKET) return wsaerr();
    if (addrlen) *addrlen = (uint32_t)alen;
    int nfd = _open_osfhandle((intptr_t)ns, 0);
    if (nfd < 0) { closesocket(ns); return -(int64_t)LINUX_EMFILE; }
    return nfd;
}

static int64_t sys_listen(int fd, int backlog)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;
    return listen(s, backlog) == SOCKET_ERROR ? wsaerr() : 0;
}

static int64_t sys_shutdown(int fd, int how)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;
    return shutdown(s, how) == SOCKET_ERROR ? wsaerr() : 0;
}

static int64_t sys_getsockname(int fd, void* addr, uint32_t* addrlen)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;
    int alen = addrlen ? (int)*addrlen : 0;
    if (getsockname(s, (struct sockaddr*)addr, &alen) == SOCKET_ERROR) return wsaerr();
    if (addrlen) *addrlen = (uint32_t)alen; return 0;
}

static int64_t sys_getpeername(int fd, void* addr, uint32_t* addrlen)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;
    int alen = addrlen ? (int)*addrlen : 0;
    if (getpeername(s, (struct sockaddr*)addr, &alen) == SOCKET_ERROR) return wsaerr();
    if (addrlen) *addrlen = (uint32_t)alen; return 0;
}

static int64_t sys_setsockopt(int fd, int level, int optname, const void* optval, uint32_t optlen)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;
    int wlevel = (level == 1) ? SOL_SOCKET : level;
    return setsockopt(s, wlevel, optname, (const char*)optval, (int)optlen) == SOCKET_ERROR ? wsaerr() : 0;
}

static int64_t sys_getsockopt(int fd, int level, int optname, void* optval, uint32_t* optlen)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;
    int wlevel = (level == 1) ? SOL_SOCKET : level, olen = optlen ? (int)*optlen : 0;
    if (getsockopt(s, wlevel, optname, (char*)optval, &olen) == SOCKET_ERROR) return wsaerr();
    if (optlen) *optlen = (uint32_t)olen; return 0;
}

static int64_t sys_sendto(int fd, const void* buf, uint64_t len, int flags,
    const void* addr, uint32_t addrlen)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return sys_write(fd, buf, len);
    int n;
    if (addr && addrlen > 0)
        n = sendto(s, (const char*)buf, (int)len, flags, (const struct sockaddr*)addr, (int)addrlen);
    else
        n = send(s, (const char*)buf, (int)len, flags);
    return n == SOCKET_ERROR ? wsaerr() : (int64_t)n;
}

static int64_t sys_recvfrom(int fd, void* buf, uint64_t len, int flags,
    void* addr, uint32_t* addrlen)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return sys_read(fd, buf, len);
    int alen = addrlen ? (int)*addrlen : 0;
    int n = recvfrom(s, (char*)buf, (int)len, flags,
        addr ? (struct sockaddr*)addr : NULL, (addr && addrlen) ? &alen : NULL);
    if (n == SOCKET_ERROR) return wsaerr();
    if (addrlen) *addrlen = (uint32_t)alen; return (int64_t)n;
}

static int64_t sys_sendmsg(int fd, const Linux_msghdr* msg, int flags)
{
    if (!msg) return -(int64_t)LINUX_EFAULT;
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_ENOTSOCK;
    const Linux_iovec* iov = (const Linux_iovec*)(uintptr_t)msg->msg_iov;
    uint64_t total = 0;
    for (uint64_t i = 0; i < msg->msg_iovlen; i++) total += iov[i].iov_len;
    char* flat = (char*)malloc((size_t)total + 1); if (!flat) return -(int64_t)LINUX_ENOMEM;
    size_t off = 0;
    for (uint64_t i = 0; i < msg->msg_iovlen; i++) {
        memcpy(flat + off, (void*)(uintptr_t)iov[i].iov_base, (size_t)iov[i].iov_len);
        off += (size_t)iov[i].iov_len;
    }
    int n;
    if (msg->msg_name && msg->msg_namelen > 0)
        n = sendto(s, flat, (int)total, flags, (const struct sockaddr*)(uintptr_t)msg->msg_name, (int)msg->msg_namelen);
    else
        n = send(s, flat, (int)total, flags);
    free(flat); return n == SOCKET_ERROR ? wsaerr() : (int64_t)n;
}

static int64_t sys_recvmsg(int fd, Linux_msghdr* msg, int flags)
{
    if (!msg) return -(int64_t)LINUX_EFAULT;
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_ENOTSOCK;
    const Linux_iovec* iov = (const Linux_iovec*)(uintptr_t)msg->msg_iov;
    uint64_t total = 0;
    for (uint64_t i = 0; i < msg->msg_iovlen; i++) total += iov[i].iov_len;
    char* flat = (char*)malloc((size_t)total + 1); if (!flat) return -(int64_t)LINUX_ENOMEM;
    int alen = (int)msg->msg_namelen;
    int n = recvfrom(s, flat, (int)total, flags,
        msg->msg_name ? (struct sockaddr*)(uintptr_t)msg->msg_name : NULL,
        msg->msg_name ? &alen : NULL);
    if (n == SOCKET_ERROR) { free(flat); return wsaerr(); }
    size_t rem = (size_t)n;
    for (uint64_t i = 0; i < msg->msg_iovlen && rem>0; i++) {
        size_t copy = (size_t)iov[i].iov_len < rem ? (size_t)iov[i].iov_len : rem;
        memcpy((void*)(uintptr_t)iov[i].iov_base, flat + ((size_t)n - rem), copy);
        rem -= copy;
    }
    free(flat); msg->msg_namelen = (uint32_t)alen; msg->msg_controllen = 0; msg->msg_flags = 0;
    return (int64_t)n;
}

static int64_t sys_poll(void* fds, uint32_t nfds, int timeout)
{
    (void)fds; (void)nfds; if (timeout > 0)Sleep((DWORD)timeout); return 0;
}

static int64_t sys_getdents64(int fd, void* dirp, uint32_t count)
{
    (void)fd; (void)dirp; (void)count; return 0;
}

static int64_t sys_ioctl(int fd, uint64_t req, uint64_t arg)
{
    (void)fd; (void)req; (void)arg; return -(int64_t)LINUX_ENOTTY;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MineSyscall
 * ═══════════════════════════════════════════════════════════════════════════ */
uint64_t MineSyscall(uint64_t nr,
    uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6)
{
    MineTraceEnter(nr, a1, a2, a3, a4, a5, a6);
    uint64_t ret = 0;

    switch (nr) {
    case SYS_read:        ret = (uint64_t)sys_read((int)a1, (void*)a2, a3); break;
    case SYS_write:       ret = (uint64_t)sys_write((int)a1, (const void*)a2, a3); break;
    case SYS_writev:      ret = (uint64_t)sys_writev((int)a1, (Linux_iovec*)a2, (int)a3); break;
    case SYS_open:        ret = (uint64_t)sys_open((char*)a1, (int)a2, (int)a3); break;
    case SYS_openat:      ret = (uint64_t)sys_openat((int)a1, (char*)a2, (int)a3, (int)a4); break;
    case SYS_close:       ret = (uint64_t)sys_close((int)a1); break;
    case SYS_lseek:       ret = (uint64_t)sys_lseek((int)a1, (int64_t)a2, (int)a3); break;
    case SYS_fcntl:       ret = (uint64_t)sys_fcntl((int)a1, (int)a2, a3); break;
    case SYS_access:      ret = (uint64_t)sys_access((char*)a1, (int)a2); break;
    case SYS_getcwd:      ret = (uint64_t)sys_getcwd((char*)a1, a2); break;
    case SYS_ftruncate:   ret = (uint64_t)sys_ftruncate((int)a1, (int64_t)a2); break;
    case SYS_dup: { int r = _dup((int)a1); ret = r < 0 ? (uint64_t)-(int64_t)LINUX_EBADF : (uint64_t)r; } break;
    case SYS_dup2: { int r = _dup2((int)a1, (int)a2); ret = r < 0 ? (uint64_t)-(int64_t)LINUX_EBADF : a2; } break;
    case SYS_pipe: case SYS_pipe2: ret = (uint64_t)-(int64_t)LINUX_ENOSYS; break;
    case SYS_getdents64:  ret = (uint64_t)sys_getdents64((int)a1, (void*)a2, (uint32_t)a3); break;
    case SYS_ioctl:       ret = (uint64_t)sys_ioctl((int)a1, a2, a3); break;
    case SYS_poll:        ret = (uint64_t)sys_poll((void*)a1, (uint32_t)a2, (int)a3); break;
    case SYS_select:      ret = 0; break;
    case SYS_fstat:       ret = (uint64_t)sys_fstat((int)a1, (Linux_stat*)a2); break;
    case SYS_stat: case SYS_lstat: ret = (uint64_t)sys_stat((char*)a1, (Linux_stat*)a2); break;
    case SYS_mmap:        ret = (uint64_t)sys_mmap(a1, a2, (uint32_t)a3, (uint32_t)a4, (int)a5, a6); break;
    case SYS_munmap:      ret = (uint64_t)sys_munmap(a1, a2); break;
    case SYS_mprotect:    ret = (uint64_t)sys_mprotect(a1, a2, (uint32_t)a3); break;
    case SYS_brk:         ret = (uint64_t)sys_brk(a1); break;
    case SYS_madvise: case SYS_mincore: case SYS_msync:
    case SYS_mlock: case SYS_munlock: case SYS_mlockall: case SYS_munlockall: ret = 0; break;
    case SYS_clock_gettime: ret = (uint64_t)sys_clock_gettime((int)a1, (Linux_timespec*)a2); break;
    case SYS_clock_getres:  ret = (uint64_t)sys_clock_getres((int)a1, (Linux_timespec*)a2); break;
    case SYS_gettimeofday:  ret = (uint64_t)sys_gettimeofday((Linux_timeval*)a1, (void*)a2); break;
    case SYS_nanosleep:     ret = (uint64_t)sys_nanosleep((Linux_timespec*)a1, (Linux_timespec*)a2); break;
    case SYS_settimeofday:  ret = 0; break;
    case SYS_getpid:      ret = (uint64_t)GetCurrentProcessId(); break;
    case SYS_getppid:     ret = (uint64_t)GetCurrentProcessId(); break;
    case SYS_getpgrp:     ret = (uint64_t)GetCurrentProcessId(); break;
    case SYS_gettid:      ret = (uint64_t)GetCurrentThreadId(); break;
    case SYS_getuid: case SYS_getgid: case SYS_geteuid: case SYS_getegid: ret = 1000; break;
    case SYS_setuid: case SYS_setgid: ret = 0; break;
    case SYS_getgroups: case SYS_setgroups: ret = 0; break;
    case SYS_umask:       ret = 022; break;
    case SYS_uname:       ret = (uint64_t)sys_uname((uint8_t*)a1); break;
    case SYS_getrlimit:   ret = (uint64_t)sys_getrlimit((uint32_t)a1, (Linux_rlimit*)a2); break;
    case SYS_prlimit64:   ret = (uint64_t)sys_getrlimit((uint32_t)a2, (Linux_rlimit*)a4); break;
    case SYS_getrandom:   ret = (uint64_t)sys_getrandom((void*)a1, a2, (uint32_t)a3); break;
    case SYS_sysinfo: case SYS_times: case SYS_getrusage: ret = 0; break;
    case SYS_arch_prctl:  ret = (uint64_t)sys_arch_prctl(a1, a2); break;
    case SYS_socket:      ret = (uint64_t)sys_socket((int)a1, (int)a2, (int)a3); break;
    case SYS_bind:        ret = (uint64_t)sys_bind((int)a1, (void*)a2, (uint32_t)a3); break;
    case SYS_connect:     ret = (uint64_t)sys_connect((int)a1, (void*)a2, (uint32_t)a3); break;
    case SYS_accept:      ret = (uint64_t)sys_accept((int)a1, (void*)a2, (uint32_t*)a3); break;
    case SYS_listen:      ret = (uint64_t)sys_listen((int)a1, (int)a2); break;
    case SYS_shutdown:    ret = (uint64_t)sys_shutdown((int)a1, (int)a2); break;
    case SYS_getsockname: ret = (uint64_t)sys_getsockname((int)a1, (void*)a2, (uint32_t*)a3); break;
    case SYS_getpeername: ret = (uint64_t)sys_getpeername((int)a1, (void*)a2, (uint32_t*)a3); break;
    case SYS_setsockopt:  ret = (uint64_t)sys_setsockopt((int)a1, (int)a2, (int)a3, (void*)a4, (uint32_t)a5); break;
    case SYS_getsockopt:  ret = (uint64_t)sys_getsockopt((int)a1, (int)a2, (int)a3, (void*)a4, (uint32_t*)a5); break;
    case SYS_sendto:      ret = (uint64_t)sys_sendto((int)a1, (void*)a2, a3, (int)a4, (void*)a5, (uint32_t)a6); break;
    case SYS_recvfrom:    ret = (uint64_t)sys_recvfrom((int)a1, (void*)a2, a3, (int)a4, (void*)a5, (uint32_t*)a6); break;
    case SYS_sendmsg:     ret = (uint64_t)sys_sendmsg((int)a1, (Linux_msghdr*)a2, (int)a3); break;
    case SYS_recvmsg:     ret = (uint64_t)sys_recvmsg((int)a1, (Linux_msghdr*)a2, (int)a3); break;
    case SYS_sendfile:    ret = (uint64_t)-(int64_t)LINUX_ENOSYS; break;
    case SYS_set_tid_address: g_tid_addr = a1; ret = (uint64_t)GetCurrentThreadId(); break;
    case SYS_set_robust_list: g_robust_list = a1; ret = 0; break;
    case SYS_get_robust_list: ret = 0; break;
    case SYS_futex:       ret = 0; break;
    case SYS_sched_yield: SwitchToThread(); ret = 0; break;
    case SYS_sigaltstack: ret = 0; break;
    case SYS_prctl:       ret = 0; break;
    case SYS_rt_sigaction: case SYS_rt_sigprocmask: case SYS_rt_sigreturn:
    case SYS_rt_sigsuspend: ret = 0; break;
    case SYS_capget: case SYS_capset: ret = 0; break;
    case SYS_chdir:       ret = SetCurrentDirectoryA((char*)a1) ? 0 : winerr(); break;
    case SYS_readlink:    ret = (uint64_t)-(int64_t)LINUX_ENOENT; break;
    case SYS_mkdir:       ret = CreateDirectoryA((char*)a1, NULL) ? 0 : winerr(); break;
    case SYS_rmdir:       ret = RemoveDirectoryA((char*)a1) ? 0 : winerr(); break;
    case SYS_unlink:      ret = DeleteFileA((char*)a1) ? 0 : winerr(); break;
    case SYS_rename:      ret = MoveFileExA((char*)a1, (char*)a2, MOVEFILE_REPLACE_EXISTING) ? 0 : winerr(); break;
    case SYS_chmod: case SYS_fchmod: case SYS_chown:
    case SYS_fchown: case SYS_lchown: ret = 0; break;
    case SYS_exit: case SYS_exit_group:
        MineTraceExit(nr, a1); ExitProcess((UINT)a1); return 0;
    default:
        fprintf(stderr, "\n[MinE] !! Unhandled syscall %llu (ENOSYS)\n", (unsigned long long)nr);
        ret = (uint64_t)(-(int64_t)LINUX_ENOSYS); break;
    }

    MineTraceExit(nr, ret);
 
    return ret;
}