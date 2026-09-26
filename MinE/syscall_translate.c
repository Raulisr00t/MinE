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
#include "mine_vfs.h"
#include "mine_signal.h"
#include "mine_thread.h"
#include "mine_process.h"
#include "mine_TLS.h"
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <wincrypt.h>
#include <intrin.h>

#include <psapi.h>
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
#define SYS_pread64           17
#define SYS_pwrite64          18
#define SYS_writev            20
#define SYS_access            21
#define SYS_pipe              22
#define SYS_select            23
#define SYS_sched_yield       24
#define SYS_msync             26
#define SYS_mincore           27
#define SYS_mremap            25
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
#define SYS_newfstatat        262
#define SYS_readlinkat        267
#define SYS_set_robust_list   273
#define SYS_get_robust_list   274
#define SYS_pipe2             293
#define SYS_prlimit64         302
#define SYS_getrandom         318
#define SYS_rseq              334
#define SYS_capget            125
#define SYS_capset            126
#define SYS_rt_sigsuspend     130
#define SYS_mlock             149
#define SYS_munlock           150
#define SYS_mlockall          151
#define SYS_munlockall        152
#define SYS_clock_nanosleep   230
#define SYS_tgkill            234
#define SYS_settimeofday      164
#define SYS_clone             56
#define SYS_execve            59
#define SYS_wait4             61
#define SYS_socketpair        53
#define SYS_epoll_create      213
#define SYS_epoll_ctl         233
#define SYS_epoll_wait        232
#define SYS_epoll_create1     291
#define SYS_epoll_pwait       281
#define SYS_eventfd2          290
#define SYS_dup3              292
#define SYS_tkill             200
#define SYS_time              201
#define SYS_readv             19
#define SYS_accept4           288
#define SYS_ppoll             271
#define SYS_pselect6          270
#define SYS_recvmmsg          299
#define SYS_sendmmsg          307
#define SYS_timerfd_create    283
#define SYS_timerfd_settime   286
#define SYS_timerfd_gettime   287
#define SYS_signalfd4         289
#define SYS_inotify_init1     294
#define SYS_inotify_add_watch 254
#define SYS_inotify_rm_watch  255
#define SYS_statfs            137
#define SYS_fstatfs           138
#define SYS_faccessat         269
#define SYS_faccessat2        439
#define SYS_fadvise64         221
#define SYS_fallocate         285
#define SYS_sync              162
#define SYS_syncfs            306
#define SYS_fdatasync         75
#define SYS_fsync             74
#define SYS_flock             73
#define SYS_truncate          76
#define SYS_getdents          78
#define SYS_utimensat         280
#define SYS_renameat          264
#define SYS_renameat2         316
#define SYS_unlinkat          263
#define SYS_mkdirat           258
#define SYS_fchmodat          268
#define SYS_fchownat          260
#define SYS_linkat            265
#define SYS_symlinkat         266
#define SYS_statx             332
#define SYS_copy_file_range   326
#define SYS_memfd_create      319
#define SYS_sched_getaffinity 204
#define SYS_sched_setaffinity 203

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

/* ─── Directory state for getdents64 ─────────────────────────────────────── */
#define MAX_DIR_HANDLES 32
typedef struct {
    int fd;
    HANDLE hFind;
    bool started;
    bool finished;
} DirState;
static DirState g_dirs[MAX_DIR_HANDLES];

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
    if (MineVFSIsVFD(fd)) return MineVFSRead(fd, buf, count);
    HANDLE h = fd_to_handle(fd); if (!h) return -(int64_t)LINUX_EBADF;
    DWORD got = 0; if (!ReadFile(h, buf, (DWORD)count, &got, NULL)) return -(int64_t)LINUX_EIO;
    return (int64_t)got;
}

static int64_t sys_write(int fd, const void* buf, uint64_t count)
{
    if (MineVFSIsVFD(fd)) return MineVFSWrite(fd, buf, count);
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

static int64_t sys_pread64(int fd, void* buf, uint64_t count, uint64_t offset)
{
    HANDLE h = fd_to_handle(fd); if (!h) return -(int64_t)LINUX_EBADF;
    OVERLAPPED ov; memset(&ov, 0, sizeof(ov));
    ov.Offset = (DWORD)(offset & 0xFFFFFFFF);
    ov.OffsetHigh = (DWORD)(offset >> 32);
    DWORD got = 0;
    if (!ReadFile(h, buf, (DWORD)count, &got, &ov)) {
        if (GetLastError() == ERROR_HANDLE_EOF) return 0;
        return -(int64_t)LINUX_EIO;
    }
    return (int64_t)got;
}

static int64_t sys_pwrite64(int fd, const void* buf, uint64_t count, uint64_t offset)
{
    HANDLE h = fd_to_handle(fd); if (!h) return -(int64_t)LINUX_EBADF;
    OVERLAPPED ov; memset(&ov, 0, sizeof(ov));
    ov.Offset = (DWORD)(offset & 0xFFFFFFFF);
    ov.OffsetHigh = (DWORD)(offset >> 32);
    DWORD wrote = 0;
    if (!WriteFile(h, buf, (DWORD)count, &wrote, &ov)) return -(int64_t)LINUX_EIO;
    return (int64_t)wrote;
}

static int64_t sys_open_real(const char* win_path, int flags, int mode)
{
    (void)mode;
    DWORD access = GENERIC_READ, create = OPEN_EXISTING;
    if ((flags & 3) == 1) access = GENERIC_WRITE;
    if ((flags & 3) == 2) access = GENERIC_READ | GENERIC_WRITE;
    if (flags & 0x40)
        create = (flags & 0x200) ? CREATE_ALWAYS : OPEN_ALWAYS;
    else if (flags & 0x200)
        create = TRUNCATE_EXISTING;
    DWORD dwattr = GetFileAttributesA(win_path);
    DWORD extra = (dwattr != INVALID_FILE_ATTRIBUTES && (dwattr & FILE_ATTRIBUTE_DIRECTORY))
        ? FILE_FLAG_BACKUP_SEMANTICS : 0;
    HANDLE h = CreateFileA(win_path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, create, FILE_ATTRIBUTE_NORMAL | extra, NULL);
    if (h == INVALID_HANDLE_VALUE) return winerr();
    if (flags & 0x400) {
        LARGE_INTEGER li; li.QuadPart = 0;
        SetFilePointerEx(h, li, NULL, FILE_END);
    }
    int fd = _open_osfhandle((intptr_t)h, 0);
    if (fd < 0) { CloseHandle(h); return -(int64_t)LINUX_EIO; }
    return fd;
}

static int64_t sys_open_internal(const char* path, int flags, int mode)
{
    int virt_type = VFS_REAL;
    const char* win_path = MineVFSTranslate(path, &virt_type);

    if (virt_type != VFS_REAL) {
        if (virt_type == VFS_UNKNOWN) return -(int64_t)LINUX_ENOENT;
        int vfd = MineVFSOpen(virt_type, flags);
        return vfd >= 0 ? (int64_t)vfd : -(int64_t)LINUX_ENOENT;
    }

    return sys_open_real(win_path ? win_path : path, flags, mode);
}

static int64_t sys_open(const char* path, int flags, int mode) { return sys_open_internal(path, flags, mode); }
static int64_t sys_openat(int d, const char* path, int flags, int mode)
{
    /* AT_FDCWD = -100 or absolute path -> use as-is */
    (void)d;
    return sys_open_internal(path, flags, mode);
}
static int64_t sys_close(int fd) {
    if (fd < 0) return -(int64_t)LINUX_EBADF;
    if (fd <= 2) return 0;
    if (MineVFSIsVFD(fd)) return MineVFSClose(fd) == 0 ? 0 : -(int64_t)LINUX_EBADF;
    for (int i = 0; i < MAX_DIR_HANDLES; i++) {
        if (g_dirs[i].fd == fd && g_dirs[i].started) {
            if (g_dirs[i].hFind != INVALID_HANDLE_VALUE) FindClose(g_dirs[i].hFind);
            g_dirs[i].started = false;
        }
    }
    return _close(fd) == 0 ? 0 : -(int64_t)LINUX_EBADF;
}

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
    if (MineVFSIsVFD(fd)) return MineVFSFstat(fd, st);
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
    int virt_type = VFS_REAL;
    const char* win_path = MineVFSTranslate(path, &virt_type);

    if (virt_type != VFS_REAL) {
        if (virt_type == VFS_UNKNOWN) return -(int64_t)LINUX_ENOENT;
        /* Virtual files always "exist" */
        memset(st, 0, sizeof(*st));
        st->st_nlink = 1; st->st_blksize = 4096;
        if (virt_type <= VFS_DEV_STDERR || virt_type == VFS_DEV_TTY)
            st->st_mode = 0020666;
        else
            st->st_mode = 0100444;
        return 0;
    }

    const char* p = win_path ? win_path : path;
    WIN32_FILE_ATTRIBUTE_DATA fa; memset(&fa, 0, sizeof(fa));
    if (!GetFileAttributesExA(p, GetFileExInfoStandard, &fa)) return winerr();
    ULARGE_INTEGER sz = { 0 }; sz.LowPart = fa.nFileSizeLow; sz.HighPart = fa.nFileSizeHigh;
    fill_stat(st, fa.dwFileAttributes, sz.QuadPart); return 0;
}

static int64_t sys_lseek(int fd, int64_t off, int whence)
{
    if (MineVFSIsVFD(fd))
        return MineVFSLseek(fd, off, whence);
    int64_t r = _lseeki64(fd, off, whence); return r < 0 ? -(int64_t)LINUX_EIO : r;
}

static int64_t sys_access(const char* path, int mode)
{
    (void)mode;
    int virt_type = VFS_REAL;
    const char* win_path = MineVFSTranslate(path, &virt_type);
    if (virt_type != VFS_REAL)
        return (virt_type == VFS_UNKNOWN) ? -(int64_t)LINUX_ENOENT : 0;
    const char* p = win_path ? win_path : path;
    return GetFileAttributesA(p) == INVALID_FILE_ATTRIBUTES ? -(int64_t)LINUX_ENOENT : 0;
}

static int64_t sys_getcwd(char* buf, uint64_t size)
{
    char tmp[4096]; if (!GetCurrentDirectoryA(sizeof(tmp), tmp)) return winerr();
    for (char* p = tmp; *p; p++) if (*p == '\\') *p = '/';
    char out[4096];
    if (tmp[0] && tmp[1] == ':' && tmp[2] == '/') {
        out[0] = '/'; out[1] = (char)tolower((unsigned char)tmp[0]);
        strcpy(out + 2, tmp + 2);
    } else {
        strcpy(out, tmp);
    }
    size_t len = strlen(out); if (len + 1 > size) return -(int64_t)LINUX_EINVAL;
    memcpy(buf, out, len + 1); return (int64_t)(len + 1);
}

/* ─── Per-fd flags tracking ──────────────────────────────────────────────── */
#define MAX_FD_TRACK 1024
static struct { int flags; bool used; } g_fd_flags[MAX_FD_TRACK];

static int get_fd_flags(int fd) {
    if (fd >= 0 && fd < MAX_FD_TRACK && g_fd_flags[fd].used) return g_fd_flags[fd].flags;
    return 0;
}
static void set_fd_flags(int fd, int flags) {
    if (fd >= 0 && fd < MAX_FD_TRACK) { g_fd_flags[fd].flags = flags; g_fd_flags[fd].used = true; }
}

#define LINUX_F_DUPFD     0
#define LINUX_F_GETFD     1
#define LINUX_F_SETFD     2
#define LINUX_F_GETFL     3
#define LINUX_F_SETFL     4
#define LINUX_F_GETLK     5
#define LINUX_F_SETLK     6
#define LINUX_F_SETLKW    7
#define LINUX_F_DUPFD_CLOEXEC 1030
#define LINUX_O_NONBLOCK  0x800
#define LINUX_O_CLOEXEC   0x80000
#define LINUX_FD_CLOEXEC  1

static int64_t sys_fcntl(int fd, int cmd, uint64_t arg)
{
    switch (cmd) {
    case LINUX_F_DUPFD:
    case LINUX_F_DUPFD_CLOEXEC: {
        int newfd = _dup(fd);
        if (newfd < 0) return -(int64_t)LINUX_EBADF;
        set_fd_flags(newfd, get_fd_flags(fd));
        return newfd;
    }
    case LINUX_F_GETFD:
        return (get_fd_flags(fd) & LINUX_FD_CLOEXEC) ? LINUX_FD_CLOEXEC : 0;
    case LINUX_F_SETFD:
        if ((int)arg & LINUX_FD_CLOEXEC)
            set_fd_flags(fd, get_fd_flags(fd) | LINUX_FD_CLOEXEC);
        else
            set_fd_flags(fd, get_fd_flags(fd) & ~LINUX_FD_CLOEXEC);
        return 0;
    case LINUX_F_GETFL:
        return get_fd_flags(fd) & ~LINUX_FD_CLOEXEC;
    case LINUX_F_SETFL: {
        int fl = get_fd_flags(fd);
        fl = (fl & LINUX_FD_CLOEXEC) | ((int)arg & ~LINUX_FD_CLOEXEC);
        set_fd_flags(fd, fl);
        if ((int)arg & LINUX_O_NONBLOCK) {
            SOCKET s = (SOCKET)_get_osfhandle(fd);
            if (s != (SOCKET)INVALID_HANDLE_VALUE) {
                u_long mode = 1;
                ioctlsocket(s, FIONBIO, &mode);
            }
        }
        return 0;
    }
    case LINUX_F_GETLK: case LINUX_F_SETLK: case LINUX_F_SETLKW:
        return 0;
    default:
        return 0;
    }
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
    if (!p && (flags & LINUX_MAP_FIXED))
        p = VirtualAlloc(addr, (SIZE_T)alen, MEM_COMMIT, PAGE_READWRITE);
    if (!p && !(flags & LINUX_MAP_FIXED))
        p = VirtualAlloc(NULL, (SIZE_T)alen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
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
    VirtualFree((LPVOID)(uintptr_t)addr, 0, MEM_RELEASE); /* succeeds only for base alloc */
    return 0;
}

#define LINUX_MAP_NORESERVE 0x4000

static int64_t sys_mprotect(uint64_t addr, uint64_t len, uint32_t prot)
{
    DWORD old = 0; return VirtualProtect((LPVOID)(uintptr_t)addr, (SIZE_T)len, linux_prot_to_win(prot), &old) ? 0 : -(int64_t)LINUX_EINVAL;
}

static int64_t sys_mremap(uint64_t old_addr, uint64_t old_size, uint64_t new_size, uint32_t flags)
{
    uint64_t oa = old_addr & ~0xFFFULL;
    uint64_t os = (old_size + 0xFFFULL) & ~0xFFFULL;
    uint64_t ns = (new_size + 0xFFFULL) & ~0xFFFULL;

    if (ns <= os) {
        if (ns < os)
            VirtualFree((LPVOID)(uintptr_t)(oa + ns), (SIZE_T)(os - ns), MEM_DECOMMIT);
        return (int64_t)oa;
    }

    LPVOID ext = VirtualAlloc((LPVOID)(uintptr_t)(oa + os), (SIZE_T)(ns - os),
                              MEM_COMMIT, PAGE_READWRITE);
    if (ext) return (int64_t)oa;

    if (!(flags & 1)) return -(int64_t)LINUX_ENOMEM;

    LPVOID p = VirtualAlloc(NULL, (SIZE_T)ns, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) return -(int64_t)LINUX_ENOMEM;
    memcpy(p, (void*)(uintptr_t)oa, (size_t)os);
    VirtualFree((LPVOID)(uintptr_t)oa, (SIZE_T)os, MEM_DECOMMIT);
    VirtualFree((LPVOID)(uintptr_t)oa, 0, MEM_RELEASE);
    return (int64_t)(uintptr_t)p;
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
    uint64_t aligned = (req + 0xFFFULL) & ~0xFFFULL;
    if (aligned > brk_end) {
        uint64_t need = aligned - brk_end;
        if (!VirtualAlloc((LPVOID)(uintptr_t)brk_end, (SIZE_T)need, MEM_COMMIT, PAGE_READWRITE))
            return (int64_t)brk_cur;
        brk_end = aligned;
    }
    brk_cur = aligned; return (int64_t)brk_cur;
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
    ensure_wsa();
    int wtype = type & 0xF;
    /* Linux "ping socket": SOCK_DGRAM + IPPROTO_ICMP → SOCK_RAW on Windows */
    if (wtype == SOCK_DGRAM && (protocol == 1 /*IPPROTO_ICMP*/ || protocol == 58 /*IPPROTO_ICMPV6*/))
        wtype = SOCK_RAW;
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

static int translate_sockopt(int level, int optname, int* wlevel, int* woptname)
{
    *wlevel = level;
    *woptname = optname;
    if (level == 1) { /* Linux SOL_SOCKET → Windows SOL_SOCKET */
        *wlevel = SOL_SOCKET;
        switch (optname) {
        case 2:  *woptname = SO_REUSEADDR; break;
        case 6:  *woptname = SO_BROADCAST; break;
        case 7:  *woptname = SO_SNDBUF; break;
        case 8:  *woptname = SO_RCVBUF; break;
        case 9:  *woptname = SO_KEEPALIVE; break;
        case 13: *woptname = SO_LINGER; break;
        case 20: *woptname = SO_RCVTIMEO; break;
        case 21: *woptname = SO_SNDTIMEO; break;
        case 11: return -1; /* SO_NO_CHECK — not supported */
        case 15: *woptname = SO_REUSEADDR; break; /* SO_REUSEPORT */
        default: break;
        }
    } else if (level == 0) { /* IPPROTO_IP */
        switch (optname) {
        case 2:  *woptname = 4; break;   /* Linux IP_TTL(2) → Win IP_TTL(4) */
        case 3:  *woptname = 3; break;   /* IP_TOS → IP_TOS (same) */
        case 11: return -1;              /* IP_RECVERR — not supported on Windows */
        case 12: *woptname = 12; break;  /* IP_MULTICAST_TTL */
        default: break;
        }
    }
    return 0;
}

static int64_t sys_setsockopt(int fd, int level, int optname, const void* optval, uint32_t optlen)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;
    int wlevel, woptname;
    if (translate_sockopt(level, optname, &wlevel, &woptname) < 0) return 0;
    return setsockopt(s, wlevel, woptname, (const char*)optval, (int)optlen) == SOCKET_ERROR ? wsaerr() : 0;
}

static int64_t sys_getsockopt(int fd, int level, int optname, void* optval, uint32_t* optlen)
{
    SOCKET s = (SOCKET)_get_osfhandle(fd);
    if (s == (SOCKET)INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;
    int wlevel, woptname, olen = optlen ? (int)*optlen : 0;
    if (translate_sockopt(level, optname, &wlevel, &woptname) < 0) return -(int64_t)92 /*ENOPROTOOPT*/;
    if (getsockopt(s, wlevel, woptname, (char*)optval, &olen) == SOCKET_ERROR) return wsaerr();
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

static int64_t sys_getdents64(int fd, void* dirp, uint32_t count)
{
    DirState* ds = NULL;
    for (int i = 0; i < MAX_DIR_HANDLES; i++) {
        if (g_dirs[i].fd == fd && g_dirs[i].started) { ds = &g_dirs[i]; break; }
    }
    if (!ds) {
        for (int i = 0; i < MAX_DIR_HANDLES; i++) {
            if (!g_dirs[i].started) { ds = &g_dirs[i]; break; }
        }
        if (!ds) return -(int64_t)LINUX_ENOMEM;
        ds->fd = fd;
        ds->started = true;
        ds->finished = false;

        char path[4096];
        HANDLE h = fd_to_handle(fd);
        DWORD plen = GetFinalPathNameByHandleA(h, path, sizeof(path) - 3, FILE_NAME_NORMALIZED);
        if (plen == 0 || plen >= sizeof(path) - 3) {
            GetCurrentDirectoryA(sizeof(path) - 3, path);
        } else {
            if (strncmp(path, "\\\\?\\", 4) == 0) memmove(path, path + 4, strlen(path + 4) + 1);
        }
        strcat(path, "\\*");
        WIN32_FIND_DATAA fdata;
        ds->hFind = FindFirstFileA(path, &fdata);
        if (ds->hFind == INVALID_HANDLE_VALUE) { ds->finished = true; return 0; }

        uint8_t* buf = (uint8_t*)dirp;
        uint32_t pos = 0;
        do {
            size_t nlen = strlen(fdata.cFileName);
            uint16_t reclen = (uint16_t)((19 + nlen + 1 + 7) & ~7);
            if (pos + reclen > count) break;
            memset(buf + pos, 0, reclen);
            uint64_t ino = 1;  memcpy(buf + pos, &ino, 8);
            int64_t  off = (int64_t)(pos + reclen); memcpy(buf + pos + 8, &off, 8);
            memcpy(buf + pos + 16, &reclen, 2);
            uint8_t dtype = (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 4 : 8;
            buf[pos + 18] = dtype;
            memcpy(buf + pos + 19, fdata.cFileName, nlen);
            pos += reclen;
        } while (FindNextFileA(ds->hFind, &fdata));
        if (GetLastError() == ERROR_NO_MORE_FILES) ds->finished = true;
        return (int64_t)pos;
    }

    if (ds->finished) {
        FindClose(ds->hFind);
        ds->started = false;
        return 0;
    }

    WIN32_FIND_DATAA fdata;
    uint8_t* buf = (uint8_t*)dirp;
    uint32_t pos = 0;
    while (FindNextFileA(ds->hFind, &fdata)) {
        size_t nlen = strlen(fdata.cFileName);
        uint16_t reclen = (uint16_t)((19 + nlen + 1 + 7) & ~7);
        if (pos + reclen > count) break;
        memset(buf + pos, 0, reclen);
        uint64_t ino = 1; memcpy(buf + pos, &ino, 8);
        int64_t off = (int64_t)(pos + reclen); memcpy(buf + pos + 8, &off, 8);
        memcpy(buf + pos + 16, &reclen, 2);
        uint8_t dtype = (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 4 : 8;
        buf[pos + 18] = dtype;
        memcpy(buf + pos + 19, fdata.cFileName, nlen);
        pos += reclen;
    }
    if (GetLastError() == ERROR_NO_MORE_FILES) ds->finished = true;
    return (int64_t)pos;
}

#define LINUX_TIOCGWINSZ  0x5413
#define LINUX_TIOCSWINSZ  0x5414
#define LINUX_FIONREAD    0x541B
#define LINUX_TCGETS      0x5401

#pragma pack(push, 1)
typedef struct { uint16_t ws_row; uint16_t ws_col; uint16_t ws_xpixel; uint16_t ws_ypixel; } Linux_winsize;
#pragma pack(pop)

static int64_t sys_ioctl(int fd, uint64_t req, uint64_t arg)
{
    switch (req) {
    case LINUX_TIOCGWINSZ: {
        Linux_winsize* ws = (Linux_winsize*)(uintptr_t)arg;
        if (!ws) return -(int64_t)LINUX_EFAULT;
        HANDLE h = fd_to_handle(fd);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (h && GetConsoleScreenBufferInfo(h, &csbi)) {
            ws->ws_col = (uint16_t)(csbi.srWindow.Right - csbi.srWindow.Left + 1);
            ws->ws_row = (uint16_t)(csbi.srWindow.Bottom - csbi.srWindow.Top + 1);
        } else {
            ws->ws_col = 80;
            ws->ws_row = 24;
        }
        ws->ws_xpixel = 0;
        ws->ws_ypixel = 0;
        return 0;
    }
    case LINUX_TIOCSWINSZ:
        return 0;
    case LINUX_FIONREAD: {
        uint32_t* nbytes = (uint32_t*)(uintptr_t)arg;
        if (!nbytes) return -(int64_t)LINUX_EFAULT;
        HANDLE h = fd_to_handle(fd);
        DWORD avail = 0;
        if (h && PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL))
            *nbytes = avail;
        else
            *nbytes = 0;
        return 0;
    }
    case LINUX_TCGETS:
        if (fd <= 2) return 0;
        return -(int64_t)LINUX_ENOTTY;
    default:
        return -(int64_t)LINUX_ENOTTY;
    }
}

/* ─── sysinfo ─────────────────────────────────────────────────────────────── */
#pragma pack(push,1)
typedef struct {
    int64_t  uptime;
    uint64_t loads[3];
    uint64_t totalram;
    uint64_t freeram;
    uint64_t sharedram;
    uint64_t bufferram;
    uint64_t totalswap;
    uint64_t freeswap;
    uint16_t procs;
    uint16_t pad;
    uint32_t pad2;
    uint64_t totalhigh;
    uint64_t freehigh;
    uint32_t mem_unit;
} Linux_sysinfo;
#pragma pack(pop)

static int64_t sys_sysinfo(void* buf)
{
    if (!buf) return -(int64_t)LINUX_EFAULT;
    Linux_sysinfo* si = (Linux_sysinfo*)buf;
    memset(si, 0, sizeof(*si));

    si->uptime = (int64_t)(GetTickCount64() / 1000ULL);
    si->loads[0] = 0; si->loads[1] = 0; si->loads[2] = 0;

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        si->totalram = ms.ullTotalPhys;
        si->freeram = ms.ullAvailPhys;
        si->totalswap = ms.ullTotalPageFile - ms.ullTotalPhys;
        si->freeswap = ms.ullAvailPageFile > ms.ullTotalPhys
            ? ms.ullAvailPageFile - ms.ullTotalPhys : 0;
    }

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    si->procs = (uint16_t)sysinfo.dwNumberOfProcessors;
    si->mem_unit = 1;
    return 0;
}

/* ─── getrusage ───────────────────────────────────────────────────────────── */
typedef struct {
    Linux_timeval ru_utime;
    Linux_timeval ru_stime;
    int64_t ru_maxrss;
    int64_t ru_ixrss;
    int64_t ru_idrss;
    int64_t ru_isrss;
    int64_t ru_minflt;
    int64_t ru_majflt;
    int64_t ru_nswap;
    int64_t ru_inblock;
    int64_t ru_oublock;
    int64_t ru_msgsnd;
    int64_t ru_msgrcv;
    int64_t ru_nsignals;
    int64_t ru_nvcsw;
    int64_t ru_nivcsw;
} Linux_rusage;

static int64_t sys_getrusage(int who, void* buf)
{
    if (!buf) return -(int64_t)LINUX_EFAULT;
    Linux_rusage* ru = (Linux_rusage*)buf;
    memset(ru, 0, sizeof(*ru));

    FILETIME ct, et, kt, ut;
    HANDLE h = (who == 0) ? GetCurrentProcess() : GetCurrentThread();
    if (GetProcessTimes(h, &ct, &et, &kt, &ut)) {
        ULARGE_INTEGER k, u;
        k.LowPart = kt.dwLowDateTime; k.HighPart = kt.dwHighDateTime;
        u.LowPart = ut.dwLowDateTime; u.HighPart = ut.dwHighDateTime;
        uint64_t kus = k.QuadPart / 10;
        uint64_t uus = u.QuadPart / 10;
        ru->ru_stime.tv_sec = (int64_t)(kus / 1000000ULL);
        ru->ru_stime.tv_usec = (int64_t)(kus % 1000000ULL);
        ru->ru_utime.tv_sec = (int64_t)(uus / 1000000ULL);
        ru->ru_utime.tv_usec = (int64_t)(uus % 1000000ULL);
    }

    PROCESS_MEMORY_COUNTERS pmc;
    memset(&pmc, 0, sizeof(pmc));
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        ru->ru_maxrss = (int64_t)(pmc.PeakWorkingSetSize / 1024);
        ru->ru_minflt = (int64_t)pmc.PageFaultCount;
    }
    return 0;
}

/* ─── sendfile ────────────────────────────────────────────────────────────── */
static int64_t sys_sendfile(int out_fd, int in_fd, int64_t* offset, uint64_t count)
{
    /* Handle VFD sources (e.g. /etc/passwd, /proc/*) */
    if (MineVFSIsVFD(in_fd)) {
        if (offset) MineVFSLseek(in_fd, *offset, 0);
        char buf[8192];
        int64_t total = 0;
        while ((uint64_t)total < count) {
            uint64_t to_read = (count - total) < sizeof(buf) ? (count - total) : sizeof(buf);
            int64_t got = MineVFSRead(in_fd, buf, to_read);
            if (got <= 0) break;
            int64_t w = sys_write(out_fd, buf, (uint64_t)got);
            if (w < 0) return total > 0 ? total : w;
            total += w;
            if (w < got) break;
        }
        if (offset) *offset += total;
        return total;
    }

    HANDLE hin = (HANDLE)_get_osfhandle(in_fd);
    if (hin == INVALID_HANDLE_VALUE) return -(int64_t)LINUX_EBADF;

    if (offset) {
        LARGE_INTEGER li; li.QuadPart = *offset;
        SetFilePointerEx(hin, li, NULL, FILE_BEGIN);
    }

    char buf[8192];
    int64_t total = 0;
    while ((uint64_t)total < count) {
        DWORD to_read = (DWORD)((count - total) < sizeof(buf) ? (count - total) : sizeof(buf));
        DWORD got = 0;
        if (!ReadFile(hin, buf, to_read, &got, NULL) || got == 0) break;
        int64_t w = sys_write(out_fd, buf, got);
        if (w < 0) return total > 0 ? total : w;
        total += w;
        if ((uint64_t)w < got) break;
    }

    if (offset) *offset += total;
    return total;
}

/* ─── readv ───────────────────────────────────────────────────────────────── */
static int64_t sys_readv(int fd, const Linux_iovec* iov, int iovcnt)
{
    int64_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        int64_t n = sys_read(fd, (void*)(uintptr_t)iov[i].iov_base, iov[i].iov_len);
        if (n < 0) return total ? total : n;
        total += n;
        if ((uint64_t)n < iov[i].iov_len) break;
    }
    return total;
}

/* ─── eventfd ─────────────────────────────────────────────────────────────── */
#define MAX_EVENTFDS 32
static struct {
    bool used;
    int  fd_read;
    int  fd_write;
    int  efd;
    uint64_t counter;
    CRITICAL_SECTION lock;
    bool semaphore;
} g_eventfds[MAX_EVENTFDS];
static int g_eventfd_next = 2000;

static int64_t sys_eventfd(uint32_t initval, int flags)
{
    for (int i = 0; i < MAX_EVENTFDS; i++) {
        if (!g_eventfds[i].used) {
            int fds[2];
            if (MineVFSPipe(fds, 0) < 0) return -(int64_t)LINUX_EMFILE;
            g_eventfds[i].used = true;
            g_eventfds[i].fd_read = fds[0];
            g_eventfds[i].fd_write = fds[1];
            g_eventfds[i].efd = g_eventfd_next++;
            g_eventfds[i].counter = initval;
            g_eventfds[i].semaphore = !!(flags & 0x1);
            InitializeCriticalSection(&g_eventfds[i].lock);
            if (initval > 0) {
                uint8_t one = 1;
                sys_write(g_eventfds[i].fd_write, &one, 1);
            }
            return g_eventfds[i].fd_read;
        }
    }
    return -(int64_t)LINUX_EMFILE;
}

/* ─── clone (basic thread creation) ───────────────────────────────────────── */
#define LINUX_CLONE_VM         0x00000100
#define LINUX_CLONE_FS         0x00000200
#define LINUX_CLONE_FILES      0x00000400
#define LINUX_CLONE_SIGHAND    0x00000800
#define LINUX_CLONE_THREAD     0x00010000
#define LINUX_CLONE_SETTLS     0x00080000
#define LINUX_CLONE_PARENT_SETTID 0x00100000
#define LINUX_CLONE_CHILD_CLEARTID 0x00200000
#define LINUX_CLONE_CHILD_SETTID  0x01000000

typedef struct {
    uint64_t fn;
    uint64_t child_stack;
    uint64_t arg;
    uint64_t tls;
    uint64_t ctid;
} CloneCtx;

extern void MineWinToLinux(void);

static DWORD WINAPI clone_thread_entry(LPVOID param)
{
    CloneCtx* ctx = (CloneCtx*)param;
    uint64_t fn = ctx->fn;
    uint64_t child_stack = ctx->child_stack;
    uint64_t arg = ctx->arg;
    uint64_t tls = ctx->tls;
    uint64_t ctid = ctx->ctid;
    free(ctx);

    MineTLSInitThread();

    if (tls) {
        MineDynSetGuestFS(tls);
        __try { _writefsbase_u64(tls); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    DWORD tid = GetCurrentThreadId();
    if (ctid) *(uint32_t*)(uintptr_t)ctid = (uint32_t)tid;

    typedef int(*win_fn_t)(void*, uint64_t, uint64_t, uint64_t);
    int ret = ((win_fn_t)MineWinToLinux)((void*)(uintptr_t)fn, arg, 0, 0);

    if (ctid) {
        *(uint32_t*)(uintptr_t)ctid = 0;
        MineFutex((uint32_t*)(uintptr_t)ctid, 1, 1, NULL, NULL, 0);
    }

    return (DWORD)ret;
}

static int64_t sys_clone(uint64_t flags, uint64_t child_stack,
    uint64_t ptid, uint64_t ctid, uint64_t tls)
{
    if (!(flags & LINUX_CLONE_THREAD)) {
        return -(int64_t)LINUX_ENOSYS;
    }

    CloneCtx* ctx = (CloneCtx*)calloc(1, sizeof(CloneCtx));
    if (!ctx) return -(int64_t)LINUX_ENOMEM;

    ctx->child_stack = child_stack;
    ctx->tls = (flags & LINUX_CLONE_SETTLS) ? tls : 0;
    ctx->ctid = (flags & LINUX_CLONE_CHILD_CLEARTID) ? ctid : 0;

    if (child_stack) {
        uint64_t* sp = (uint64_t*)(uintptr_t)child_stack;
        ctx->fn = *(sp - 1);
        ctx->arg = *(sp - 2);
    }

    DWORD tid = 0;
    HANDLE h = CreateThread(NULL, 0, clone_thread_entry, ctx, 0, &tid);
    if (!h) {
        free(ctx);
        return -(int64_t)LINUX_ENOMEM;
    }

    if ((flags & LINUX_CLONE_PARENT_SETTID) && ptid)
        *(uint32_t*)(uintptr_t)ptid = (uint32_t)tid;

    CloseHandle(h);
    return (int64_t)tid;
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
    case SYS_pread64:     ret = (uint64_t)sys_pread64((int)a1, (void*)a2, a3, a4); break;
    case SYS_pwrite64:    ret = (uint64_t)sys_pwrite64((int)a1, (void*)a2, a3, a4); break;
    case SYS_lseek:       ret = (uint64_t)sys_lseek((int)a1, (int64_t)a2, (int)a3); break;
    case SYS_fcntl:       ret = (uint64_t)sys_fcntl((int)a1, (int)a2, a3); break;
    case SYS_access:      ret = (uint64_t)sys_access((char*)a1, (int)a2); break;
    case SYS_getcwd:      ret = (uint64_t)sys_getcwd((char*)a1, a2); break;
    case SYS_ftruncate:   ret = (uint64_t)sys_ftruncate((int)a1, (int64_t)a2); break;
    case SYS_dup: { int r = _dup((int)a1); ret = r < 0 ? (uint64_t)-(int64_t)LINUX_EBADF : (uint64_t)r; } break;
    case SYS_dup2: { int r = _dup2((int)a1, (int)a2); ret = r < 0 ? (uint64_t)-(int64_t)LINUX_EBADF : a2; } break;
    case SYS_pipe: case SYS_pipe2: ret = (uint64_t)MineVFSPipe((int*)(uintptr_t)a1, (nr == SYS_pipe2) ? (int)a2 : 0); break;
    case SYS_getdents64:  ret = (uint64_t)sys_getdents64((int)a1, (void*)a2, (uint32_t)a3); break;
    case SYS_ioctl:       ret = (uint64_t)sys_ioctl((int)a1, a2, a3); break;
    case SYS_poll:        ret = (uint64_t)MinePoll((void*)a1, (uint32_t)a2, (int)a3); break;
    case SYS_select:      ret = (uint64_t)MineSelect((int)a1, (void*)a2, (void*)a3, (void*)a4, (void*)a5); break;
    case SYS_fstat:       ret = (uint64_t)sys_fstat((int)a1, (Linux_stat*)a2); break;
    case SYS_stat: case SYS_lstat: ret = (uint64_t)sys_stat((char*)a1, (Linux_stat*)a2); break;
    case SYS_newfstatat: {
        const char* p = (const char*)a2;
        if (p && *p) ret = (uint64_t)sys_stat(p, (Linux_stat*)a3);
        else ret = (uint64_t)sys_fstat((int)a1, (Linux_stat*)a3);
        break;
    }
    case SYS_readlinkat: {
        const char* rpath = (a1 == (uint64_t)-100) ? (const char*)a2 : (const char*)a2;
        int rvt = VFS_REAL;
        MineVFSTranslate(rpath, &rvt);
        if (rvt == VFS_PROC_SELF_EXE)
            ret = (uint64_t)MineVFSReadlink(rvt, (char*)a3, a4);
        else
            ret = (uint64_t)-(int64_t)LINUX_ENOENT;
        break;
    }
    case SYS_mmap:        ret = (uint64_t)sys_mmap(a1, a2, (uint32_t)a3, (uint32_t)a4, (int)a5, a6); break;
    case SYS_munmap:      ret = (uint64_t)sys_munmap(a1, a2); break;
    case SYS_mprotect:    ret = (uint64_t)sys_mprotect(a1, a2, (uint32_t)a3); break;
    case SYS_mremap:      ret = (uint64_t)sys_mremap(a1, a2, a3, (uint32_t)a4); break;
    case SYS_brk:         ret = (uint64_t)sys_brk(a1); break;
    case SYS_madvise: case SYS_mincore: case SYS_msync:
    case SYS_mlock: case SYS_munlock: case SYS_mlockall: case SYS_munlockall: ret = 0; break;
    case SYS_clock_gettime: ret = (uint64_t)sys_clock_gettime((int)a1, (Linux_timespec*)a2); break;
    case SYS_clock_getres:  ret = (uint64_t)sys_clock_getres((int)a1, (Linux_timespec*)a2); break;
    case SYS_gettimeofday:  ret = (uint64_t)sys_gettimeofday((Linux_timeval*)a1, (void*)a2); break;
    case SYS_nanosleep:     ret = (uint64_t)sys_nanosleep((Linux_timespec*)a1, (Linux_timespec*)a2); break;
    case SYS_clock_nanosleep: ret = (uint64_t)sys_nanosleep((Linux_timespec*)a3, (Linux_timespec*)a4); break;
    case SYS_settimeofday:  ret = 0; break;
    case SYS_time: {
        FILETIME ft; GetSystemTimeAsFileTime(&ft);
        uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        t = (t - 116444736000000000ULL) / 10000000ULL;
        if (a1) *(uint64_t*)a1 = t;
        ret = t;
    } break;
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
    case SYS_sysinfo: ret = (uint64_t)sys_sysinfo((void*)a1); break;
    case SYS_getrusage: ret = (uint64_t)sys_getrusage((int)a1, (void*)a2); break;
    case SYS_times: ret = 0; break;
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
    case SYS_sendfile:    ret = (uint64_t)sys_sendfile((int)a1, (int)a2, (int64_t*)a3, a4); break;
    case SYS_clone:       ret = (uint64_t)sys_clone(a1, a2, a3, a4, a5); break;
    case SYS_readv:       ret = (uint64_t)sys_readv((int)a1, (Linux_iovec*)a2, (int)a3); break;
    case SYS_accept4:     ret = (uint64_t)sys_accept((int)a1, (void*)a2, (uint32_t*)a3); break;
    case SYS_ppoll:       ret = (uint64_t)MinePoll((void*)a1, (uint32_t)a2, -1); break;
    case SYS_pselect6:    ret = (uint64_t)MineSelect((int)a1, (void*)a2, (void*)a3, (void*)a4, (void*)a5); break;
    case SYS_recvmmsg:    ret = (uint64_t)-(int64_t)LINUX_ENOSYS; break;
    case SYS_sendmmsg:    ret = (uint64_t)-(int64_t)LINUX_ENOSYS; break;
    case SYS_timerfd_create:  ret = (uint64_t)MineTimerfdCreate((int)a1, (int)a2); break;
    case SYS_timerfd_settime: ret = (uint64_t)MineTimerfdSettime((int)a1, (int)a2, (void*)a3, (void*)a4); break;
    case SYS_timerfd_gettime: ret = (uint64_t)MineTimerfdGettime((int)a1, (void*)a2); break;
    case SYS_signalfd4:   ret = (uint64_t)-(int64_t)LINUX_ENOSYS; break;
    case SYS_inotify_init1: ret = (uint64_t)-(int64_t)LINUX_ENOSYS; break;
    case SYS_inotify_add_watch: ret = (uint64_t)-(int64_t)LINUX_ENOSYS; break;
    case SYS_inotify_rm_watch: ret = (uint64_t)-(int64_t)LINUX_ENOSYS; break;
    case SYS_faccessat: case SYS_faccessat2:
        ret = (uint64_t)sys_access((char*)a2, (int)a3); break;
    case SYS_fadvise64:   ret = 0; break;
    case SYS_fallocate: {
        HANDLE h = (HANDLE)_get_osfhandle((int)a1);
        if (h == INVALID_HANDLE_VALUE) { ret = (uint64_t)-(int64_t)LINUX_EBADF; break; }
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)(a3 + a4);
        SetFilePointerEx(h, li, NULL, FILE_BEGIN);
        SetEndOfFile(h);
        ret = 0;
    } break;
    case SYS_sync: case SYS_syncfs: ret = 0; break;
    case SYS_fdatasync: case SYS_fsync: {
        HANDLE h = (HANDLE)_get_osfhandle((int)a1);
        if (h != INVALID_HANDLE_VALUE) FlushFileBuffers(h);
        ret = 0;
    } break;
    case SYS_flock: ret = 0; break;
    case SYS_truncate: {
        HANDLE h = CreateFileA((char*)a1, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) { ret = (uint64_t)winerr(); break; }
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)a2;
        SetFilePointerEx(h, li, NULL, FILE_BEGIN);
        SetEndOfFile(h);
        CloseHandle(h);
        ret = 0;
    } break;
    case SYS_getdents:    ret = (uint64_t)sys_getdents64((int)a1, (void*)a2, (uint32_t)a3); break;
    case SYS_utimensat:   ret = 0; break;
    case SYS_renameat: case SYS_renameat2: {
        int vt1 = VFS_REAL, vt2 = VFS_REAL;
        const char* wp1 = MineVFSTranslate((char*)a2, &vt1);
        const char* wp2 = MineVFSTranslate((char*)a4, &vt2);
        ret = MoveFileExA(wp1 ? wp1 : (char*)a2, wp2 ? wp2 : (char*)a4, MOVEFILE_REPLACE_EXISTING) ? 0 : (uint64_t)winerr();
    } break;
    case SYS_unlinkat: {
        int vt = VFS_REAL;
        const char* wp = MineVFSTranslate((const char*)a2, &vt);
        const char* rp = wp ? wp : (const char*)a2;
        if ((int)a3 & 0x200) ret = RemoveDirectoryA(rp) ? 0 : (uint64_t)winerr();
        else ret = DeleteFileA(rp) ? 0 : (uint64_t)winerr();
    } break;
    case SYS_mkdirat: {
        int vt = VFS_REAL;
        const char* wp = MineVFSTranslate((char*)a2, &vt);
        ret = CreateDirectoryA(wp ? wp : (char*)a2, NULL) ? 0 : (uint64_t)winerr();
    } break;
    case SYS_fchmodat: case SYS_fchownat: case SYS_linkat: case SYS_symlinkat:
        ret = 0; break;
    case SYS_statfs: case SYS_fstatfs: {
        if (!a2) { ret = (uint64_t)-(int64_t)LINUX_EFAULT; break; }
        memset((void*)a2, 0, 120);
        uint64_t* fs = (uint64_t*)a2;
        fs[0] = 0xEF53; /* EXT4 magic */
        fs[1] = 4096;   /* block size */
        fs[2] = 4096;   /* fragment size */
        ret = 0;
    } break;
    case SYS_execve:      ret = (uint64_t)MineExecve((const char*)a1, (char* const*)a2, (char* const*)a3); break;
    case SYS_wait4:       ret = (uint64_t)MineWaitpid((int)a1, (int*)(uintptr_t)a2, (int)a3); break;
    case SYS_socketpair:  ret = (uint64_t)MineVFSPipe((int*)(uintptr_t)a4, 0); break;
    case SYS_epoll_create: case SYS_epoll_create1:
        ret = (uint64_t)MineEpollCreate((int)a1); break;
    case SYS_epoll_ctl:   ret = (uint64_t)MineEpollCtl((int)a1, (int)a2, (int)a3, (void*)a4); break;
    case SYS_epoll_wait: case SYS_epoll_pwait:
        ret = (uint64_t)MineEpollWait((int)a1, (void*)a2, (int)a3, (int)a4); break;
    case SYS_eventfd2:    ret = (uint64_t)sys_eventfd((uint32_t)a1, (int)a2); break;
    case SYS_dup3: {
        int r = _dup2((int)a1, (int)a2);
        ret = r < 0 ? (uint64_t)-(int64_t)LINUX_EBADF : a2;
    } break;
    case SYS_set_tid_address: g_tid_addr = a1; ret = (uint64_t)GetCurrentThreadId(); break;
    case SYS_set_robust_list: g_robust_list = a1; ret = 0; break;
    case SYS_get_robust_list: ret = 0; break;
    case SYS_futex:       ret = (uint64_t)MineFutex((uint32_t*)(uintptr_t)a1, (int)a2, (uint32_t)a3, (void*)a4, (uint32_t*)(uintptr_t)a5, (uint32_t)a6); break;
    case SYS_sched_yield: SwitchToThread(); ret = 0; break;
    case SYS_sigaltstack: ret = (uint64_t)MineSignalSigaltstack((void*)a1, (void*)a2); break;
    case SYS_prctl:       ret = 0; break;
    case SYS_rt_sigaction:
        ret = (uint64_t)MineSignalAction((int)a1, (const MineSigAction*)a2,
              (MineSigAction*)a3, a4);
        break;
    case SYS_rt_sigprocmask:
        ret = (uint64_t)MineSignalProcmask((int)a1, (const uint64_t*)a2,
              (uint64_t*)a3, a4);
        break;
    case SYS_rt_sigreturn: ret = 0; break;
    case SYS_rt_sigsuspend: ret = 0; break;
    case SYS_capget: case SYS_capset: ret = 0; break;
    case SYS_rseq:        ret = (uint64_t)-(int64_t)LINUX_ENOSYS; break;
    case SYS_tgkill: case SYS_tkill:
        MineSignalRaise((int)a3 ? (int)a3 : (int)a2);
        ret = 0;
        break;
    case SYS_chdir:       ret = SetCurrentDirectoryA((char*)a1) ? 0 : winerr(); break;
    case SYS_readlink: {
        int rvt = VFS_REAL;
        MineVFSTranslate((const char*)a1, &rvt);
        if (rvt == VFS_PROC_SELF_EXE)
            ret = (uint64_t)MineVFSReadlink(rvt, (char*)a2, a3);
        else
            ret = (uint64_t)-(int64_t)LINUX_ENOENT;
        break;
    }
    case SYS_mkdir:       ret = CreateDirectoryA((char*)a1, NULL) ? 0 : winerr(); break;
    case SYS_rmdir:       ret = RemoveDirectoryA((char*)a1) ? 0 : winerr(); break;
    case SYS_unlink:      ret = DeleteFileA((char*)a1) ? 0 : winerr(); break;
    case SYS_rename:      ret = MoveFileExA((char*)a1, (char*)a2, MOVEFILE_REPLACE_EXISTING) ? 0 : winerr(); break;
    case SYS_chmod: case SYS_fchmod: case SYS_chown:
    case SYS_fchown: case SYS_lchown: ret = 0; break;
    case SYS_statx: {
        const char* p = (const char*)a2;
        if (!a5) { ret = (uint64_t)-(int64_t)LINUX_EFAULT; break; }
        Linux_stat st; memset(&st, 0, sizeof(st));
        int64_t sr = sys_stat(p, &st);
        if (sr < 0) { ret = (uint64_t)sr; break; }
        uint8_t* sx = (uint8_t*)a5;
        memset(sx, 0, 256);
        *(uint32_t*)(sx + 0) = 0x7FF;
        *(uint32_t*)(sx + 4) = 4096;
        *(uint32_t*)(sx + 16) = (uint32_t)st.st_nlink;
        *(uint32_t*)(sx + 20) = (uint32_t)st.st_uid;
        *(uint32_t*)(sx + 24) = (uint32_t)st.st_gid;
        *(uint16_t*)(sx + 28) = (uint16_t)st.st_mode;
        *(uint64_t*)(sx + 32) = st.st_ino;
        *(uint64_t*)(sx + 40) = st.st_size;
        *(uint64_t*)(sx + 48) = st.st_blocks;
        ret = 0;
    } break;
    case SYS_copy_file_range: {
        char buf[8192];
        int64_t* off_in = a3 ? (int64_t*)a3 : NULL;
        int64_t* off_out = a5 ? (int64_t*)a5 : NULL;
        if (off_in) _lseeki64((int)a1, *off_in, SEEK_SET);
        if (off_out) _lseeki64((int)a2, *off_out, SEEK_SET);
        size_t total = 0, len = (size_t)a4;
        while (total < len) {
            size_t chunk = len - total;
            if (chunk > sizeof(buf)) chunk = sizeof(buf);
            int r = _read((int)a1, buf, (unsigned int)chunk);
            if (r <= 0) break;
            int w = _write((int)a2, buf, r);
            if (w <= 0) break;
            total += w;
            if (off_in) *off_in += w;
            if (off_out) *off_out += w;
        }
        ret = (uint64_t)total;
    } break;
    case SYS_memfd_create: {
        char tmp[MAX_PATH];
        GetTempPathA(sizeof(tmp), tmp);
        char name[MAX_PATH];
        snprintf(name, sizeof(name), "%smfd_%u_%u", tmp, GetCurrentProcessId(), GetCurrentThreadId());
        int fd = _open(name, _O_RDWR | _O_CREAT | _O_TRUNC | _O_BINARY, _S_IREAD | _S_IWRITE);
        ret = fd < 0 ? (uint64_t)-(int64_t)LINUX_ENOMEM : (uint64_t)fd;
    } break;
    case SYS_sched_getaffinity: {
        DWORD_PTR proc_mask, sys_mask;
        GetProcessAffinityMask(GetCurrentProcess(), &proc_mask, &sys_mask);
        size_t sz = (size_t)a2;
        if (sz > sizeof(DWORD_PTR)) sz = sizeof(DWORD_PTR);
        if (a3) { memset((void*)a3, 0, (size_t)a2); memcpy((void*)a3, &proc_mask, sz); }
        ret = (uint64_t)sz;
    } break;
    case SYS_sched_setaffinity: ret = 0; break;
    case SYS_exit: case SYS_exit_group:
        MineTraceExit(nr, a1); ExitProcess((UINT)a1); return 0;
    default:
        fprintf(stderr, "\n[MinE] !! Unhandled syscall %llu (ENOSYS)\n", (unsigned long long)nr);
        ret = (uint64_t)(-(int64_t)LINUX_ENOSYS); break;
    }

    MineTraceExit(nr, ret);

    MineSignalDeliver();

    return ret;
}