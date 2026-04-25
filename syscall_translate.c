#define _CRT_SECURE_NO_WARNINGS
#include "syscall_translate.h"
#include "mine_trace.h"

#include <Windows.h>
#include <io.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <wincrypt.h>

// Linux syscall numbers 

#define SYS_read              0
#define SYS_write             1
#define SYS_open              2
#define SYS_close             3
#define SYS_stat              4
#define SYS_fstat             5
#define SYS_lstat             6
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
#define SYS_sched_yield       24
#define SYS_dup               32
#define SYS_dup2              33
#define SYS_nanosleep         35
#define SYS_getpid            39
#define SYS_exit              60
#define SYS_uname             63
#define SYS_fcntl             72
#define SYS_getcwd            79
#define SYS_gettimeofday      96
#define SYS_getrlimit         97
#define SYS_getuid            102
#define SYS_getgid            104
#define SYS_geteuid           107
#define SYS_getegid           108
#define SYS_getppid           110
#define SYS_getpgrp           111
#define SYS_gettid            186
#define SYS_arch_prctl        158
#define SYS_exit_group        231
#define SYS_clock_gettime     228
#define SYS_clock_getres      229
#define SYS_set_tid_address   218
#define SYS_set_robust_list   273
#define SYS_get_robust_list   274
#define SYS_futex             202
#define SYS_openat            257
#define SYS_prlimit64         302
#define SYS_getrandom         318
#define SYS_getdents64        217
#define SYS_sigaltstack       131
#define SYS_prctl             157

#define LINUX_EPERM     1
#define LINUX_ENOENT    2
#define LINUX_EBADF     9
#define LINUX_ENOMEM    12
#define LINUX_EACCES    13
#define LINUX_EFAULT    14
#define LINUX_EINVAL    22
#define LINUX_ENOSYS    38
#define LINUX_EIO       5

#define LINUX_PROT_NONE  0x0
#define LINUX_PROT_READ  0x1
#define LINUX_PROT_WRITE 0x2
#define LINUX_PROT_EXEC  0x4
#define LINUX_MAP_ANON   0x20
#define LINUX_MAP_FIXED  0x10

#define ARCH_SET_FS  0x1002
#define ARCH_GET_FS  0x1003
#define ARCH_SET_GS  0x1001
#define ARCH_GET_GS  0x1004

typedef struct {
    uint64_t st_dev;     uint64_t st_ino;    uint64_t st_nlink;
    uint32_t st_mode;    uint32_t st_uid;    uint32_t st_gid;   uint32_t __pad;
    uint64_t st_rdev;    int64_t  st_size;
    int64_t  st_blksize; int64_t  st_blocks;
    uint64_t st_atime;   uint64_t st_atime_ns;
    uint64_t st_mtime;   uint64_t st_mtime_ns;
    uint64_t st_ctime;   uint64_t st_ctime_ns;
    int64_t  __unused[3];
} Linux_stat;

typedef struct { int64_t tv_sec; int64_t tv_nsec; } Linux_timespec;
typedef struct { int64_t tv_sec; int64_t tv_usec; } Linux_timeval;
typedef struct { uint64_t iov_base; uint64_t iov_len; } Linux_iovec;
typedef struct { uint64_t rlim_cur; uint64_t rlim_max; } Linux_rlimit;

/* ─── State ───────────────────────────────────────────────────────────────── */

static uint64_t g_fs_base = 0;
static uint64_t g_tid_addr = 0;   /* set_tid_address target             */
static uint64_t g_robust_list = 0;

/* ─── Error helpers ───────────────────────────────────────────────────────── */

static int64_t winerr(void)
{
    switch (GetLastError()) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:    return -(int64_t)LINUX_ENOENT;
    case ERROR_ACCESS_DENIED:     return -(int64_t)LINUX_EACCES;
    case ERROR_INVALID_HANDLE:    return -(int64_t)LINUX_EBADF;
    case ERROR_NOT_ENOUGH_MEMORY: return -(int64_t)LINUX_ENOMEM;
    default:                      return -(int64_t)LINUX_EIO;
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

static FILETIME ft_now(void)
{
    FILETIME ft; GetSystemTimeAsFileTime(&ft); return ft;
}

static uint64_t filetime_to_unix(FILETIME ft)
{
    ULARGE_INTEGER ul;
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;
    return (ul.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

/* ─── Syscall implementations ─────────────────────────────────────────────── */

static int64_t sys_read(int fd, void* buf, uint64_t count)
{
    int n = _read(fd, buf, (unsigned)count);
    return n < 0 ? -(int64_t)LINUX_EIO : n;
}

static int64_t sys_write(int fd, const void* buf, uint64_t count)
{
    int n = _write(fd, buf, (unsigned)count);
    return n < 0 ? -(int64_t)LINUX_EIO : n;
}

static int64_t sys_writev(int fd, const Linux_iovec* iov, int iovcnt)
{
    int64_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        int n = _write(fd, (void*)iov[i].iov_base, (unsigned)iov[i].iov_len);
        if (n < 0) return total ? total : -(int64_t)LINUX_EIO;
        total += n;
    }
    return total;
}

static int64_t sys_open_internal(const char* path, int flags)
{
    DWORD access = GENERIC_READ;
    DWORD create = OPEN_EXISTING;
    if (flags & 1)     access = GENERIC_WRITE;
    if (flags & 2)     access = GENERIC_READ | GENERIC_WRITE;
    if (flags & 0x40)  create = OPEN_ALWAYS;
    if (flags & 0x200) create = CREATE_ALWAYS;

    HANDLE h = CreateFileA(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, create, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return winerr();

    int fd = _open_osfhandle((intptr_t)h, 0);
    if (fd < 0) { CloseHandle(h); return -(int64_t)LINUX_EIO; }
    return fd;
}

static int64_t sys_open(const char* path, int flags, int mode)
{
    return sys_open_internal(path, flags);
}

static int64_t sys_openat(int dirfd, const char* path, int flags, int mode)
{
    if (path[0] == '/' || dirfd == -100)
        return sys_open_internal(path, flags);
    return sys_open_internal(path, flags);
}

static int64_t sys_close(int fd)
{
    if (fd <= 2) return 0;
    return _close(fd) == 0 ? 0 : -(int64_t)LINUX_EBADF;
}

static void fill_stat(Linux_stat* st, HANDLE h, DWORD attr, uint64_t size)
{
    memset(st, 0, sizeof(*st));
    st->st_dev = 1;
    st->st_ino = 1;
    st->st_nlink = 1;
    st->st_uid = 1000;
    st->st_gid = 1000;
    st->st_blksize = 512;

    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        st->st_mode = 0040755;
        st->st_size = 4096;
    }

    else {
        st->st_mode = 0100644;
        st->st_size = (int64_t)size;
    }
    
    st->st_blocks = (st->st_size + 511) / 512;

    FILETIME ft = ft_now();
    uint64_t t = filetime_to_unix(ft);
    st->st_atime = st->st_mtime = st->st_ctime = t;
}

static int64_t sys_fstat(int fd, Linux_stat* st)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd);

    if (h == INVALID_HANDLE_VALUE) {
        memset(st, 0, sizeof(*st));

        st->st_mode = 0020666;
        st->st_nlink = 1;
        st->st_blksize = 512;
        return 0;
    }

    BY_HANDLE_FILE_INFORMATION info;
    
    if (!GetFileInformationByHandle(h, &info)) 
        return winerr();
    
    ULARGE_INTEGER sz;
    sz.LowPart = info.nFileSizeLow;
    sz.HighPart = info.nFileSizeHigh;
    fill_stat(st, h, info.dwFileAttributes, sz.QuadPart);

    st->st_ino = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
    
    return 0;
}

static int64_t sys_stat(const char* path, Linux_stat* st)
{
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fa))
        return winerr();

    ULARGE_INTEGER sz;
    sz.LowPart = fa.nFileSizeLow;
    sz.HighPart = fa.nFileSizeHigh;
    fill_stat(st, NULL, fa.dwFileAttributes, sz.QuadPart);
    
    return 0;
}

static int64_t sys_lseek(int fd, int64_t off, int whence)
{
    int64_t r = _lseeki64(fd, off, whence);
    return r < 0 ? -(int64_t)LINUX_EIO : r;
}

static int64_t sys_mmap(uint64_t hint, uint64_t len, uint32_t prot,
    uint32_t flags, int fd, uint64_t off)
{
    uint64_t alen = (len + (uint64_t)0xFFF) & ~(uint64_t)0xFFF;
    DWORD    wprot = linux_prot_to_win(prot);
    LPVOID   addr = (flags & LINUX_MAP_FIXED) ? (LPVOID)hint : NULL;

    LPVOID p = VirtualAlloc(addr, (SIZE_T)alen,
        MEM_RESERVE | MEM_COMMIT,
        wprot ? wprot : PAGE_READWRITE);
    if (!p) return -(int64_t)LINUX_ENOMEM;

    if (fd >= 0 && !(flags & LINUX_MAP_ANON)) {
        HANDLE fh = (HANDLE)_get_osfhandle(fd);

        if (fh != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER li; li.QuadPart = (LONGLONG)off;
            SetFilePointerEx(fh, li, NULL, FILE_BEGIN);
            DWORD got = 0; ReadFile(fh, p, (DWORD)alen, &got, NULL);
        }
    }

    else 
        memset(p, 0, (size_t)alen);
    
    if (wprot) { 
        DWORD old; 
        VirtualProtect(p, (SIZE_T)alen, wprot, &old); 
    }

    return (int64_t)(uint64_t)p;
}

static int64_t sys_munmap(uint64_t addr, uint64_t len)
{
    uint64_t alen = (len + (uint64_t)0xFFF) & ~(uint64_t)0xFFF;

    VirtualFree((LPVOID)addr, (SIZE_T)alen, MEM_DECOMMIT);
    return 0;
}

static int64_t sys_mprotect(uint64_t addr, uint64_t len, uint32_t prot)
{
    DWORD old;
    
    return VirtualProtect((LPVOID)addr, (SIZE_T)len,
        linux_prot_to_win(prot), &old) ? 0 : -(int64_t)LINUX_EINVAL;
}

static int64_t sys_brk(uint64_t req)
{
    static uint64_t brk_cur = 0, brk_end = 0;
    
    if (!brk_cur) {
        LPVOID r = VirtualAlloc(NULL, (SIZE_T)256 * 1024 * 1024, MEM_RESERVE, PAGE_NOACCESS);
        
        if (!r) 
            return -(int64_t)LINUX_ENOMEM;

        brk_cur = brk_end = (uint64_t)r;
    }
    
    if (req == 0) 
        return (int64_t)brk_cur;
    
    if (req > brk_cur) {
        uint64_t need = (req - brk_end + (uint64_t)0xFFF) & ~(uint64_t)0xFFF;

        if (!VirtualAlloc((LPVOID)brk_end, (SIZE_T)need, MEM_COMMIT, PAGE_READWRITE))
            return (int64_t)brk_cur;
        brk_end += need;
    }

    brk_cur = req;
    return (int64_t)brk_cur;
}

static int64_t sys_arch_prctl(uint64_t code, uint64_t addr)
{
    switch (code) {
    case ARCH_SET_FS:
        g_fs_base = addr;
        __try { _writefsbase_u64(addr); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            
        }

        return 0;
    
    case ARCH_GET_FS:
        *(uint64_t*)addr = g_fs_base;
        return 0;
    
    case ARCH_SET_GS: return 0;
    
    case ARCH_GET_GS: *(uint64_t*)addr = 0; return 0;
    
    default: 
        return -(int64_t)LINUX_EINVAL;
    }
}

static int64_t sys_uname(uint8_t* buf)
{
    memset(buf, 0, 6 * 65);

    strcpy((char*)buf + 0 * 65, "Linux");
    strcpy((char*)buf + 1 * 65, "mine");
    strcpy((char*)buf + 2 * 65, "5.15.0-mine");
    strcpy((char*)buf + 3 * 65, "#1 Mine");
    strcpy((char*)buf + 4 * 65, "x86_64");
    
    return 0;
}

static int64_t sys_clock_gettime(int clk, Linux_timespec* ts)
{
    LARGE_INTEGER freq = { 0 }, cnt = { 0 };

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    
    uint64_t ns = (uint64_t)((double)cnt.QuadPart / (double)freq.QuadPart * 1e9);
    ts->tv_sec = (int64_t)(ns / 1000000000ULL);
    ts->tv_nsec = (int64_t)(ns % 1000000000ULL);
    
    return 0;
}

static int64_t sys_clock_getres(int clk, Linux_timespec* ts)
{
    if (!ts)
        return 0;
    LARGE_INTEGER freq = { 0 };

    QueryPerformanceFrequency(&freq);
    ts->tv_sec = 0;
    ts->tv_nsec = (int64_t)(1000000000LL / freq.QuadPart);
    
    return 0;
}

static int64_t sys_gettimeofday(Linux_timeval* tv, void* tz)
{
    if (!tv)
        return 0;
    
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ul;

    ul.LowPart = ft.dwLowDateTime; ul.HighPart = ft.dwHighDateTime;
    uint64_t usec = (ul.QuadPart - 116444736000000000ULL) / 10ULL;
    
    tv->tv_sec = (int64_t)(usec / 1000000ULL);
    tv->tv_usec = (int64_t)(usec % 1000000ULL);
    
    return 0;
}

static int64_t sys_getcwd(char* buf, uint64_t size)
{
    char tmp[4096];
    if (!GetCurrentDirectoryA(sizeof(tmp), tmp)) return winerr();

    for (char* p = tmp; *p; p++) if (*p == '\\') *p = '/';
    size_t len = strlen(tmp);

    if (len + 1 > size) 
        return -(int64_t)LINUX_EINVAL;
    memcpy(buf, tmp, len + 1);
    
    return (int64_t)(uint64_t)buf;
}

static int64_t sys_getrandom(void* buf, uint64_t count, uint32_t flags)
{
    HCRYPTPROV p = 0;
    if (!CryptAcquireContextA(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return -(int64_t)LINUX_EIO;

    CryptGenRandom(p, (DWORD)count, (BYTE*)buf);
    CryptReleaseContext(p, 0);

    return (int64_t)count;
}

static int64_t sys_getrlimit(uint32_t resource, Linux_rlimit* rl)
{
    if (!rl) 
        return -(int64_t)LINUX_EFAULT;

    switch (resource) {
    case 3:  
        rl->rlim_cur = 8 * 1024 * 1024; rl->rlim_max = 8 * 1024 * 1024; break;

    case 7:  
        rl->rlim_cur = 1024; rl->rlim_max = 4096; break;

    default:
        rl->rlim_cur = (uint64_t)-1; rl->rlim_max = (uint64_t)-1; break;
    }

    return 0;
}

static int64_t sys_nanosleep(const Linux_timespec* req, Linux_timespec* rem)
{
    if (!req) return -(int64_t)LINUX_EFAULT;
    DWORD ms = (DWORD)(req->tv_sec * 1000 + req->tv_nsec / 1000000);
    Sleep(ms);

    return 0;
}

static int64_t sys_fcntl(int fd, int cmd, uint64_t arg)
{
    switch (cmd) {
    case 1:  return 0;
    case 2:  return 0;
    case 3:  return 0;
    case 4:  return 0;
    default: return -(int64_t)LINUX_EINVAL;
    }
}

typedef struct {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[1];
} Linux_dirent64;

#define DT_UNKNOWN  0
#define DT_DIR      4
#define DT_REG      8
#define DT_LNK      10

static int64_t sys_getdents64(int fd, void* dirp, uint32_t count)
{
    return 0;
}

uint64_t MineSyscall(uint64_t nr,
    uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6)
{
    MineTraceEnter(nr, a1, a2, a3, a4, a5, a6);

    uint64_t ret;

    switch (nr) {
        /* ── I/O ── */
    case SYS_read:    ret = (uint64_t)sys_read((int)a1, (void*)a2, a3); break;
    case SYS_write:   ret = (uint64_t)sys_write((int)a1, (void*)a2, a3); break;
    case SYS_writev:  ret = (uint64_t)sys_writev((int)a1, (Linux_iovec*)a2, (int)a3); break;
    case SYS_open:    ret = (uint64_t)sys_open((char*)a1, (int)a2, (int)a3); break;
    case SYS_openat:  ret = (uint64_t)sys_openat((int)a1, (char*)a2, (int)a3, (int)a4); break;
    case SYS_close:   ret = (uint64_t)sys_close((int)a1); break;
    case SYS_lseek:   ret = (uint64_t)sys_lseek((int)a1, (int64_t)a2, (int)a3); break;
    case SYS_fcntl:   ret = (uint64_t)sys_fcntl((int)a1, (int)a2, a3); break;
    case SYS_dup: { int r = _dup((int)a1); ret = r < 0 ? (uint64_t)-(int64_t)LINUX_EBADF : (uint64_t)r; } break;
    case SYS_dup2: { int r = _dup2((int)a1, (int)a2); ret = r < 0 ? (uint64_t)-(int64_t)LINUX_EBADF : a2; } break;
    case SYS_getdents64: ret = (uint64_t)sys_getdents64((int)a1, (void*)a2, (uint32_t)a3); break;

        /* ── stat ── */
    case SYS_fstat:   ret = (uint64_t)sys_fstat((int)a1, (Linux_stat*)a2); break;
    case SYS_stat:
    case SYS_lstat:   ret = (uint64_t)sys_stat((char*)a1, (Linux_stat*)a2); break;

        /* ── memory ── */
    case SYS_mmap:    ret = (uint64_t)sys_mmap(a1, a2, (uint32_t)a3, (uint32_t)a4, (int)a5, a6); break;
    case SYS_munmap:  ret = (uint64_t)sys_munmap(a1, a2); break;
    case SYS_mprotect:ret = (uint64_t)sys_mprotect(a1, a2, (uint32_t)a3); break;
    case SYS_brk:     ret = (uint64_t)sys_brk(a1); break;

        /* ── time ── */
    case SYS_clock_gettime: ret = (uint64_t)sys_clock_gettime((int)a1, (Linux_timespec*)a2); break;
    case SYS_clock_getres:  ret = (uint64_t)sys_clock_getres((int)a1, (Linux_timespec*)a2); break;
    case SYS_gettimeofday:  ret = (uint64_t)sys_gettimeofday((Linux_timeval*)a1, (void*)a2); break;
    case SYS_nanosleep:     ret = (uint64_t)sys_nanosleep((Linux_timespec*)a1, (Linux_timespec*)a2); break;

        /* ── process identity ── */
    case SYS_getpid:  ret = (uint64_t)GetCurrentProcessId(); break;
    case SYS_getppid: ret = (uint64_t)GetCurrentProcessId(); break;
    case SYS_getpgrp: ret = (uint64_t)GetCurrentProcessId(); break;
    case SYS_gettid:  ret = (uint64_t)GetCurrentThreadId(); break;
    case SYS_getuid:
    case SYS_getgid:
    case SYS_geteuid:
    case SYS_getegid: ret = 1000; break;

        /* ── system info ── */
    case SYS_uname:   ret = (uint64_t)sys_uname((uint8_t*)a1); break;
    case SYS_getcwd:  ret = (uint64_t)sys_getcwd((char*)a1, a2); break;
    case SYS_getrlimit:
    case SYS_prlimit64: ret = (uint64_t)sys_getrlimit((uint32_t)a2, (Linux_rlimit*)a3); break;
    case SYS_getrandom: ret = (uint64_t)sys_getrandom((void*)a1, a2, (uint32_t)a3); break;

        /* ── arch ── */
    case SYS_arch_prctl: ret = (uint64_t)sys_arch_prctl(a1, a2); break;

        /* ── thread / sync ── */
    case SYS_set_tid_address:
        g_tid_addr = a1;
        ret = (uint64_t)GetCurrentThreadId();
        break;
    case SYS_set_robust_list:
        g_robust_list = a1;
        ret = 0;
        break;
    case SYS_get_robust_list:
        ret = 0;
        break;
    case SYS_futex:          ret = 0; break;
    case SYS_sigaltstack:    ret = 0; break;
    case SYS_sched_yield:    SwitchToThread(); ret = 0; break;
    case SYS_prctl:          ret = 0; break;

        /* ── signals (stub — succeed silently) ── */
    case SYS_rt_sigaction:
    case SYS_rt_sigprocmask:
    case SYS_rt_sigreturn:   ret = 0; break;

    case SYS_access:         ret = 0; break;
    case SYS_ioctl:          ret = (uint64_t)-(int64_t)25; break; /* ENOTTY */

    case SYS_exit:

    case SYS_exit_group:
        MineTraceExit(nr, a1);
        ExitProcess((UINT)a1);
        return 0;

    default:
        fprintf(stderr, "\n[MinE] !! Unhandled syscall %llu  (returning ENOSYS)\n",
            (unsigned long long)nr);
        ret = (uint64_t)(-(int64_t)LINUX_ENOSYS);
        break;
    }

    MineTraceExit(nr, ret);

    return ret;
}