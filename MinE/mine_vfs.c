#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include "mine_vfs.h"

#include <Psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <wincrypt.h>
#include <ctype.h>
#include "mine_dynamic.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")

/* ─── State ──────────────────────────────────────────────────────────────── */

static char g_elf_path[MAX_PATH];
static char g_elf_path_linux[MAX_PATH];

void MineVFSInit(const char* elf_path)
{
    /* Store the Windows path */
    GetFullPathNameA(elf_path, sizeof(g_elf_path), g_elf_path, NULL);

    /* Build a Linux-style path: D:\foo\bar -> /d/foo/bar */
    char tmp[MAX_PATH];
    strncpy(tmp, g_elf_path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    for (char* p = tmp; *p; p++)
        if (*p == '\\') *p = '/';

    if (tmp[0] && tmp[1] == ':' && tmp[2] == '/') {
        g_elf_path_linux[0] = '/';
        g_elf_path_linux[1] = (char)tolower((unsigned char)tmp[0]);
        strcpy(g_elf_path_linux + 2, tmp + 2);
    }
    else {
        strcpy(g_elf_path_linux, tmp);
    }
}

/* ─── Path translation ───────────────────────────────────────────────────── */

static char g_translate_buf[4096];

static const char* translate_linux_to_win(const char* path)
{
    /* /tmp -> %TEMP% */
    if (strncmp(path, "/tmp", 4) == 0 && (path[4] == '/' || path[4] == '\0')) {
        char temp[MAX_PATH];
        if (!GetTempPathA(sizeof(temp), temp))
            strcpy(temp, "C:\\Temp");
        /* Remove trailing backslash */
        size_t len = strlen(temp);
        if (len > 0 && temp[len - 1] == '\\') temp[len - 1] = '\0';
        snprintf(g_translate_buf, sizeof(g_translate_buf), "%s%s", temp, path + 4);
        for (char* p = g_translate_buf; *p; p++)
            if (*p == '/') *p = '\\';
        return g_translate_buf;
    }

    /* /home/<user> -> %USERPROFILE% */
    if (strncmp(path, "/home/", 6) == 0) {
        const char* rest = path + 6;
        /* Skip username part */
        const char* slash = strchr(rest, '/');
        const char* userprofile = getenv("USERPROFILE");
        if (userprofile) {
            if (slash)
                snprintf(g_translate_buf, sizeof(g_translate_buf), "%s%s", userprofile, slash);
            else
                snprintf(g_translate_buf, sizeof(g_translate_buf), "%s", userprofile);
            for (char* p = g_translate_buf; *p; p++)
                if (*p == '/') *p = '\\';
            return g_translate_buf;
        }
    }

    /* /root -> %USERPROFILE% (when running as admin) */
    if (strncmp(path, "/root", 5) == 0 && (path[5] == '/' || path[5] == '\0')) {
        const char* userprofile = getenv("USERPROFILE");
        if (userprofile) {
            snprintf(g_translate_buf, sizeof(g_translate_buf), "%s%s", userprofile, path + 5);
            for (char* p = g_translate_buf; *p; p++)
                if (*p == '/') *p = '\\';
            return g_translate_buf;
        }
    }

    /* /etc -> translate known real files */
    if (strncmp(path, "/etc/", 5) == 0) {
        if (strcmp(path, "/etc/hosts") == 0) {
            snprintf(g_translate_buf, sizeof(g_translate_buf),
                "C:\\Windows\\System32\\drivers\\etc\\hosts");
            return g_translate_buf;
        }
        if (strcmp(path, "/etc/resolv.conf") == 0) {
            snprintf(g_translate_buf, sizeof(g_translate_buf),
                "C:\\Windows\\System32\\drivers\\etc\\resolv.conf");
            return g_translate_buf;
        }
    }

    /* /var/tmp -> %TEMP% */
    if (strncmp(path, "/var/tmp", 8) == 0 && (path[8] == '/' || path[8] == '\0')) {
        char temp[MAX_PATH];
        if (!GetTempPathA(sizeof(temp), temp))
            strcpy(temp, "C:\\Temp");
        size_t len = strlen(temp);
        if (len > 0 && temp[len - 1] == '\\') temp[len - 1] = '\0';
        snprintf(g_translate_buf, sizeof(g_translate_buf), "%s%s", temp, path + 8);
        for (char* p = g_translate_buf; *p; p++)
            if (*p == '/') *p = '\\';
        return g_translate_buf;
    }

    /* /usr/share, /usr/lib, etc. -> ignore (return original, will fail gracefully) */

    /* Generic: convert /x/y/z -> x:\y\z if x is a single letter (drive) */
    if (path[0] == '/' && path[1] && path[2] == '/') {
        char drive = path[1];
        if ((drive >= 'a' && drive <= 'z') || (drive >= 'A' && drive <= 'Z')) {
            snprintf(g_translate_buf, sizeof(g_translate_buf), "%c:%s",
                (char)toupper((unsigned char)drive), path + 2);
            for (char* p = g_translate_buf; *p; p++)
                if (*p == '/') *p = '\\';
            return g_translate_buf;
        }
    }

    /* No translation needed — convert slashes only */
    strncpy(g_translate_buf, path, sizeof(g_translate_buf) - 1);
    g_translate_buf[sizeof(g_translate_buf) - 1] = '\0';
    for (char* p = g_translate_buf; *p; p++)
        if (*p == '/') *p = '\\';
    return g_translate_buf;
}

static int classify_proc_path(const char* path)
{
    /* /proc/self/exe */
    if (strcmp(path, "/proc/self/exe") == 0) return VFS_PROC_SELF_EXE;

    /* /proc/<pid>/exe where pid matches ours */
    {
        DWORD pid = GetCurrentProcessId();
        char pidbuf[64];
        snprintf(pidbuf, sizeof(pidbuf), "/proc/%lu/exe", (unsigned long)pid);
        if (strcmp(path, pidbuf) == 0) return VFS_PROC_SELF_EXE;
    }

    if (strcmp(path, "/proc/self/status") == 0) return VFS_PROC_SELF_STATUS;
    if (strcmp(path, "/proc/self/maps") == 0)   return VFS_PROC_SELF_MAPS;
    if (strcmp(path, "/proc/self/stat") == 0)    return VFS_PROC_SELF_STAT;
    if (strcmp(path, "/proc/self/cmdline") == 0) return VFS_PROC_SELF_CMDLINE;
    if (strncmp(path, "/proc/self/fd/", 14) == 0) return VFS_PROC_SELF_FD;
    if (strcmp(path, "/proc/meminfo") == 0)      return VFS_PROC_MEMINFO;
    if (strcmp(path, "/proc/cpuinfo") == 0)      return VFS_PROC_CPUINFO;
    if (strcmp(path, "/proc/stat") == 0)         return VFS_PROC_STAT;
    if (strcmp(path, "/proc/uptime") == 0)       return VFS_PROC_UPTIME;
    if (strcmp(path, "/proc/loadavg") == 0)      return VFS_PROC_LOADAVG;
    if (strcmp(path, "/proc/version") == 0)      return VFS_PROC_VERSION;
    if (strncmp(path, "/proc/sys/", 10) == 0)   return VFS_PROC_SYS;
    if (strcmp(path, "/proc/mounts") == 0)      return VFS_PROC_MOUNTS;
    if (strcmp(path, "/proc/self/mounts") == 0) return VFS_PROC_MOUNTS;
    if (strcmp(path, "/proc/self/mountinfo") == 0) return VFS_PROC_MOUNTS;

    /* Any other /proc path */
    if (strncmp(path, "/proc/", 6) == 0) return VFS_UNKNOWN;

    return VFS_REAL;
}

static int classify_dev_path(const char* path)
{
    if (strcmp(path, "/dev/null") == 0)    return VFS_DEV_NULL;
    if (strcmp(path, "/dev/zero") == 0)    return VFS_DEV_ZERO;
    if (strcmp(path, "/dev/urandom") == 0) return VFS_DEV_URANDOM;
    if (strcmp(path, "/dev/random") == 0)  return VFS_DEV_URANDOM;
    if (strcmp(path, "/dev/stdin") == 0)   return VFS_DEV_STDIN;
    if (strcmp(path, "/dev/stdout") == 0)  return VFS_DEV_STDOUT;
    if (strcmp(path, "/dev/stderr") == 0)  return VFS_DEV_STDERR;
    if (strcmp(path, "/dev/fd/0") == 0)    return VFS_DEV_STDIN;
    if (strcmp(path, "/dev/fd/1") == 0)    return VFS_DEV_STDOUT;
    if (strcmp(path, "/dev/fd/2") == 0)    return VFS_DEV_STDERR;
    if (strcmp(path, "/dev/tty") == 0)     return VFS_DEV_TTY;
    if (strcmp(path, "/dev/ptmx") == 0)    return VFS_DEV_PTMX;

    /* Any other /dev path */
    if (strncmp(path, "/dev/", 5) == 0) return VFS_UNKNOWN;

    return VFS_REAL;
}

const char* MineVFSTranslate(const char* linux_path, int* virt_type)
{
    *virt_type = VFS_REAL;

    if (!linux_path || !*linux_path) return linux_path;

    /* "/" -> current drive root */
    if (strcmp(linux_path, "/") == 0) {
        char cwd[MAX_PATH];
        GetCurrentDirectoryA(sizeof(cwd), cwd);
        snprintf(g_translate_buf, sizeof(g_translate_buf), "%c:\\", cwd[0]);
        return g_translate_buf;
    }

    /* Check /proc paths */
    if (strncmp(linux_path, "/proc", 5) == 0) {
        *virt_type = classify_proc_path(linux_path);
        return NULL;
    }

    /* Check /dev paths */
    if (strncmp(linux_path, "/dev", 4) == 0) {
        *virt_type = classify_dev_path(linux_path);
        if (*virt_type != VFS_REAL) return NULL;
    }

    /* Check /etc virtual files */
    if (strncmp(linux_path, "/etc/", 5) == 0) {
        if (strcmp(linux_path, "/etc/passwd") == 0) { *virt_type = VFS_ETC_PASSWD; return NULL; }
        if (strcmp(linux_path, "/etc/group") == 0)  { *virt_type = VFS_ETC_GROUP;  return NULL; }
        if (strcmp(linux_path, "/etc/nsswitch.conf") == 0) { *virt_type = VFS_ETC_NSSWITCH; return NULL; }
    }

    /* Real file — translate path */
    return translate_linux_to_win(linux_path);
}

/* ─── Virtual file descriptors ───────────────────────────────────────────── */

#define MAX_VFDS 32

typedef struct {
    bool   active;
    int    virt_type;
    char*  content;
    size_t content_len;
    size_t read_pos;
} VFD;

static VFD g_vfds[MAX_VFDS];

static int alloc_vfd(void)
{
    for (int i = 0; i < MAX_VFDS; i++) {
        if (!g_vfds[i].active) {
            memset(&g_vfds[i], 0, sizeof(VFD));
            g_vfds[i].active = true;
            return MINE_VFD_BASE + i;
        }
    }
    return -1;
}

static VFD* get_vfd(int fd)
{
    if (fd < MINE_VFD_BASE || fd >= MINE_VFD_BASE + MAX_VFDS) return NULL;
    VFD* v = &g_vfds[fd - MINE_VFD_BASE];
    return v->active ? v : NULL;
}

bool MineVFSIsVFD(int fd)
{
    return get_vfd(fd) != NULL;
}

/* ─── /proc content generators ───────────────────────────────────────────── */

static char* gen_proc_self_status(void)
{
    DWORD pid = GetCurrentProcessId();
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms); GlobalMemoryStatusEx(&ms);

    PROCESS_MEMORY_COUNTERS_EX pmc;
    memset(&pmc, 0, sizeof(pmc)); pmc.cb = sizeof(pmc);
    GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));

    char* buf = (char*)malloc(4096);
    if (!buf) return NULL;

    snprintf(buf, 4096,
        "Name:\tMinE\n"
        "Umask:\t0022\n"
        "State:\tR (running)\n"
        "Tgid:\t%lu\n"
        "Pid:\t%lu\n"
        "PPid:\t1\n"
        "Uid:\t1000\t1000\t1000\t1000\n"
        "Gid:\t1000\t1000\t1000\t1000\n"
        "FDSize:\t256\n"
        "VmPeak:\t%llu kB\n"
        "VmSize:\t%llu kB\n"
        "VmRSS:\t%llu kB\n"
        "VmData:\t%llu kB\n"
        "Threads:\t1\n",
        (unsigned long)pid, (unsigned long)pid,
        (unsigned long long)(pmc.PeakWorkingSetSize / 1024),
        (unsigned long long)(pmc.WorkingSetSize / 1024),
        (unsigned long long)(pmc.WorkingSetSize / 1024),
        (unsigned long long)(pmc.PrivateUsage / 1024));
    return buf;
}

static char* gen_proc_self_maps(void)
{
    char* buf = (char*)malloc(8192);
    if (!buf) return NULL;
    size_t pos = 0;

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr = NULL;

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Type != MEM_PRIVATE) {
            /* Skip — only show committed private mappings */
        }
        if (mbi.State == MEM_COMMIT) {
            char perms[5] = "----";
            if (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
                perms[0] = 'r';
            if (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))
                perms[1] = 'w';
            if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
                perms[2] = 'x';
            perms[3] = 'p';

            uint64_t start = (uint64_t)(uintptr_t)mbi.BaseAddress;
            uint64_t end = start + mbi.RegionSize;

            int n = snprintf(buf + pos, 8192 - pos,
                "%012llx-%012llx %s %08x 00:00 0\n",
                (unsigned long long)start, (unsigned long long)end,
                perms, 0);
            if (n > 0 && pos + (size_t)n < 8192) pos += (size_t)n;
            else break;
        }
        addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if ((uint64_t)(uintptr_t)addr < (uint64_t)(uintptr_t)mbi.BaseAddress)
            break;
    }
    buf[pos] = '\0';
    return buf;
}

static char* gen_proc_self_stat(void)
{
    DWORD pid = GetCurrentProcessId();
    char* buf = (char*)malloc(512);
    if (!buf) return NULL;
    snprintf(buf, 512, "%lu (MinE) R 1 %lu %lu 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        (unsigned long)pid, (unsigned long)pid, (unsigned long)pid);
    return buf;
}

static char* gen_proc_self_cmdline(void)
{
    int argc = MineGetGuestArgc();
    char** argv = MineGetGuestArgv();
    if (argc > 0 && argv) {
        size_t total = 0;
        for (int i = 0; i < argc; i++)
            total += strlen(argv[i]) + 1;
        char* buf = (char*)malloc(total + 1);
        if (!buf) return NULL;
        size_t pos = 0;
        for (int i = 0; i < argc; i++) {
            size_t slen = strlen(argv[i]);
            memcpy(buf + pos, argv[i], slen);
            pos += slen;
            buf[pos++] = '\0';
        }
        return buf;
    }
    size_t len = strlen(g_elf_path_linux) + 1;
    char* buf = (char*)malloc(len + 1);
    if (!buf) return NULL;
    memcpy(buf, g_elf_path_linux, len);
    buf[len] = '\0';
    return buf;
}

static char* gen_proc_meminfo(void)
{
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms); GlobalMemoryStatusEx(&ms);
    char* buf = (char*)malloc(2048);
    if (!buf) return NULL;

    uint64_t total_kb = ms.ullTotalPhys / 1024;
    uint64_t free_kb = ms.ullAvailPhys / 1024;
    uint64_t buffers = free_kb / 10;
    uint64_t cached = free_kb / 5;

    snprintf(buf, 2048,
        "MemTotal:       %llu kB\n"
        "MemFree:        %llu kB\n"
        "MemAvailable:   %llu kB\n"
        "Buffers:        %llu kB\n"
        "Cached:         %llu kB\n"
        "SwapTotal:      %llu kB\n"
        "SwapFree:       %llu kB\n",
        (unsigned long long)total_kb,
        (unsigned long long)free_kb,
        (unsigned long long)(free_kb + cached),
        (unsigned long long)buffers,
        (unsigned long long)cached,
        (unsigned long long)(ms.ullTotalPageFile / 1024),
        (unsigned long long)(ms.ullAvailPageFile / 1024));
    return buf;
}

static char* gen_proc_cpuinfo(void)
{
    SYSTEM_INFO si; GetSystemInfo(&si);
    char* buf = (char*)malloc(4096);
    if (!buf) return NULL;

    size_t pos = 0;
    for (DWORD i = 0; i < si.dwNumberOfProcessors && pos < 3800; i++) {
        int n = snprintf(buf + pos, 4096 - pos,
            "processor\t: %lu\n"
            "vendor_id\t: GenuineIntel\n"
            "model name\t: MinE Virtual CPU\n"
            "cpu MHz\t\t: 3000.000\n"
            "cache size\t: 8192 KB\n"
            "physical id\t: 0\n"
            "cpu cores\t: %lu\n"
            "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx rdtscp lm\n"
            "bogomips\t: 6000.00\n\n",
            (unsigned long)i, (unsigned long)si.dwNumberOfProcessors);
        if (n > 0) pos += (size_t)n;
    }
    buf[pos] = '\0';
    return buf;
}

static char* gen_proc_stat(void)
{
    SYSTEM_INFO si; GetSystemInfo(&si);
    char* buf = (char*)malloc(2048);
    if (!buf) return NULL;

    size_t pos = 0;
    int n = snprintf(buf, 2048, "cpu  0 0 0 0 0 0 0 0 0 0\n");
    if (n > 0) pos = (size_t)n;

    for (DWORD i = 0; i < si.dwNumberOfProcessors && pos < 1900; i++) {
        n = snprintf(buf + pos, 2048 - pos, "cpu%lu 0 0 0 0 0 0 0 0 0 0\n", (unsigned long)i);
        if (n > 0) pos += (size_t)n;
    }

    n = snprintf(buf + pos, 2048 - pos,
        "intr 0\n"
        "ctxt 0\n"
        "btime %llu\n"
        "processes 1\n"
        "procs_running 1\n"
        "procs_blocked 0\n",
        (unsigned long long)(GetTickCount64() / 1000));
    if (n > 0) pos += (size_t)n;
    buf[pos] = '\0';
    return buf;
}

static char* gen_proc_uptime(void)
{
    char* buf = (char*)malloc(64);
    if (!buf) return NULL;
    double up = (double)GetTickCount64() / 1000.0;
    snprintf(buf, 64, "%.2f 0.00\n", up);
    return buf;
}

static char* gen_proc_loadavg(void)
{
    char* buf = (char*)malloc(64);
    if (!buf) return NULL;
    snprintf(buf, 64, "0.00 0.00 0.00 1/1 %lu\n", (unsigned long)GetCurrentProcessId());
    return buf;
}

static char* gen_proc_version(void)
{
    char* buf = (char*)malloc(256);
    if (!buf) return NULL;
    snprintf(buf, 256, "Linux version 5.15.0-mine (mine@windows) (gcc 12.0.0) #1 SMP MinE\n");
    return buf;
}

static char* gen_proc_sys(const char* path)
{
    /* Common /proc/sys values programs check */
    if (strstr(path, "kernel/osrelease"))  return _strdup("5.15.0-mine\n");
    if (strstr(path, "kernel/hostname")) {
        char name[256];
        if (gethostname(name, sizeof(name)) == 0) {
            char* buf = (char*)malloc(strlen(name) + 2);
            sprintf(buf, "%s\n", name);
            return buf;
        }
        return _strdup("mine\n");
    }
    if (strstr(path, "kernel/pid_max"))    return _strdup("32768\n");
    if (strstr(path, "kernel/threads-max")) return _strdup("32768\n");
    if (strstr(path, "vm/overcommit_memory")) return _strdup("0\n");
    if (strstr(path, "net/core/somaxconn"))  return _strdup("4096\n");
    if (strstr(path, "net/ipv4/ip_forward")) return _strdup("0\n");

    return _strdup("0\n");
}

static char* gen_proc_mounts(void)
{
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(sizeof(cwd), cwd);
    char drive_root[4] = "C:\\";
    if (cwd[0] && cwd[1] == ':') drive_root[0] = cwd[0];

    ULARGE_INTEGER total = {0};
    GetDiskFreeSpaceExA(drive_root, NULL, &total, NULL);

    char* buf = (char*)malloc(1024);
    if (!buf) return _strdup("/dev/sda1 / ext4 rw,relatime 0 0\n");
    int n = 0;
    n += sprintf(buf + n, "/dev/sda1 / ext4 rw,relatime 0 0\n");
    n += sprintf(buf + n, "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n");
    n += sprintf(buf + n, "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n");
    n += sprintf(buf + n, "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n");
    n += sprintf(buf + n, "devtmpfs /dev devtmpfs rw,nosuid 0 0\n");
    (void)n;
    return buf;
}

static char* gen_etc_passwd(void)
{
    char name[256];
    DWORD sz = sizeof(name);
    if (!GetUserNameA(name, &sz)) strcpy(name, "user");
    char* buf = (char*)malloc(512);
    if (!buf) return _strdup("root:x:0:0:root:/root:/bin/bash\n");
    sprintf(buf, "root:x:0:0:root:/root:/bin/bash\n"
                 "%s:x:1000:1000:%s:/home/%s:/bin/bash\n"
                 "nobody:x:65534:65534:Nobody:/:/usr/bin/nologin\n",
                 name, name, name);
    return buf;
}

static char* gen_etc_group(void)
{
    char name[256];
    DWORD sz = sizeof(name);
    if (!GetUserNameA(name, &sz)) strcpy(name, "user");
    char* buf = (char*)malloc(512);
    if (!buf) return _strdup("root:x:0:\n");
    sprintf(buf, "root:x:0:\n%s:x:1000:\nnogroup:x:65534:\n", name);
    return buf;
}

static char* gen_etc_nsswitch(void)
{
    return _strdup("passwd: files\ngroup: files\nhosts: files dns\n");
}

/* ─── Open virtual files ─────────────────────────────────────────────────── */

int MineVFSOpen(int virt_type, int flags)
{
    (void)flags;

    /* /dev/null -> Windows NUL device */
    if (virt_type == VFS_DEV_NULL) {
        HANDLE h = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) return -1;
        int fd = _open_osfhandle((intptr_t)h, 0);
        return fd >= 0 ? fd : -1;
    }

    /* /dev/stdin, stdout, stderr -> return the fd directly */
    if (virt_type == VFS_DEV_STDIN)  return 0;
    if (virt_type == VFS_DEV_STDOUT) return 1;
    if (virt_type == VFS_DEV_STDERR) return 2;

    /* /dev/tty -> console */
    if (virt_type == VFS_DEV_TTY) {
        HANDLE h = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) return -1;
        int fd = _open_osfhandle((intptr_t)h, 0);
        return fd >= 0 ? fd : -1;
    }

    /* Virtual readable files (/dev/zero, /dev/urandom, /proc/*) */
    int vfd = alloc_vfd();
    if (vfd < 0) return -1;

    VFD* v = get_vfd(vfd);
    v->virt_type = virt_type;
    v->read_pos = 0;
    v->content = NULL;
    v->content_len = 0;

    /* Generate content for proc files */
    char* content = NULL;
    switch (virt_type) {
    case VFS_DEV_ZERO:
    case VFS_DEV_URANDOM:
        /* These are infinite streams — handled in read */
        break;
    case VFS_PROC_SELF_STATUS:  content = gen_proc_self_status(); break;
    case VFS_PROC_SELF_MAPS:    content = gen_proc_self_maps();   break;
    case VFS_PROC_SELF_STAT:    content = gen_proc_self_stat();   break;
    case VFS_PROC_SELF_CMDLINE: content = gen_proc_self_cmdline(); break;
    case VFS_PROC_MEMINFO:      content = gen_proc_meminfo();     break;
    case VFS_PROC_CPUINFO:      content = gen_proc_cpuinfo();     break;
    case VFS_PROC_STAT:         content = gen_proc_stat();        break;
    case VFS_PROC_UPTIME:       content = gen_proc_uptime();      break;
    case VFS_PROC_LOADAVG:      content = gen_proc_loadavg();     break;
    case VFS_PROC_VERSION:      content = gen_proc_version();     break;
    case VFS_PROC_SYS:          content = gen_proc_sys("");        break;
    case VFS_PROC_MOUNTS:       content = gen_proc_mounts();      break;
    case VFS_ETC_PASSWD:        content = gen_etc_passwd();       break;
    case VFS_ETC_GROUP:         content = gen_etc_group();        break;
    case VFS_ETC_NSSWITCH:      content = gen_etc_nsswitch();     break;
    default:
        /* Unknown proc file — return empty */
        content = _strdup("");
        break;
    }

    if (content) {
        v->content = content;
        v->content_len = strlen(content);
    }

    return vfd;
}

int64_t MineVFSRead(int vfd, void* buf, uint64_t count)
{
    VFD* v = get_vfd(vfd);
    if (!v) return -9; /* EBADF */

    /* /dev/zero: return zeros */
    if (v->virt_type == VFS_DEV_ZERO) {
        memset(buf, 0, (size_t)count);
        return (int64_t)count;
    }

    /* /dev/urandom: return random bytes */
    if (v->virt_type == VFS_DEV_URANDOM) {
        HCRYPTPROV cp = 0;
        if (CryptAcquireContextA(&cp, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(cp, (DWORD)count, (BYTE*)buf);
            CryptReleaseContext(cp, 0);
        }
        else {
            /* Fallback: fill with pseudo-random */
            uint8_t* p = (uint8_t*)buf;
            for (uint64_t i = 0; i < count; i++)
                p[i] = (uint8_t)(rand() & 0xFF);
        }
        return (int64_t)count;
    }

    /* Content-based virtual files */
    if (!v->content) return 0;

    if (v->read_pos >= v->content_len) return 0;

    size_t avail = v->content_len - v->read_pos;
    size_t to_read = (size_t)count < avail ? (size_t)count : avail;
    memcpy(buf, v->content + v->read_pos, to_read);
    v->read_pos += to_read;
    return (int64_t)to_read;
}

int64_t MineVFSWrite(int vfd, const void* buf, uint64_t count)
{
    VFD* v = get_vfd(vfd);
    if (!v) return -9;

    /* /dev/null: discard */
    if (v->virt_type == VFS_DEV_NULL) return (int64_t)count;

    /* /dev/zero, /dev/urandom: discard writes */
    if (v->virt_type == VFS_DEV_ZERO || v->virt_type == VFS_DEV_URANDOM)
        return (int64_t)count;

    (void)buf;
    return (int64_t)count;
}

int MineVFSClose(int vfd)
{
    VFD* v = get_vfd(vfd);
    if (!v) return -1;

    if (v->content) { free(v->content); v->content = NULL; }
    v->active = false;
    return 0;
}

int64_t MineVFSFstat(int vfd, void* stat_buf)
{
    VFD* v = get_vfd(vfd);
    if (!v) return -9;

    /* Fill a Linux_stat with reasonable values for a virtual file */
    memset(stat_buf, 0, 144); /* sizeof(Linux_stat) */

    /* st_mode at offset 24: S_IFCHR for devices, S_IFREG for proc files */
    uint32_t mode;
    if (v->virt_type <= VFS_DEV_STDERR || v->virt_type == VFS_DEV_TTY)
        mode = 0020666; /* char device */
    else
        mode = 0100444; /* regular file, read-only */
    memcpy((uint8_t*)stat_buf + 24, &mode, 4);

    /* st_nlink at offset 16 */
    uint64_t nlink = 1;
    memcpy((uint8_t*)stat_buf + 16, &nlink, 8);

    /* st_size at offset 48 */
    int64_t size = v->content ? (int64_t)v->content_len : 0;
    memcpy((uint8_t*)stat_buf + 48, &size, 8);

    /* st_blksize at offset 56 */
    int64_t blksz = 4096;
    memcpy((uint8_t*)stat_buf + 56, &blksz, 8);

    return 0;
}

int64_t MineVFSLseek(int vfd, int64_t offset, int whence)
{
    VFD* v = get_vfd(vfd);
    if (!v) return -9; /* EBADF */
    if (!v->content) return -29; /* ESPIPE — can't seek /dev/zero etc */

    int64_t newpos;
    switch (whence) {
    case 0: newpos = offset; break;                              /* SEEK_SET */
    case 1: newpos = (int64_t)v->read_pos + offset; break;      /* SEEK_CUR */
    case 2: newpos = (int64_t)v->content_len + offset; break;   /* SEEK_END */
    default: return -22; /* EINVAL */
    }
    if (newpos < 0) return -22;
    v->read_pos = (size_t)newpos;
    return newpos;
}

/* ─── readlink ───────────────────────────────────────────────────────────── */

int64_t MineVFSReadlink(int virt_type, char* buf, uint64_t bufsiz)
{
    if (virt_type == VFS_PROC_SELF_EXE) {
        size_t len = strlen(g_elf_path_linux);
        if (len > bufsiz) len = (size_t)bufsiz;
        memcpy(buf, g_elf_path_linux, len);
        return (int64_t)len;
    }

    return -2; /* ENOENT */
}

/* ─── Pipe ───────────────────────────────────────────────────────────────── */

int64_t MineVFSPipe(int pipefd[2], int flags)
{
    (void)flags;
    int fds[2];
    if (_pipe(fds, 65536, _O_BINARY) != 0)
        return -12; /* ENOMEM */
    pipefd[0] = fds[0];
    pipefd[1] = fds[1];
    return 0;
}
