#define _CRT_SECURE_NO_WARNINGS
#define WIN32_NO_STATUS
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <wincrypt.h>
#include "mine_dynamic.h"
#include "mine_thunk.h"
#include <io.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>
#include <intrin.h>

#pragma comment(lib, "ws2_32.lib")

/* POSIX types missing from MSVC */
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned int mode_t;

#ifndef _O_BINARY
#define _O_BINARY 0x8000
#endif
#ifndef _O_RDONLY
#define _O_RDONLY 0
#endif

/* Forward declarations — defined later in passwd/group section */
static char g_username[256];
static char g_homedir[512];

/* ─── ELF64 structs ───────────────────────────────────────────────────────── */
#pragma pack(push,1)
typedef struct {
    uint8_t e_ident[16]; uint16_t e_type, e_machine; uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff; uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;
typedef struct { uint32_t p_type, p_flags; uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align; } Elf64_Phdr;
typedef struct { int64_t d_tag; uint64_t d_val; } Elf64_Dyn;
typedef struct { uint64_t r_offset, r_info; int64_t r_addend; } Elf64_Rela;
typedef struct { uint32_t st_name; uint8_t st_info, st_other; uint16_t st_shndx; uint64_t st_value, st_size; } Elf64_Sym;
#pragma pack(pop)

#define PT_DYNAMIC        2
#define DT_NULL           0
#define DT_NEEDED         1
#define DT_PLTRELSZ       2
#define DT_STRTAB         5
#define DT_SYMTAB         6
#define DT_RELA           7
#define DT_RELASZ         8
#define DT_INIT           12
#define DT_FINI           13
#define DT_JMPREL         23
#define DT_INIT_ARRAY     25
#define DT_FINI_ARRAY     26
#define DT_INIT_ARRAYSZ   27
#define DT_FINI_ARRAYSZ   28

#define R_X86_64_NONE      0
#define R_X86_64_64        1
#define R_X86_64_COPY      5
#define R_X86_64_GLOB_DAT  6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_RELATIVE  8
#define R_X86_64_IRELATIVE 37

#define ELF64_R_SYM(i)   ((uint32_t)((i)>>32))
#define ELF64_R_TYPE(i)  ((uint32_t)((i)&0xFFFFFFFFULL))

/* ─── FS helpers ──────────────────────────────────────────────────────────── */
static uint64_t save_fs(void)
{
    uint64_t fs = 0;
    __try { fs = _readfsbase_u64(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return fs;
}

static void restore_fs(uint64_t fs)
{
    if (fs) { __try { _writefsbase_u64(fs); } __except (EXCEPTION_EXECUTE_HANDLER) {} }
}

/* ─── Fake FILE objects ───────────────────────────────────────────────────── */
typedef struct { int fd; } MineFile;
static MineFile g_stdin_obj = { 0 };
static MineFile g_stdout_obj = { 1 };
static MineFile g_stderr_obj = { 2 };

void* mine_stdin = &g_stdin_obj;
void* mine_stdout = &g_stdout_obj;
void* mine_stderr = &g_stderr_obj;

static int file_fd(void* f)
{
    if (!f) return -1;
    if (f == &g_stdin_obj)  return 0;
    if (f == &g_stdout_obj) return 1;
    if (f == &g_stderr_obj) return 2;
    return 1;
}

static HANDLE fd_handle(int fd)
{
    switch (fd) {
    case 0:  return GetStdHandle(STD_INPUT_HANDLE);
    case 1:  return GetStdHandle(STD_OUTPUT_HANDLE);
    case 2:  return GetStdHandle(STD_ERROR_HANDLE);
    default: { intptr_t h = _get_osfhandle(fd); return h == -1 ? INVALID_HANDLE_VALUE : (HANDLE)h; }
    }
}

/* ─── Stubs ───────────────────────────────────────────────────────────────── */
static void  stub_noop(void) {}
static void  stub_exit(int c) { TerminateProcess(GetCurrentProcess(), (UINT)c); }
static void  stub_abort(void) { TerminateProcess(GetCurrentProcess(), 134); }
static int* stub_errno_loc(void) { return &errno; }
static void  stub_stack_chk(void) { TerminateProcess(GetCurrentProcess(), 127); }

static int stub_write_fd(int fd, const void* buf, size_t n)
{
    HANDLE h = fd_handle(fd);
    if (!h || h == INVALID_HANDLE_VALUE) return -1;
    DWORD w = 0; WriteFile(h, buf, (DWORD)n, &w, NULL); return (int)w;
}

static int stub_puts(const char* s)
{
    stub_write_fd(1, s, strlen(s)); stub_write_fd(1, "\n", 1); return 0;
}

static int stub_printf(const char* fmt, ...)
{
    char b[4096]; va_list a; va_start(a, fmt);
    int n = vsnprintf(b, sizeof(b), fmt, a); va_end(a);
    if (n > 0) stub_write_fd(1, b, (size_t)n); return n;
}

static int stub_fprintf(void* f, const char* fmt, ...)
{
    char b[4096]; va_list a; va_start(a, fmt);
    int n = vsnprintf(b, sizeof(b), fmt, a); va_end(a);
    if (n > 0) stub_write_fd(file_fd(f), b, (size_t)n); return n;
}

static int stub_sprintf(char* buf, const char* fmt, ...)
{
    va_list a; va_start(a, fmt); int n = vsnprintf(buf, 65536, fmt, a); va_end(a); return n;
}

static int stub_snprintf(char* buf, size_t sz, const char* fmt, ...)
{
    va_list a; va_start(a, fmt); int n = vsnprintf(buf, sz, fmt, a); va_end(a); return n;
}

static int stub_sscanf(const char* s, const char* fmt, ...)
{
    va_list a; va_start(a, fmt); int n = vsscanf(s, fmt, a); va_end(a); return n;
}

static int stub_printf_chk(int flag, const char* fmt, ...)
{
    (void)flag; char b[4096]; va_list a; va_start(a, fmt);
    int n = vsnprintf(b, sizeof(b), fmt, a); va_end(a);
    if (n > 0) stub_write_fd(1, b, (size_t)n); return n;
}

static int stub_fprintf_chk(void* f, int flag, const char* fmt, ...)
{
    (void)flag; char b[4096]; va_list a; va_start(a, fmt);
    int n = vsnprintf(b, sizeof(b), fmt, a); va_end(a);
    if (n > 0) stub_write_fd(file_fd(f), b, (size_t)n); return n;
}

static int stub_snprintf_chk(char* buf, size_t sz, int flag, size_t slen, const char* fmt, ...)
{
    (void)flag; (void)slen; va_list a; va_start(a, fmt); int n = vsnprintf(buf, sz, fmt, a); va_end(a); return n;
}

static int stub_sprintf_chk(char* buf, int flag, size_t slen, const char* fmt, ...)
{
    (void)flag; (void)slen; va_list a; va_start(a, fmt); int n = vsnprintf(buf, 65536, fmt, a); va_end(a); return n;
}

static void* stub_memcpy_chk(void* d, const void* s, size_t n, size_t ds) { (void)ds; return memcpy(d, s, n); }

static void* stub_malloc(size_t n) { return malloc(n); }
static void  stub_free(void* p) { free(p); }
static void* stub_calloc(size_t n, size_t s) { return calloc(n, s); }
static void* stub_realloc(void* p, size_t n) { return realloc(p, n); }
static void* stub_memcpy_w(void* d, const void* s, size_t n) { return memcpy(d, s, n); }
static void* stub_memmove_w(void* d, const void* s, size_t n) { return memmove(d, s, n); }
static void* stub_memset_w(void* d, int c, size_t n) { return memset(d, c, n); }
static int   stub_memcmp_w(const void* a, const void* b, size_t n) { return memcmp(a, b, n); }
static size_t stub_strlen_w(const char* s)
{
    /* Guard against obviously invalid pointers (e.g. integer values passed as strings) */
    return (uintptr_t)s < 0x1000 ? 0 : strlen(s);
}
static int   stub_strcmp_w(const char* a, const char* b) { return strcmp(a, b); }
static int   stub_strncmp_w(const char* a, const char* b, size_t n) { return strncmp(a, b, n); }
static char* stub_strcpy_w(char* d, const char* s) { return strcpy(d, s); }
static char* stub_strncpy_w(char* d, const char* s, size_t n) { return strncpy(d, s, n); }
static char* stub_strcat_w(char* d, const char* s) { return strcat(d, s); }
static char* stub_strncat_w(char* d, const char* s, size_t n) { return strncat(d, s, n); }
static char* stub_strchr_w(const char* s, int c) { return strchr(s, c); }
static char* stub_strrchr_w(const char* s, int c) { return strrchr(s, c); }
static char* stub_strstr_w(const char* h, const char* n) { return strstr(h, n); }
static int   stub_atoi_w(const char* s) { return atoi(s); }
static long  stub_atol_w(const char* s) { return atol(s); }
static long  stub_strtol_w(const char* s, char** e, int b) { return strtol(s, e, b); }
static unsigned long stub_strtoul_w(const char* s, char** e, int b) { return strtoul(s, e, b); }
static double stub_strtod_w(const char* s, char** e) { return strtod(s, e); }
static char* stub_strpbrk_w(const char* s, const char* a) { return strpbrk(s, a); }
static char* stub_strtok_w(char* s, const char* d) { return strtok(s, d); }
static float stub_strtof_w(const char* s, char** e) { return strtof(s, e); }
static long double stub_strtold_w(const char* s, char** e) { return strtold(s, e); }
static long long   stub_strtoll_w(const char* s, char** e, int b) { return strtoll(s, e, b); }
static unsigned long long stub_strtoull_w(const char* s, char** e, int b) { return strtoull(s, e, b); }
static int   stub_isdigit_w(int c) { return isdigit(c); }
static int   stub_isalpha_w(int c) { return isalpha(c); }
static int   stub_isspace_w(int c) { return isspace(c); }
static int   stub_isupper_w(int c) { return isupper(c); }
static int   stub_islower_w(int c) { return islower(c); }
static int   stub_isprint_w(int c) { return isprint(c); }
static int   stub_toupper_w(int c) { return toupper(c); }
static int   stub_tolower_w(int c) { return tolower(c); }
static double stub_sqrt_w(double x) { return sqrt(x); }
static double stub_pow_w(double x, double y) { return pow(x, y); }
static double stub_floor_w(double x) { return floor(x); }
static double stub_ceil_w(double x) { return ceil(x); }
static double stub_fabs_w(double x) { return fabs(x); }
static int stub_scanf_w(const char* fmt, ...)
{
    va_list a; va_start(a, fmt); int n = vscanf(fmt, a); va_end(a); return n;
}
static int stub_fscanf_w(FILE* f, const char* fmt, ...)
{
    va_list a; va_start(a, fmt); int n = vfscanf(f, fmt, a); va_end(a); return n;
}
static int stub_vsprintf_w(char* b, const char* fmt, va_list a) { return vsprintf(b, fmt, a); }
static int stub_vsnprintf_w(char* b, size_t n, const char* fmt, va_list a) { return vsnprintf(b, n, fmt, a); }
static int stub_vprintf_w(const char* fmt, va_list a) { return vprintf(fmt, a); }
static int stub_vfprintf_w(FILE* f, const char* fmt, va_list a) { return vfprintf(f, fmt, a); }

static int    stub_fflush(void* f) { (void)f; return 0; }
static int    stub_fclose(void* f) { (void)f; return 0; }
static int    stub_ferror(void* f) { (void)f; return 0; }
static int    stub_putc(int c, void* f) { char ch = (char)c; stub_write_fd(file_fd(f), &ch, 1); return c; }
static void   stub_setbuf(void* f, char* b) { (void)f; (void)b; }
static int    stub_isatty(int fd) { return fd <= 2 ? 1 : 0; }
static size_t stub_fpending(void* f) { (void)f; return 0; }
static char* stub_setlocale(int c, const char* l) { (void)c; (void)l; return "C"; }
static char* stub_strdup(const char* s) { return _strdup(s); }
static char* stub_strerror_w(int e) { return strerror(e); }
static void* stub_memchr_w(const void* s, int c, size_t n) { return memchr(s, c, n); }
static int    stub_rand_w(void) { return rand(); }
static void   stub_srand_w(unsigned s) { srand(s); }
/* Check if current Windows user is an administrator */
static int g_is_admin = -1;  /* -1 = not yet checked */
static int mine_is_admin(void)
{
    if (g_is_admin >= 0) return g_is_admin;
    BOOL admin = FALSE;
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    PSID sid = NULL;
    if (AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid)) {
        CheckTokenMembership(NULL, sid, &admin);
        FreeSid(sid);
    }
    g_is_admin = admin ? 1 : 0;
    return g_is_admin;
}
static unsigned mine_uid(void) { return mine_is_admin() ? 0 : 1000; }
static unsigned mine_gid(void) { return mine_is_admin() ? 0 : 1000; }

static unsigned stub_getuid(void) { return mine_uid(); }
static unsigned stub_geteuid(void) { return mine_uid(); }
static int      stub_setuid(unsigned u) { (void)u; return 0; }
static int      stub_getgid(void) { return (int)mine_gid(); }
static int      stub_getegid(void) { return (int)mine_gid(); }

static int stub_clock_gettime(int clk, void* ts)
{
    typedef struct { int64_t tv_sec; int64_t tv_nsec; } Lts;
    (void)clk;
    LARGE_INTEGER f = { 0 }, c = { 0 };
    QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    uint64_t ns = f.QuadPart > 0 ? (uint64_t)((double)c.QuadPart / (double)f.QuadPart * 1e9) : 0;
    ((Lts*)ts)->tv_sec = (int64_t)(ns / 1000000000ULL);
    ((Lts*)ts)->tv_nsec = (int64_t)(ns % 1000000000ULL);
    return 0;
}

static int stub_gettimeofday(void* tv, void* tz)
{
    typedef struct { int64_t tv_sec; int64_t tv_usec; } Ltv;
    (void)tz; if (!tv) return 0;
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ul = { 0 };
    ul.LowPart = ft.dwLowDateTime; ul.HighPart = ft.dwHighDateTime;
    uint64_t us = (ul.QuadPart - 116444736000000000ULL) / 10ULL;
    ((Ltv*)tv)->tv_sec = (int64_t)(us / 1000000ULL); ((Ltv*)tv)->tv_usec = (int64_t)(us % 1000000ULL);
    return 0;
}

static int stub_setitimer(int w, void* nv, void* ov) { (void)w; (void)nv; (void)ov; return 0; }
static int stub_getpid(void) { return (int)GetCurrentProcessId(); }
static int stub_sigaction(int s, void* a, void* o) { (void)s; (void)a; (void)o; return 0; }
static int stub_sigprocmask(int h, void* s, void* o) { (void)h; (void)s; (void)o; return 0; }
static int stub_sigemptyset(void* s) { if (s)memset(s, 0, 8); return 0; }
static int stub_raise(int s) { (void)s; return 0; }
static int stub_prctl(int op, ...) { (void)op; return 0; }
static int stub_ioctl(int fd, unsigned long r, ...) { (void)fd; (void)r; return 0; }
static int stub_sched_yield(void) { SwitchToThread(); return 0; }
static void stub_error(int status, int err, const char* fmt, ...)
{
    (void)err; char b[512]; va_list a; va_start(a, fmt);
    vsnprintf(b, sizeof(b), fmt, a); va_end(a);
    stub_write_fd(2, b, strlen(b)); stub_write_fd(2, "\n", 1);
    if (status) TerminateProcess(GetCurrentProcess(), (UINT)status);
}

static WSADATA g_wsa; static bool g_wsa_init = false;
static void ensure_wsa(void)
{
    if (!g_wsa_init) {
        memset(&g_wsa, 0, sizeof(g_wsa));
        if (WSAStartup(MAKEWORD(2, 2), &g_wsa) == 0) g_wsa_init = true;
    }
}

static int stub_socket(int d, int t, int p)
{
    ensure_wsa();
    SOCKET s = socket(d, t & 0xF, p);
    if (s == INVALID_SOCKET) return -1;
    int fd = _open_osfhandle((intptr_t)s, 0);
    if (fd < 0) { closesocket(s); return -1; }
    return fd;
}
static int stub_bind(int s, void* a, int l)
{
    SOCKET sk = (SOCKET)_get_osfhandle(s);
    if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    return bind(sk, (struct sockaddr*)a, l) == SOCKET_ERROR ? -1 : 0;
}
static int stub_connect(int s, void* a, int l)
{
    SOCKET sk = (SOCKET)_get_osfhandle(s);
    if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    return connect(sk, (struct sockaddr*)a, l) == SOCKET_ERROR ? -1 : 0;
}
static int stub_setsockopt(int s, int l, int o, void* v, int vl)
{
    SOCKET sk = (SOCKET)_get_osfhandle(s);
    if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    return setsockopt(sk, l == 1 ? SOL_SOCKET : l, o, (char*)v, vl);
}
static int stub_getsockopt(int s, int l, int o, void* v, int* vl)
{
    SOCKET sk = (SOCKET)_get_osfhandle(s);
    if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    return getsockopt(sk, l == 1 ? SOL_SOCKET : l, o, (char*)v, vl);
}
static int stub_getsockname(int s, void* a, int* l)
{
    SOCKET sk = (SOCKET)_get_osfhandle(s);
    if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    return getsockname(sk, (struct sockaddr*)a, l);
}
static int stub_sendto(int s, void* b, size_t n, int f, void* a, int al)
{
    SOCKET sk = (SOCKET)_get_osfhandle(s);
    if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    if (a && al > 0)
        return sendto(sk, (char*)b, (int)n, f, (struct sockaddr*)a, al);
    return send(sk, (char*)b, (int)n, f);
}
static int stub_sendmsg(int s, void* mh, int f) { (void)s; (void)mh; (void)f; return -1; }
static int stub_recvmsg(int s, void* mh, int f) { (void)s; (void)mh; (void)f; return -1; }
static int stub_close_sock(int fd)
{
    /* _close handles both regular fds and socket fds wrapped with _open_osfhandle */
    return _close(fd);
}
static int stub_poll(void* fds, unsigned n, int to) { (void)fds; (void)n; if (to > 0)Sleep((DWORD)to); return 0; }
static const char* stub_inet_ntoa(struct in_addr in)
{
    static char b[16]; InetNtopA(AF_INET, &in, b, sizeof(b)); return b;
}
static int stub_inet_pton(int af, const char* s, void* d) { ensure_wsa(); return InetPtonA(af, s, d); }
static const char* stub_inet_ntop(int af, void* s, char* d, size_t sz)
{
    ensure_wsa(); return InetNtopA(af, s, d, (ULONG)sz);
}
static int stub_inet_aton(const char* s, struct in_addr* a) { return InetPtonA(AF_INET, s, a) == 1 ? 1 : 0; }
/*
 * Linux vs Windows addrinfo layout (64-bit):
 *
 * Linux:
 *   int     ai_flags;      // +0
 *   int     ai_family;     // +4
 *   int     ai_socktype;   // +8
 *   int     ai_protocol;   // +12
 *   uint32  ai_addrlen;    // +16  <- 4 bytes + 4 pad
 *   void*   ai_addr;       // +24
 *   char*   ai_canonname;  // +32
 *   void*   ai_next;       // +40
 *
 * Windows:
 *   int     ai_flags;      // +0
 *   int     ai_family;     // +4
 *   int     ai_socktype;   // +8
 *   int     ai_protocol;   // +12
 *   size_t  ai_addrlen;    // +16  <- 8 bytes (uint64)
 *   char*   ai_canonname;  // +24
 *   void*   ai_addr;       // +32  <- SWAPPED vs Linux!
 *   void*   ai_next;       // +40
 *
 * ping reads offset+32 expecting ai_canonname but gets Windows ai_addr (sockaddr*).
 * sockaddr_in starts with sin_family=AF_INET=2, so the pointer value looks like 0x2.
 * ping then calls strlen(0x2) -> crash.
 *
 * Fix: allocate Linux-layout addrinfo structs and copy fields in correct order.
 */
typedef struct linux_addrinfo_s {
    int                      ai_flags;
    int                      ai_family;
    int                      ai_socktype;
    int                      ai_protocol;
    uint32_t                 ai_addrlen;
    uint32_t                 _pad;
    struct sockaddr* ai_addr;
    char* ai_canonname;
    struct linux_addrinfo_s* ai_next;
} linux_addrinfo;

/* Head of list so we can free it all */
static linux_addrinfo* g_addrinfo_list = NULL;

static linux_addrinfo* win_to_linux_addrinfo(struct addrinfo* win)
{
    if (!win) return NULL;
    linux_addrinfo* head = NULL;
    linux_addrinfo** tail = &head;
    for (struct addrinfo* w = win; w; w = w->ai_next) {
        linux_addrinfo* l = (linux_addrinfo*)calloc(1, sizeof(linux_addrinfo));
        if (!l) break;
        l->ai_flags = w->ai_flags;
        l->ai_family = w->ai_family;
        l->ai_socktype = w->ai_socktype;
        l->ai_protocol = w->ai_protocol;
        l->ai_addrlen = (uint32_t)w->ai_addrlen;
        /* Copy sockaddr */
        if (w->ai_addr && w->ai_addrlen > 0) {
            l->ai_addr = (struct sockaddr*)malloc(w->ai_addrlen);
            if (l->ai_addr)
                memcpy(l->ai_addr, w->ai_addr, w->ai_addrlen);
        }
        l->ai_canonname = w->ai_canonname ? _strdup(w->ai_canonname) : NULL;
        l->ai_next = NULL;
        *tail = l;
        tail = &l->ai_next;
    }
    return head;
}

static void free_linux_addrinfo(linux_addrinfo* l)
{
    while (l) {
        linux_addrinfo* next = l->ai_next;
        free(l->ai_addr);
        free(l->ai_canonname);
        free(l);
        l = next;
    }
}

static int stub_getaddrinfo(const char* n, const char* s, void* hints_linux, void** r)
{
    ensure_wsa();

    /* Convert Linux hints to Windows layout if provided */
    struct addrinfo win_hints;
    struct addrinfo* phints = NULL;
    if (hints_linux) {
        /* Linux addrinfo: flags(0) family(4) socktype(8) protocol(12)
                           addrlen_u32(16) pad(20) addr*(24) canonname*(32) next*(40)
           Windows addrinfo: flags(0) family(4) socktype(8) protocol(12)
                              addrlen_u64(16) canonname*(24) addr*(32) next*(40) */
        typedef struct {
            int      ai_flags;
            int      ai_family;
            int      ai_socktype;
            int      ai_protocol;
            uint32_t ai_addrlen;
            uint32_t _pad;
            uint64_t ai_addr;
            uint64_t ai_canonname;
            uint64_t ai_next;
        } lin_hints_t;
        lin_hints_t* lh = (lin_hints_t*)hints_linux;
        memset(&win_hints, 0, sizeof(win_hints));
        win_hints.ai_flags = lh->ai_flags;
        win_hints.ai_family = lh->ai_family;
        win_hints.ai_socktype = lh->ai_socktype;
        win_hints.ai_protocol = lh->ai_protocol;
        phints = &win_hints;
    }

    struct addrinfo* win_res = NULL;
    int ret = getaddrinfo(n, s, phints, &win_res);
    if (ret != 0) { *r = NULL; return ret; }
    linux_addrinfo* lres = win_to_linux_addrinfo(win_res);
    freeaddrinfo(win_res);
    *r = lres;
    return 0;
}
static void stub_freeaddrinfo(void* r) { free_linux_addrinfo((linux_addrinfo*)r); }
static int stub_getnameinfo(void* a, int al, char* h, size_t hl, char* s, size_t sl, int f)
{
    return getnameinfo((struct sockaddr*)a, al, h, (DWORD)hl, s, (DWORD)sl, f);
}
static const char* stub_gai_strerror(int e) { return gai_strerrorA(e); }
static int stub_if_nametoindex(const char* n) { (void)n; return 0; }
static int stub_getrandom(void* buf, size_t n, unsigned f)
{
    (void)f; HCRYPTPROV p = 0;
    if (CryptAcquireContextA(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        CryptGenRandom(p, (DWORD)n, (BYTE*)buf); CryptReleaseContext(p, 0);
    }
    return (int)n;
}
static int   stub_getifaddrs(void** p) { *p = NULL; return -1; }
static void  stub_freeifaddrs(void* p) { (void)p; }
static char* stub_idn2_strerror(int e) { (void)e; return "idn2 error"; }
static int   stub_idn2_lookup_ul(const char* s, char** r, unsigned f)
{
    (void)f;
    if (!s) { *r = NULL; return 1; }
    *r = _strdup(s);
    return 0;
}
static int stub_dn_comp(const char* e, unsigned char* c, int l, unsigned char** dn, unsigned char** de)
{
    (void)e; (void)c; (void)l; (void)dn; (void)de; return -1;
}
static int stub_dn_expand(const unsigned char* m, const unsigned char* e, const unsigned char* c, char* e2, int l)
{
    (void)m; (void)e; (void)c; (void)e2; (void)l; return -1;
}
static void stub_assert_fail(const char* a, const char* f, int l, const char* fn)
{
    fprintf(stderr, "Assertion '%s' failed at %s:%d in %s\n", a, f, l, fn); TerminateProcess(GetCurrentProcess(), 1);
}
static unsigned short** stub_ctype_b_loc(void)
{
    static unsigned short t[384] = { 0 }; static unsigned short* p = t + 128; return &p;
}
static int** stub_ctype_tolower_loc(void)
{
    static int t[384] = { 0 }; static int* p = t + 128; int i; for (i = -128; i < 256; i++)p[i] = i; return &p;
}
static int  stub_setjmp(void* e) { (void)e; return 0; }
static void stub_longjmp_chk(void* e, int v) { (void)e; (void)v; TerminateProcess(GetCurrentProcess(), 1); }
/* ─── Working getopt / getopt_long implementation ─────────────────────────
 * ping uses getopt_long heavily. Our previous stub always returned -1 which
 * left optind at 1, but ping's internal state machine still ran and corrupted
 * registers. Provide a real implementation that properly scans argv.
 */

 /* g_optind/g_optarg/g_optopt: the host-side copies used by our getopt impl.
  * Declared here so the getopt stubs below can use them.
  * The sym data table below also references these — they must be declared first. */
static int   g_optind = 1;
static int   g_optopt = 0;
static int   g_opterr = 1;
static char* g_optarg = NULL;

/* These mirror the guest's COPY-relocated optind/optarg/optopt locations.
 * We update both our local copies and the guest's BSS locations via the
 * pointers captured during COPY relocation. Since we can't easily find the
 * guest BSS pointer here, we update g_optind/g_optarg which were memcpy'd
 * to the guest during COPY relocation -- but that was a one-time copy.
 * The guest reads its own optind from its BSS, not from g_optind.
 * So we need to find and update the guest's optind location directly.
 *
 * Simplest approach: track the guest optind BSS address when the COPY
 * relocation happens, and write to it after each getopt call.
 */
static void* g_guest_optind_ptr = NULL;
static void* g_guest_optarg_ptr = NULL;
static void* g_guest_optopt_ptr = NULL;

/* Called from apply_rela when a COPY relocation for optind/optarg/optopt
 * is processed. We record the guest BSS address so we can update it. */
void MineRecordOptPtr(const char* name, void* guest_ptr)
{
    if (strcmp(name, "optind") == 0) g_guest_optind_ptr = guest_ptr;
    else if (strcmp(name, "optarg") == 0) g_guest_optarg_ptr = guest_ptr;
    else if (strcmp(name, "optopt") == 0) g_guest_optopt_ptr = guest_ptr;
}

static void sync_opt_to_guest(void)
{
    if (g_guest_optind_ptr) *(int*)g_guest_optind_ptr = g_optind;
    if (g_guest_optarg_ptr) *(char**)g_guest_optarg_ptr = g_optarg;
    if (g_guest_optopt_ptr) *(int*)g_guest_optopt_ptr = g_optopt;
}

/* Simple but functional getopt implementation */
static int mine_optind = 1;
static int mine_opterr = 1;
static int mine_optopt = 0;
static char* mine_optarg = NULL;
static int mine_optpos = 0;   /* position within current argv[i] */

static int mine_getopt(int argc, char* const* argv, const char* opts)
{
    if (mine_optind >= argc) return -1;

    char* arg = argv[mine_optind];
    if (!arg || arg[0] != '-' || arg[1] == '\0') return -1;
    if (arg[1] == '-' && arg[2] == '\0') { mine_optind++; return -1; }

    /* find current char in current arg */
    if (mine_optpos == 0) mine_optpos = 1;
    int c = (unsigned char)arg[mine_optpos];
    mine_optpos++;
    if (arg[mine_optpos] == '\0') { mine_optind++; mine_optpos = 0; }

    /* find c in opts */
    const char* p = strchr(opts, c);
    if (!p) { mine_optopt = c; return '?'; }

    if (p[1] == ':') {
        /* requires argument */
        if (mine_optpos > 0 && arg[mine_optpos] != '\0') {
            mine_optarg = arg + mine_optpos;
            mine_optind++; mine_optpos = 0;
        }
        else if (mine_optind < argc) {
            mine_optarg = argv[mine_optind++];
            mine_optpos = 0;
        }
        else {
            mine_optopt = c; mine_optarg = NULL; return '?';
        }
    }
    else {
        mine_optarg = NULL;
    }
    return c;
}

typedef struct {
    const char* name;
    int         has_arg;  /* 0=no, 1=required, 2=optional */
    int* flag;
    int         val;
} linux_option;

static int g_getopt_synced = 0;  /* shared sync flag — getopt and getopt_long share state */

/* Reset getopt state for each new binary (called from init_stubs) */
static void reset_getopt(void)
{
    mine_optind = 1;
    mine_optpos = 0;
    mine_optopt = 0;
    mine_optarg = NULL;
    g_getopt_synced = 0;
    g_guest_optind_ptr = NULL;
    g_guest_optarg_ptr = NULL;
    g_guest_optopt_ptr = NULL;
}

static int stub_getopt_real(int ac, char* const* av, const char* opts)
{
    /* Sync mine_optind from guest BSS, but guard against 0 (uninitialized) */
    if (g_guest_optind_ptr) {
        int guest_oi = *(int*)g_guest_optind_ptr;
        if (guest_oi >= 1) mine_optind = guest_oi;
        else mine_optind = 1;  /* never start before argv[1] */
    }

    int ret = mine_getopt(ac, av, opts ? opts : "");
    g_optind = mine_optind;
    g_optarg = mine_optarg;
    g_optopt = mine_optopt;
    sync_opt_to_guest();
    return ret;
}

static int stub_getopt_long(int ac, char* const* av, const char* opts,
    const linux_option* longopts, int* idx)
{
    /* Sync from guest BSS, guarding against 0 */
    if (g_guest_optind_ptr) {
        int guest_oi = *(int*)g_guest_optind_ptr;
        mine_optind = (guest_oi >= 1) ? guest_oi : 1;
    }

    if (mine_optind >= ac) goto done;

    char* arg = av[mine_optind];
    if (!arg) goto done;

    /* Long option: --name or --name=val */
    if (arg[0] == '-' && arg[1] == '-' && arg[2] != '\0' && longopts) {
        mine_optind++;
        const char* name = arg + 2;
        const char* eq = strchr(name, '=');
        size_t nlen = eq ? (size_t)(eq - name) : strlen(name);
        for (int i = 0; longopts[i].name; i++) {
            if (strncmp(longopts[i].name, name, nlen) == 0 &&
                strlen(longopts[i].name) == nlen) {
                if (idx) *idx = i;
                if (longopts[i].has_arg == 1) {
                    mine_optarg = eq ? (char*)(eq + 1)
                        : (mine_optind < ac ? av[mine_optind++] : NULL);
                }
                else {
                    mine_optarg = eq ? (char*)(eq + 1) : NULL;
                }
                g_optind = mine_optind; g_optarg = mine_optarg;
                sync_opt_to_guest();
                if (longopts[i].flag) { *longopts[i].flag = longopts[i].val; return 0; }
                return longopts[i].val;
            }
        }
        mine_optopt = 0; mine_optarg = NULL;
        goto done;
    }

    {
        int ret = mine_getopt(ac, av, opts ? opts : "");
        g_optind = mine_optind; g_optarg = mine_optarg; g_optopt = mine_optopt;
        sync_opt_to_guest();
        return ret;
    }

done:
    g_optind = mine_optind; g_optarg = mine_optarg;
    sync_opt_to_guest();
    return -1;
}
static void* stub_cap_init(void) { return malloc(64); }
static void  stub_cap_free(void* c) { free(c); }
static void* stub_cap_get_proc(void) { return malloc(64); }
static int   stub_cap_set_proc(void* c) { (void)c; return 0; }
static int   stub_cap_get_flag(void* c, int v, int t, int* r) { (void)c; (void)v; (void)t; *r = 0; return 0; }
static int   stub_cap_set_flag(void* c, int t, int n, int* v, int s)
{
    (void)c; (void)t; (void)n; (void)v; (void)s; return 0;
}

/* stub for unresolved symbols — return NULL/0 silently */
static int stub_unresolved(void) { return 0; }

/* ─── time / locale ─────────────────────────────────────────────────────── */
static void* stub_localtime(const int64_t* t)
{
    static struct {
        int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year,
            tm_wday, tm_yday, tm_isdst; long tm_gmtoff; char* tm_zone;
    } r;
    time_t tt = t ? (time_t)*t : time(NULL);
    struct tm* lt = localtime(&tt);
    if (!lt) return NULL;
    r.tm_sec = lt->tm_sec; r.tm_min = lt->tm_min; r.tm_hour = lt->tm_hour;
    r.tm_mday = lt->tm_mday; r.tm_mon = lt->tm_mon; r.tm_year = lt->tm_year;
    r.tm_wday = lt->tm_wday; r.tm_yday = lt->tm_yday; r.tm_isdst = lt->tm_isdst;
    r.tm_gmtoff = 0; r.tm_zone = (char*)"UTC";
    return &r;
}
static void* stub_gmtime(const int64_t* t) { return stub_localtime(t); }
static int64_t stub_mktime(void* tm)
{
    struct tm* t = (struct tm*)tm; return t ? (int64_t)mktime(t) : -1;
}
static void* stub_localtime_r(const int64_t* t, void* res) { (void)res; return stub_localtime(t); }
static char* stub_strftime_noop(char* s, size_t n, const char* f, const void* t)
{
    (void)f; (void)t; if (s && n > 0) s[0] = 0; return s;
}
static char* stub_ctime(const int64_t* t)
{
    time_t tt = t ? (time_t)*t : time(NULL); return ctime(&tt);
}
static int64_t stub_time(int64_t* t)
{
    int64_t r = (int64_t)time(NULL); if (t)*t = r; return r;
}
static unsigned stub_alarm(unsigned s) { (void)s; return 0; }
static int stub_nanosleep2(const void* req, void* rem)
{
    typedef struct { int64_t tv_sec; int64_t tv_nsec; } Lts;
    const Lts* r = (const Lts*)req; (void)rem;
    if (r) { DWORD ms = (DWORD)(r->tv_sec * 1000 + r->tv_nsec / 1000000); Sleep(ms); }
    return 0;
}

/* ─── file I/O ──────────────────────────────────────────────────────────── */
static int stub_open(const char* path, int flags, ...)
{
    (void)flags; return _open(path, _O_RDONLY | _O_BINARY);
}
static int stub_close2(int fd) { return _close(fd); }
static int stub_read(int fd, void* buf, size_t n)
{
    DWORD got = 0; ReadFile(fd_handle(fd), buf, (DWORD)n, &got, NULL); return (int)got;
}
static int64_t stub_lseek64(int fd, int64_t off, int w)
{
    return _lseeki64(fd, off, w);
}
static int stub_stat(const char* p, void* s) { (void)p; (void)s; return -1; }
static int stub_fstat(int fd, void* s) { (void)fd; (void)s; return -1; }
static int stub_access(const char* p, int m) { (void)m; return _access(p, 0); }
static int stub_unlink(const char* p) { return _unlink(p); }
static int stub_mkdir(const char* p, int m) { (void)m; return _mkdir(p); }
static int stub_rmdir(const char* p) { return _rmdir(p); }
static char* stub_getcwd(char* b, size_t n) { return _getcwd(b, (int)n); }
static int stub_chdir(const char* p) { return _chdir(p); }
static void* stub_opendir(const char* p) { (void)p; return NULL; }
static void* stub_readdir(void* d) { (void)d; return NULL; }
static int stub_closedir(void* d) { (void)d; return 0; }
static int stub_truncate(const char* p, int64_t l) { (void)p; (void)l; return -1; }
static int stub_ftruncate(int fd, int64_t l) { (void)fd; (void)l; return -1; }
static int stub_chmod(const char* p, int m) { (void)p; (void)m; return 0; }
static int stub_fchmod(int fd, int m) { (void)fd; (void)m; return 0; }
static int stub_rename(const char* o, const char* n) { return rename(o, n); }
static int stub_link(const char* o, const char* n) { (void)o; (void)n; return -1; }
static int stub_symlink(const char* t, const char* l) { (void)t; (void)l; return -1; }
static int stub_readlink(const char* p, char* b, size_t n) { (void)p; (void)b; (void)n; return -1; }
static void* stub_fopen(const char* p, const char* m)
{
    FILE* f = fopen(p, m);
    return f ? f : NULL;
}
static int stub_fread(void* p, size_t s, size_t n, void* f)
{
    if (!f)return 0; if (f == mine_stdin || f == mine_stdout || f == mine_stderr) return 0;
    return (int)fread(p, s, n, (FILE*)f);
}
static char* stub_fgets(char* s, int n, void* f)
{
    if (!f || f == mine_stdout || f == mine_stderr) return NULL;
    if (f == mine_stdin) return fgets(s, n, stdin);
    return fgets(s, n, (FILE*)f);
}
static int stub_feof(void* f) {
    if (!f)return 1;
    if (f == mine_stdin || f == mine_stdout || f == mine_stderr) return 0;
    return feof((FILE*)f);
}
static int stub_ftell(void* f) {
    if (!f)return -1;
    if (f == mine_stdin || f == mine_stdout || f == mine_stderr) return 0;
    return (int)ftell((FILE*)f);
}
static int stub_fseek(void* f, long off, int w) {
    if (!f)return -1;
    if (f == mine_stdin || f == mine_stdout || f == mine_stderr) return 0;
    return fseek((FILE*)f, off, w);
}
static void stub_rewind(void* f) { (void)f; }

/* ─── memory / process ──────────────────────────────────────────────────── */
static void* stub_mmap(void* a, size_t l, int p, int f, int fd, int64_t o)
{
    (void)a; (void)p; (void)f; (void)fd; (void)o;
    void* r = VirtualAlloc(NULL, l, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return r ? r : (void*)(uintptr_t)-1;
}
static int stub_munmap(void* a, size_t l)
{
    VirtualFree(a, l, MEM_DECOMMIT); VirtualFree(a, 0, MEM_RELEASE); return 0;
}
static int stub_mprotect(void* a, size_t l, int p)
{
    DWORD old, wp = PAGE_READWRITE;
    if (p == 1) wp = PAGE_READONLY; if (p == 5) wp = PAGE_EXECUTE_READ; if (p == 7) wp = PAGE_EXECUTE_READWRITE;
    return VirtualProtect(a, (DWORD)l, wp, &old) ? 0 : -1;
}
static int stub_madvise(void* a, size_t l, int adv) { (void)a; (void)l; (void)adv; return 0; }
static int stub_msync(void* a, size_t l, int f) { (void)a; (void)l; (void)f; return 0; }
static int stub_mlockall(int f) { (void)f; return 0; }
static int stub_mlock(void* a, size_t l) { (void)a; (void)l; return 0; }
static pid_t stub_fork(void) { return -1; }  /* no fork on Windows */
static int stub_waitpid(int p, int* s, int o) { (void)p; (void)s; (void)o; return -1; }
static int stub_execve(const char* p, char** av, char** ev) { (void)p; (void)av; (void)ev; return -1; }
static int stub_system(const char* cmd) { return system(cmd); }
static int stub_pipe(int* fds) { return _pipe(fds, 4096, _O_BINARY); }
static int stub_dup(int fd) { return _dup(fd); }
static int stub_dup2(int fd, int fd2) { return _dup2(fd, fd2); }
static unsigned stub_sleep(unsigned s) { Sleep(s * 1000); return 0; }
static int stub_usleep(unsigned us) { Sleep(us / 1000 + 1); return 0; }
static int stub_gethostname(char* b, size_t n)
{
    return gethostname(b, (int)n) == 0 ? 0 : -1;
}
static int stub_uname(void* b)
{
    typedef struct { char sysname[65], nodename[65], release[65], version[65], machine[65]; } utsname;
    utsname* u = (utsname*)b; if (!u) return -1;
    strcpy(u->sysname, "Linux"); gethostname(u->nodename, 64);
    strcpy(u->release, "5.15.0"); strcpy(u->version, "MinE"); strcpy(u->machine, "x86_64");
    return 0;
}
static int stub_getrlimit(int r, void* l)
{
    typedef struct { uint64_t cur, max; }rlim; rlim* p = (rlim*)l;
    (void)r; if (p) { p->cur = p->max = (uint64_t)-1; } return 0;
}
static int stub_setrlimit(int r, void* l) { (void)r; (void)l; return 0; }
static int stub_getrusage(int w, void* r) { (void)w; (void)r; return 0; }
static int stub_getpgrp(void) { return (int)GetCurrentProcessId(); }
static int stub_getppid(void) { return 1; }
static int stub_setpgid(int p, int g) { (void)p; (void)g; return 0; }
static int stub_setsid(void) { return (int)GetCurrentProcessId(); }
static int stub_kill(int p, int s) { (void)p; (void)s; return 0; }
static int stub_signal(int s, void* h) { (void)s; (void)h; return 0; }
static unsigned stub_umask(unsigned m) { (void)m; return 022; }
static int stub_chown(const char* p, unsigned u, unsigned g) { (void)p; (void)u; (void)g; return 0; }
static int stub_lchown(const char* p, unsigned u, unsigned g) { (void)p; (void)u; (void)g; return 0; }
static int stub_fchown(int fd, unsigned u, unsigned g) { (void)fd; (void)u; (void)g; return 0; }

/* ─── string / wide char ────────────────────────────────────────────────── */
static size_t stub_strspn_w(const char* s, const char* a) { return strspn(s, a); }
static size_t stub_strcspn_w(const char* s, const char* a) { return strcspn(s, a); }
static char* stub_strsep(char** s, const char* d)
{
    if (!s || !*s) return NULL; char* t = *s;
    char* p = strpbrk(t, d); if (p) { *p = 0; *s = p + 1; }
    else *s = NULL; return t;
}
static int stub_strcasecmp(const char* a, const char* b) { return _stricmp(a, b); }
static int stub_strncasecmp(const char* a, const char* b, size_t n) { return _strnicmp(a, b, n); }
static char* stub_strndup(const char* s, size_t n)
{
    size_t l = strlen(s); if (l > n)l = n; char* r = (char*)malloc(l + 1); if (r) { memcpy(r, s, l); r[l] = 0; } return r;
}
static int stub_asprintf(char** p, const char* fmt, ...)
{
    va_list a; va_start(a, fmt); int n = vsnprintf(NULL, 0, fmt, a); va_end(a);
    *p = (char*)malloc(n + 1); va_start(a, fmt); vsnprintf(*p, n + 1, fmt, a); va_end(a); return n;
}
static int stub_vasprintf(char** p, const char* fmt, va_list a)
{
    int n = vsnprintf(NULL, 0, fmt, a); *p = (char*)malloc(n + 1); vsnprintf(*p, n + 1, fmt, a); return n;
}
static size_t stub_wcstombs(char* d, const wchar_t* s, size_t n)
{
    return wcstombs(d, s, n);
}
static size_t stub_mbstowcs(wchar_t* d, const char* s, size_t n)
{
    return mbstowcs(d, s, n);
}
static int stub_wprintf(const wchar_t* fmt, ...) { (void)fmt; return 0; }
static int stub_isalnum_w(int c) { return isalnum(c); }
static int stub_iscntrl_w(int c) { return iscntrl(c); }
static int stub_ispunct_w(int c) { return ispunct(c); }
static int stub_isxdigit_w(int c) { return isxdigit(c); }
static int stub_isgraph_w(int c) { return isgraph(c); }
static int stub_isblank_w(int c) { return c == ' ' || c == '\t'; }
static size_t stub_strlen_for_wchar(const void* s) { return s ? wcslen((wchar_t*)s) * 2 : 0; }

/* ─── math ──────────────────────────────────────────────────────────────── */
static double stub_sin_w(double x) { return sin(x); }
static double stub_cos_w(double x) { return cos(x); }
static double stub_tan_w(double x) { return tan(x); }
static double stub_atan2_w(double y, double x) { return atan2(y, x); }
static double stub_log_w(double x) { return log(x); }
static double stub_log2_w(double x) { return log2(x); }
static double stub_log10_w(double x) { return log10(x); }
static double stub_exp_w(double x) { return exp(x); }
static double stub_exp2_w(double x) { return exp2(x); }
static double stub_round_w(double x) { return round(x); }
static double stub_fmod_w(double x, double y) { return fmod(x, y); }
static double stub_modf_w(double x, double* i) { return modf(x, i); }
static double stub_frexp_w(double x, int* e) { return frexp(x, e); }
static double stub_ldexp_w(double x, int e) { return ldexp(x, e); }
static double stub_hypot_w(double a, double b) { return hypot(a, b); }
static float  stub_sinf(float x) { return sinf(x); }
static float  stub_cosf(float x) { return cosf(x); }
static float  stub_sqrtf(float x) { return sqrtf(x); }
static float  stub_fabsf(float x) { return fabsf(x); }
static int    stub_abs_w(int x) { return abs(x); }
static long   stub_labs_w(long x) { return labs(x); }
static long long stub_llabs_w(long long x) { return llabs(x); }

/* ─── network extras ────────────────────────────────────────────────────── */
static int stub_recvfrom(int s, void* b, size_t n, int f, void* a, int* al)
{
    SOCKET sk = (SOCKET)_get_osfhandle(s); if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    return recvfrom(sk, (char*)b, (int)n, f, (struct sockaddr*)a, al);
}
static int stub_recv(int s, void* b, size_t n, int f)
{
    SOCKET sk = (SOCKET)_get_osfhandle(s); if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    return recv(sk, (char*)b, (int)n, f);
}
static int stub_send(int s, const void* b, size_t n, int f)
{
    SOCKET sk = (SOCKET)_get_osfhandle(s); if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    return send(sk, (const char*)b, (int)n, f);
}
static int stub_listen(int s, int b)
{
    SOCKET sk = (SOCKET)_get_osfhandle(s); if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    return listen(sk, b);
}
static int stub_accept(int s, void* a, int* al)
{
    SOCKET sk = (SOCKET)_get_osfhandle(s); if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    SOCKET ns = accept(sk, (struct sockaddr*)a, al); if (ns == INVALID_SOCKET) return -1;
    int fd = _open_osfhandle((intptr_t)ns, 0); if (fd < 0) { closesocket(ns); return -1; } return fd;
}
static int stub_shutdown(int s, int h)
{
    SOCKET sk = (SOCKET)_get_osfhandle(s); if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    return shutdown(sk, h);
}
static int stub_select(int n, void* r, void* w, void* e, void* t)
{
    (void)n; (void)r; (void)w; (void)e; (void)t; return 0;
}
static char* stub_inet_addr_str(const char* s)
{
    static char b[16]; strncpy(b, s ? s : "", 15); return b;
}
static uint32_t stub_htonl(uint32_t x) { return htonl(x); }
static uint16_t stub_htons(uint16_t x) { return htons(x); }
static uint32_t stub_ntohl(uint32_t x) { return ntohl(x); }
static uint16_t stub_ntohs(uint16_t x) { return ntohs(x); }

/* ─── real recvmsg / sendmsg via WSARecvMsg / WSASendMsg ────────────────── */
typedef struct {
    void* msg_name; int msg_namelen; void* msg_iov; size_t msg_iovlen;
    void* msg_control; size_t msg_controllen; int msg_flags;
} linux_msghdr;
typedef struct { void* iov_base; size_t iov_len; } linux_iovec;

static int stub_recvmsg2(int s, void* mh, int f)
{
    linux_msghdr* m = (linux_msghdr*)mh;
    if (!m) return -1;
    SOCKET sk = (SOCKET)_get_osfhandle(s);
    if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    /* Build a single receive into first iov */
    if (m->msg_iovlen > 0) {
        linux_iovec* iov = (linux_iovec*)m->msg_iov;
        int r = recvfrom(sk, (char*)iov->iov_base, (int)iov->iov_len, f,
            (struct sockaddr*)m->msg_name, (int*)&m->msg_namelen);
        return r;
    }
    return -1;
}
static int stub_sendmsg2(int s, void* mh, int f)
{
    linux_msghdr* m = (linux_msghdr*)mh;
    if (!m) return -1;
    SOCKET sk = (SOCKET)_get_osfhandle(s);
    if (sk == (SOCKET)INVALID_HANDLE_VALUE) return -1;
    if (m->msg_iovlen > 0) {
        linux_iovec* iov = (linux_iovec*)m->msg_iov;
        return sendto(sk, (char*)iov->iov_base, (int)iov->iov_len, f,
            (struct sockaddr*)m->msg_name, m->msg_namelen);
    }
    return -1;
}

/* ─── misc GNU extensions ───────────────────────────────────────────────── */
static void* stub_dlopen(const char* p, int f) { (void)p; (void)f; return NULL; }
static void* stub_dlsym(void* h, const char* s) { (void)h; (void)s; return NULL; }
static int   stub_dlclose(void* h) { (void)h; return 0; }
static char* stub_dlerror(void) { return (char*)"dlopen not supported"; }
static int   stub_pthread_create(void** t, void* a, void* fn, void* arg) { (void)t; (void)a; (void)fn; (void)arg; return 11; }
static int   stub_pthread_join(void* t, void** r) { (void)t; (void)r; return 0; }
static int   stub_pthread_mutex_init(void* m, void* a) { (void)m; (void)a; return 0; }
static int   stub_pthread_mutex_lock(void* m) { (void)m; return 0; }
static int   stub_pthread_mutex_unlock(void* m) { (void)m; return 0; }
static int   stub_pthread_mutex_destroy(void* m) { (void)m; return 0; }
static int   stub_pthread_key_create(void* k, void* d) { (void)k; (void)d; return 0; }
static void* stub_pthread_getspecific(void* k) { (void)k; return NULL; }
static int   stub_pthread_setspecific(void* k, void* v) { (void)k; (void)v; return 0; }
static int   stub_pthread_once(void* o, void* fn) { (void)o; (void)fn; return 0; }
static void* stub_pthread_self(void) { return (void*)(uintptr_t)GetCurrentThreadId(); }
static int   stub_pthread_atfork(void* p, void* c1, void* c2) { (void)p; (void)c1; (void)c2; return 0; }
static void  stub_pthread_exit(void* r) { (void)r; ExitThread(0); }
static int   stub_sem_init(void* s, int p, unsigned v) { (void)s; (void)p; (void)v; return 0; }
static int   stub_sem_wait(void* s) { (void)s; return 0; }
static int   stub_sem_post(void* s) { (void)s; return 0; }
static int   stub_sem_destroy(void* s) { (void)s; return 0; }
static void  stub_qsort_w(void* b, size_t n, size_t s, int(*c)(const void*, const void*))
{
    qsort(b, n, s, c);
}
static void* stub_bsearch_w(const void* k, const void* b, size_t n, size_t s,
    int(*c)(const void*, const void*)) {
    return bsearch(k, b, n, s, c);
}
static void  stub_longjmp_w(void* e, int v) { (void)e; (void)v; TerminateProcess(GetCurrentProcess(), 1); }
static int   stub_atexit_w(void* fn) { (void)fn; return 0; }
static void  stub_perror(const char* s) { if (s) stub_write_fd(2, s, strlen(s)); stub_write_fd(2, "\n", 1); }
static char* stub_getlogin(void) { return g_username; }
static char* stub_ttyname(int fd) { (void)fd; return NULL; }
static int   stub_isatty_w(int fd) { return fd <= 2 ? 1 : 0; }
static int   stub_tcgetattr(int fd, void* t) { (void)fd; (void)t; return -1; }
static int   stub_tcsetattr(int fd, int a, void* t) { (void)fd; (void)a; (void)t; return -1; }
static int   stub_ioctl_w(int fd, unsigned long r, ...) { (void)fd; (void)r; return 0; }
static int   stub_fcntl(int fd, int cmd, ...) { (void)fd; (void)cmd; return 0; }
static int   stub_epoll_create(int s) { (void)s; return -1; }
static int   stub_epoll_ctl(int e, int o, int f, void* v) { (void)e; (void)o; (void)f; (void)v; return -1; }
static int   stub_epoll_wait(int e, void* v, int m, int t) { (void)e; (void)v; (void)m; if (t > 0)Sleep((DWORD)t); return 0; }
static int   stub_eventfd(unsigned v, int f) { (void)v; (void)f; return -1; }
static int   stub_signalfd(int f, void* m, int fl) { (void)f; (void)m; (void)fl; return -1; }
static int   stub_timerfd_create(int c, int f) { (void)c; (void)f; return -1; }
static int   stub_inotify_init(void) { return -1; }
static int   stub_fallocate(int f, int m, int64_t o, int64_t l) { (void)f; (void)m; (void)o; (void)l; return -1; }
static int   stub_posix_memalign(void** p, size_t a, size_t s)
{
    *p = _aligned_malloc(s, a); return *p ? 0 : 12;
}
static void* stub_aligned_alloc(size_t a, size_t s) { return _aligned_malloc(s, a); }
static void  stub_aligned_free(void* p) { _aligned_free(p); }
static int   stub_getpagesize(void) { SYSTEM_INFO si; GetSystemInfo(&si); return (int)si.dwPageSize; }
static int   stub_sysinfo(void* i)
{
    typedef struct { long up; unsigned long load[3], totalram, freeram, pad[8]; unsigned short procs; }sysinfo_t;
    sysinfo_t* s = (sysinfo_t*)i; if (!s) return -1;
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms); GlobalMemoryStatusEx(&ms);
    s->totalram = ms.ullTotalPhys; s->freeram = ms.ullAvailPhys; s->procs = 1;
    s->up = (long)(GetTickCount64() / 1000); return 0;
}
static int   stub_setenv(const char* n, const char* v, int ov)
{
    (void)ov; return _putenv_s(n, v);
}
static int   stub_unsetenv(const char* n) { return _putenv_s(n, ""); }
static void  stub_clearenv(void) {}
static int   stub_putenv(char* s) { return _putenv(s); }
static char** stub_environ_ptr(void) { return _environ; }
static int   stub_raise_w(int s) { (void)s; return 0; }
static int   stub_sigfillset(void* s) { if (s) memset(s, 0xFF, 8); return 0; }
static int   stub_sigaddset(void* s, int n) { (void)s; (void)n; return 0; }
static int   stub_sigdelset(void* s, int n) { (void)s; (void)n; return 0; }
static int   stub_sigismember(void* s, int n) { (void)s; (void)n; return 0; }
static int   stub_sigwait(void* s, int* n) { (void)s; if (n)*n = 0; return 0; }
static int   stub_clone(void* fn, void* s, int f, void* a) { (void)fn; (void)s; (void)f; (void)a; return -1; }
static int   stub_capget(void* h, void* d) { (void)h; (void)d; return 0; }
static int   stub_capset(void* h, void* d) { (void)h; (void)d; return 0; }
static int   stub_getsid(int p) { (void)p; return (int)GetCurrentProcessId(); }
static void* stub_shmat(int id, void* a, int f) { (void)id; (void)a; (void)f; return (void*)-1; }
static int   stub_shmdt(void* a) { (void)a; return -1; }
static int   stub_shmget(int k, size_t s, int f) { (void)k; (void)s; (void)f; return -1; }
static int   stub_memfd_create(const char* n, unsigned f) { (void)n; (void)f; return -1; }
static long  stub_ptrace(int r, int p, void* a, void* d) { (void)r; (void)p; (void)a; (void)d; return -1; }
static int   stub_seccomp(unsigned o, unsigned f, void* a) { (void)o; (void)f; (void)a; return 0; }
static int   stub_landlock_create(void* a, size_t s, unsigned f) { (void)a; (void)s; (void)f; return -1; }
static int   stub_isoc99_sscanf(const char* s, const char* f, ...)
{
    va_list a; va_start(a, f); int n = vsscanf(s, f, a); va_end(a); return n;
}
static unsigned long long stub_isoc23_strtoull(const char* s, char** e, int b)
{
    return strtoull(s, e, b);
}
static long long stub_isoc23_strtoll(const char* s, char** e, int b)
{
    return strtoll(s, e, b);
}
static unsigned long stub_isoc23_strtoul2(const char* s, char** e, int b)
{
    return strtoul(s, e, b);
}
static long stub_isoc23_strtol(const char* s, char** e, int b)
{
    return strtol(s, e, b);
}
typedef struct {
    char* pw_name; char* pw_passwd; unsigned pw_uid; unsigned pw_gid;
    char* pw_gecos; char* pw_dir; char* pw_shell;
} linux_passwd;
typedef struct { char* gr_name; char* gr_passwd; unsigned gr_gid; char** gr_mem; } linux_group;


static void init_user_info(void)
{
    /* Get real Windows username */
    DWORD sz = sizeof(g_username);
    if (!GetUserNameA(g_username, &sz))
        strcpy(g_username, "user");

    /* Build home dir from username */
    snprintf(g_homedir, sizeof(g_homedir), "/home/%s", g_username);
}

static linux_passwd g_fake_passwd;
static linux_group  g_fake_group;

static void init_fake_identity(void)
{
    init_user_info();
    /* If running as Windows admin, present as root (uid=0) */
    unsigned uid = mine_uid();
    unsigned gid = mine_gid();
    char* name = (uid == 0) ? (char*)"root" : g_username;
    char* home = (uid == 0) ? (char*)"/root" : g_homedir;

    g_fake_passwd.pw_name = name;
    g_fake_passwd.pw_passwd = (char*)"x";
    g_fake_passwd.pw_uid = uid;
    g_fake_passwd.pw_gid = gid;
    g_fake_passwd.pw_gecos = name;
    g_fake_passwd.pw_dir = home;
    g_fake_passwd.pw_shell = (char*)"/bin/bash";

    g_fake_group.gr_name = name;
    g_fake_group.gr_passwd = (char*)"x";
    g_fake_group.gr_gid = gid;
    g_fake_group.gr_mem = NULL;
}

static linux_passwd* stub_getpwuid(unsigned uid) { (void)uid; return &g_fake_passwd; }
static linux_passwd* stub_getpwnam(const char* n) { (void)n;  return &g_fake_passwd; }
static linux_group* stub_getgrgid(unsigned gid) { (void)gid; return &g_fake_group; }
static linux_group* stub_getgrnam(const char* n) { (void)n;   return &g_fake_group; }
static int   stub_getgroups(int sz, unsigned* buf)
{
    (void)sz; (void)buf; return 0;
}  /* 0 supplementary groups avoids enumeration crash */
static int   stub_getgrouplist(const char* u, unsigned g, unsigned* gs, int* ngs)
{
    (void)u; (void)g; if (gs && *ngs > 0) gs[0] = 1000; *ngs = 1; return 1;
}
static void  stub_endpwent(void) {}
static void  stub_endgrent(void) {}

/* Additional C runtime stubs */
static void* stub_reallocarray(void* p, size_t n, size_t s)
{
    return realloc(p, n * s);
}
static char* stub_getenv(const char* n)
{
    return getenv(n);
}
static long  stub_sysconf(int n) { (void)n; return 4096; }
static int   stub_fileno(void* f) { return file_fd(f); }
static int   stub_fseeko(void* f, int64_t off, int w)
{
    (void)f; (void)off; (void)w; return 0;
}
static size_t stub_fwrite(const void* p, size_t sz, size_t n, void* f)
{
    size_t total = sz * n;
    stub_write_fd(file_fd(f), p, total);
    return n;
}
static int stub_fputs_unlocked(const char* s, void* f)
{
    if (!s) return 0; return stub_write_fd(file_fd(f), s, strlen(s));
}
static int stub_fputc_unlocked(int c, void* f)
{
    if (c == 0) return 0; /* skip null bytes */ char ch = (char)c; stub_write_fd(file_fd(f), &ch, 1); return c;
}
static int stub_nl_langinfo(int item) { (void)item; return 0; }
static int stub_mbrtoc32(void* pc, const char* s, size_t n, void* ps)
{
    (void)pc; (void)s; (void)n; (void)ps; return 0;
}
static int stub_mbsinit(const void* ps) { (void)ps; return 1; }
static int stub_iswprint(unsigned wc) { return wc >= 0x20 && wc != 0x7F; }
static size_t stub_ctype_get_mb_cur_max(void) { return 1; }
static int stub_freading(void* f) { (void)f; return 0; }
static int stub_overflow(int c, void* f) { char ch = (char)c; stub_write_fd(file_fd(f), &ch, 1); return c; }
static int stub_lseek(int fd, int64_t off, int w)
{
    return (int)_lseeki64(fd, off, w);
}
static int stub_getcon(char** ctx) { if (ctx) *ctx = NULL; return -1; }
static int stub_is_selinux_enabled(void) { return 0; }
static int stub_isoc23_strtoul(const char* s, char** e, int b)
{
    return (int)strtoul(s, e, b);
}

/* i18n stubs */
static char* stub_textdomain(const char* d) { (void)d; return (char*)""; }
static char* stub_bindtextdomain(const char* d, const char* p) { (void)d; (void)p; return (char*)""; }
static char* stub_dcgettext(const char* d, const char* s, int c) { (void)d; (void)c; return (char*)s; }
static int   stub_fputs(const char* s, void* f) { return stub_write_fd(file_fd(f), s, strlen(s)); }

/*
 * procps / libproc2 stubs for uptime.
 *
 * procps_uptime(double* uptime_secs, double* idle_secs) -> int (0 on success)
 *   Fills uptime and idle seconds from system boot time.
 *
 * procps_uptime_sprint() -> char*
 *   Returns a string like " 14:32:01 up 2:15,  1 user,  load average: 0.00, 0.00, 0.00"
 *
 * procps_uptime_sprint_short() -> char*
 *   Returns abbreviated form like " 2:15"
 */
static int stub_procps_uptime(double* up, double* idle)
{
    /* Get system uptime via GetTickCount64 (milliseconds since boot) */
    ULONGLONG ticks = GetTickCount64();
    double secs = (double)ticks / 1000.0;
    if (up)   *up = secs;
    if (idle) *idle = 0.0;
    return 0;
}

static const char* stub_procps_uptime_sprint(void)
{
    static char buf[128];
    ULONGLONG ticks = GetTickCount64();
    uint64_t total_secs = ticks / 1000ULL;
    uint64_t days = total_secs / 86400ULL;
    uint64_t hours = (total_secs % 86400ULL) / 3600ULL;
    uint64_t mins = (total_secs % 3600ULL) / 60ULL;

    SYSTEMTIME st; GetLocalTime(&st);

    if (days > 0)
        snprintf(buf, sizeof(buf),
            " %02u:%02u:%02u up %llu day%s, %llu:%02llu,  1 user,  load average: 0.00, 0.00, 0.00",
            st.wHour, st.wMinute, st.wSecond,
            (unsigned long long)days, days == 1 ? "" : "s",
            (unsigned long long)hours, (unsigned long long)mins);
    else
        snprintf(buf, sizeof(buf),
            " %02u:%02u:%02u up %llu:%02llu,  1 user,  load average: 0.00, 0.00, 0.00",
            st.wHour, st.wMinute, st.wSecond,
            (unsigned long long)hours, (unsigned long long)mins);
    return buf;
}

static const char* stub_procps_uptime_sprint_short(void)
{
    static char buf[64];
    ULONGLONG ticks = GetTickCount64();
    uint64_t total_secs = ticks / 1000ULL;
    uint64_t days = total_secs / 86400ULL;
    uint64_t hours = (total_secs % 86400ULL) / 3600ULL;
    uint64_t mins = (total_secs % 3600ULL) / 60ULL;

    if (days > 0)
        snprintf(buf, sizeof(buf), " %llu day%s, %llu:%02llu",
            (unsigned long long)days, days == 1 ? "" : "s",
            (unsigned long long)hours, (unsigned long long)mins);
    else
        snprintf(buf, sizeof(buf), " %llu:%02llu",
            (unsigned long long)hours, (unsigned long long)mins);
    return buf;
}

/* ─── __libc_start_main ───────────────────────────────────────────────────── */
typedef int(*main_fn_t)(int, char**, char**);
static char** g_envp = NULL;
extern void MineWinToLinux(void);

/*
 * g_saved_guest_fs: written by arch_prctl(ARCH_SET_FS) via MineDynSetGuestFS().
 * Declared BEFORE call_linux_fn3 so it is visible when that function uses it.
 * Plain C static — no ASM symbol sharing needed.
 */
static uint64_t g_saved_guest_fs = 0;

/* DT_INIT_ARRAY deferred until stub_libc_start_main has argc/argv */
#define MAX_INIT_ARRAY 32
static uint64_t g_init_array[MAX_INIT_ARRAY];
static int      g_init_array_count = 0;

/*
 * call_linux_fn3: call a Linux-ABI function from Windows code.
 * Restores guest FS as the very last step before jumping to Linux code.
 */
static int call_linux_fn3(void* fn, uint64_t a1, uint64_t a2, uint64_t a3)
{
    typedef int (*win_fn_t)(void*, uint64_t, uint64_t, uint64_t);
    restore_fs(g_saved_guest_fs);
    return ((win_fn_t)MineWinToLinux)(fn, a1, a2, a3);
}

void MineDynSetGuestFS(uint64_t fs)
{
    g_saved_guest_fs = fs;
}

uint64_t MineGetGuestFS(void)
{
    return g_saved_guest_fs;
}

static int stub_libc_start_main(main_fn_t m, int argc, char** argv,
    void* init, void* fini, void* r, void* s)
{
    (void)r; (void)s; (void)fini;

    uint64_t win_fs = save_fs();

    /* The 'init' parameter is __libc_csu_init which expects (argc,argv,envp).
     * Call it via Linux ABI using MineWinToLinux. */
    if (init) {
        typedef int (*win_fn_t)(void*, uint64_t, uint64_t, uint64_t);
        ((win_fn_t)MineWinToLinux)(init,
            (uint64_t)argc,
            (uint64_t)(uintptr_t)argv,
            (uint64_t)(uintptr_t)g_envp);
        g_saved_guest_fs = save_fs();
        restore_fs(win_fs);
    }

    /* DT_INIT_ARRAY constructors are __attribute__((constructor)) functions.
     * They take NO arguments (void fn(void)).
     * Passing argc=2 in RDI caused crashes because some constructors
     * treated RDI as a string pointer. Call with zero args. */
    for (int k = 0; k < g_init_array_count; k++) {
        uint64_t fn = g_init_array[k];
        if (fn && fn != (uint64_t)-1) {
            typedef int (*win_fn_t)(void*, uint64_t, uint64_t, uint64_t);
            __try {
                ((win_fn_t)MineWinToLinux)((void*)(uintptr_t)fn, 0, 0, 0);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            g_saved_guest_fs = save_fs();
            restore_fs(win_fs);
        }
    }
    g_init_array_count = 0;

    int ret = call_linux_fn3((void*)m,
        (uint64_t)argc,
        (uint64_t)(uintptr_t)argv,
        (uint64_t)(uintptr_t)g_envp);
    TerminateProcess(GetCurrentProcess(), (UINT)ret);
    return 0;
}

/* ─── stub table ──────────────────────────────────────────────────────────── */
typedef struct { const char* name; void(*fn)(void); } SymStub;
#define MAX_STUBS 450
static SymStub s_stubs[MAX_STUBS];

static void init_stubs(void)
{
    int i = 0;
    reset_getopt();
    init_fake_identity();
#define S(nm,fp) do { s_stubs[i].name=(nm); s_stubs[i].fn=(void(*)(void))(fp); i++; } while(0)
    S("exit", stub_exit);
    S("_exit", stub_exit);
    S("abort", stub_abort);
    S("write", stub_write_fd);
    S("puts", stub_puts);
    S("fputs", stub_fputs);
    S("printf", stub_printf);
    S("fprintf", stub_fprintf);
    S("vprintf", stub_vprintf_w);
    S("vfprintf", stub_vfprintf_w);
    S("sprintf", stub_sprintf);
    S("snprintf", stub_snprintf);
    S("vsprintf", stub_vsprintf_w);
    S("vsnprintf", stub_vsnprintf_w);
    S("sscanf", stub_sscanf);
    S("__isoc99_sscanf", stub_sscanf);
    S("__printf_chk", stub_printf_chk);
    S("__fprintf_chk", stub_fprintf_chk);
    S("__snprintf_chk", stub_snprintf_chk);
    S("__sprintf_chk", stub_sprintf_chk);
    S("__memcpy_chk", stub_memcpy_chk);
    S("malloc", stub_malloc);
    S("free", stub_free);
    S("calloc", stub_calloc);
    S("realloc", stub_realloc);
    S("strdup", stub_strdup);
    S("memcpy", stub_memcpy_w);
    S("memmove", stub_memmove_w);
    S("memset", stub_memset_w);
    S("memcmp", stub_memcmp_w);
    S("memchr", stub_memchr_w);
    S("strlen", stub_strlen_w);
    S("strcmp", stub_strcmp_w);
    S("strncmp", stub_strncmp_w);
    S("strcpy", stub_strcpy_w);
    S("strncpy", stub_strncpy_w);
    S("strcat", stub_strcat_w);
    S("strncat", stub_strncat_w);
    S("strchr", stub_strchr_w);
    S("strrchr", stub_strrchr_w);
    S("strstr", stub_strstr_w);
    S("strerror", stub_strerror_w);
    S("atoi", stub_atoi_w);
    S("atol", stub_atol_w);
    S("strtol", stub_strtol_w);
    S("strtoul", stub_strtoul_w);
    S("strtod", stub_strtod_w);
    S("rand", stub_rand_w);
    S("srand", stub_srand_w);
    S("fflush", stub_fflush);
    S("fclose", stub_fclose);
    S("ferror", stub_ferror);
    S("putc", stub_putc);
    S("setbuf", stub_setbuf);
    S("isatty", stub_isatty);
    S("__fpending", stub_fpending);
    S("setlocale", stub_setlocale);
    S("getopt", stub_getopt_real);
    S("getopt_long", stub_getopt_long);
    S("getpid", stub_getpid);
    S("getuid", stub_getuid);
    S("geteuid", stub_geteuid);
    S("setuid", stub_setuid);
    S("clock_gettime", stub_clock_gettime);
    S("gettimeofday", stub_gettimeofday);
    S("setitimer", stub_setitimer);
    S("nanosleep", stub_setitimer);
    S("sigaction", stub_sigaction);
    S("sigprocmask", stub_sigprocmask);
    S("sigemptyset", stub_sigemptyset);
    S("raise", stub_raise);
    S("prctl", stub_prctl);
    S("ioctl", stub_ioctl);
    S("sched_yield", stub_sched_yield);
    S("error", stub_error);
    S("getrandom", stub_getrandom);
    S("socket", stub_socket);
    S("bind", stub_bind);
    S("connect", stub_connect);
    S("close", stub_close_sock);
    S("setsockopt", stub_setsockopt);
    S("getsockopt", stub_getsockopt);
    S("getsockname", stub_getsockname);
    S("sendto", stub_sendto);
    S("sendmsg", stub_sendmsg);
    S("recvmsg", stub_recvmsg);
    S("poll", stub_poll);
    S("inet_ntoa", stub_inet_ntoa);
    S("inet_pton", stub_inet_pton);
    S("inet_ntop", stub_inet_ntop);
    S("inet_aton", stub_inet_aton);
    S("getaddrinfo", stub_getaddrinfo);
    S("freeaddrinfo", stub_freeaddrinfo);
    S("getnameinfo", stub_getnameinfo);
    S("gai_strerror", stub_gai_strerror);
    S("if_nametoindex", stub_if_nametoindex);
    S("getifaddrs", stub_getifaddrs);
    S("freeifaddrs", stub_freeifaddrs);
    S("idn2_strerror", stub_idn2_strerror);
    S("idn2_lookup_ul", stub_idn2_lookup_ul);
    S("dn_comp", stub_dn_comp);
    S("dn_expand", stub_dn_expand);
    S("__assert_fail", stub_assert_fail);
    S("__ctype_b_loc", stub_ctype_b_loc);
    S("__ctype_tolower_loc", stub_ctype_tolower_loc);
    S("_setjmp", stub_setjmp);
    S("__longjmp_chk", stub_longjmp_chk);
    S("cap_init", stub_cap_init);
    S("cap_free", stub_cap_free);
    S("cap_get_proc", stub_cap_get_proc);
    S("cap_set_proc", stub_cap_set_proc);
    S("cap_get_flag", stub_cap_get_flag);
    S("cap_set_flag", stub_cap_set_flag);
    S("__errno_location", stub_errno_loc);
    S("__stack_chk_fail", stub_stack_chk);
    S("__cxa_finalize", stub_noop);
    S("__cxa_atexit", stub_noop);
    S("_ITM_deregisterTMCloneTable", stub_noop);
    S("_ITM_registerTMCloneTable", stub_noop);
    S("__gmon_start__", stub_noop);
    S("_Jv_RegisterClasses", stub_noop);
    S("scanf", stub_scanf_w);
    S("__isoc99_scanf", stub_scanf_w);
    S("fscanf", stub_fscanf_w);
    S("__isoc99_fscanf", stub_fscanf_w);
    S("strpbrk", stub_strpbrk_w);
    S("strtok", stub_strtok_w);
    S("strtof", stub_strtof_w);
    S("strtold", stub_strtold_w);
    S("strtoll", stub_strtoll_w);
    S("strtoull", stub_strtoull_w);
    S("isdigit", stub_isdigit_w);
    S("isalpha", stub_isalpha_w);
    S("isspace", stub_isspace_w);
    S("isupper", stub_isupper_w);
    S("islower", stub_islower_w);
    S("isprint", stub_isprint_w);
    S("toupper", stub_toupper_w);
    S("tolower", stub_tolower_w);
    S("sqrt", stub_sqrt_w);
    S("pow", stub_pow_w);
    S("floor", stub_floor_w);
    S("ceil", stub_ceil_w);
    S("fabs", stub_fabs_w);
    /* i18n */
    S("textdomain", stub_textdomain);
    S("bindtextdomain", stub_bindtextdomain);
    S("dcgettext", stub_dcgettext);
    /* procps / libproc2 — needed by uptime */
    S("procps_uptime", stub_procps_uptime);
    S("procps_uptime_sprint", stub_procps_uptime_sprint);
    S("procps_uptime_sprint_short", stub_procps_uptime_sprint_short);
    /* localtime family */
    S("localtime", stub_localtime);
    S("localtime_r", stub_localtime_r);
    S("gmtime", stub_gmtime);
    S("mktime", stub_mktime);
    S("strftime", stub_strftime_noop);
    S("ctime", stub_ctime);
    S("time", stub_time);
    S("alarm", stub_alarm);
    S("nanosleep", stub_nanosleep2);
    /* file I/O */
    S("open", stub_open);
    S("close", stub_close2);
    S("read", stub_read);
    S("lseek64", stub_lseek64);
    S("stat", stub_stat);
    S("fstat", stub_fstat);
    S("access", stub_access);
    S("unlink", stub_unlink);
    S("mkdir", stub_mkdir);
    S("rmdir", stub_rmdir);
    S("getcwd", stub_getcwd);
    S("chdir", stub_chdir);
    S("opendir", stub_opendir);
    S("readdir", stub_readdir);
    S("closedir", stub_closedir);
    S("truncate", stub_truncate);
    S("ftruncate", stub_ftruncate);
    S("chmod", stub_chmod);
    S("fchmod", stub_fchmod);
    S("rename", stub_rename);
    S("link", stub_link);
    S("symlink", stub_symlink);
    S("readlink", stub_readlink);
    S("fopen", stub_fopen);
    S("fread", stub_fread);
    S("fgets", stub_fgets);
    S("feof", stub_feof);
    S("ftell", stub_ftell);
    S("fseek", stub_fseek);
    S("rewind", stub_rewind);
    /* memory / process */
    S("mmap", stub_mmap);
    S("munmap", stub_munmap);
    S("mprotect", stub_mprotect);
    S("madvise", stub_madvise);
    S("msync", stub_msync);
    S("mlockall", stub_mlockall);
    S("mlock", stub_mlock);
    S("fork", stub_fork);
    S("waitpid", stub_waitpid);
    S("execve", stub_execve);
    S("system", stub_system);
    S("pipe", stub_pipe);
    S("dup", stub_dup);
    S("dup2", stub_dup2);
    S("sleep", stub_sleep);
    S("usleep", stub_usleep);
    S("gethostname", stub_gethostname);
    S("uname", stub_uname);
    S("getrlimit", stub_getrlimit);
    S("setrlimit", stub_setrlimit);
    S("getrusage", stub_getrusage);
    S("getpgrp", stub_getpgrp);
    S("getppid", stub_getppid);
    S("setpgid", stub_setpgid);
    S("setsid", stub_setsid);
    S("kill", stub_kill);
    S("signal", stub_signal);
    S("umask", stub_umask);
    S("chown", stub_chown);
    S("lchown", stub_lchown);
    S("fchown", stub_fchown);
    /* string extras */
    S("strspn", stub_strspn_w);
    S("strcspn", stub_strcspn_w);
    S("strsep", stub_strsep);
    S("strcasecmp", stub_strcasecmp);
    S("strncasecmp", stub_strncasecmp);
    S("strndup", stub_strndup);
    S("asprintf", stub_asprintf);
    S("vasprintf", stub_vasprintf);
    S("wcstombs", stub_wcstombs);
    S("mbstowcs", stub_mbstowcs);
    S("isalnum", stub_isalnum_w);
    S("iscntrl", stub_iscntrl_w);
    S("ispunct", stub_ispunct_w);
    S("isxdigit", stub_isxdigit_w);
    S("isgraph", stub_isgraph_w);
    S("isblank", stub_isblank_w);
    /* math */
    S("sin", stub_sin_w);
    S("cos", stub_cos_w);
    S("tan", stub_tan_w);
    S("atan2", stub_atan2_w);
    S("log", stub_log_w);
    S("log2", stub_log2_w);
    S("log10", stub_log10_w);
    S("exp", stub_exp_w);
    S("exp2", stub_exp2_w);
    S("round", stub_round_w);
    S("fmod", stub_fmod_w);
    S("modf", stub_modf_w);
    S("frexp", stub_frexp_w);
    S("ldexp", stub_ldexp_w);
    S("hypot", stub_hypot_w);
    S("sinf", stub_sinf);
    S("cosf", stub_cosf);
    S("sqrtf", stub_sqrtf);
    S("fabsf", stub_fabsf);
    S("abs", stub_abs_w);
    S("labs", stub_labs_w);
    S("llabs", stub_llabs_w);
    /* network extras */
    S("recvfrom", stub_recvfrom);
    S("recv", stub_recv);
    S("send", stub_send);
    S("listen", stub_listen);
    S("accept", stub_accept);
    S("shutdown", stub_shutdown);
    S("select", stub_select);
    S("htonl", stub_htonl);
    S("htons", stub_htons);
    S("ntohl", stub_ntohl);
    S("ntohs", stub_ntohs);
    /* better recvmsg/sendmsg */
    S("recvmsg", stub_recvmsg2);
    S("sendmsg", stub_sendmsg2);
    /* dlopen */
    S("dlopen", stub_dlopen);
    S("dlsym", stub_dlsym);
    S("dlclose", stub_dlclose);
    S("dlerror", stub_dlerror);
    /* pthreads */
    S("pthread_create", stub_pthread_create);
    S("pthread_join", stub_pthread_join);
    S("pthread_mutex_init", stub_pthread_mutex_init);
    S("pthread_mutex_lock", stub_pthread_mutex_lock);
    S("pthread_mutex_unlock", stub_pthread_mutex_unlock);
    S("pthread_mutex_destroy", stub_pthread_mutex_destroy);
    S("pthread_key_create", stub_pthread_key_create);
    S("pthread_getspecific", stub_pthread_getspecific);
    S("pthread_setspecific", stub_pthread_setspecific);
    S("pthread_once", stub_pthread_once);
    S("pthread_self", stub_pthread_self);
    S("pthread_atfork", stub_pthread_atfork);
    S("pthread_exit", stub_pthread_exit);
    S("sem_init", stub_sem_init);
    S("sem_wait", stub_sem_wait);
    S("sem_post", stub_sem_post);
    S("sem_destroy", stub_sem_destroy);
    /* misc */
    S("qsort", stub_qsort_w);
    S("bsearch", stub_bsearch_w);
    S("longjmp", stub_longjmp_w);
    S("atexit", stub_atexit_w);
    S("perror", stub_perror);
    S("getlogin", stub_getlogin);
    S("ttyname", stub_ttyname);
    S("tcgetattr", stub_tcgetattr);
    S("tcsetattr", stub_tcsetattr);
    S("fcntl", stub_fcntl);
    S("epoll_create", stub_epoll_create);
    S("epoll_create1", stub_epoll_create);
    S("epoll_ctl", stub_epoll_ctl);
    S("epoll_wait", stub_epoll_wait);
    S("eventfd", stub_eventfd);
    S("signalfd", stub_signalfd);
    S("timerfd_create", stub_timerfd_create);
    S("inotify_init", stub_inotify_init);
    S("inotify_init1", stub_inotify_init);
    S("fallocate", stub_fallocate);
    S("posix_memalign", stub_posix_memalign);
    S("aligned_alloc", stub_aligned_alloc);
    S("getpagesize", stub_getpagesize);
    S("sysinfo", stub_sysinfo);
    S("setenv", stub_setenv);
    S("unsetenv", stub_unsetenv);
    S("clearenv", stub_clearenv);
    S("putenv", stub_putenv);
    S("sigfillset", stub_sigfillset);
    S("sigaddset", stub_sigaddset);
    S("sigdelset", stub_sigdelset);
    S("sigismember", stub_sigismember);
    S("sigwait", stub_sigwait);
    S("clone", stub_clone);
    S("getsid", stub_getsid);
    S("memfd_create", stub_memfd_create);
    S("seccomp", stub_seccomp);
    /* newer glibc versioned names */
    S("__isoc99_sscanf", stub_isoc99_sscanf);
    S("__isoc23_strtoull", stub_isoc23_strtoull);
    S("__isoc23_strtoll", stub_isoc23_strtoll);
    S("__isoc23_strtoul", stub_isoc23_strtoul2);
    S("__isoc23_strtol", stub_isoc23_strtol);
    /* passwd/group — for whoami, id */
    S("getpwuid", stub_getpwuid);
    S("getpwnam", stub_getpwnam);
    S("getgrgid", stub_getgrgid);
    S("getgrnam", stub_getgrnam);
    S("getgroups", stub_getgroups);
    S("getgrouplist", stub_getgrouplist);
    S("getgid", stub_getgid);
    S("getegid", stub_getegid);
    S("endpwent", stub_endpwent);
    S("endgrent", stub_endgrent);
    /* additional C runtime */
    S("reallocarray", stub_reallocarray);
    S("getenv", stub_getenv);
    S("sysconf", stub_sysconf);
    S("fileno", stub_fileno);
    S("fseeko", stub_fseeko);
    S("fwrite", stub_fwrite);
    S("fputs_unlocked", stub_fputs_unlocked);
    S("fputc_unlocked", stub_fputc_unlocked);
    S("nl_langinfo", stub_nl_langinfo);
    S("mbrtoc32", stub_mbrtoc32);
    S("mbsinit", stub_mbsinit);
    S("iswprint", stub_iswprint);
    S("__ctype_get_mb_cur_max", stub_ctype_get_mb_cur_max);
    S("__freading", stub_freading);
    S("__overflow", stub_overflow);
    S("lseek", stub_lseek);
    /* SELinux stubs — id uses these */
    S("getcon", stub_getcon);
    S("is_selinux_enabled", stub_is_selinux_enabled);
    /* newer glibc */
    S("__isoc23_strtoul", stub_isoc23_strtoul);
#undef S
    s_stubs[i].name = NULL;
    s_stubs[i].fn = NULL;
}

/* ─── symbol data table ───────────────────────────────────────────────────── */
typedef struct { const char* name; void* data; size_t size; } SymData;

/* __progname / __progname_full — used by uptime and other GNU tools */
static char* g_progname = (char*)"mine";
static char* g_progname_full = (char*)"mine";

#define SYM_DATA_COUNT 10
static SymData s_data[SYM_DATA_COUNT];

static void init_sym_data(void)
{
    int i = 0;
    s_data[i].name = "stdout";         s_data[i].data = &mine_stdout;      s_data[i].size = sizeof(void*); i++;
    s_data[i].name = "stderr";         s_data[i].data = &mine_stderr;      s_data[i].size = sizeof(void*); i++;
    s_data[i].name = "stdin";          s_data[i].data = &mine_stdin;       s_data[i].size = sizeof(void*); i++;
    s_data[i].name = "optind";         s_data[i].data = &g_optind;         s_data[i].size = sizeof(int);   i++;
    s_data[i].name = "optarg";         s_data[i].data = &g_optarg;         s_data[i].size = sizeof(char*); i++;
    s_data[i].name = "optopt";         s_data[i].data = &g_optopt;         s_data[i].size = sizeof(int);   i++;
    s_data[i].name = "opterr";         s_data[i].data = &g_opterr;         s_data[i].size = sizeof(int);   i++;
    s_data[i].name = "__progname";     s_data[i].data = &g_progname;       s_data[i].size = sizeof(char*); i++;
    s_data[i].name = "__progname_full"; s_data[i].data = &g_progname_full;  s_data[i].size = sizeof(char*); i++;
    s_data[i].name = NULL; s_data[i].data = NULL; s_data[i].size = 0;
}

static void* find_stub(const char* name)
{
    for (int i = 0; s_stubs[i].name; i++)
        if (strcmp(s_stubs[i].name, name) == 0)
            return MineThunkFor(s_stubs[i].fn);
    return NULL;
}

static const SymData* find_data(const char* name)
{
    for (int i = 0; s_data[i].name; i++)
        if (strcmp(s_data[i].name, name) == 0)
            return &s_data[i];
    return NULL;
}

/* ─── file helper ─────────────────────────────────────────────────────────── */
static bool fread_at(HANDLE fh, uint64_t off, void* buf, DWORD n)
{
    LARGE_INTEGER li = { 0 }; li.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(fh, li, NULL, FILE_BEGIN)) return false;
    DWORD got = 0; BOOL ok = ReadFile(fh, buf, n, &got, NULL);
    return ok && (got == n);
}

/* ─── apply one relocation ────────────────────────────────────────────────── */
static void apply_rela(const Elf64_Rela* r, uint64_t bias,
    const Elf64_Sym* symtab, const char* strtab)
{
    uint32_t    type = ELF64_R_TYPE(r->r_info);
    uint32_t    sym_idx = ELF64_R_SYM(r->r_info);
    uint64_t* target = (uint64_t*)(uintptr_t)(r->r_offset + bias);
    uint64_t    S = 0;
    int64_t     A = r->r_addend;
    const char* sym_name = NULL;
    DWORD       old = 0;

    if (sym_idx && symtab && strtab) {
        const Elf64_Sym* sym = &symtab[sym_idx];
        sym_name = strtab + sym->st_name;
        if (sym->st_value) S = sym->st_value + bias;
        if (!S && sym_name && *sym_name) {
            if (strcmp(sym_name, "__libc_start_main") == 0)
                S = (uint64_t)(uintptr_t)MineThunkFor((void*)stub_libc_start_main);
            else { void* st = find_stub(sym_name); if (st) S = (uint64_t)(uintptr_t)st; }
        }
        if ((type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT) && sym_name && !S) {
            /* Unknown symbol — install a safe no-op thunk so calling it
             * returns 0 instead of jumping to NULL and crashing. */
            S = (uint64_t)(uintptr_t)MineThunkFor((void*)stub_unresolved);
            fprintf(stderr, "[MinE-Dyn]   %-32s -> 0x%016llX  (stub)\n",
                sym_name, (unsigned long long)S);
        }
        else if ((type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT) && sym_name)
            fprintf(stderr, "[MinE-Dyn]   %-32s -> 0x%016llX\n",
                sym_name, (unsigned long long)S);
    }

    VirtualProtect(target, 8, PAGE_EXECUTE_READWRITE, &old);
    switch (type) {
    case R_X86_64_NONE:      break;
    case R_X86_64_RELATIVE:  *target = (uint64_t)((int64_t)bias + A); break;
    case R_X86_64_64:        *target = S + (uint64_t)A; break;
    case R_X86_64_GLOB_DAT:
    case R_X86_64_JUMP_SLOT: *target = S; break;
    case R_X86_64_COPY:
        if (sym_name) {
            const SymData* sd = find_data(sym_name);
            if (sd) {
                fprintf(stderr, "[MinE-Dyn]   COPY %-28s @ 0x%llX\n",
                    sym_name, (unsigned long long)(uintptr_t)target);
                VirtualProtect(target, sd->size, PAGE_READWRITE, &old);
                memcpy(target, sd->data, sd->size);
                MineRecordOptPtr(sym_name, target);
                break;
            }
            void* st = find_stub(sym_name);
            if (st) { memcpy(target, &st, sizeof(void*)); break; }
            fprintf(stderr, "[MinE-Dyn]   COPY unresolved: %s\n", sym_name);
        }
        break;
    case R_X86_64_IRELATIVE: {
        typedef uint64_t(*ifn)(void);
        ifn f = (ifn)(uintptr_t)((uint64_t)((int64_t)bias + A));
        __try { *target = f(); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    } break;
    default:
        fprintf(stderr, "[MinE-Dyn] Unknown reloc %u at 0x%llx\n",
            type, (unsigned long long)r->r_offset);
        break;
    }
    VirtualProtect(target, 8, old, &old);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * MineDynLink
 * ═══════════════════════════════════════════════════════════════════════════ */
bool MineDynLink(const char* path, MineImage* img)
{
    init_stubs();
    init_sym_data();
    g_envp = (char**)_environ;

    /* Set __progname to the binary filename (basename of path) */
    {
        const char* base = path;
        for (const char* p = path; *p; p++)
            if (*p == '/' || *p == '\\') base = p + 1;
        g_progname = g_progname_full = (char*)base;
    }

    MineThunkInit();

    HANDLE fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return false;

    Elf64_Ehdr ehdr; memset(&ehdr, 0, sizeof(ehdr));
    if (!fread_at(fh, 0, &ehdr, (DWORD)sizeof(ehdr))) { CloseHandle(fh); return false; }

    DWORD ph_bytes = (DWORD)ehdr.e_phnum * (DWORD)ehdr.e_phentsize;
    Elf64_Phdr* phdrs = (Elf64_Phdr*)calloc(1, (size_t)ph_bytes + 8);
    if (!phdrs) { CloseHandle(fh); return false; }
    if (!fread_at(fh, ehdr.e_phoff, phdrs, ph_bytes))
    {
        free(phdrs); CloseHandle(fh); return false;
    }
    CloseHandle(fh);

    uint64_t dyn_va = 0;
    for (int i = 0; i < (int)ehdr.e_phnum; i++)
        if (phdrs[i].p_type == PT_DYNAMIC)
        {
            dyn_va = phdrs[i].p_vaddr + img->load_bias; break;
        }
    free(phdrs);

    if (!dyn_va) { printf("[MinE-Dyn] Static binary\n"); return true; }

#define BIAS_ADDR(v) (((v)>=img->base&&(v)<img->base+0x800000ULL)?(v):(v)+img->load_bias)

    Elf64_Dyn* dyn = (Elf64_Dyn*)(uintptr_t)dyn_va;
    uint64_t strtab = 0, symtab = 0, rela = 0, relasz = 0, jmprel = 0, pltrelsz = 0;
    uint64_t init_fn = 0, init_arr = 0, init_arr_sz = 0;

    for (Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        switch ((uint64_t)d->d_tag) {
        case DT_STRTAB:       strtab = BIAS_ADDR(d->d_val); break;
        case DT_SYMTAB:       symtab = BIAS_ADDR(d->d_val); break;
        case DT_RELA:         rela = BIAS_ADDR(d->d_val); break;
        case DT_RELASZ:       relasz = d->d_val;            break;
        case DT_JMPREL:       jmprel = BIAS_ADDR(d->d_val); break;
        case DT_PLTRELSZ:     pltrelsz = d->d_val;            break;
        case DT_INIT:         init_fn = BIAS_ADDR(d->d_val); break;
        case DT_INIT_ARRAY:   init_arr = BIAS_ADDR(d->d_val); break;
        case DT_INIT_ARRAYSZ: init_arr_sz = d->d_val;            break;
        default: break;
        }
    }

    if (strtab)
        for (Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++)
            if (d->d_tag == DT_NEEDED)
                printf("[MinE-Dyn] Requires: %s\n",
                    (const char*)(uintptr_t)(strtab + d->d_val));

    fprintf(stderr,
        "[MinE-Dyn] strtab=0x%llX symtab=0x%llX\n"
        "[MinE-Dyn] rela=0x%llX sz=%llu  plt=0x%llX sz=%llu\n",
        (unsigned long long)strtab, (unsigned long long)symtab,
        (unsigned long long)rela, (unsigned long long)relasz,
        (unsigned long long)jmprel, (unsigned long long)pltrelsz);

    const Elf64_Sym* sym_table = symtab ? (const Elf64_Sym*)(uintptr_t)symtab : NULL;
    const char* str_table = strtab ? (const char*)(uintptr_t)strtab : NULL;

    if (rela && relasz) {
        uint64_t n = relasz / sizeof(Elf64_Rela);
        printf("[MinE-Dyn] .rela.dyn  %llu relocations\n", (unsigned long long)n);
        Elf64_Rela* rels = (Elf64_Rela*)(uintptr_t)rela;
        for (uint64_t i = 0; i < n; i++)
            apply_rela(&rels[i], img->load_bias, sym_table, str_table);
    }

    if (jmprel && pltrelsz) {
        uint64_t n = pltrelsz / sizeof(Elf64_Rela);
        printf("[MinE-Dyn] .rela.plt  %llu relocations\n", (unsigned long long)n);
        Elf64_Rela* rels = (Elf64_Rela*)(uintptr_t)jmprel;
        for (uint64_t i = 0; i < n; i++)
            apply_rela(&rels[i], img->load_bias, sym_table, str_table);
    }

    if (init_fn) {
        printf("[MinE-Dyn] DT_INIT @ 0x%llX\n", (unsigned long long)init_fn);
        /* DT_INIT (_init) is just frame setup — safe to call with no meaningful args */
        uint64_t fs = save_fs();
        __try { ((void(*)(void))(uintptr_t)init_fn)(); }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            fprintf(stderr, "[MinE-Dyn] DT_INIT faulted\n");
        }
        g_saved_guest_fs = save_fs();
        restore_fs(fs);
    }

    /* Defer INIT_ARRAY to stub_libc_start_main which has correct argc/argv/envp.
     * Calling init_array functions here with no args causes crashes in programs
     * like ping whose init_array accesses argv[0] for program name setup. */
    if (init_arr && init_arr_sz) {
        uint64_t n = init_arr_sz / sizeof(uint64_t);
        uint64_t* arr = (uint64_t*)(uintptr_t)init_arr;
        g_init_array_count = 0;
        for (uint64_t i = 0; i < n; i++) {
            if (arr[i] && arr[i] != (uint64_t)-1 &&
                g_init_array_count < MAX_INIT_ARRAY) {
                g_init_array[g_init_array_count++] = arr[i];
            }
        }
        if (g_init_array_count)
            printf("[MinE-Dyn] Deferred %d INIT_ARRAY fn(s) to libc_start_main\n",
                g_init_array_count);
    }

    printf("[MinE-Dyn] Dynamic linking complete\n");

    return true;
}