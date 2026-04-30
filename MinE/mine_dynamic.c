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
    if ((uintptr_t)s < 0x1000) {
        /* Print the return address (caller's next instruction) so we can
           identify exactly which instruction in ping called strlen(bad_ptr) */
        void* caller = _ReturnAddress();
        fprintf(stderr,
            "[MinE-DBG] strlen(0x%llX) -- caller RIP=0x%llX -- returning 0\n",
            (unsigned long long)(uintptr_t)s,
            (unsigned long long)(uintptr_t)caller);
        fflush(stderr);
        return 0;
    }
    return strlen(s);
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
static unsigned stub_getuid(void) { return 1000; }
static unsigned stub_geteuid(void) { return 1000; }
static int      stub_setuid(unsigned u) { (void)u; return 0; }

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
    fprintf(stderr, "[MinE-DBG] socket(domain=%d, type=%d, proto=%d)\n", d, t, p);
    SOCKET s = socket(d, t & 0xF, p);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "[MinE-DBG] socket() FAILED WSAErr=%d -> returning -1\n", WSAGetLastError());
        return -1;
    }
    int fd = _open_osfhandle((intptr_t)s, 0);
    if (fd < 0) { closesocket(s); return -1; }
    fprintf(stderr, "[MinE-DBG] socket() -> fd=%d\n", fd);
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
    fprintf(stderr, "[MinE-DBG] getaddrinfo('%s', '%s', hints=%p)\n",
        n ? n : "(null)", s ? s : "(null)", hints_linux);
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
    fprintf(stderr, "[MinE-DBG] idn2_lookup_ul('%s')\n", s ? s : "(null)");
    (void)f;
    if (!s) { *r = NULL; return 1; }
    *r = _strdup(s);
    fprintf(stderr, "[MinE-DBG] idn2_lookup_ul -> '%s'\n", *r);
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
static int  stub_getopt_real(int ac, char* const* av, const char* opts) { (void)ac; (void)av; (void)opts; return -1; }
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
    if (init) {
        uint64_t fs = save_fs();
        ((void(*)(void))init)();
        /* After init, arch_prctl may have set a new FS. Save it. */
        g_saved_guest_fs = save_fs();
        restore_fs(fs);  /* temporarily restore Windows FS for our code */
    }
    /* call_linux_fn3 will restore g_saved_guest_fs before jumping to main */
    int ret = call_linux_fn3((void*)m,
        (uint64_t)argc,
        (uint64_t)(uintptr_t)argv,
        (uint64_t)(uintptr_t)g_envp);
    TerminateProcess(GetCurrentProcess(), (UINT)ret);
    return 0;
}

/* ─── stub table ──────────────────────────────────────────────────────────── */
typedef struct { const char* name; void(*fn)(void); } SymStub;
#define MAX_STUBS 165
static SymStub s_stubs[MAX_STUBS];

static void init_stubs(void)
{
    int i = 0;
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
    S("getopt_long", stub_getopt_real);
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
    /* localtime — stub returning NULL is safe, caller checks */
    S("localtime", stub_unresolved);
#undef S
    s_stubs[i].name = NULL;
    s_stubs[i].fn = NULL;
}

/* ─── symbol data table ───────────────────────────────────────────────────── */
typedef struct { const char* name; void* data; size_t size; } SymData;
static int   g_optind = 1, g_optopt = 0, g_opterr = 1;
static char* g_optarg = NULL;

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
        if ((type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT) && sym_name)
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
                memcpy(target, sd->data, sd->size); break;
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
        uint64_t fs = save_fs();
        __try { ((void(*)(void))(uintptr_t)init_fn)(); }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            fprintf(stderr, "[MinE-Dyn] DT_INIT faulted\n");
        }
        /* Capture FS that DT_INIT may have set via arch_prctl */
        g_saved_guest_fs = save_fs();
        restore_fs(fs);
    }

    if (init_arr && init_arr_sz) {
        uint64_t n = init_arr_sz / sizeof(uint64_t);
        uint64_t* arr = (uint64_t*)(uintptr_t)init_arr;
        for (uint64_t i = 0; i < n; i++) {
            if (arr[i] && arr[i] != (uint64_t)-1) {
                uint64_t fs = save_fs();
                __try { ((void(*)(void))(uintptr_t)arr[i])(); }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
                g_saved_guest_fs = save_fs();
                restore_fs(fs);
            }
        }
    }

    printf("[MinE-Dyn] Dynamic linking complete\n");
 
    return true;
}