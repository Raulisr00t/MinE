#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)
int main(void) {
    /* many small + some large allocations (brk + mmap paths) */
    void* ps[1000];
    for (int i = 0; i < 1000; i++) { ps[i] = malloc(16 + i * 37); CHECK(ps[i]); memset(ps[i], i & 0xff, 16 + i * 37); }
    for (int i = 0; i < 1000; i += 2) free(ps[i]);
    char* big = malloc(64 << 20); CHECK(big); memset(big, 1, 64 << 20); free(big);
    /* 4K-granular mmap/munmap/mprotect semantics */
    char* m = mmap(0, 16 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(m != MAP_FAILED);
    for (int i = 0; i < 16; i++) CHECK(m[i * 4096] == 0);
    m[5 * 4096] = 7;
    CHECK(munmap(m + 4 * 4096, 4096) == 0);                 /* hole in the middle */
    CHECK(mprotect(m, 4096, PROT_READ) == 0);
    char* f = mmap(m + 4 * 4096, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(f == m + 4 * 4096); CHECK(f[0] == 0); CHECK(m[5 * 4096] == 7);
    /* reserve big, touch sparse (lazy commit) */
    char* r = mmap(0, 1ul << 32, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    CHECK(r != MAP_FAILED); r[0] = 1; r[(1ul << 32) - 1] = 2; CHECK(munmap(r, 1ul << 32) == 0);
    printf("mem: PASS\n");
    return 0;
}
