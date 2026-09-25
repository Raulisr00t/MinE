#include <stdio.h>
#include <errno.h>
#include <unistd.h>
__thread int tvar = 42;
__thread char tbuf[64] = "tls-init";
int main(void) {
    int ok = 1;
    for (int i = 0; i < 2000000; i++) { tvar++; if (i % 100000 == 0) usleep(1); }
    ok &= tvar == 42 + 2000000;
    errno = 0; close(-1); ok &= errno == EBADF;
    printf("tvar=%d tbuf=%s errno-ok=%d => %s\n", tvar, tbuf, errno == EBADF, ok ? "PASS" : "FAIL");
    return !ok;
}
