#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>
int main(int argc, char** argv, char** envp) {
    for (int i = 0; i < argc; i++) printf("argv[%d]=%s\n", i, argv[i]);
    printf("HOME=%s\n", getenv("HOME") ? getenv("HOME") : "(null)");
    printf("AT_PAGESZ=%lu AT_RANDOM=%s\n", getauxval(AT_PAGESZ), getauxval(AT_RANDOM) ? "set" : "missing");
    return argc == 3 ? 0 : 1;
}
