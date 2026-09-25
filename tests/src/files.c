#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)
int main(void) {
    const char* p = "mine_test_file.txt";
    int fd = open(p, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    CHECK(fd >= 3);
    CHECK(write(fd, "0123456789", 10) == 10);
    CHECK(close(fd) == 0);
    struct stat st; CHECK(stat(p, &st) == 0); CHECK(st.st_size == 10); CHECK(S_ISREG(st.st_mode));
    fd = open(p, O_RDONLY); CHECK(fd >= 0);
    char b[16] = {0};
    CHECK(lseek(fd, 3, SEEK_SET) == 3);
    CHECK(read(fd, b, 4) == 4); CHECK(memcmp(b, "3456", 4) == 0);
    CHECK(pread(fd, b, 2, 8) == 2); CHECK(memcmp(b, "89", 2) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_size == 10);
    close(fd);
    FILE* f = fopen(p, "a"); CHECK(f); fputs("abc\n", f); fclose(f);
    CHECK(stat(p, &st) == 0 && st.st_size == 14);
    DIR* d = opendir("."); CHECK(d);
    int found = 0; struct dirent* e;
    while ((e = readdir(d))) if (!strcmp(e->d_name, p)) found = 1;
    closedir(d); CHECK(found);
    CHECK(access(p, R_OK) == 0);
    CHECK(rename(p, "mine_test_file2.txt") == 0);
    CHECK(unlink("mine_test_file2.txt") == 0);
    CHECK(open("does/not/exist", O_RDONLY) == -1);
    CHECK(mkdir("mine_test_dir", 0755) == 0 && rmdir("mine_test_dir") == 0);
    char cwd[512]; CHECK(getcwd(cwd, sizeof cwd)); CHECK(cwd[0] == '/');
    printf("cwd=%s\nfiles: PASS\n", cwd);
    return 0;
}
