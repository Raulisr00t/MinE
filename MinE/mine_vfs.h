#ifndef MINE_VFS_H
#define MINE_VFS_H

#include <Windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

    /* Call once at startup with the ELF path passed to MinE */
    void MineVFSInit(const char* elf_path);

    /*
     * Translate a Linux path to a Windows path.
     * Returns a pointer to a static buffer (NOT thread-safe).
     * If the path is a virtual file (/proc, /dev), returns NULL
     * and sets *virt_type to the virtual file type.
     *
     * virt_type values:
     *   0 = real file (translated path returned)
     *   1 = /dev/null
     *   2 = /dev/zero
     *   3 = /dev/urandom or /dev/random
     *   4 = /dev/stdin
     *   5 = /dev/stdout
     *   6 = /dev/stderr
     *  10 = /proc/self/exe       (readlink target)
     *  11 = /proc/self/status    (readable virtual)
     *  12 = /proc/self/maps      (readable virtual)
     *  13 = /proc/self/stat      (readable virtual)
     *  14 = /proc/self/cmdline   (readable virtual)
     *  15 = /proc/self/fd/<n>    (readable virtual)
     *  16 = /proc/meminfo        (readable virtual)
     *  17 = /proc/cpuinfo        (readable virtual)
     *  18 = /proc/stat           (readable virtual)
     *  19 = /proc/uptime         (readable virtual)
     *  20 = /proc/loadavg        (readable virtual)
     *  21 = /proc/version        (readable virtual)
     *  22 = /proc/sys/*          (readable virtual)
     *  30 = /dev/tty
     *  31 = /dev/ptmx
     *  99 = unknown virtual (return ENOENT)
     */
#define VFS_REAL            0
#define VFS_DEV_NULL        1
#define VFS_DEV_ZERO        2
#define VFS_DEV_URANDOM     3
#define VFS_DEV_STDIN       4
#define VFS_DEV_STDOUT      5
#define VFS_DEV_STDERR      6
#define VFS_PROC_SELF_EXE   10
#define VFS_PROC_SELF_STATUS 11
#define VFS_PROC_SELF_MAPS  12
#define VFS_PROC_SELF_STAT  13
#define VFS_PROC_SELF_CMDLINE 14
#define VFS_PROC_SELF_FD    15
#define VFS_PROC_MEMINFO    16
#define VFS_PROC_CPUINFO    17
#define VFS_PROC_STAT       18
#define VFS_PROC_UPTIME     19
#define VFS_PROC_LOADAVG    20
#define VFS_PROC_VERSION    21
#define VFS_PROC_SYS        22
#define VFS_DEV_TTY         30
#define VFS_DEV_PTMX        31
#define VFS_PROC_MOUNTS     23
#define VFS_ETC_PASSWD      40
#define VFS_ETC_GROUP       41
#define VFS_ETC_NSSWITCH    42
#define VFS_UNKNOWN         99

    const char* MineVFSTranslate(const char* linux_path, int* virt_type);

    /*
     * Open a virtual file. Returns a synthetic fd (>= MINE_VFD_BASE)
     * that can be read/closed via MineVFSRead/MineVFSClose.
     * Returns -1 if the virtual type is not openable.
     */
#define MINE_VFD_BASE 900

    int     MineVFSOpen(int virt_type, int flags);
    int64_t MineVFSRead(int vfd, void* buf, uint64_t count);
    int64_t MineVFSWrite(int vfd, const void* buf, uint64_t count);
    int     MineVFSClose(int vfd);
    bool    MineVFSIsVFD(int fd);
    int64_t MineVFSFstat(int vfd, void* stat_buf);
    int64_t MineVFSLseek(int vfd, int64_t offset, int whence);

    /* Generate readlink content for /proc/self/exe */
    int64_t MineVFSReadlink(int virt_type, char* buf, uint64_t bufsiz);

    /* Pipe implementation */
    int64_t MineVFSPipe(int pipefd[2], int flags);

#ifdef __cplusplus
}
#endif

#endif /* MINE_VFS_H */
