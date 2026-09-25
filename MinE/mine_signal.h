#ifndef MINE_SIGNAL_H
#define MINE_SIGNAL_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MINE_NSIG 64

#define MINE_SIGHUP     1
#define MINE_SIGINT     2
#define MINE_SIGQUIT    3
#define MINE_SIGILL     4
#define MINE_SIGTRAP    5
#define MINE_SIGABRT    6
#define MINE_SIGBUS     7
#define MINE_SIGFPE     8
#define MINE_SIGKILL    9
#define MINE_SIGUSR1   10
#define MINE_SIGSEGV   11
#define MINE_SIGUSR2   12
#define MINE_SIGPIPE   13
#define MINE_SIGALRM   14
#define MINE_SIGTERM   15
#define MINE_SIGSTKFLT 16
#define MINE_SIGCHLD   17
#define MINE_SIGCONT   18
#define MINE_SIGSTOP   19
#define MINE_SIGTSTP   20
#define MINE_SIGTTIN   21
#define MINE_SIGTTOU   22
#define MINE_SIGURG    23
#define MINE_SIGXCPU   24
#define MINE_SIGXFSZ   25
#define MINE_SIGVTALRM 26
#define MINE_SIGPROF   27
#define MINE_SIGWINCH  28
#define MINE_SIGIO     29
#define MINE_SIGPWR    30
#define MINE_SIGSYS    31

#define MINE_SIG_DFL   ((uint64_t)0)
#define MINE_SIG_IGN   ((uint64_t)1)
#define MINE_SIG_ERR   ((uint64_t)-1)

#define MINE_SA_NOCLDSTOP  0x00000001
#define MINE_SA_NOCLDWAIT  0x00000002
#define MINE_SA_SIGINFO    0x00000004
#define MINE_SA_RESTORER   0x04000000
#define MINE_SA_ONSTACK    0x08000000
#define MINE_SA_RESTART    0x10000000
#define MINE_SA_NODEFER    0x40000000
#define MINE_SA_RESETHAND  0x80000000

#define MINE_SIG_BLOCK     0
#define MINE_SIG_UNBLOCK   1
#define MINE_SIG_SETMASK   2

#pragma pack(push, 1)
typedef struct {
    uint64_t sa_handler;
    uint64_t sa_flags;
    uint64_t sa_restorer;
    uint64_t sa_mask[2];
} MineSigAction;
#pragma pack(pop)

    void MineSignalInit(void);

    int64_t MineSignalAction(int signum, const MineSigAction* act,
                             MineSigAction* oldact, uint64_t sigsetsize);

    int64_t MineSignalProcmask(int how, const uint64_t* set,
                               uint64_t* oldset, uint64_t sigsetsize);

    int64_t MineSignalSigaltstack(const void* ss, void* old_ss);

    /*
     * Queue a signal for delivery. Can be called from any thread
     * (e.g. Console Ctrl handler thread).
     */
    void MineSignalRaise(int signum);

    /*
     * Check and deliver pending signals. Called at every syscall exit.
     * Returns true if a signal handler was invoked.
     */
    bool MineSignalDeliver(void);

    /*
     * Check if a signal has a registered handler (not SIG_DFL/SIG_IGN).
     * Used by VEH to decide whether to call a guest handler for
     * synchronous signals (SIGSEGV, SIGFPE, SIGILL).
     */
    bool MineSignalHasHandler(int signum);

    /*
     * Get the handler address for a signal.
     */
    uint64_t MineSignalGetHandler(int signum);

#ifdef __cplusplus
}
#endif

#endif /* MINE_SIGNAL_H */
