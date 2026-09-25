#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include "mine_signal.h"
#include "mine_dynamic.h"
#include "mine_thunk.h"

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <intrin.h>

/* ─── Per-signal state ───────────────────────────────────────────────────── */

static MineSigAction g_actions[MINE_NSIG + 1];
static uint64_t      g_mask[2];
static volatile LONG g_pending[MINE_NSIG + 1];

static bool sig_valid(int sig)
{
    return sig >= 1 && sig <= MINE_NSIG;
}

static bool sig_in_set(const uint64_t set[2], int sig)
{
    if (sig < 1 || sig > 128) return false;
    int idx = (sig - 1) / 64;
    int bit = (sig - 1) % 64;
    if (idx >= 2) return false;
    return (set[idx] >> bit) & 1;
}

static void sig_add_set(uint64_t set[2], int sig)
{
    if (sig < 1 || sig > 128) return;
    int idx = (sig - 1) / 64;
    int bit = (sig - 1) % 64;
    if (idx < 2) set[idx] |= (1ULL << bit);
}

/* Signals that terminate the process by default */
static bool sig_default_terminate(int sig)
{
    switch (sig) {
    case MINE_SIGHUP: case MINE_SIGINT: case MINE_SIGQUIT:
    case MINE_SIGILL: case MINE_SIGABRT: case MINE_SIGFPE:
    case MINE_SIGKILL: case MINE_SIGSEGV: case MINE_SIGPIPE:
    case MINE_SIGALRM: case MINE_SIGTERM: case MINE_SIGUSR1:
    case MINE_SIGUSR2: case MINE_SIGBUS: case MINE_SIGSYS:
    case MINE_SIGXCPU: case MINE_SIGXFSZ: case MINE_SIGVTALRM:
    case MINE_SIGPROF: case MINE_SIGPWR: case MINE_SIGSTKFLT:
    case MINE_SIGIO:
        return true;
    default:
        return false;
    }
}

/* Signals that are ignored by default */
static bool sig_default_ignore(int sig)
{
    switch (sig) {
    case MINE_SIGCHLD: case MINE_SIGURG: case MINE_SIGWINCH:
    case MINE_SIGCONT:
        return true;
    default:
        return false;
    }
}

/* ─── Console Ctrl handler ───────────────────────────────────────────────── */

static BOOL WINAPI ctrl_handler(DWORD type)
{
    switch (type) {
    case CTRL_C_EVENT:
        MineSignalRaise(MINE_SIGINT);
        return TRUE;
    case CTRL_BREAK_EVENT:
        MineSignalRaise(MINE_SIGQUIT);
        return TRUE;
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        MineSignalRaise(MINE_SIGTERM);
        return TRUE;
    default:
        return FALSE;
    }
}

/* ─── Init ───────────────────────────────────────────────────────────────── */

void MineSignalInit(void)
{
    memset(g_actions, 0, sizeof(g_actions));
    memset(g_mask, 0, sizeof(g_mask));
    memset((void*)g_pending, 0, sizeof(g_pending));

    for (int i = 1; i <= MINE_NSIG; i++)
        g_actions[i].sa_handler = MINE_SIG_DFL;

    SetConsoleCtrlHandler(ctrl_handler, TRUE);
}

/* ─── rt_sigaction ───────────────────────────────────────────────────────── */

int64_t MineSignalAction(int signum, const MineSigAction* act,
                         MineSigAction* oldact, uint64_t sigsetsize)
{
    (void)sigsetsize;

    if (!sig_valid(signum))
        return -22; /* EINVAL */

    /* SIGKILL and SIGSTOP cannot be caught */
    if (signum == MINE_SIGKILL || signum == MINE_SIGSTOP) {
        if (act) return -22;
        if (oldact) *oldact = g_actions[signum];
        return 0;
    }

    if (oldact)
        *oldact = g_actions[signum];

    if (act) {
        g_actions[signum] = *act;
    }

    return 0;
}

/* ─── rt_sigprocmask ─────────────────────────────────────────────────────── */

int64_t MineSignalProcmask(int how, const uint64_t* set,
                           uint64_t* oldset, uint64_t sigsetsize)
{
    (void)sigsetsize;

    if (oldset) {
        oldset[0] = g_mask[0];
        if (sigsetsize >= 16) oldset[1] = g_mask[1];
    }

    if (set) {
        switch (how) {
        case MINE_SIG_BLOCK:
            g_mask[0] |= set[0];
            if (sigsetsize >= 16) g_mask[1] |= set[1];
            break;
        case MINE_SIG_UNBLOCK:
            g_mask[0] &= ~set[0];
            if (sigsetsize >= 16) g_mask[1] &= ~set[1];
            break;
        case MINE_SIG_SETMASK:
            g_mask[0] = set[0];
            if (sigsetsize >= 16) g_mask[1] = set[1];
            break;
        default:
            return -22; /* EINVAL */
        }
        /* SIGKILL and SIGSTOP cannot be blocked */
        uint64_t kill_bit = 1ULL << (MINE_SIGKILL - 1);
        uint64_t stop_bit = 1ULL << (MINE_SIGSTOP - 1);
        g_mask[0] &= ~(kill_bit | stop_bit);
    }

    return 0;
}

/* ─── sigaltstack ────────────────────────────────────────────────────────── */

static uint64_t g_altstack_sp = 0;
static uint64_t g_altstack_size = 0;
static int      g_altstack_flags = 0;

int64_t MineSignalSigaltstack(const void* ss, void* old_ss)
{
    typedef struct { uint64_t sp; int flags; int _pad; uint64_t size; } linux_stack_t;

    if (old_ss) {
        linux_stack_t* o = (linux_stack_t*)old_ss;
        o->sp = g_altstack_sp;
        o->size = g_altstack_size;
        o->flags = g_altstack_flags;
    }

    if (ss) {
        const linux_stack_t* s = (const linux_stack_t*)ss;
        g_altstack_sp = s->sp;
        g_altstack_size = s->size;
        g_altstack_flags = s->flags;
    }

    return 0;
}

/* ─── Raise (queue a signal) ─────────────────────────────────────────────── */

void MineSignalRaise(int signum)
{
    if (!sig_valid(signum)) return;
    InterlockedExchange(&g_pending[signum], 1);
}

/* ─── Deliver pending signals ────────────────────────────────────────────── */

extern void MineWinToLinux(void);

static void invoke_handler(int signum, uint64_t handler)
{
    /*
     * Save and restore Windows FS across the handler call.
     * The handler is a Linux-ABI function: rdi=signum.
     * For SA_SIGINFO handlers, we'd pass (signum, siginfo*, ucontext*)
     * but most programs only use the simple handler form.
     */
    uint64_t win_fs = 0;
    __try { win_fs = _readfsbase_u64(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    uint64_t guest_fs = MineGetGuestFS();
    if (guest_fs) {
        __try { _writefsbase_u64(guest_fs); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    typedef int (*win_fn_t)(void*, uint64_t, uint64_t, uint64_t);
    __try {
        ((win_fn_t)MineWinToLinux)((void*)(uintptr_t)handler,
            (uint64_t)signum, 0, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[MinE-Signal] Handler for signal %d faulted\n", signum);
    }

    /* Save guest FS (handler may have changed it) and restore Windows FS */
    __try {
        uint64_t new_fs = _readfsbase_u64();
        if (new_fs != win_fs) MineDynSetGuestFS(new_fs);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (win_fs) {
        __try { _writefsbase_u64(win_fs); }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
}

bool MineSignalDeliver(void)
{
    bool delivered = false;

    for (int sig = 1; sig <= MINE_NSIG; sig++) {
        if (!InterlockedCompareExchange(&g_pending[sig], 0, 1))
            continue;

        /* Signal is pending — check mask */
        if (sig_in_set(g_mask, sig)) {
            /* Blocked — re-queue */
            InterlockedExchange(&g_pending[sig], 1);
            continue;
        }

        uint64_t handler = g_actions[sig].sa_handler;
        uint64_t flags = g_actions[sig].sa_flags;

        if (handler == MINE_SIG_IGN) {
            /* Ignored */
            continue;
        }

        if (handler == MINE_SIG_DFL) {
            /* Default action */
            if (sig_default_ignore(sig))
                continue;

            if (sig_default_terminate(sig)) {
                fprintf(stderr, "\n[MinE] Terminated by signal %d\n", sig);
                /* Map signal to Linux exit code: 128 + signum */
                ExitProcess(128 + (UINT)sig);
            }
            continue;
        }

        /* User handler — block this signal during handler (unless SA_NODEFER) */
        uint64_t saved_mask[2];
        saved_mask[0] = g_mask[0];
        saved_mask[1] = g_mask[1];

        /* Add the signal's mask to the process mask */
        g_mask[0] |= g_actions[sig].sa_mask[0];
        g_mask[1] |= g_actions[sig].sa_mask[1];

        if (!(flags & MINE_SA_NODEFER))
            sig_add_set(g_mask, sig);

        invoke_handler(sig, handler);
        delivered = true;

        /* Restore mask */
        g_mask[0] = saved_mask[0];
        g_mask[1] = saved_mask[1];

        /* SA_RESETHAND: reset handler to SIG_DFL after delivery */
        if (flags & MINE_SA_RESETHAND)
            g_actions[sig].sa_handler = MINE_SIG_DFL;
    }

    return delivered;
}

/* ─── Query ──────────────────────────────────────────────────────────────── */

bool MineSignalHasHandler(int signum)
{
    if (!sig_valid(signum)) return false;
    uint64_t h = g_actions[signum].sa_handler;
    return h != MINE_SIG_DFL && h != MINE_SIG_IGN;
}

uint64_t MineSignalGetHandler(int signum)
{
    if (!sig_valid(signum)) return MINE_SIG_DFL;
    return g_actions[signum].sa_handler;
}
