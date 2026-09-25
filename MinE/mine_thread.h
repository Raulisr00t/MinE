#ifndef MINE_THREAD_H
#define MINE_THREAD_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Futex ──────────────────────────────────────────────────────────────── */
#define FUTEX_WAIT            0
#define FUTEX_WAKE            1
#define FUTEX_FD              2
#define FUTEX_REQUEUE         3
#define FUTEX_CMP_REQUEUE     4
#define FUTEX_WAKE_OP         5
#define FUTEX_WAIT_BITSET     9
#define FUTEX_WAKE_BITSET     10
#define FUTEX_PRIVATE_FLAG    128
#define FUTEX_CLOCK_REALTIME  256
#define FUTEX_CMD_MASK        (~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME))

int64_t MineFutex(uint32_t* uaddr, int op, uint32_t val,
                  const void* timeout, uint32_t* uaddr2, uint32_t val3);

/* ── Pthreads ───────────────────────────────────────────────────────────── */
typedef struct { void* handle; uint64_t tid; } MineThread;

typedef struct { void* cs; } MineMutex;

typedef struct { void* cv; } MineCond;

typedef struct { void* srw; } MineRWLock;

int  MineThreadCreate(MineThread* t, const void* attr,
                      uint64_t fn, uint64_t arg);
int  MineThreadJoin(MineThread t, void** retval);
int  MineThreadDetach(MineThread t);

int  MineMutexInit(MineMutex* m, const void* attr);
int  MineMutexLock(MineMutex* m);
int  MineMutexTrylock(MineMutex* m);
int  MineMutexUnlock(MineMutex* m);
int  MineMutexDestroy(MineMutex* m);

int  MineCondInit(MineCond* c, const void* attr);
int  MineCondWait(MineCond* c, MineMutex* m);
int  MineCondTimedwait(MineCond* c, MineMutex* m, const void* abstime);
int  MineCondSignal(MineCond* c);
int  MineCondBroadcast(MineCond* c);
int  MineCondDestroy(MineCond* c);

int  MineRWLockInit(MineRWLock* rw, const void* attr);
int  MineRWLockRdlock(MineRWLock* rw);
int  MineRWLockWrlock(MineRWLock* rw);
int  MineRWLockUnlock(MineRWLock* rw);
int  MineRWLockDestroy(MineRWLock* rw);

uint32_t MineTlsCreate(void (*dtor)(void*));
void*    MineTlsGet(uint32_t key);
int      MineTlsSet(uint32_t key, const void* val);

int  MineOnce(void* once_control, void (*init_routine)(void));

/* ── Poll / Select ──────────────────────────────────────────────────────── */
int64_t MinePoll(void* fds, uint32_t nfds, int timeout_ms);
int64_t MineSelect(int nfds, void* readfds, void* writefds,
                   void* exceptfds, void* timeout);

/* ── Directory ──────────────────────────────────────────────────────────── */
typedef struct MineDIR MineDIR;
typedef struct {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[256];
} MineDirent;

MineDIR*    MineOpendir(const char* path);
MineDirent* MineReaddir(MineDIR* dir);
int         MineClosedir(MineDIR* dir);

#ifdef __cplusplus
}
#endif

#endif /* MINE_THREAD_H */
