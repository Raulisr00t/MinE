#ifndef MINE_PROCESS_H
#define MINE_PROCESS_H

#include <stdint.h>
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

int64_t MineExecve(const char* path, char* const argv[], char* const envp[]);
int64_t MineWaitpid(int pid, int* status, int options);
int64_t MineFork(void);

/* epoll emulation */
int64_t MineEpollCreate(int flags);
int64_t MineEpollCtl(int epfd, int op, int fd, void* event);
int64_t MineEpollWait(int epfd, void* events, int maxevents, int timeout);

/* timerfd */
int64_t MineTimerfdCreate(int clockid, int flags);
int64_t MineTimerfdSettime(int fd, int flags, const void* new_value, void* old_value);
int64_t MineTimerfdGettime(int fd, void* curr_value);

/* child process registration */
void MineRegisterChild(HANDLE hProcess, DWORD pid);

#ifdef __cplusplus
}
#endif

#endif /* MINE_PROCESS_H */
