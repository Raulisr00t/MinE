#ifndef MINE_DYNAMIC_H
#define MINE_DYNAMIC_H

#include "mine_load.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool MineDynLink(const char* path, MineImage* img);

	/*
	 * MineDynSetGuestFS / MineGetGuestFS:
	 * Called by syscall_translate.c when arch_prctl(ARCH_SET_FS) is processed.
	 * mine_dynamic.c stores the value so call_linux_fn3() and the VEH handler
	 * can restore it before any transition into guest Linux code.
	 */
	void     MineDynSetGuestFS(uint64_t fs);
	uint64_t MineGetGuestFS(void);

#ifdef __cplusplus
}
#endif

#endif /* MINE_DYNAMIC_H */