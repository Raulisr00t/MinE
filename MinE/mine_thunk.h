#ifndef MINE_THUNK_H
#define MINE_THUNK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	/*
	 * Defined in mine_ABI.asm
	 *
	 * MineLinuxToWinFS  — primary ABI bridge (USE THIS ONE)
	 *   Called from thunk with RAX = Windows fn ptr.
	 *   Saves guest FS (rdfsbase), maps 6 Linux args -> Windows ABI,
	 *   calls fn, restores guest FS (wrfsbase), returns.
	 *
	 * MineLinuxToWin  — legacy (no FS save/restore)
	 *
	 * MineWinToLinux  — call Linux-ABI fn from Windows code
	 *   Windows: RCX=fn, RDX=a1, R8=a2, R9=a3
	 *
	 * MineJump  — jump to guest entry with clean regs
	 *   RCX = entry VA, RDX = guest RSP
	 */
	void MineLinuxToWinFS(void);
	void MineLinuxToWin(void);
	void MineWinToLinux(void);
	void MineJump(void);

	/* Allocate thunk pool near MineLinuxToWinFS. Call once at startup. */
	void  MineThunkInit(void);

	/*
	 * Return a Linux-ABI-callable thunk for the given Windows function.
	 * The thunk saves/restores FS around the Windows call.
	 * Returns win_fn unchanged if pool is exhausted (fallback, wrong ABI).
	 */
	void* MineThunkFor(void* win_fn);

#ifdef __cplusplus
}
#endif

#endif /* MINE_THUNK_H */