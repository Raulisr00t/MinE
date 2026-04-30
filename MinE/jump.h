#ifndef MINE_JUMP_H
#define MINE_JUMP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	/* Jump to ELF _start. Sets FS base, loads RSP, zeroes GPRs, jmps entry. */
	void MineJump(uint64_t entry, uint64_t rsp, uint64_t fs_base);

	/* Convert Linux ABI call to Windows ABI. RAX=fn set by caller. */
	void MineLinuxToWin(void);

	/* Call a guest Linux-ABI function from Windows code.
	   fn=RCX, a1=RDX, a2=R8, a3=R9 -> RDI RSI RDX then jmp fn */
	void MineWinToLinux(void);

#ifdef __cplusplus
}
#endif

#endif