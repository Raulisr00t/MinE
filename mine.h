#ifndef MINE_H
#define MINE_H

#include <Windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool CheckApp(LPCSTR path);
	void MineRun(LPCSTR path);

#ifdef __cplusplus
}
#endif

#endif