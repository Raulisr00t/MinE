#ifndef MINE_DYNAMIC_H
#define MINE_DYNAMIC_H

#include "mine_load.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool MineDynLink(const char* path, MineImage* img);

#ifdef __cplusplus
}
#endif

#endif