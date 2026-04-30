#ifndef MINE_TLS_H
#define MINE_TLS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

	bool MineTLSInit(void);

	/* Returns the FS base we installed */
	uint64_t MineTLSBase(void);

#ifdef __cplusplus
}
#endif

#endif