#ifndef MINE_TLS_H
#define MINE_TLS_H

#include <stdint.h>
#include <stdbool.h>
#include "mine_load.h"

#ifdef __cplusplus
extern "C" {
#endif

	bool MineTLSInit(const MineImage* img);

	/* Per-thread TLS setup for new threads (pthread_create) */
	void MineTLSInitThread(void);

	/* Returns the FS base we installed */
	uint64_t MineTLSBase(void);

	/* Returns pointer to the TLS data block (for __tls_get_addr) */
	uint8_t* MineTLSGetBlock(void);

	/* Returns the total TLS block size */
	uint64_t MineTLSGetSize(void);

#ifdef __cplusplus
}
#endif

#endif