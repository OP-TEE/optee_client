/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <teec_trace.h>
#include <teec_ta_load.h>

#ifndef TEEC_LOAD_PATH
#define TEEC_LOAD_PATH "/lib"
#endif

#ifndef PATH_MAX
#define PATH_MAX 255
#endif

struct tee_rpc_cmd {
	void *buffer;
	uint32_t size;
	uint32_t type;
	int fd;
};

/*
 * Based on the uuid this function will try to find a TA-binary on the
 * filesystem and return it back to the caller in the parameter ta.
 *
 * @param: destination  The uuid of the TA we are searching for.
 * @param: ta           A pointer which this function will allocate and copy
 *                      the TA from the filesystem to the pointer itself. It is
 *                      the callers responsibility to free the pointer.
 * @param: ta_size      The size of the TA found on file system. It will be 0
 *                      if no TA was not found.
 *
 * @return              0 if TA was found, otherwise -1.
 */
int TEECI_LoadSecureModule(const char* dev_path,
			   const TEEC_UUID *destination, void **ta,
			   size_t *ta_size)
{
	char fname[PATH_MAX];
	FILE *file = NULL;
	int n;

	if (!ta_size || !ta || !destination) {
		printf("wrong inparameter to TEECI_LoadSecureModule\n");
		return TA_BINARY_NOT_FOUND;
	}

	n = snprintf(fname, PATH_MAX,
		     "%s/%s/%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x.ta",
		     TEEC_LOAD_PATH, dev_path,
		     destination->timeLow,
		     destination->timeMid,
		     destination->timeHiAndVersion,
		     destination->clockSeqAndNode[0],
		     destination->clockSeqAndNode[1],
		     destination->clockSeqAndNode[2],
		     destination->clockSeqAndNode[3],
		     destination->clockSeqAndNode[4],
		     destination->clockSeqAndNode[5],
		     destination->clockSeqAndNode[6],
		     destination->clockSeqAndNode[7]);

	DMSG("Attempt to load %s", fname);

	if ((n < 0) || (n >= PATH_MAX)) {
		EMSG("wrong TA path [%s]", fname);
		return TA_BINARY_NOT_FOUND;
	}

	file = fopen(fname, "r");
	if (file == NULL) {
		DMSG("failed to open the ta %s TA-file", fname);
		return TA_BINARY_NOT_FOUND;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return TA_BINARY_NOT_FOUND;
	}

	*ta_size = ftell(file);

	if (fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		return TA_BINARY_NOT_FOUND;
	}

	*ta = malloc(*ta_size);
	if (*ta == NULL) {
		printf("OOM: failed allocating ta\n");
		fclose(file);
		return TA_BINARY_NOT_FOUND;
	}

	if (*ta_size != fread(*ta, 1, *ta_size, file)) {
		printf("error fread TA file\n");
		free(*ta);
		fclose(file);
		return TA_BINARY_NOT_FOUND;
	}

	fclose(file);
	return TA_BINARY_FOUND;
}
