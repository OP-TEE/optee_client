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
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <teec_trace.h>
#include <teec_ta_load.h>

/*
 * Attempt to first load TAs from a writable directory.  This is
 * intended for testing (xtest 1008, load_corrupt_ta specifically),
 * and should not be enabled in a production system, as it would
 * greatly facilitate loading rogue TA code.
 */
#ifdef CFG_TA_TEST_PATH
# ifndef TEEC_TEST_LOAD_PATH
#  ifdef __ANDROID__
#   define TEEC_TEST_LOAD_PATH "/data/vendor/tee"
#  else
#   define TEEC_TEST_LOAD_PATH "/tmp"
#  endif
# endif
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
static int try_load_secure_module(const char* prefix,
				  const char* dev_path,
				  const TEEC_UUID *destination, void *ta,
				  size_t *ta_size)
{
	char fname[PATH_MAX];
	FILE *file = NULL;
	bool first_try = true;
	size_t s;
	int n;

	if (!ta_size || !destination) {
		printf("wrong inparameter to TEECI_LoadSecureModule\n");
		return TA_BINARY_NOT_FOUND;
	}

	/*
	 * We expect the TA binary to be named after the UUID as per RFC4122,
	 * that is: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.ta
	 * If the file cannot be open, try the deprecated format:
	 * xxxxxxxx-xxxx-xxxx-xxxxxxxxxxxxxxxx.ta
	 */
again:
	n = snprintf(fname, PATH_MAX,
		     "%s/%s/%08x-%04x-%04x-%02x%02x%s%02x%02x%02x%02x%02x%02x.ta",
		     prefix, dev_path,
		     destination->timeLow,
		     destination->timeMid,
		     destination->timeHiAndVersion,
		     destination->clockSeqAndNode[0],
		     destination->clockSeqAndNode[1],
		     first_try ? "-" : "",
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
		if (first_try) {
			first_try = false;
			goto again;
		}
		return TA_BINARY_NOT_FOUND;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return TA_BINARY_NOT_FOUND;
	}

	s = ftell(file);
	if (s > *ta_size || !ta) {
		/*
		 * Buffer isn't large enough, return the required size to
		 * let the caller increase the size of the buffer and try
		 * again.
		 */
		goto out;
	}

	if (fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		return TA_BINARY_NOT_FOUND;
	}

	if (s != fread(ta, 1, s, file)) {
		printf("error fread TA file\n");
		fclose(file);
		return TA_BINARY_NOT_FOUND;
	}

out:
	*ta_size = s;
	fclose(file);
	return TA_BINARY_FOUND;
}

int TEECI_LoadSecureModule(const char* dev_path,
			   const TEEC_UUID *destination, void *ta,
			   size_t *ta_size)
{
#ifdef TEEC_TEST_LOAD_PATH
	int res;

	res = try_load_secure_module(TEEC_TEST_LOAD_PATH,
				     dev_path, destination, ta, ta_size);
	if (res != TA_BINARY_NOT_FOUND)
		return res;
#endif

	return try_load_secure_module(TEEC_LOAD_PATH,
				      dev_path, destination, ta, ta_size);
}
