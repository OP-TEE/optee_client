/*
 * Copyright (c) 2016, Linaro Limited
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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <tee_client_api.h>
#include <tee_supplicant.h>
#include "gprof.h"

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

TEEC_Result gprof_process(size_t num_params, struct tee_ioctl_param *params)
{
	char vers[5] = "";
	char path[255];
	size_t bufsize;
	TEEC_UUID *u;
	int fd = -1;
	void *buf;
	int flags;
	int id;
	int st;
	int n;

	if (num_params != 3 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
		TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT ||
	    (params[1].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
		TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
                TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	id = params[0].u.value.a;

	if (params[1].u.memref.size != sizeof(TEEC_UUID))
		return TEEC_ERROR_BAD_PARAMETERS;

	u = tee_supp_param_to_va(params + 1);
	if (!u)
		return TEEC_ERROR_BAD_PARAMETERS;

	buf = tee_supp_param_to_va(params + 2);
	if (!buf)
		return TEEC_ERROR_BAD_PARAMETERS;

	bufsize = params[2].u.memref.size;

	if (id < 0 || id > 100)
		return TEEC_ERROR_BAD_PARAMETERS;

	flags = O_APPEND | O_WRONLY;
	if (!id) {
		/* id == 0 means create file */
		flags |= O_CREAT | O_EXCL;
		id = 1;
	}

	for (;;) {
		if (id > 1) {
			/*
			 * id == 1 is file 0 (no suffix), id == 2 is file .1
			 * etc.
			 */
			if (id > 100)
				id = 100; /* Avoid GCC truncation warning */
			snprintf(vers, sizeof(vers), ".%d", id - 1);
		}
		n = snprintf(path, sizeof(path),
			"/tmp/gmon-"
			"%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x"
			"%s.out",
			u->timeLow, u->timeMid, u->timeHiAndVersion,
			u->clockSeqAndNode[0], u->clockSeqAndNode[1],
			u->clockSeqAndNode[2], u->clockSeqAndNode[3],
			u->clockSeqAndNode[4], u->clockSeqAndNode[5],
			u->clockSeqAndNode[6], u->clockSeqAndNode[7],
			vers);
	        if ((n < 0) || (n >= (int)sizeof(path)))
			break;
		fd = open(path, flags, 0600);
		if (fd >= 0) {
			do {
				st = write(fd, buf, bufsize);
			} while (st < 0 && errno == EINTR);
			close(fd);
			if (st < 0 || st != (int)bufsize)
				break;
			params[0].u.value.a = id;
			goto success;
		}
		if (errno != EEXIST)
			break;
		if (id++ == 100)
			break;
	}

	/* An error occured */
	return TEEC_ERROR_GENERIC;

success:
	return TEEC_SUCCESS;
}
