/*
 * Copyright 2020 NXP
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
#include <teec_trace.h>

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

#include "tee_supp_fs.h"
#include "coverage.h"

#define MAX_PATH_SIZE 255

static const char *s_storage_dir = CFG_TEE_CLIENT_COV_DIR"/";

static void fldump(const char* desc, const uint8_t *buf, uint32_t size)
{
	uint32_t i;

	printf("%s(%d): [", desc, size);
	for (i = 0; i < size; i++)
		printf("%.2x ", buf[i]);
	printf("]\n");
}

TEEC_Result coverage_process(size_t num_params, struct tee_ioctl_param *params)
{
	char *filepath;
	uint32_t filepath_size;
	char *cov_data;
	uint32_t cov_data_size;
	char path[MAX_PATH_SIZE] = { 0 };
	int n;
	int fd = -1;
	int bytes_written = 0;
	int total_bytes_written = 0;
	int cov_data_size_left = 0;
	char *p;

	/* Process RPC parameters */
	if (num_params != 2 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
		TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[1].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
		TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT) {
		EMSG("Invalid parameters\n");
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	filepath = tee_supp_param_to_va(params + 0);
	if (!filepath) {
		EMSG("Cannot retrieve filepath\n");
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	filepath_size = MEMREF_SIZE(params + 0);

	cov_data = tee_supp_param_to_va(params + 1);
	if (!cov_data) {
		EMSG("Cannot retrieve coverage data");
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	cov_data_size = MEMREF_SIZE(params + 1);

	/* Check the filepath is a string (null terminated) */
	if (filepath[filepath_size - 1] != '\0') {
		EMSG("filepath is not a null terminated string");
		fldump("filpath", (const uint8_t *)filepath, filepath_size);
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	IMSG("Writing %d bytes of coverage data for %s", cov_data_size,
	     filepath);

	/* Create the path of the file */
	n = snprintf(path, sizeof(path), "%s%s", s_storage_dir, filepath);
	if (n < 0 || n >= MAX_PATH_SIZE) {
		EMSG("Path too long");
		return TEEC_ERROR_SHORT_BUFFER;
	}

	/* Create the path
	 * The path includes the file of the name which is created as a
	 * directory by mkpath so we temporly replace the last / by a null
	 * terminator
	 */
	p = strrchr(path, '/');
	if (!p) {
		EMSG("Could not find a slash");
		return TEEC_ERROR_GENERIC;
	}
	*p = '\0';

	n = mkpath(path, 0775);
	*p = '/';
	if (n != 0) {
		EMSG("failed to create path for [%s] err: %d", path, n);
		return TEEC_ERROR_STORAGE_NOT_AVAILABLE;
	}

	/* Write the file */
	fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0664);
	if (fd < 0) {
		EMSG("failed to open [%s] err: %d(%s)", path, errno,
		     strerror(errno));
		return TEEC_ERROR_STORAGE_NOT_AVAILABLE;
	}

	cov_data_size_left = cov_data_size;
	do {
		bytes_written = write(fd, cov_data, cov_data_size_left);
		IMSG("bytes_written: %d", bytes_written);
		if (bytes_written > 0) {
			total_bytes_written += bytes_written;
			cov_data_size_left -= bytes_written;
		}
	} while (bytes_written < 0 && errno == EINTR);
	close(fd);

	if (bytes_written < 0 || total_bytes_written != (int)cov_data_size) {
		EMSG("Issue when writing, written %d/%d, err: %d(%s)",
		     total_bytes_written, cov_data_size, errno,
		     strerror(errno));
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}
