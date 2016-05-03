/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 * Copyright (c) 2015, Linaro Limited
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
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <teec_trace.h>
#include <teec_ta_load.h>
#include <tee_supp_fs.h>

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

#include <rpmb.h>
#include <sql_fs.h>
#define RPC_NUM_PARAMS	2

#define RPC_BUF_SIZE	(sizeof(struct tee_iocl_supp_send_arg) + \
			 RPC_NUM_PARAMS * sizeof(struct tee_ioctl_param))

#define RPC_CMD_LOAD_TA		0
#define RPC_CMD_RPMB		1
#define RPC_CMD_FS		2
#define RPC_CMD_SHM_ALLOC	6
#define RPC_CMD_SHM_FREE	7
#define RPC_CMD_SQL_FS		8

union tee_rpc_invoke {
	uint64_t buf[RPC_BUF_SIZE / sizeof(uint64_t)];
	struct tee_iocl_supp_recv_arg recv;
	struct tee_iocl_supp_send_arg send;
};

struct tee_shm {
	int id;
	void *p;
	size_t size;
	struct tee_shm *next;
};

static struct tee_shm *shm_head;

static int read_request(int fd, union tee_rpc_invoke *request);
static int write_response(int fd, union tee_rpc_invoke *request);

static const char *ta_dir;

static int get_value(union tee_rpc_invoke *request, const uint32_t idx,
		     struct tee_ioctl_param_value **value)
{
	struct tee_ioctl_param *params;

	if (idx >= request->recv.num_params)
		return -1;

	params = (struct tee_ioctl_param *)(&request->send + 1);
	switch (params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
		*value = &params[idx].u.value;
		return 0;
	default:
		return -1;
	}
}

/* Get parameter allocated by secure world */
static int get_param(union tee_rpc_invoke *request, const uint32_t idx,
		     TEEC_SharedMemory *shm)
{
	struct tee_ioctl_param *params;
	struct tee_shm *tshm;

	if (idx >= request->recv.num_params)
		return -1;

	params = (struct tee_ioctl_param *)(&request->send + 1);
	switch (params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
		break;
	default:
		return -1;
	}

	memset(shm, 0, sizeof(*shm));

	tshm = shm_head;
	while (tshm && tshm->id != params[idx].u.memref.shm_id)
		tshm = tshm->next;
	if (!tshm) {
		/*
		 * It doesn't make sense to query required size of an
		 * input buffer.
		 */
		if ((params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) ==
		    TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT)
			return -1;

		/*
		 * Buffer isn't found, the caller is querying required size
		 * of the buffer.
		 */
		return 0;
	}
	if ((params[idx].u.memref.size + params[idx].u.memref.shm_offs) <
	    params[idx].u.memref.size)
		return -1;
	if ((params[idx].u.memref.size + params[idx].u.memref.shm_offs) >
	    tshm->size)
		return -1;

	shm->flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shm->size = params[idx].u.memref.size - params[idx].u.memref.shm_offs;
	shm->id = params[idx].u.memref.shm_id;
	shm->buffer = (uint8_t *)tshm->p + params[idx].u.memref.shm_offs;
	return 0;
}

static void process_fs(union tee_rpc_invoke *request)
{
	TEEC_SharedMemory shm;

	if (request->recv.num_params != 1 || get_param(request, 0, &shm)) {
		request->send.ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	if (tee_supp_fs_process(shm.buffer, shm.size) < 0) {
		request->send.ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	request->send.ret = TEEC_SUCCESS;
}


static void process_sql_fs(union tee_rpc_invoke *request)
{
	TEEC_SharedMemory shm;

	if (request->recv.num_params != 1 || get_param(request, 0, &shm)) {
		request->send.ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	if (sql_fs_process(shm.buffer, shm.size) < 0) {
		request->send.ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	request->send.ret = TEEC_SUCCESS;
}

static void load_ta(union tee_rpc_invoke *request)
{
	int ta_found = 0;
	size_t size = 0;
	TEEC_UUID uuid;
	struct tee_ioctl_param_value *val_cmd;
	TEEC_SharedMemory shm_ta;

	memset(&shm_ta, 0, sizeof(shm_ta));

	if (request->recv.num_params != 2 || get_value(request, 0, &val_cmd) ||
	    get_param(request, 1, &shm_ta)) {
		request->send.ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}
	memcpy(&uuid, val_cmd, sizeof(uuid));

	size = shm_ta.size;
	ta_found = TEECI_LoadSecureModule(ta_dir, &uuid, shm_ta.buffer, &size);
	if (ta_found == TA_BINARY_FOUND) {
		struct tee_ioctl_param *params =
			(struct tee_ioctl_param *)(&request->recv + 1);

		params[1].u.memref.size = size;
		request->send.ret = TEEC_SUCCESS;
	} else {
		EMSG("  TA not found");
		request->send.ret = TEEC_ERROR_ITEM_NOT_FOUND;
	}
}

static void process_alloc(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_shm_alloc_data data;
	struct tee_ioctl_param_value *val;
	struct tee_shm *shm;
	int shm_fd;

	memset(&data, 0, sizeof(data));

	if (request->recv.num_params != 1 || get_value(request, 0, &val)) {
		request->send.ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	shm = calloc(1, sizeof(*shm));
	if (!shm) {
		request->send.ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	data.size = val->b;
	shm_fd = ioctl(fd, TEE_IOC_SHM_ALLOC, &data);
	if (shm_fd < 0) {
		free(shm);
		request->send.ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	shm->p = mmap(NULL, data.size, PROT_READ | PROT_WRITE, MAP_SHARED,
		      shm_fd, 0);
	close(shm_fd);
	if (shm->p == (void *)MAP_FAILED) {
		free(shm);
		request->send.ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	shm->id = data.id;
	shm->size = data.size;
	shm->next = shm_head;
	shm_head = shm;
	val->c = data.id;
	request->send.ret = TEEC_SUCCESS;
}

static void process_free(union tee_rpc_invoke *request)
{
	struct tee_ioctl_param_value *val;
	struct tee_shm *shm;
	int id;

	if (request->recv.num_params != 1 || get_value(request, 0, &val))
		goto bad;

	id = val->b;

	shm = shm_head;
	if (!shm)
		goto bad;
	if (shm->id == id) {
		shm_head = shm->next;
	} else {
		struct tee_shm *prev;

		do {
			prev = shm;
			shm = shm->next;
			if (!shm)
				goto bad;
		} while (shm->id != id);
		prev->next = shm->next;
	}

	if (munmap(shm->p, shm->size) != 0) {
		EMSG("munmap(%p, %zu) failed - Error = %s",
		     shm->p, shm->size, strerror(errno));
		free(shm);
		goto bad;
	}

	free(shm);
	request->send.ret = TEEC_SUCCESS;
	return;
bad:
	request->send.ret = TEEC_ERROR_BAD_PARAMETERS;
}



/* How many device sequence numbers will be tried before giving up */
#define MAX_DEV_SEQ	10

static int open_dev(const char *devname)
{
	struct tee_ioctl_version_data vers;
	int fd;

	fd = open(devname, O_RDWR);
	if (fd < 0)
		return -1;

	if (ioctl(fd, TEE_IOC_VERSION, &vers))
		goto err;

	/* Only OP-TEE supported */
	if (vers.impl_id != TEE_IMPL_ID_OPTEE)
		goto err;

	ta_dir = "optee_armtz";

	DMSG("using device \"%s\"", devname);
	return fd;
err:
	close(fd);
	return -1;
}

static int get_dev_fd(void)
{
	int fd;
	char name[PATH_MAX];
	size_t n;

	for (n = 0; n < MAX_DEV_SEQ; n++) {
		snprintf(name, sizeof(name), "/dev/teepriv%zu", n);
		fd = open_dev(name);
		if (fd >= 0)
			return fd;
	}
	return -1;
}

static int usage(void)
{
	fprintf(stderr, "usage: tee-supplicant [<device-name>]");
	return EXIT_FAILURE;
}

static void process_rpmb(union tee_rpc_invoke *inv)
{
	TEEC_SharedMemory req, rsp;

	INMSG();
	if (get_param(inv, 0, &req)) {
		inv->send.ret = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}
	if (get_param(inv, 1, &rsp)) {
		inv->send.ret = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	inv->send.ret = rpmb_process_request(req.buffer, req.size, rsp.buffer,
					     rsp.size);

out:
	OUTMSG();
}

int main(int argc, char *argv[])
{
	int fd;
	union tee_rpc_invoke request;
	int ret;

	if (argc > 2)
		return usage();
	if (argc == 2) {
		fd = open_dev(argv[1]);
		if (fd < 0) {
			EMSG("failed to open \"%s\"", argv[1]);
			exit(EXIT_FAILURE);
		}
	} else {
		fd = get_dev_fd();
		if (fd < 0) {
			EMSG("failed to find an OP-TEE supplicant device");
			exit(EXIT_FAILURE);
		}
	}

	if (tee_supp_fs_init() != 0) {
		EMSG("error tee_supp_fs_init");
		exit(EXIT_FAILURE);
	}

	if (sql_fs_init() != 0) {
		EMSG("sql_fs_init() failed ");
		exit(EXIT_FAILURE);
	}

	/* major failure on read kills supplicant, malformed data will not */
	do {
		DMSG("looping");
		memset(&request, 0, sizeof(request));
		request.recv.num_params = RPC_NUM_PARAMS;
		ret = read_request(fd, &request);
		if (ret == 0) {
			switch (request.recv.func) {
			case RPC_CMD_LOAD_TA:
				load_ta(&request);
				break;
			case RPC_CMD_FS:
				process_fs(&request);
				break;
			case RPC_CMD_SQL_FS:
				process_sql_fs(&request);
				break;
			case RPC_CMD_RPMB:
				process_rpmb(&request);
				break;
			case RPC_CMD_SHM_ALLOC:
				process_alloc(fd, &request);
				break;
			case RPC_CMD_SHM_FREE:
				process_free(&request);
				break;
			default:
				EMSG("Cmd [0x%" PRIx32 "] not supported",
				     request.recv.func);
				/* Not supported. */
				break;
			}

			ret = write_response(fd, &request);
		}
	} while (ret >= 0);

	close(fd);

	return EXIT_FAILURE;
}

static int read_request(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_buf_data data;

	data.buf_ptr = (uintptr_t)request;
	data.buf_len = sizeof(*request);
	if (ioctl(fd, TEE_IOC_SUPPL_RECV, &data)) {
		EMSG("TEE_IOC_SUPPL_RECV: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static int write_response(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_buf_data data;

	data.buf_ptr = (uintptr_t)&request->send;
	data.buf_len = sizeof(struct tee_iocl_supp_send_arg) +
		       sizeof(struct tee_ioctl_param) *
				request->send.num_params;
	if (ioctl(fd, TEE_IOC_SUPPL_SEND, &data)) {
		EMSG("TEE_IOC_SUPPL_SEND: %s", strerror(errno));
		return -1;
	}
	return 0;
}
