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

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <gprof.h>
#include <inttypes.h>
#include <pthread.h>
#include <rpmb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <teec_ta_load.h>
#include <teec_trace.h>
#include <tee_socket.h>
#include <tee_supp_fs.h>
#include <tee_supplicant.h>
#include <unistd.h>

#include "optee_msg_supplicant.h"

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

#define RPC_NUM_PARAMS	5

#define RPC_BUF_SIZE	(sizeof(struct tee_iocl_supp_send_arg) + \
			 RPC_NUM_PARAMS * sizeof(struct tee_ioctl_param))

union tee_rpc_invoke {
	uint64_t buf[(RPC_BUF_SIZE - 1) / sizeof(uint64_t) + 1];
	struct tee_iocl_supp_recv_arg recv;
	struct tee_iocl_supp_send_arg send;
};

struct tee_shm {
	int id;
	void *p;
	size_t size;
	bool registered;
	int fd;
	struct tee_shm *next;
};

struct thread_arg {
	int fd;
	uint32_t gen_caps;
	bool abort;
	size_t num_waiters;
	pthread_mutex_t mutex;
};

static pthread_mutex_t shm_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct tee_shm *shm_head;

static const char *ta_dir;

static void *thread_main(void *a);

static size_t num_waiters_inc(struct thread_arg *arg)
{
	size_t ret;

	tee_supp_mutex_lock(&arg->mutex);
	arg->num_waiters++;
	assert(arg->num_waiters);
	ret = arg->num_waiters;
	tee_supp_mutex_unlock(&arg->mutex);

	return ret;
}

static size_t num_waiters_dec(struct thread_arg *arg)
{
	size_t ret;

	tee_supp_mutex_lock(&arg->mutex);
	assert(arg->num_waiters);
	arg->num_waiters--;
	ret = arg->num_waiters;
	tee_supp_mutex_unlock(&arg->mutex);

	return ret;
}

static int get_value(size_t num_params, struct tee_ioctl_param *params,
		     const uint32_t idx, struct tee_ioctl_param_value **value)
{
	if (idx >= num_params)
		return -1;

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

static struct tee_shm *find_tshm(int id)
{
	struct tee_shm *tshm;

	tee_supp_mutex_lock(&shm_mutex);

	tshm = shm_head;
	while (tshm && tshm->id != id)
		tshm = tshm->next;

	tee_supp_mutex_unlock(&shm_mutex);

	return tshm;
}

static struct tee_shm *pop_tshm(int id)
{
	struct tee_shm *tshm;
	struct tee_shm *prev;

	tee_supp_mutex_lock(&shm_mutex);

	tshm = shm_head;
	if (!tshm)
		goto out;

	if (tshm->id == id) {
		shm_head = tshm->next;
		goto out;
	}

	do {
		prev = tshm;
		tshm = tshm->next;
		if (!tshm)
			goto out;
	} while (tshm->id != id);
	prev->next = tshm->next;

out:
	tee_supp_mutex_unlock(&shm_mutex);

	return tshm;
}

static void push_tshm(struct tee_shm *tshm)
{
	tee_supp_mutex_lock(&shm_mutex);

	tshm->next = shm_head;
	shm_head = tshm;

	tee_supp_mutex_unlock(&shm_mutex);
}

/* Get parameter allocated by secure world */
static int get_param(size_t num_params, struct tee_ioctl_param *params,
		     const uint32_t idx, TEEC_SharedMemory *shm)
{
	struct tee_shm *tshm;

	if (idx >= num_params)
		return -1;

	switch (params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
		break;
	default:
		return -1;
	}

	memset(shm, 0, sizeof(*shm));

	tshm = find_tshm(params[idx].u.memref.shm_id);
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

static void uuid_from_octets(TEEC_UUID *d, const uint8_t s[TEE_IOCTL_UUID_LEN])
{
	d->timeLow = (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3];
	d->timeMid = (s[4] << 8) | s[5];
	d->timeHiAndVersion = (s[6] << 8) | s[7];
	memcpy(d->clockSeqAndNode, s + 8, sizeof(d->clockSeqAndNode));
}

static uint32_t load_ta(size_t num_params, struct tee_ioctl_param *params)
{
	int ta_found = 0;
	size_t size = 0;
	TEEC_UUID uuid;
	struct tee_ioctl_param_value *val_cmd;
	TEEC_SharedMemory shm_ta;

	memset(&shm_ta, 0, sizeof(shm_ta));

	if (num_params != 2 || get_value(num_params, params, 0, &val_cmd) ||
	    get_param(num_params, params, 1, &shm_ta))
		return TEEC_ERROR_BAD_PARAMETERS;

	uuid_from_octets(&uuid, (void *)val_cmd);

	size = shm_ta.size;
	ta_found = TEECI_LoadSecureModule(ta_dir, &uuid, shm_ta.buffer, &size);
	if (ta_found != TA_BINARY_FOUND) {
		EMSG("  TA not found");
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	params[1].u.memref.size = size;

	/*
	 * If a buffer wasn't provided, just tell which size it should be.
	 * If it was provided but isn't big enough, report an error.
	 */
	if (shm_ta.buffer && size > shm_ta.size)
		return TEEC_ERROR_SHORT_BUFFER;

	return TEEC_SUCCESS;
}

static struct tee_shm *alloc_shm(int fd, size_t size)
{
	struct tee_ioctl_shm_alloc_data data;
	struct tee_shm *shm;

	memset(&data, 0, sizeof(data));

	shm = calloc(1, sizeof(*shm));
	if (!shm)
		return NULL;

	data.size = size;
	shm->fd = ioctl(fd, TEE_IOC_SHM_ALLOC, &data);
	if (shm->fd < 0) {
		free(shm);
		return NULL;
	}

	shm->p = mmap(NULL, data.size, PROT_READ | PROT_WRITE, MAP_SHARED,
		      shm->fd, 0);
	if (shm->p == (void *)MAP_FAILED) {
		close(shm->fd);
		free(shm);
		return NULL;
	}

	shm->id = data.id;
	shm->registered = false;
	return shm;
}

static struct tee_shm *register_local_shm(int fd, size_t size)
{
	struct tee_ioctl_shm_register_data data;
	struct tee_shm *shm;
	void *buf;

	memset(&data, 0, sizeof(data));

	buf = malloc(size);
	if (!buf)
		return NULL;

	shm = calloc(1, sizeof(*shm));
	if (!shm) {
		free(buf);
		return NULL;
	}

	data.addr = (uintptr_t)buf;
	data.length = size;

	shm->fd = ioctl(fd, TEE_IOC_SHM_REGISTER, &data);
	if (shm->fd < 0) {
		free(shm);
		free(buf);
		return NULL;
	}

	shm->p = buf;
	shm->registered = true;
	shm->id = data.id;

	return shm;
}

static uint32_t process_alloc(struct thread_arg *arg, size_t num_params,
			      struct tee_ioctl_param *params)
{
	struct tee_ioctl_param_value *val;
	struct tee_shm *shm;

	if (num_params != 1 || get_value(num_params, params, 0, &val))
		return TEEC_ERROR_BAD_PARAMETERS;

	if (arg->gen_caps & TEE_GEN_CAP_REG_MEM)
		shm = register_local_shm(arg->fd, val->b);
	else
		shm = alloc_shm(arg->fd, val->b);

	if (!shm)
		return TEEC_ERROR_OUT_OF_MEMORY;

	shm->size = val->b;
	val->c = shm->id;
	push_tshm(shm);

	return TEEC_SUCCESS;
}

static uint32_t process_free(size_t num_params, struct tee_ioctl_param *params)
{
	struct tee_ioctl_param_value *val;
	struct tee_shm *shm;
	int id;

	if (num_params != 1 || get_value(num_params, params, 0, &val))
		return TEEC_ERROR_BAD_PARAMETERS;

	id = val->b;

	shm = pop_tshm(id);
	if (!shm)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (shm->registered) {
		free(shm->p);
	} else  {
		if (munmap(shm->p, shm->size) != 0) {
			EMSG("munmap(%p, %zu) failed - Error = %s",
			     shm->p, shm->size, strerror(errno));
			close(shm->fd);
			free(shm);
			return TEEC_ERROR_BAD_PARAMETERS;
		}
	}

	close(shm->fd);
	free(shm);
	return TEEC_SUCCESS;
}



/* How many device sequence numbers will be tried before giving up */
#define MAX_DEV_SEQ	10

static int open_dev(const char *devname, uint32_t *gen_caps)
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
	if (gen_caps)
		*gen_caps = vers.gen_caps;

	DMSG("using device \"%s\"", devname);
	return fd;
err:
	close(fd);
	return -1;
}

static int get_dev_fd(uint32_t *gen_caps)
{
	int fd;
	char name[PATH_MAX];
	size_t n;

	for (n = 0; n < MAX_DEV_SEQ; n++) {
		snprintf(name, sizeof(name), "/dev/teepriv%zu", n);
		fd = open_dev(name, gen_caps);
		if (fd >= 0)
			return fd;
	}
	return -1;
}

static int usage(int status)
{
	fprintf(stderr, "Usage: tee-supplicant [-d] [<device-name>]\n");
	fprintf(stderr, "       -d: run as a daemon (fork after successful "
			"initialization)\n");
	return status;
}

static uint32_t process_rpmb(size_t num_params, struct tee_ioctl_param *params)
{
	TEEC_SharedMemory req;
	TEEC_SharedMemory rsp;

	if (get_param(num_params, params, 0, &req) ||
	    get_param(num_params, params, 1, &rsp))
		return TEEC_ERROR_BAD_PARAMETERS;

	return rpmb_process_request(req.buffer, req.size, rsp.buffer, rsp.size);
}

static bool read_request(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_buf_data data;

	data.buf_ptr = (uintptr_t)request;
	data.buf_len = sizeof(*request);
	if (ioctl(fd, TEE_IOC_SUPPL_RECV, &data)) {
		EMSG("TEE_IOC_SUPPL_RECV: %s", strerror(errno));
		return false;
	}
	return true;
}

static bool write_response(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_buf_data data;

	data.buf_ptr = (uintptr_t)&request->send;
	data.buf_len = sizeof(struct tee_iocl_supp_send_arg) +
		       sizeof(struct tee_ioctl_param) *
				request->send.num_params;
	if (ioctl(fd, TEE_IOC_SUPPL_SEND, &data)) {
		EMSG("TEE_IOC_SUPPL_SEND: %s", strerror(errno));
		return false;
	}
	return true;
}

static bool find_params(union tee_rpc_invoke *request, uint32_t *func,
			size_t *num_params, struct tee_ioctl_param **params,
			size_t *num_meta)
{
	struct tee_ioctl_param *p;
	size_t n;

	p = (struct tee_ioctl_param *)(&request->recv + 1);

	/* Skip meta parameters in the front */
	for (n = 0; n < request->recv.num_params; n++)
		if (!(p[n].attr & TEE_IOCTL_PARAM_ATTR_META))
			break;

	*func = request->recv.func;
	*num_params = request->recv.num_params - n;
	*params = p + n;
	*num_meta = n;

	/* Make sure that no meta parameters follows a non-meta parameter */
	for (; n < request->recv.num_params; n++) {
		if (p[n].attr & TEE_IOCTL_PARAM_ATTR_META) {
			EMSG("Unexpected meta parameter");
			return false;
		}
	}

	return true;
}

static bool spawn_thread(struct thread_arg *arg)
{
	pthread_t tid;
	int e;

	DMSG("Spawning a new thread");

	/*
	 * Increase number of waiters now to avoid starting another thread
	 * before this thread has been scheduled.
	 */
	num_waiters_inc(arg);

	e = pthread_create(&tid, NULL, thread_main, arg);
	if (e) {
		EMSG("pthread_create: %s", strerror(e));
		num_waiters_dec(arg);
		return false;
	}

	e = pthread_detach(tid);
	if (e)
		EMSG("pthread_detach: %s", strerror(e));

	return true;
}

static bool process_one_request(struct thread_arg *arg)
{
	union tee_rpc_invoke request;
	size_t num_params;
	size_t num_meta;
	struct tee_ioctl_param *params;
	uint32_t func;
	uint32_t ret;

	DMSG("looping");
	memset(&request, 0, sizeof(request));
	request.recv.num_params = RPC_NUM_PARAMS;

	/* Let it be known that we can deal with meta parameters */
	params = (struct tee_ioctl_param *)(&request.send + 1);
	params->attr = TEE_IOCTL_PARAM_ATTR_META;

	num_waiters_inc(arg);

	if (!read_request(arg->fd, &request))
		return false;

	if (!find_params(&request, &func, &num_params, &params, &num_meta))
		return false;

	if (num_meta && !num_waiters_dec(arg) && !spawn_thread(arg))
		return false;

	switch (func) {
	case OPTEE_MSG_RPC_CMD_LOAD_TA:
		ret = load_ta(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_FS:
		ret = tee_supp_fs_process(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_RPMB:
		ret = process_rpmb(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
		ret = process_alloc(arg, num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_FREE:
		ret = process_free(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_GPROF:
		ret = gprof_process(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_SOCKET:
		ret = tee_socket_process(num_params, params);
		break;
	default:
		EMSG("Cmd [0x%" PRIx32 "] not supported", func);
		/* Not supported. */
		ret = TEEC_ERROR_NOT_SUPPORTED;
		break;
	}

	request.send.ret = ret;
	return write_response(arg->fd, &request);
}

static void *thread_main(void *a)
{
	struct thread_arg *arg = a;

	/*
	 * Now that this thread has been scheduled, compensate for the
	 * initial increase in spawn_thread() before.
	 */
	num_waiters_dec(arg);

	while (!arg->abort) {
		if (!process_one_request(arg))
			arg->abort = true;
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	struct thread_arg arg = { .fd = -1 };
	bool daemonize = false;
	char *dev = NULL;
	int e;
	int i;

	e = pthread_mutex_init(&arg.mutex, NULL);
	if (e) {
		EMSG("pthread_mutex_init: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}

	if (argc > 3)
		return usage(EXIT_FAILURE);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d"))
			daemonize = true;
		else if (!strcmp(argv[i], "-h"))
			return usage(EXIT_SUCCESS);
		else
			dev = argv[i];
	}

	if (dev) {
		arg.fd = open_dev(dev, &arg.gen_caps);
		if (arg.fd < 0) {
			EMSG("failed to open \"%s\"", argv[1]);
			exit(EXIT_FAILURE);
		}
	} else {
		arg.fd = get_dev_fd(&arg.gen_caps);
		if (arg.fd < 0) {
			EMSG("failed to find an OP-TEE supplicant device");
			exit(EXIT_FAILURE);
		}
	}

	if (tee_supp_fs_init() != 0) {
		EMSG("error tee_supp_fs_init");
		exit(EXIT_FAILURE);
	}

	if (daemonize && daemon(0, 0) < 0) {
		EMSG("daemon(): %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	while (!arg.abort) {
		if (!process_one_request(&arg))
			arg.abort = true;
	}

	close(arg.fd);

	return EXIT_FAILURE;
}

bool tee_supp_param_is_memref(struct tee_ioctl_param *param)
{
	switch (param->attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
		return true;
	default:
		return false;
	}
}

bool tee_supp_param_is_value(struct tee_ioctl_param *param)
{
	switch (param->attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
		return true;
	default:
		return false;
	}
}

void *tee_supp_param_to_va(struct tee_ioctl_param *param)
{
	struct tee_shm *tshm;
	size_t end_offs;

	if (!tee_supp_param_is_memref(param))
		return NULL;

	end_offs = param->u.memref.size + param->u.memref.shm_offs;
	if (end_offs < param->u.memref.size ||
	    end_offs < param->u.memref.shm_offs)
		return NULL;

	tshm = find_tshm(param->u.memref.shm_id);
	if (!tshm)
		return NULL;

	if (end_offs > tshm->size)
		return NULL;

	return (uint8_t *)tshm->p + param->u.memref.shm_offs;
}

void tee_supp_mutex_lock(pthread_mutex_t *mu)
{
	int e = pthread_mutex_lock(mu);

	if (e) {
		EMSG("pthread_mutex_lock: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}
}

void tee_supp_mutex_unlock(pthread_mutex_t *mu)
{
	int e = pthread_mutex_unlock(mu);

	if (e) {
		EMSG("pthread_mutex_unlock: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}
}
