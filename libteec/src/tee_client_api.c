/*
 * Copyright (c) 2015-2016, Linaro Limited
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
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tee_client_api_extensions.h>
#include <tee_client_api.h>
#include <teec_trace.h>
#include <unistd.h>

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

#include "teec_benchmark.h"

/* How many device sequence numbers will be tried before giving up */
#define TEEC_MAX_DEV_SEQ	10

static pthread_mutex_t teec_mutex = PTHREAD_MUTEX_INITIALIZER;

static void teec_mutex_lock(pthread_mutex_t *mu)
{
	pthread_mutex_lock(mu);
}

static void teec_mutex_unlock(pthread_mutex_t *mu)
{
	pthread_mutex_unlock(mu);
}

static int teec_open_dev(const char *devname, const char *capabilities,
			 uint32_t *gen_caps)
{
	struct tee_ioctl_version_data vers;
	int fd;

	fd = open(devname, O_RDWR);
	if (fd < 0)
		return -1;

	if (ioctl(fd, TEE_IOC_VERSION, &vers)) {
		EMSG("TEE_IOC_VERSION failed");
		goto err;
	}

	/* We can only handle GP TEEs */
	if (!(vers.gen_caps & TEE_GEN_CAP_GP))
		goto err;

	if (capabilities) {
		if (strcmp(capabilities, "optee-tz") == 0) {
			if (vers.impl_id != TEE_IMPL_ID_OPTEE)
				goto err;
			if (!(vers.impl_caps & TEE_OPTEE_CAP_TZ))
				goto err;
		} else {
			/* Unrecognized capability requested */
			goto err;
		}
	}

	*gen_caps = vers.gen_caps;
	return fd;
err:
	close(fd);
	return -1;
}

static int teec_shm_alloc(int fd, size_t size, int *id)
{
	int shm_fd;
	struct tee_ioctl_shm_alloc_data data;

	memset(&data, 0, sizeof(data));
	data.size = size;
	shm_fd = ioctl(fd, TEE_IOC_SHM_ALLOC, &data);
	if (shm_fd < 0)
		return -1;
	*id = data.id;
	return shm_fd;
}

static int teec_shm_register(int fd, void *buf, size_t size, int *id)
{
	int shm_fd;
	struct tee_ioctl_shm_register_data data;

	memset(&data, 0, sizeof(data));
	data.addr = (uintptr_t)buf;
	data.length = size;
	shm_fd = ioctl(fd, TEE_IOC_SHM_REGISTER, &data);
	if (shm_fd < 0)
		return -1;
	*id = data.id;
	return shm_fd;
}

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *ctx)
{
	char devname[PATH_MAX];
	int fd;
	size_t n;

	if (!ctx)
		return TEEC_ERROR_BAD_PARAMETERS;

	for (n = 0; n < TEEC_MAX_DEV_SEQ; n++) {
		uint32_t gen_caps;

		snprintf(devname, sizeof(devname), "/dev/tee%zu", n);
		fd = teec_open_dev(devname, name, &gen_caps);
		if (fd >= 0) {
			ctx->fd = fd;
			ctx->reg_mem = gen_caps & TEE_GEN_CAP_REG_MEM;
			return TEEC_SUCCESS;
		}
	}

	return TEEC_ERROR_ITEM_NOT_FOUND;
}

void TEEC_FinalizeContext(TEEC_Context *ctx)
{
	if (ctx)
		close(ctx->fd);
}


static TEEC_Result teec_pre_process_tmpref(TEEC_Context *ctx,
			uint32_t param_type, TEEC_TempMemoryReference *tmpref,
			struct tee_ioctl_param *param,
			TEEC_SharedMemory *shm)
{
	TEEC_Result res;

	switch (param_type) {
	case TEEC_MEMREF_TEMP_INPUT:
		param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
		shm->flags = TEEC_MEM_INPUT;
		break;
	case TEEC_MEMREF_TEMP_OUTPUT:
		param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
		shm->flags = TEEC_MEM_OUTPUT;
		break;
	case TEEC_MEMREF_TEMP_INOUT:
		param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT;
		shm->flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	shm->size = tmpref->size;

	res = TEEC_AllocateSharedMemory(ctx, shm);
	if (res != TEEC_SUCCESS)
		return res;

	memcpy(shm->buffer, tmpref->buffer, tmpref->size);
	param->u.memref.size = tmpref->size;
	param->u.memref.shm_id = shm->id;
	return TEEC_SUCCESS;
}

static TEEC_Result teec_pre_process_whole(
			TEEC_RegisteredMemoryReference *memref,
			struct tee_ioctl_param *param)
{
	const uint32_t inout = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	uint32_t flags = memref->parent->flags & inout;
	TEEC_SharedMemory *shm;

	if (flags == inout)
		param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT;
	else if (flags & TEEC_MEM_INPUT)
		param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
	else if (flags & TEEC_MEM_OUTPUT)
		param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
	else
		return TEEC_ERROR_BAD_PARAMETERS;

	shm = memref->parent;
	/*
	 * We're using a shadow buffer in this reference, copy the real buffer
	 * into the shadow buffer if needed. We'll copy it back once we've
	 * returned from the call to secure world.
	 */
	if (shm->shadow_buffer && (flags & TEEC_MEM_INPUT))
		memcpy(shm->shadow_buffer, shm->buffer, shm->size);

	param->u.memref.shm_id = shm->id;
	param->u.memref.size = shm->size;
	return TEEC_SUCCESS;
}

static TEEC_Result teec_pre_process_partial(uint32_t param_type,
			TEEC_RegisteredMemoryReference *memref,
			struct tee_ioctl_param *param)
{
	uint32_t req_shm_flags;
	TEEC_SharedMemory *shm;

	switch (param_type) {
	case TEEC_MEMREF_PARTIAL_INPUT:
		req_shm_flags = TEEC_MEM_INPUT;
		param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
		break;
	case TEEC_MEMREF_PARTIAL_OUTPUT:
		req_shm_flags = TEEC_MEM_OUTPUT;
		param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
		break;
	case TEEC_MEMREF_PARTIAL_INOUT:
		req_shm_flags = TEEC_MEM_OUTPUT | TEEC_MEM_INPUT;
		param->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	shm = memref->parent;

	if ((shm->flags & req_shm_flags) != req_shm_flags)
		return TEEC_ERROR_BAD_PARAMETERS;

	/*
	 * We're using a shadow buffer in this reference, copy the real buffer
	 * into the shadow buffer if needed. We'll copy it back once we've
	 * returned from the call to secure world.
	 */
	if (shm->shadow_buffer && param_type != TEEC_MEMREF_PARTIAL_OUTPUT)
		memcpy((char *)shm->shadow_buffer + memref->offset,
		       (char *)shm->buffer + memref->offset, memref->size);

	param->u.memref.shm_id = shm->id;
	param->u.memref.shm_offs = memref->offset;
	param->u.memref.size = memref->size;
	return TEEC_SUCCESS;
}

static TEEC_Result teec_pre_process_operation(TEEC_Context *ctx,
			TEEC_Operation *operation,
			struct tee_ioctl_param *params,
			TEEC_SharedMemory *shms)
{
	TEEC_Result res;
	size_t n;

	memset(shms, 0, sizeof(TEEC_SharedMemory) *
			TEEC_CONFIG_PAYLOAD_REF_COUNT);
	if (!operation) {
		memset(params, 0, sizeof(struct tee_ioctl_param) *
				  TEEC_CONFIG_PAYLOAD_REF_COUNT);
		return TEEC_SUCCESS;
	}

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint32_t param_type;

		param_type = TEEC_PARAM_TYPE_GET(operation->paramTypes, n);
		switch (param_type) {
		case TEEC_NONE:
			params[n].attr = param_type;
			break;
		case TEEC_VALUE_INPUT:
		case TEEC_VALUE_OUTPUT:
		case TEEC_VALUE_INOUT:
			params[n].attr = param_type;
			params[n].u.value.a = operation->params[n].value.a;
			params[n].u.value.b = operation->params[n].value.b;
			break;
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:
			res = teec_pre_process_tmpref(ctx, param_type,
				&operation->params[n].tmpref, params + n,
				shms + n);
			if (res != TEEC_SUCCESS)
				return res;
			break;
		case TEEC_MEMREF_WHOLE:
			res = teec_pre_process_whole(
					&operation->params[n].memref,
					params + n);
			if (res != TEEC_SUCCESS)
				return res;
			break;
		case TEEC_MEMREF_PARTIAL_INPUT:
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:
			res = teec_pre_process_partial(param_type,
				&operation->params[n].memref, params + n);
			if (res != TEEC_SUCCESS)
				return res;
			break;
		default:
			return TEEC_ERROR_BAD_PARAMETERS;
		}
	}

	return TEEC_SUCCESS;
}

static void teec_post_process_tmpref(uint32_t param_type,
			TEEC_TempMemoryReference *tmpref,
			struct tee_ioctl_param *param,
			TEEC_SharedMemory *shm)
{
	if (param_type != TEEC_MEMREF_TEMP_INPUT) {
		if (param->u.memref.size <= tmpref->size && tmpref->buffer)
			memcpy(tmpref->buffer, shm->buffer,
			       param->u.memref.size);

		tmpref->size = param->u.memref.size;
	}
}

static void teec_post_process_whole(TEEC_RegisteredMemoryReference *memref,
			struct tee_ioctl_param *param)
{
	TEEC_SharedMemory *shm = memref->parent;

	if (shm->flags & TEEC_MEM_OUTPUT) {

		/*
		 * We're using a shadow buffer in this reference, copy back
		 * the shadow buffer into the real buffer now that we've
		 * returned from secure world.
		 */
		if (shm->shadow_buffer && param->u.memref.size <= shm->size)
			memcpy(shm->buffer, shm->shadow_buffer,
			       param->u.memref.size);

		memref->size = param->u.memref.size;
	}
}

static void teec_post_process_partial(uint32_t param_type,
			TEEC_RegisteredMemoryReference *memref,
			struct tee_ioctl_param *param)
{
	if (param_type != TEEC_MEMREF_PARTIAL_INPUT) {
		TEEC_SharedMemory *shm = memref->parent;

		/*
		 * We're using a shadow buffer in this reference, copy back
		 * the shadow buffer into the real buffer now that we've
		 * returned from secure world.
		 */
		if (shm->shadow_buffer && param->u.memref.size <= memref->size)
			memcpy((char *)shm->buffer + memref->offset,
			       (char *)shm->shadow_buffer + memref->offset,
			       param->u.memref.size);

		memref->size = param->u.memref.size;
	}
}

static void teec_post_process_operation(TEEC_Operation *operation,
			struct tee_ioctl_param *params,
			TEEC_SharedMemory *shms)
{
	size_t n;

	if (!operation)
		return;

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint32_t param_type;

		param_type = TEEC_PARAM_TYPE_GET(operation->paramTypes, n);
		switch (param_type) {
		case TEEC_VALUE_INPUT:
			break;
		case TEEC_VALUE_OUTPUT:
		case TEEC_VALUE_INOUT:
			operation->params[n].value.a = params[n].u.value.a;
			operation->params[n].value.b = params[n].u.value.b;
			break;
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:
			teec_post_process_tmpref(param_type,
				&operation->params[n].tmpref, params + n,
				shms + n);
			break;
		case TEEC_MEMREF_WHOLE:
			teec_post_process_whole(&operation->params[n].memref,
						params + n);
			break;
		case TEEC_MEMREF_PARTIAL_INPUT:
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:
			teec_post_process_partial(param_type,
				&operation->params[n].memref, params + n);
		default:
			break;
		}
	}
}

static void teec_free_temp_refs(TEEC_Operation *operation,
			TEEC_SharedMemory *shms)
{
	size_t n;

	if (!operation)
		return;

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		switch (TEEC_PARAM_TYPE_GET(operation->paramTypes, n)) {
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:
			TEEC_ReleaseSharedMemory(shms + n);
			break;
		default:
			break;
		}
	}
}

static TEEC_Result ioctl_errno_to_res(int err)
{
	switch (err) {
	case ENOMEM:
		return TEEC_ERROR_OUT_OF_MEMORY;
	default:
		return TEEC_ERROR_GENERIC;
	}
}

static void uuid_to_octets(uint8_t d[TEE_IOCTL_UUID_LEN], const TEEC_UUID *s)
{
	d[0] = s->timeLow >> 24;
	d[1] = s->timeLow >> 16;
	d[2] = s->timeLow >> 8;
	d[3] = s->timeLow;
	d[4] = s->timeMid >> 8;
	d[5] = s->timeMid;
	d[6] = s->timeHiAndVersion >> 8;
	d[7] = s->timeHiAndVersion;
	memcpy(d + 8, s->clockSeqAndNode, sizeof(s->clockSeqAndNode));
}

TEEC_Result TEEC_OpenSession(TEEC_Context *ctx, TEEC_Session *session,
			const TEEC_UUID *destination,
			uint32_t connection_method, const void *connection_data,
			TEEC_Operation *operation, uint32_t *ret_origin)
{
	uint64_t buf[(sizeof(struct tee_ioctl_open_session_arg) +
			TEEC_CONFIG_PAYLOAD_REF_COUNT *
				sizeof(struct tee_ioctl_param)) /
			sizeof(uint64_t)] = { 0 };
	struct tee_ioctl_buf_data buf_data;
	struct tee_ioctl_open_session_arg *arg;
	struct tee_ioctl_param *params;
	TEEC_Result res;
	uint32_t eorig;
	TEEC_SharedMemory shm[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	int rc;

	(void)&connection_data;

	if (!ctx || !session) {
		eorig = TEEC_ORIGIN_API;
		res = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	buf_data.buf_ptr = (uintptr_t)buf;
	buf_data.buf_len = sizeof(buf);

	arg = (struct tee_ioctl_open_session_arg *)buf;
	arg->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT;
	params = (struct tee_ioctl_param *)(arg + 1);

	uuid_to_octets(arg->uuid, destination);
	arg->clnt_login = connection_method;

	res = teec_pre_process_operation(ctx, operation, params, shm);
	if (res != TEEC_SUCCESS) {
		eorig = TEEC_ORIGIN_API;
		goto out_free_temp_refs;
	}

	rc = ioctl(ctx->fd, TEE_IOC_OPEN_SESSION, &buf_data);
	if (rc) {
		EMSG("TEE_IOC_OPEN_SESSION failed");
		eorig = TEEC_ORIGIN_COMMS;
		res = ioctl_errno_to_res(errno);
		goto out_free_temp_refs;
	}
	res = arg->ret;
	eorig = arg->ret_origin;
	if (res == TEEC_SUCCESS) {
		session->ctx = ctx;
		session->session_id = arg->session;
	}
	teec_post_process_operation(operation, params, shm);

out_free_temp_refs:
	teec_free_temp_refs(operation, shm);
out:
	if (ret_origin)
		*ret_origin = eorig;
	return res;
}

void TEEC_CloseSession(TEEC_Session *session)
{
	struct tee_ioctl_close_session_arg arg;

	if (!session)
		return;

	arg.session = session->session_id;
	if (ioctl(session->ctx->fd, TEE_IOC_CLOSE_SESSION, &arg))
		EMSG("Failed to close session 0x%x", session->session_id);
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t cmd_id,
			TEEC_Operation *operation, uint32_t *error_origin)
{
	uint64_t buf[(sizeof(struct tee_ioctl_invoke_arg) +
			TEEC_CONFIG_PAYLOAD_REF_COUNT *
				sizeof(struct tee_ioctl_param)) /
			sizeof(uint64_t)] = { 0 };
	struct tee_ioctl_buf_data buf_data;
	struct tee_ioctl_invoke_arg *arg;
	struct tee_ioctl_param *params;
	TEEC_Result res;
	uint32_t eorig;
	TEEC_SharedMemory shm[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	int rc;

	if (!session) {
		eorig = TEEC_ORIGIN_API;
		res = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	bm_timestamp();

	buf_data.buf_ptr = (uintptr_t)buf;
	buf_data.buf_len = sizeof(buf);

	arg = (struct tee_ioctl_invoke_arg *)buf;
	arg->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT;
	params = (struct tee_ioctl_param *)(arg + 1);

	arg->session = session->session_id;
	arg->func = cmd_id;

	if (operation) {
		teec_mutex_lock(&teec_mutex);
		operation->session = session;
		teec_mutex_unlock(&teec_mutex);
	}

	res = teec_pre_process_operation(session->ctx, operation, params, shm);
	if (res != TEEC_SUCCESS) {
		eorig = TEEC_ORIGIN_API;
		goto out_free_temp_refs;
	}

	rc = ioctl(session->ctx->fd, TEE_IOC_INVOKE, &buf_data);
	if (rc) {
		EMSG("TEE_IOC_INVOKE failed");
		eorig = TEEC_ORIGIN_COMMS;
		res = ioctl_errno_to_res(errno);
		goto out_free_temp_refs;
	}

	res = arg->ret;
	eorig = arg->ret_origin;
	teec_post_process_operation(operation, params, shm);

	bm_timestamp();

out_free_temp_refs:
	teec_free_temp_refs(operation, shm);
out:
	if (error_origin)
		*error_origin = eorig;
	return res;
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
	struct tee_ioctl_cancel_arg arg;
	TEEC_Session *session;

	if (!operation)
		return;

	teec_mutex_lock(&teec_mutex);
	session = operation->session;
	teec_mutex_unlock(&teec_mutex);

	if (!session)
		return;

	arg.session = session->session_id;
	arg.cancel_id = 0;

	if (ioctl(session->ctx->fd, TEE_IOC_CANCEL, &arg))
		EMSG("TEE_IOC_CANCEL: %s", strerror(errno));
}

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *ctx, TEEC_SharedMemory *shm)
{
	int fd;
	size_t s;

	if (!ctx || !shm)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!shm->flags || (shm->flags & ~(TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)))
		return TEEC_ERROR_BAD_PARAMETERS;

	s = shm->size;
	if (!s)
		s = 8;
	if (ctx->reg_mem) {
		fd = teec_shm_register(ctx->fd, shm->buffer, s, &shm->id);
		if (fd < 0)
			return TEEC_ERROR_OUT_OF_MEMORY;
		shm->registered_fd = fd;
		shm->shadow_buffer = NULL;
	} else {
		fd = teec_shm_alloc(ctx->fd, s, &shm->id);
		if (fd < 0)
			return TEEC_ERROR_OUT_OF_MEMORY;

		shm->shadow_buffer = mmap(NULL, s, PROT_READ | PROT_WRITE,
					  MAP_SHARED, fd, 0);
		close(fd);
		if (shm->shadow_buffer == (void *)MAP_FAILED) {
			shm->id = -1;
			return TEEC_ERROR_OUT_OF_MEMORY;
		}
		shm->registered_fd = -1;
	}

	shm->alloced_size = s;
	shm->buffer_allocated = false;
	return TEEC_SUCCESS;
}

TEEC_Result TEEC_RegisterSharedMemoryFileDescriptor(TEEC_Context *ctx,
						    TEEC_SharedMemory *shm,
						    int fd)
{
	struct tee_ioctl_shm_register_fd_data data;
	int rfd;

	if (!ctx || !shm || fd < 0)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!shm->flags || (shm->flags & ~(TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)))
		return TEEC_ERROR_BAD_PARAMETERS;

	memset(&data, 0, sizeof(data));
	data.fd = fd;
	rfd = ioctl(ctx->fd, TEE_IOC_SHM_REGISTER_FD, &data);
	if (rfd < 0)
		return TEEC_ERROR_BAD_PARAMETERS;

	shm->buffer = NULL;
	shm->shadow_buffer = NULL;
	shm->registered_fd = rfd;
	shm->id = data.id;
	shm->size = data.size;
	return TEEC_SUCCESS;
}

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *ctx, TEEC_SharedMemory *shm)
{
	int fd;
	size_t s;

	if (!ctx || !shm)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!shm->flags || (shm->flags & ~(TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)))
		return TEEC_ERROR_BAD_PARAMETERS;

	s = shm->size;
	if (!s)
		s = 8;

	if (ctx->reg_mem) {
		shm->buffer = malloc(s);
		if (!shm->buffer)
			return TEEC_ERROR_OUT_OF_MEMORY;

		fd = teec_shm_register(ctx->fd, shm->buffer, s, &shm->id);
		if (fd < 0) {
			free(shm->buffer);
			shm->buffer = NULL;
			return TEEC_ERROR_OUT_OF_MEMORY;
		}
		shm->registered_fd = fd;
	} else {
		fd = teec_shm_alloc(ctx->fd, s, &shm->id);
		if (fd < 0)
			return TEEC_ERROR_OUT_OF_MEMORY;

		shm->buffer = mmap(NULL, s, PROT_READ | PROT_WRITE,
				   MAP_SHARED, fd, 0);
		close(fd);
		if (shm->buffer == (void *)MAP_FAILED) {
			shm->id = -1;
			return TEEC_ERROR_OUT_OF_MEMORY;
		}
		shm->registered_fd = -1;
	}

	shm->shadow_buffer = NULL;
	shm->alloced_size = s;
	shm->buffer_allocated = true;
	return TEEC_SUCCESS;
}

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *shm)
{
	if (!shm || shm->id == -1)
		return;

	if (shm->shadow_buffer)
		munmap(shm->shadow_buffer, shm->alloced_size);
	else if (shm->buffer) {
		if (shm->registered_fd >= 0) {
			if (shm->buffer_allocated)
				free(shm->buffer);
			close(shm->registered_fd);
		} else
			munmap(shm->buffer, shm->alloced_size);
	} else if (shm->registered_fd >= 0)
		close(shm->registered_fd);

	shm->id = -1;
	shm->shadow_buffer = NULL;
	shm->buffer = NULL;
	shm->registered_fd = -1;
	shm->buffer_allocated = false;
}
