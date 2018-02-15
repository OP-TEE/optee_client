/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <pkcs11.h>
#include <sks_ta.h>
#include <stdlib.h>
#include <string.h>

#include "ck_helpers.h"
#include "invoke_ta.h"
#include "local_utils.h"

/*
 * All requests (invocation of the SKS) currently go through a
 * single GPD TEE session toward the SKS TA.
 */
struct sks_primary_context {
	TEEC_Context context;
	TEEC_Session session;
};

static struct sks_primary_context primary_ctx;
static struct sks_invoke primary_invoke;

static int open_primary_context(void)
{
	TEEC_UUID uuid = TA_SKS_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* TODO: mutex */
	if (primary_invoke.session)
		return 0;

	res = TEEC_InitializeContext(NULL, &primary_ctx.context);
	if (res != TEEC_SUCCESS) {
		LOG_ERROR("TEEC init context failed\n");
		return -1;
	}

	/* TODO: application could provide a knwon login ID */
	res = TEEC_OpenSession(&primary_ctx.context, &primary_ctx.session,
				&uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS) {
		LOG_ERROR("TEEC open session failed %x from %d\n", res, origin);
		TEEC_FinalizeContext(&primary_ctx.context);
		return -1;
	}

	primary_invoke.context = &primary_ctx.context;
	primary_invoke.session = &primary_ctx.session;

	return 0;
}

static void close_primary_context(void)
{
	/*  TODO: mutex */
	if (!primary_invoke.session)
		return;

	TEEC_CloseSession(&primary_ctx.session);
	TEEC_FinalizeContext(&primary_ctx.context);
	primary_invoke.context = NULL;
	primary_invoke.session = NULL;
}

static struct sks_invoke *get_invoke_context(struct sks_invoke *sks_ctx)
{
	struct sks_invoke *ctx = sks_ctx;

	if (open_primary_context())
		return NULL;

	if (!ctx)
		return &primary_invoke;

	if (!ctx->context)
		ctx->context = primary_invoke.context;
	if (!ctx->session)
		ctx->session = primary_invoke.session;

	return ctx;
}

static TEEC_Context *teec_ctx(struct sks_invoke *sks_ctx)
{
	return (TEEC_Context *)sks_ctx->context;
}

static TEEC_Session *teec_sess(struct sks_invoke *sks_ctx)
{
	return (TEEC_Session *)sks_ctx->session;
}

TEEC_SharedMemory *sks_alloc_shm(struct sks_invoke *sks_ctx,
				 size_t size, int in, int out)
{
	struct sks_invoke *ctx = get_invoke_context(sks_ctx);
	TEEC_SharedMemory *shm;

	if (!ctx || (!in && !out))
		return NULL;

	shm = calloc(1, sizeof(TEEC_SharedMemory));
	if (!shm)
		return NULL;

	shm->size = size;

	if (in)
		shm->flags |= TEEC_MEM_INPUT;
	if (out)
		shm->flags |= TEEC_MEM_OUTPUT;

	if (TEEC_AllocateSharedMemory(teec_ctx(ctx), shm)) {
		free(shm);
		return NULL;
	}

	return shm;
}

TEEC_SharedMemory *sks_register_shm(struct sks_invoke *sks_ctx,
				    void *buf, size_t size, int in, int out)
{
	struct sks_invoke *ctx = get_invoke_context(sks_ctx);
	TEEC_SharedMemory *shm;

	if (!ctx || (!in && !out))
		return NULL;

	shm = calloc(1, sizeof(TEEC_SharedMemory));
	if (!shm)
		return NULL;

	shm->buffer = buf;
	shm->size = size;

	if (in)
		shm->flags |= TEEC_MEM_INPUT;
	if (out)
		shm->flags |= TEEC_MEM_OUTPUT;

	if (TEEC_RegisterSharedMemory(teec_ctx(ctx), shm)) {
		free(shm);
		return NULL;
	}

	return shm;
}

void sks_free_shm(TEEC_SharedMemory *shm)
{
	TEEC_ReleaseSharedMemory(shm);
	free(shm);
}

CK_RV ck_invoke_ta(struct sks_invoke *sks_ctx,
		   unsigned long cmd,
		   void *ctrl, size_t ctrl_sz,
		   void *in, size_t in_sz,
		   void *out, size_t *out_sz)
{
	struct sks_invoke *ctx = get_invoke_context(sks_ctx);
	uint32_t command = (uint32_t)cmd;
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	TEEC_SharedMemory *ctrl_shm = ctrl;
	TEEC_SharedMemory *in_shm = in;
	TEEC_SharedMemory *out_shm = out;

	memset(&op, 0, sizeof(op));

	/*
	 * Command control field: TEE invocation parameter #0
	 */
	if (ctrl && ctrl_sz) {
		op.params[0].tmpref.buffer = ctrl;
		op.params[0].tmpref.size = ctrl_sz;
		op.paramTypes |= TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						  0, 0, 0);
	}
	if (ctrl && !ctrl_sz) {
		op.params[0].memref.parent = ctrl_shm;
		op.paramTypes |= TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, 0, 0, 0);
	}

	/*
	 * Input data field: TEE invocation parameter #1
	 */
	if (in && in_sz) {
		op.params[1].tmpref.buffer = in;
		op.params[1].tmpref.size = in_sz;
		op.paramTypes |= TEEC_PARAM_TYPES(0, TEEC_MEMREF_TEMP_INPUT,
						  0, 0);
	}
	if (in && !in_sz) {
		op.params[1].memref.parent = in_shm;
		op.paramTypes |= TEEC_PARAM_TYPES(0, TEEC_MEMREF_WHOLE, 0, 0);
	}

	/*
	 * Output data field: TEE invocation parameter #2
	 */
	if (out_sz) {
		op.params[2].tmpref.buffer = out;
		op.params[2].tmpref.size = *out_sz;
		op.paramTypes |= TEEC_PARAM_TYPES(0, 0, TEEC_MEMREF_TEMP_OUTPUT,
						  0);
	}
	if (!out_sz && out) {
		op.params[2].memref.parent = out_shm;
		op.paramTypes |= TEEC_PARAM_TYPES(0, 0, TEEC_MEMREF_WHOLE, 0);
	}

	/*
	 * Invoke the TEE and update output buffer size on exit.
	 * Too short buffers are treated as positive errors.
	 */
	res = TEEC_InvokeCommand(teec_sess(ctx), command, &op, &origin);
	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_SHORT_BUFFER:
		break;
	case TEEC_ERROR_OUT_OF_MEMORY:
		return CKR_DEVICE_MEMORY;
	default:
		return CKR_DEVICE_ERROR;
	}

	if (out_sz)
		*out_sz = op.params[2].tmpref.size;

	if (res == TEEC_ERROR_SHORT_BUFFER)
		return CKR_BUFFER_TOO_SMALL;

	return CKR_OK;
}

void sks_invoke_terminate(void)
{
	close_primary_context();
}
