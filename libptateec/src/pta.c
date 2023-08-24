// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Foundries.io Ltd
 */

#ifndef BINARY_PREFIX
#define BINARY_PREFIX "ptateec"
#endif

#include "pta.h"

TEEC_Result pta_open_session(struct pta_context *ctx)
{
	TEEC_Result ret = TEEC_SUCCESS;

	pthread_mutex_lock(&ctx->lock);
	if (!ctx->open) {
		ret = TEEC_InitializeContext(NULL, &ctx->context);
		if (!ret) {
			ret = TEEC_OpenSession(&ctx->context, &ctx->session,
					       &ctx->uuid, TEEC_LOGIN_PUBLIC,
					       NULL, NULL, NULL);
			if (!ret)
				ctx->open = true;
		}
	}
	if (ctx->open)
		atomic_fetch_add(&ctx->count, 1);
	pthread_mutex_unlock(&ctx->lock);

	return ret;
}

TEEC_Result pta_invoke_cmd(struct pta_context *ctx, uint32_t cmd_id,
			   TEEC_Operation *op, uint32_t *error_origin)
{
	TEEC_Result ret = TEEC_SUCCESS;

	pthread_mutex_lock(&ctx->lock);
	if (!ctx->open) {
		atomic_store(&ctx->count, 0);
		pthread_mutex_unlock(&ctx->lock);

		return TEEC_ERROR_COMMUNICATION;
	}
	pthread_mutex_unlock(&ctx->lock);
	ret = TEEC_InvokeCommand(&ctx->session, cmd_id, op, error_origin);
	atomic_fetch_sub(&ctx->count, 1);

	return ret;
}

TEEC_Result pta_final(struct pta_context *ctx)
{
	TEEC_Result ret = TEEC_SUCCESS;

	pthread_mutex_lock(&ctx->lock);
	if (!ctx->open) {
		pthread_mutex_unlock(&ctx->lock);
		return TEEC_SUCCESS;
	}

	if (atomic_load(&ctx->count)) {
		ret = TEEC_ERROR_BUSY;
	} else {
		TEEC_CloseSession(&ctx->session);
		TEEC_FinalizeContext(&ctx->context);
		ctx->open = false;
	}
	pthread_mutex_unlock(&ctx->lock);

	return ret;
}
