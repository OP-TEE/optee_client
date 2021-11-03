// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Foundries.io Ltd
 */

#ifndef BINARY_PREFIX
#define BINARY_PREFIX "seteec"
#endif

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <se_tee.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <teec_trace.h>

#include "pta_apdu.h"
#include "pta_scp03.h"

struct ta_context {
	pthread_mutex_t lock;
	TEEC_Context context;
	TEEC_Session session;
	TEEC_UUID uuid;
	bool open;
};

static struct ta_context apdu_ta_ctx = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.uuid = PTA_APDU_UUID,
};

static struct ta_context scp03_ta_ctx = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.uuid = PTA_SCP03_UUID,
};

static bool open_session(struct ta_context *ctx)
{
	TEEC_Result res = TEEC_SUCCESS;

	if (pthread_mutex_lock(&ctx->lock))
		return false;

	if (!ctx->open) {
		res = TEEC_InitializeContext(NULL, &ctx->context);
		if (!res) {
			res = TEEC_OpenSession(&ctx->context, &ctx->session,
					       &ctx->uuid, TEEC_LOGIN_PUBLIC,
					       NULL, NULL, NULL);
			if (!res)
				ctx->open = true;
		}
	}

	return !pthread_mutex_unlock(&ctx->lock) && !res;
}

static SE_RV do_scp03(uint32_t cmd)
{
	TEEC_Operation op = { 0 };

	if (!open_session(&scp03_ta_ctx))
		return SER_CANT_OPEN_SESSION;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, 0, 0, 0);
	op.params[0].value.a = cmd;

	if (TEEC_InvokeCommand(&scp03_ta_ctx.session,
			       PTA_CMD_ENABLE_SCP03, &op, NULL))
		return SER_ERROR_GENERIC;

	return SER_OK;
}

SE_RV se_scp03_enable(void)
{
	return do_scp03(PTA_SCP03_SESSION_CURRENT_KEYS);
}

SE_RV se_scp03_rotate_keys_and_enable(void)
{
	return do_scp03(PTA_SCP03_SESSION_ROTATE_KEYS);
}

SE_RV se_apdu_request(enum se_apdu_type apdu_type,
		      unsigned char *hdr, size_t hdr_len,
		      unsigned char *src, size_t src_len,
		      unsigned char *dst, size_t *dst_len)
{
	uint32_t type = PTA_APDU_TXRX_CASE_NO_HINT;
	TEEC_Operation op = { 0 };

	switch (apdu_type) {
	case SE_APDU_NO_HINT:
		type = PTA_APDU_TXRX_CASE_NO_HINT;
		break;
	case SE_APDU_CASE_1:
		type = PTA_APDU_TXRX_CASE_1;
		break;
	case SE_APDU_CASE_2:
		type = PTA_APDU_TXRX_CASE_2;
		break;
	case SE_APDU_CASE_2E:
		type = PTA_APDU_TXRX_CASE_2E;
		break;
	case SE_APDU_CASE_3:
		type = PTA_APDU_TXRX_CASE_3;
		break;
	case SE_APDU_CASE_3E:
		type = PTA_APDU_TXRX_CASE_3E;
		break;
	case SE_APDU_CASE_4:
		type = PTA_APDU_TXRX_CASE_4;
		break;
	case SE_APDU_CASE_4E:
		type = PTA_APDU_TXRX_CASE_4E;
		break;
	default:
		return SER_ERROR_GENERIC;
	}

	if (!open_session(&apdu_ta_ctx))
		return SER_CANT_OPEN_SESSION;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].value.a = type;
	op.params[1].tmpref.buffer = hdr;
	op.params[1].tmpref.size = hdr_len;
	op.params[2].tmpref.buffer = src;
	op.params[2].tmpref.size = src_len;
	op.params[3].tmpref.buffer = dst;
	op.params[3].tmpref.size = *dst_len;

	if (TEEC_InvokeCommand(&apdu_ta_ctx.session,
			       PTA_CMD_TXRX_APDU_RAW_FRAME, &op, NULL))
		return SER_ERROR_GENERIC;

	*dst_len = op.params[3].tmpref.size;

	return SER_OK;
}
