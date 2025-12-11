// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Vaisala Oyj.
 */

#include <asteec.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <tee_client_api.h>

#include "app_secrets_ta.h"

static TEEC_Result open_session(TEEC_Context *ctx, TEEC_Session *session,
				uint32_t login_method, gid_t login_gid)
{
	TEEC_UUID uuid = APP_SECRETS_TA_UUID;
	void *login_data = NULL;

	switch (login_method) {
	case TEEC_LOGIN_PUBLIC:
	case TEEC_LOGIN_USER:
	case TEEC_LOGIN_APPLICATION:
	case TEEC_LOGIN_USER_APPLICATION:
		break;
	case TEEC_LOGIN_GROUP:
	case TEEC_LOGIN_GROUP_APPLICATION:
		login_data = &login_gid;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	return TEEC_OpenSession(ctx, session, &uuid,
				login_method, login_data, NULL, NULL);
}

TEEC_Result asteec_seal(uint32_t login_method, gid_t login_gid,
			const void *plain, size_t plain_len,
			void *sealed, size_t *sealed_len)
{
	TEEC_Context ctx = { 0 };
	TEEC_Session session = { 0 };
	TEEC_Operation op = { 0 };
	TEEC_Result res = TEEC_ERROR_GENERIC;

	if (!plain || !plain_len || !sealed_len)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!sealed && *sealed_len)
		return TEEC_ERROR_BAD_PARAMETERS;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		return res;

	res = open_session(&ctx, &session, login_method, login_gid);
	if (res != TEEC_SUCCESS)
		goto out_ctx;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = (void *)plain;
	op.params[0].tmpref.size = plain_len;

	op.params[1].tmpref.buffer = sealed;
	op.params[1].tmpref.size = *sealed_len;

	res = TEEC_InvokeCommand(&session, TA_APPSECRETS_CMD_SEAL_SECRET,
				 &op, NULL);

	if (res == TEEC_SUCCESS || res == TEEC_ERROR_SHORT_BUFFER)
		*sealed_len = op.params[1].tmpref.size;

	TEEC_CloseSession(&session);
out_ctx:
	TEEC_FinalizeContext(&ctx);
	return res;
}

TEEC_Result asteec_unseal(uint32_t login_method, gid_t login_gid,
			  const void *sealed, size_t sealed_len,
			  void *plain, size_t *plain_len)
{
	TEEC_Context ctx = { 0 };
	TEEC_Session session = { 0 };
	TEEC_Operation op = { 0 };
	TEEC_Result res = TEEC_ERROR_GENERIC;

	if (!sealed || !sealed_len || !plain_len)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!plain && *plain_len)
		return TEEC_ERROR_BAD_PARAMETERS;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		return res;

	res = open_session(&ctx, &session, login_method, login_gid);
	if (res != TEEC_SUCCESS)
		goto out_ctx;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = (void *)sealed;
	op.params[0].tmpref.size = sealed_len;

	op.params[1].tmpref.buffer = plain;
	op.params[1].tmpref.size = *plain_len;

	res = TEEC_InvokeCommand(&session, TA_APPSECRETS_CMD_UNSEAL_SECRET,
				 &op, NULL);

	if (res == TEEC_SUCCESS || res == TEEC_ERROR_SHORT_BUFFER)
		*plain_len = op.params[1].tmpref.size;

	TEEC_CloseSession(&session);
out_ctx:
	TEEC_FinalizeContext(&ctx);
	return res;
}
