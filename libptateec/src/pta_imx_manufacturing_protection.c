// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Foundries.io Ltd
 *
 *  The CAAM features a "manufacturing protection" attestation feature.
 *
 *  It is a authentication process used to authenticate the chip to
 *  the OEM's server.
 *
 * The authentication process can ensure the chip:
 *    - is a genuine NXP part
 *    - is a correct part type
 *    - has been properly fused
 *    - is running a authenticated software
 *    - runs in secure/trusted mode.
 */

#ifndef BINARY_PREFIX
#define BINARY_PREFIX "ptateec"
#endif

#include "pta.h"
#include "pta_imx_manufacturing_protection.h"

static struct pta_context manufacturing_protection_pta_ctx = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.uuid = PTA_MANUFACT_PROTEC_UUID,
};

TEEC_Result pta_imx_mprotect_get_key(char *key, size_t *len)
{
	TEEC_Result ret = TEEC_SUCCESS;
	TEEC_Operation op = { 0 };

	if (!key || !len || !*len)
		return TEEC_ERROR_BAD_PARAMETERS;

	ret = pta_open_session(&manufacturing_protection_pta_ctx);
	if (ret) {
		if (ret == TEEC_ERROR_OUT_OF_MEMORY)
			return ret;
		return TEEC_ERROR_ACCESS_DENIED;
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = *len;

	ret = pta_invoke_cmd(&manufacturing_protection_pta_ctx,
			     PTA_IMX_MP_CMD_GET_PUBLIC_KEY, &op, NULL);

	if (ret != TEEC_SUCCESS) {
		if (ret == TEEC_ERROR_SHORT_BUFFER) {
			/* Update with expected length */
			*len = op.params[0].tmpref.size;
			return ret;
		} else if (ret == TEEC_ERROR_COMMUNICATION ||
			   ret == TEEC_ERROR_OUT_OF_MEMORY) {
			return ret;
		}
		return TEEC_ERROR_GENERIC;
	}

	*len = op.params[0].tmpref.size;

	return TEEC_SUCCESS;
}

TEEC_Result pta_imx_mprotect_sign(char *msg, size_t msg_len,
				  char *sig, size_t *sig_len,
				  char *mpmr, size_t *mpmr_len)
{
	TEEC_Result ret = TEEC_SUCCESS;
	TEEC_Operation op = { 0 };

	if (!msg || !sig || !sig_len || !mpmr || !mpmr_len)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!msg_len || !*sig_len || !*mpmr_len)
		return TEEC_ERROR_BAD_PARAMETERS;

	ret = pta_open_session(&manufacturing_protection_pta_ctx);
	if (ret) {
		if (ret == TEEC_ERROR_OUT_OF_MEMORY)
			return ret;
		return TEEC_ERROR_ACCESS_DENIED;
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	op.params[0].tmpref.buffer = msg;
	op.params[0].tmpref.size = msg_len;
	op.params[1].tmpref.buffer = sig;
	op.params[1].tmpref.size = *sig_len;
	op.params[2].tmpref.buffer = mpmr;
	op.params[2].tmpref.size = *mpmr_len;

	ret = pta_invoke_cmd(&manufacturing_protection_pta_ctx,
			     PTA_IMX_MP_CMD_SIGNATURE_MPMR, &op, NULL);

	if (ret != TEEC_SUCCESS) {
		if (ret == TEEC_ERROR_SHORT_BUFFER) {
			/* Update with the expected lengths */
			*sig_len = op.params[1].tmpref.size;
			*mpmr_len = op.params[2].tmpref.size;
			return ret;
		} else if (ret == TEEC_ERROR_COMMUNICATION ||
			   ret == TEEC_ERROR_OUT_OF_MEMORY) {
			return ret;
		}

		return TEEC_ERROR_GENERIC;
	}

	*sig_len = op.params[1].tmpref.size;
	*mpmr_len = op.params[2].tmpref.size;

	return TEEC_SUCCESS;
}

TEEC_Result pta_imx_mprotect_final(void)
{
	return pta_final(&manufacturing_protection_pta_ctx);
}
