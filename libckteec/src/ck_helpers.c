// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */

#include "ck_helpers.h"

CK_RV teec2ck_rv(TEEC_Result res)
{
	switch (res) {
	case TEEC_SUCCESS:
		return CKR_OK;
	case TEEC_ERROR_OUT_OF_MEMORY:
		return CKR_DEVICE_MEMORY;
	case TEEC_ERROR_BAD_PARAMETERS:
		return CKR_ARGUMENTS_BAD;
	case TEEC_ERROR_SHORT_BUFFER:
		return CKR_BUFFER_TOO_SMALL;
	default:
		return CKR_FUNCTION_FAILED;
	}
}
