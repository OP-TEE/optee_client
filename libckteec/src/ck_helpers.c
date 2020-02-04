// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */

#include <assert.h>
#include <pkcs11.h>
#include <stdio.h>
#include <tee_client_api.h>

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

#ifdef DEBUG
void ckteec_assert_expected_rv(const char *function, CK_RV rv,
			       const CK_RV *expected_rv, size_t expected_count)
{
	size_t n = 0;

	for (n = 0; n < expected_count; n++)
		if (rv == expected_rv[n])
			return;

	fprintf(stderr, "libckteec: unexpected return value 0x%lx for %s\n",
		rv, function);

	assert(0);
}
#endif
