// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */

#include <assert.h>
#include <ck_debug.h>
#include <pkcs11.h>
#include <stdio.h>
#include <tee_client_api.h>

#include "ck_helpers.h"

#ifdef DEBUG
void ckteec_assert_expected_rv(const char *function, CK_RV rv,
			       const CK_RV *expected_rv, size_t expected_count)
{
	size_t n = 0;

	for (n = 0; n < expected_count; n++)
		if (rv == expected_rv[n])
			return;

	fprintf(stderr, "libckteec: %s: unexpected return value 0x%lx (%s)\n",
		function, rv, ckr2str(rv));

	assert(0);
}
#endif
