/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Linaro Limited
 */

#ifndef LIBCKTEEC_CK_HELPERS_H
#define LIBCKTEEC_CK_HELPERS_H

#include <pkcs11.h>
#include <tee_client_api.h>

#include "local_utils.h"

#ifdef DEBUG
#define ASSERT_CK_RV(_rv, ...)						\
	do {								\
		const CK_RV ref[] = { __VA_ARGS__ };			\
		size_t count = ARRAY_SIZE(ref);				\
									\
		ckteec_assert_expected_rv(__func__, (_rv), ref, count);	\
	} while (0)

void ckteec_assert_expected_rv(const char *function, CK_RV rv,
			       const CK_RV *expected_rv, size_t expected_count);
#else
#define ASSERT_CK_RV(_rv, ...)		(void)0
#endif /*DEBUG*/

#endif /*LIBCKTEEC_CK_HELPERS_H*/
