/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Linaro Limited
 */

#ifndef LIBCKTEEC_CK_HELPERS_H
#define LIBCKTEEC_CK_HELPERS_H

#include <pkcs11.h>
#include <tee_client_api.h>

/*
 * Convert IDs between PKCS11 TA and Cryptoki.
 */
CK_RV teec2ck_rv(TEEC_Result res);

#endif /*LIBCKTEEC_CK_HELPERS_H*/
