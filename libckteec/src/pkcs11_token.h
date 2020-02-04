/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef LIBCKTEEC_PKCS11_TOKEN_H
#define LIBCKTEEC_PKCS11_TOKEN_H

#include <pkcs11.h>

#include "invoke_ta.h"

CK_RV ck_get_info(CK_INFO_PTR info);

#endif /*LIBCKTEEC_PKCS11_TOKEN_H*/
