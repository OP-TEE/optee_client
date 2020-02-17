/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef LIBCKTEEC_PKCS11_TOKEN_H
#define LIBCKTEEC_PKCS11_TOKEN_H

#include <pkcs11.h>

#include "invoke_ta.h"

CK_RV ck_get_info(CK_INFO_PTR info);

CK_RV ck_slot_get_list(CK_BBOOL present,
		       CK_SLOT_ID_PTR slots, CK_ULONG_PTR count);

CK_RV ck_slot_get_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info);

#endif /*LIBCKTEEC_PKCS11_TOKEN_H*/
