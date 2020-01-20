/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#ifndef LIBCKTEEC_CK_DEBUG_H
#define LIBCKTEEC_CK_DEBUG_H

#include <pkcs11.h>

/* Return a pointer to a string buffer of "CKR_xxx\0" return value ID */
const char *ckr2str(CK_RV id);

#endif /*LIBCKTEEC_CK_DEBUG_H*/
