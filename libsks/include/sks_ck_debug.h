/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SKS_CK_DEBUG_H
#define __SKS_CK_DEBUG_H

#include <pkcs11.h>

/* Return a pointer to a string buffer of "CKA_xxx\0" attribute ID */
const char *cka2str(CK_ATTRIBUTE_TYPE id);

/* Return a pointer to a string buffer of "CKR_xxx\0" return value ID */
const char *ckr2str(CK_RV id);

/* Return a pointer to a string buffer of "CKM_xxx\0" mechanism ID */
const char *ckm2str(CK_MECHANISM_TYPE id);

/* Allocate and return a string descripbing the enabled flags */
char *ck_slot_flag2str(CK_ULONG flags);
char *ck_token_flag2str(CK_ULONG flags);
char *ck_mecha_flag2str(CK_ULONG flags);

const char *ckclass2str(CK_ULONG id);
const char *cktype2str(CK_ULONG id, CK_ULONG class);

const char *skscmd2str(unsigned int id);

#endif /*__SKS_CK_DEBUG_H*/
