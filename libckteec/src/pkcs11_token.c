// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <ck_debug.h>
#include <pkcs11.h>
#include <pkcs11_ta.h>
#include <stdlib.h>
#include <string.h>

#include "ck_helpers.h"
#include "invoke_ta.h"
#include "local_utils.h"
#include "pkcs11_token.h"

#define PKCS11_LIB_MANUFACTURER		"Linaro"
#define PKCS11_LIB_DESCRIPTION		"OP-TEE PKCS11 Cryptoki library"

/**
 * ck_get_info - Get local information for C_GetInfo
 */
CK_RV ck_get_info(CK_INFO_PTR info)
{
	const CK_INFO lib_info = {
		.cryptokiVersion =  {
			CK_PKCS11_VERSION_MAJOR,
			CK_PKCS11_VERSION_MINOR,
		},
		.manufacturerID = PKCS11_LIB_MANUFACTURER,
		.flags = 0,		/* must be zero per the PKCS#11 2.40 */
		.libraryDescription = PKCS11_LIB_DESCRIPTION,
		.libraryVersion = {
			PKCS11_TA_VERSION_MAJOR,
			PKCS11_TA_VERSION_MINOR
		},
	};
	int n = 0;

	if (!info)
		return CKR_ARGUMENTS_BAD;

	*info = lib_info;

	/* Pad strings with blank characters */
	n = strnlen((char *)info->manufacturerID,
		    sizeof(info->manufacturerID));
	memset(&info->manufacturerID[n], ' ',
	       sizeof(info->manufacturerID) - n);

	n = strnlen((char *)info->libraryDescription,
		    sizeof(info->libraryDescription));
	memset(&info->libraryDescription[n], ' ',
	       sizeof(info->libraryDescription) - n);

	return CKR_OK;
}
