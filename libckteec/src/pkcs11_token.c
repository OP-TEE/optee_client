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

/**
 * ck_slot_get_list - Wrap C_GetSlotList into PKCS11_CMD_SLOT_LIST
 */
CK_RV ck_slot_get_list(CK_BBOOL present,
		       CK_SLOT_ID_PTR slots, CK_ULONG_PTR count)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *shm = NULL;
	uint32_t *slot_ids = NULL;
	size_t size = 0;

	/* Discard @present: all slots reported by TA are present */
	(void)present;

	if (!count || (*count && !slots))
		return CKR_ARGUMENTS_BAD;

	size = *count * sizeof(*slot_ids);

	shm = ckteec_alloc_shm(size, CKTEEC_SHM_OUT);
	if (!shm)
		return CKR_HOST_MEMORY;

	rv = ckteec_invoke_ta(PKCS11_CMD_SLOT_LIST, NULL,
			      NULL, shm, &size, NULL, NULL);

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL) {
		*count = size / sizeof(*slot_ids);

		if (rv == CKR_OK && slots) {
			size_t n = 0;

			slot_ids = shm->buffer;
			for (n = 0; n < *count; n++)
				slots[n] = slot_ids[n];
		}
	}

	ckteec_free_shm(shm);

	return rv;
}
