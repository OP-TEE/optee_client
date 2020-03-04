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
	size_t client_count = 0;
	size_t size = 0;

	/* Discard @present: all slots reported by TA are present */
	(void)present;

	if (!count)
		return CKR_ARGUMENTS_BAD;

	/*
	 * As per spec, if @slots is NULL, "The contents of *pulCount on
	 * entry to C_GetSlotList has no meaning in this case (...)"
	 */
	if (slots)
		client_count = *count;

	size = client_count * sizeof(*slot_ids);

	shm = ckteec_alloc_shm(size, CKTEEC_SHM_OUT);
	if (!shm)
		return CKR_HOST_MEMORY;

	rv = ckteec_invoke_ta(PKCS11_CMD_SLOT_LIST, NULL,
			      NULL, shm, &size, NULL, NULL);

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL) {
		/*
		 * When @slot != NULL and @count[0] == 0, library shall
		 * return CKR_BUFFER_TOO_SMALL if provided buffer is too
		 * small whereas TA would have returned CKR_OK since
		 * allocating a zero sized shm instance results in a NULL
		 * shm buffer reference.
		 */
		if (size && slots && !client_count)
			rv = CKR_BUFFER_TOO_SMALL;

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

/**
 * ck_slot_get_info - Wrap C_GetSlotInfo into PKCS11_CMD_SLOT_INFO
 */
CK_RV ck_slot_get_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out = NULL;
	uint32_t slot_id = slot;
	struct pkcs11_slot_info *ta_info = NULL;
	size_t out_size = 0;

	if (!info)
		return CKR_ARGUMENTS_BAD;

	ctrl = ckteec_alloc_shm(sizeof(slot_id), CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}
	memcpy(ctrl->buffer, &slot_id, sizeof(slot_id));

	out = ckteec_alloc_shm(sizeof(*ta_info), CKTEEC_SHM_OUT);
	if (!out) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_SLOT_INFO, ctrl, out, &out_size);
	if (rv != CKR_OK || out_size != out->size) {
		if (rv == CKR_OK)
			rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	ta_info = out->buffer;

	COMPILE_TIME_ASSERT(sizeof(info->slotDescription) ==
			    sizeof(ta_info->slot_description));
	memcpy(info->slotDescription, ta_info->slot_description,
	       sizeof(info->slotDescription));

	COMPILE_TIME_ASSERT(sizeof(info->manufacturerID) ==
			    sizeof(ta_info->manufacturer_id));
	memcpy(info->manufacturerID, ta_info->manufacturer_id,
	       sizeof(info->manufacturerID));

	info->flags = ta_info->flags;

	COMPILE_TIME_ASSERT(sizeof(info->hardwareVersion) ==
			    sizeof(ta_info->hardware_version));
	memcpy(&info->hardwareVersion, ta_info->hardware_version,
	       sizeof(info->hardwareVersion));

	COMPILE_TIME_ASSERT(sizeof(info->firmwareVersion) ==
			    sizeof(ta_info->firmware_version));
	memcpy(&info->firmwareVersion, ta_info->firmware_version,
	       sizeof(info->firmwareVersion));

bail:
	ckteec_free_shm(ctrl);
	ckteec_free_shm(out);

	return rv;
}

/**
 * ck_token_get_info - Wrap C_GetTokenInfo into PKCS11_CMD_TOKEN_INFO
 */
CK_RV ck_token_get_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	uint32_t slot_id = slot;
	struct pkcs11_token_info *ta_info = NULL;
	size_t out_size = 0;

	if (!info)
		return CKR_ARGUMENTS_BAD;

	ctrl = ckteec_alloc_shm(sizeof(slot_id), CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}
	memcpy(ctrl->buffer, &slot_id, sizeof(slot_id));

	out_shm = ckteec_alloc_shm(sizeof(*ta_info), CKTEEC_SHM_OUT);
	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_TOKEN_INFO, ctrl,
				    out_shm, &out_size);
	if (rv)
		goto bail;

	if (out_size != out_shm->size) {
		rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	ta_info = out_shm->buffer;

	COMPILE_TIME_ASSERT(sizeof(info->label) == sizeof(ta_info->label));
	memcpy(info->label, ta_info->label, sizeof(info->label));

	COMPILE_TIME_ASSERT(sizeof(info->manufacturerID) ==
			    sizeof(ta_info->manufacturer_id));
	memcpy(info->manufacturerID, ta_info->manufacturer_id,
	       sizeof(info->manufacturerID));

	COMPILE_TIME_ASSERT(sizeof(info->model) == sizeof(ta_info->model));
	memcpy(info->model, ta_info->model, sizeof(info->model));

	COMPILE_TIME_ASSERT(sizeof(info->serialNumber) ==
			    sizeof(ta_info->serial_number));
	memcpy(info->serialNumber, ta_info->serial_number,
	       sizeof(info->serialNumber));

	info->flags = ta_info->flags;
	info->ulMaxSessionCount = ta_info->max_session_count;
	info->ulSessionCount = ta_info->session_count;
	info->ulMaxRwSessionCount = ta_info->max_rw_session_count;
	info->ulRwSessionCount = ta_info->rw_session_count;
	info->ulMaxPinLen = ta_info->max_pin_len;
	info->ulMinPinLen = ta_info->min_pin_len;
	info->ulTotalPublicMemory = ta_info->total_public_memory;
	info->ulFreePublicMemory = ta_info->free_public_memory;
	info->ulTotalPrivateMemory = ta_info->total_private_memory;
	info->ulFreePrivateMemory = ta_info->free_private_memory;

	COMPILE_TIME_ASSERT(sizeof(info->hardwareVersion) ==
			    sizeof(ta_info->hardware_version));
	memcpy(&info->hardwareVersion, ta_info->hardware_version,
	       sizeof(info->hardwareVersion));

	COMPILE_TIME_ASSERT(sizeof(info->firmwareVersion) ==
			    sizeof(ta_info->firmware_version));
	memcpy(&info->firmwareVersion, ta_info->firmware_version,
	       sizeof(info->firmwareVersion));

	COMPILE_TIME_ASSERT(sizeof(info->utcTime) == sizeof(ta_info->utc_time));
	memcpy(&info->utcTime, ta_info->utc_time, sizeof(info->utcTime));

bail:
	ckteec_free_shm(ctrl);
	ckteec_free_shm(out_shm);

	return rv;
}
