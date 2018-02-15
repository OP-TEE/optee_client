/*
 * Copyright (c) 2017, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <pkcs11.h>
#include <sks_ck_debug.h>
#include <sks_ta.h>
#include <stdlib.h>
#include <string.h>

#include "ck_helpers.h"
#include "invoke_ta.h"
#include "local_utils.h"
#include "pkcs11_token.h"

#define SKS_CRYPTOKI_SLOT_MANUFACTURER		"Linaro"

#define PADDED_STRING_COPY(_dst, _src) \
	do { \
		memset((char *)_dst, ' ', sizeof(_dst)); \
		strncpy((char *)_dst, _src, sizeof(_dst)); \
	} while (0)

/**
 * sks_ck_get_info - implementation of C_GetInfo
 */
int sks_ck_get_info(CK_INFO_PTR info)
{
	const CK_VERSION ck_version = { 2, 40 };
	const char manuf_id[] = SKS_CRYPTOKI_SLOT_MANUFACTURER; // TODO slot?
	const CK_FLAGS flags = 0;	/* must be zero per the PKCS#11 2.40 */
	const char lib_description[] = "OP-TEE SKS Cryptoki library";
	const CK_VERSION lib_version = { 0, 0 };

	info->cryptokiVersion = ck_version;
	PADDED_STRING_COPY(info->manufacturerID, manuf_id);
	info->flags = flags;
	PADDED_STRING_COPY(info->libraryDescription, lib_description);
	info->libraryVersion = lib_version;

	return CKR_OK;
}

/**
 * slot_get_info - implementation of C_GetSlotList
 */
CK_RV sks_ck_slot_get_list(CK_BBOOL present,
			   CK_SLOT_ID_PTR slots, CK_ULONG_PTR count)
{
	TEEC_SharedMemory *shm;
	size_t size = 0;
	CK_RV rv = CKR_GENERAL_ERROR;
	unsigned int n;

	/* Discard present: all are present */
	(void)present;

	if (!count)
		return CKR_ARGUMENTS_BAD;

	if (ck_invoke_ta(NULL, SKS_CMD_CK_SLOT_LIST, NULL, 0,
			 NULL, 0, NULL, &size) != CKR_BUFFER_TOO_SMALL)
		return CKR_DEVICE_ERROR;

	if (!slots || *count < (size / sizeof(uint32_t))) {
		*count = size / sizeof(uint32_t);
		return CKR_BUFFER_TOO_SMALL;
	}

	shm = sks_alloc_shm_out(NULL, size);
	if (!shm)
		return CKR_HOST_MEMORY;

	if (ck_invoke_ta(NULL, SKS_CMD_CK_SLOT_LIST,
			 NULL, 0, NULL, 0, shm, NULL) != CKR_OK) {
		rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	for (n = 0; n < (size / sizeof(uint32_t)); n++)
		slots[n] = *((uint32_t *)shm->buffer + n);

	*count = size / sizeof(uint32_t);
	rv = CKR_OK;
bail:
	sks_free_shm(shm);
	return rv;

}

/**
 * slot_get_info - implementation of C_GetSlotInfo
 */
int sks_ck_slot_get_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info)
{
	uint32_t ctrl[1] = { slot };
	CK_SLOT_INFO *ck_info = info;
	struct sks_ck_slot_info sks_info;
	size_t out_size = sizeof(sks_info);

	if (ck_invoke_ta(NULL, SKS_CMD_CK_SLOT_INFO,
			 &ctrl, sizeof(ctrl),
			 NULL, 0, &sks_info, &out_size))
		return CKR_DEVICE_ERROR;

	if (sks2ck_slot_info(ck_info, &sks_info)) {
		LOG_ERROR("unexpected bad token info structure\n");
		return CKR_DEVICE_ERROR;
	}

	return CKR_OK;
}

/**
 * slot_get_info - implementation of C_GetTokenInfo
 */
CK_RV sks_ck_token_get_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	uint32_t ctrl[1] = { slot };
	CK_TOKEN_INFO *ck_info = info;
	TEEC_SharedMemory *shm;
	size_t size;
	CK_RV rv = CKR_GENERAL_ERROR;

	ctrl[0] = (uint32_t)slot;
	size = 0;
	if (ck_invoke_ta(NULL, SKS_CMD_CK_TOKEN_INFO,
			 ctrl, sizeof(ctrl), NULL, 0,
			 NULL, &size) != CKR_BUFFER_TOO_SMALL)
		return CKR_DEVICE_ERROR;

	shm = sks_alloc_shm_out(NULL, size);
	if (!shm)
		return CKR_HOST_MEMORY;

	ctrl[0] = (uint32_t)slot;
	rv = ck_invoke_ta(NULL, SKS_CMD_CK_TOKEN_INFO,
			  ctrl, sizeof(ctrl), NULL, 0, shm, NULL);
	if (rv)
		goto bail;

	if (shm->size < sizeof(struct sks_ck_token_info)) {
		LOG_ERROR("unexpected bad token info size\n");
		rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	rv = sks2ck_token_info(ck_info, shm->buffer);

bail:
	sks_free_shm(shm);

	return rv;
}

/**
 * sks_ck_init_token - implementation of C_InitToken
 */
CK_RV sks_ck_init_token(CK_SLOT_ID slot,
			CK_UTF8CHAR_PTR pin,
			CK_ULONG pin_len,
			CK_UTF8CHAR_PTR label)
{
	TEEC_SharedMemory *shm;
	uint32_t sks_slot = slot;
	uint32_t sks_pin_len = pin_len;
	size_t ctrl_size = 2 * sizeof(uint32_t) + sks_pin_len +
			   32 * sizeof(uint8_t);
	char *ctrl;

	shm = sks_alloc_shm_in(NULL, ctrl_size);
	if (!shm)
		return CKR_HOST_MEMORY;

	ctrl = shm->buffer;

	memcpy(ctrl, &sks_slot, sizeof(uint32_t));
	ctrl += sizeof(uint32_t);

	memcpy(ctrl, &sks_pin_len, sizeof(uint32_t));
	ctrl += sizeof(uint32_t);

	memcpy(ctrl, pin, sks_pin_len);
	ctrl += sks_pin_len;

	memcpy(ctrl, label, 32 * sizeof(uint8_t));

	return ck_invoke_ta(NULL, SKS_CMD_CK_INIT_TOKEN,
			    shm, 0, NULL, 0, NULL, NULL);
}

CK_RV sks_ck_token_mechanism_ids(CK_SLOT_ID slot,
				 CK_MECHANISM_TYPE_PTR mechanisms,
				 CK_ULONG_PTR count)
{
	uint32_t ctrl[1] = { slot };
	uint32_t outsize = *count * sizeof(uint32_t);
	void *outbuf;
	CK_RV rv;

	outbuf = malloc(outsize);
	if (!outbuf)
		return CKR_HOST_MEMORY;

	rv = ck_invoke_ta(NULL, SKS_CMD_CK_MECHANISM_IDS,
			  &ctrl, sizeof(ctrl), NULL, 0, outbuf, &outsize);
	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
		*count = outsize / sizeof(uint32_t);
	if (rv)
		goto bail;

	if (sks2ck_mechanism_type_list(mechanisms, outbuf, *count)) {
		LOG_ERROR("unexpected bad mechanism_type list\n");
		rv = CKR_DEVICE_ERROR;
	}

bail:
	free(outbuf);

	return rv;
}

/* CK_MECHANISM_INFO = 3 ulong = 3 * 32bit in SKS */
CK_RV sks_ck_token_mechanism_info(CK_SLOT_ID slot,
				  CK_MECHANISM_TYPE type,
				  CK_MECHANISM_INFO_PTR info)
{
	CK_RV rv;
	uint32_t ctrl[2];
	struct sks_ck_mecha_info outbuf;
	uint32_t outsize = sizeof(outbuf);

	ctrl[0] = (uint32_t)slot;
	ctrl[1] = ck2sks_mechanism_type(type);
	if (ctrl[1] == SKS_UNDEFINED_ID) {
		LOG_ERROR("mechanism is not support by this library\n");
		return CKR_DEVICE_ERROR;
	}

	/* info is large enought, for sure */
	rv = ck_invoke_ta(NULL, SKS_CMD_CK_MECHANISM_INFO,
			  &ctrl, sizeof(ctrl), NULL, 0, &outbuf, &outsize);
	if (rv) {
		LOG_ERROR("Unexpected bad state (%x)\n", (unsigned)rv);
		return CKR_DEVICE_ERROR;
	}

	if (sks2ck_mechanism_info(info, &outbuf)) {
		LOG_ERROR("unexpected bad mechanism info structure\n");
		rv = CKR_DEVICE_ERROR;
	}
	return rv;
}

/*
 * TODO: with following code, the session identifier are abstracted by the SKS
 * library. It could be better to let the TA provide the handle, so that
 * several applications can see the same session identifiers.
 */
CK_RV sks_ck_open_session(CK_SLOT_ID slot,
		          CK_FLAGS flags,
		          CK_VOID_PTR cookie,
		          CK_NOTIFY callback,
		          CK_SESSION_HANDLE_PTR session)
{
	uint32_t ctrl[1] = { slot };
	unsigned long cmd;
	uint32_t handle;
	size_t out_sz = sizeof(handle);
	CK_RV rv;

	if (cookie || callback) {
		LOG_ERROR("C_OpenSession does not handle callback yet\n");
		return CKR_FUNCTION_NOT_SUPPORTED;
	}

	if (flags & CKF_RW_SESSION)
		cmd = SKS_CMD_CK_OPEN_RW_SESSION;
	else
		cmd = SKS_CMD_CK_OPEN_RO_SESSION;

	rv = ck_invoke_ta(NULL, cmd, &ctrl, sizeof(ctrl),
			  NULL, 0, &handle, &out_sz);
	if (rv)
		return rv;

	*session = handle;

	return CKR_OK;
}

CK_RV sks_ck_close_session(CK_SESSION_HANDLE session)
{
	uint32_t ctrl[1] = { (uint32_t)session };

	return ck_invoke_ta(NULL, SKS_CMD_CK_CLOSE_SESSION,
			    &ctrl, sizeof(ctrl), NULL, 0, NULL, NULL);
}

/*
 * Scan all registered session handle by the lib
 * and close all session related to the target slot.
 */
CK_RV sks_ck_close_all_sessions(CK_SLOT_ID slot)
{
	uint32_t ctrl[1] = { (uint32_t)slot };

	return ck_invoke_ta(NULL, SKS_CMD_CK_CLOSE_ALL_SESSIONS,
			    &ctrl, sizeof(ctrl), NULL, 0, NULL, NULL);
}

CK_RV sks_ck_get_session_info(CK_SESSION_HANDLE session,
			      CK_SESSION_INFO_PTR info)
{
	uint32_t ctrl[1] = { (uint32_t)session };
	size_t info_size = sizeof(CK_SESSION_INFO);

	return ck_invoke_ta(NULL, SKS_CMD_CK_SESSION_INFO,
			    &ctrl, sizeof(ctrl), NULL, 0, info, &info_size);
}
