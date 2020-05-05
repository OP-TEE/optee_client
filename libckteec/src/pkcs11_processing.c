// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#include <pkcs11.h>
#include <pkcs11_ta.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>

#include "pkcs11_processing.h"
#include "invoke_ta.h"
#include "serializer.h"
#include "serialize_ck.h"

CK_RV ck_create_object(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attribs,
		       CK_ULONG count, CK_OBJECT_HANDLE_PTR handle)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	struct serializer obj = { };
	size_t ctrl_size = 0;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	uint32_t session_handle = session;
	uint32_t key_handle = 0;
	char *buf = NULL;
	size_t out_size = 0;

	if (!handle || !attribs || !count)
		return CKR_ARGUMENTS_BAD;

	rv = serialize_ck_attributes(&obj, attribs, count);
	if (rv)
		goto out;

	/* Shm io0: (i/o) [session-handle][serialized-attributes] / [status] */
	ctrl_size = sizeof(session_handle) + obj.size;
	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, obj.buffer, obj.size);

	/* Shm io2: (out) [object handle] */
	out_shm = ckteec_alloc_shm(sizeof(key_handle), CKTEEC_SHM_OUT);
	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_CREATE_OBJECT,
				    ctrl, out_shm, &out_size);

	if (rv != CKR_OK || out_size != out_shm->size) {
		if (rv == CKR_OK)
			rv = CKR_DEVICE_ERROR;
		goto out;
	}

	memcpy(&key_handle, out_shm->buffer, sizeof(key_handle));
	*handle = key_handle;

out:
	release_serial_object(&obj);
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_destroy_object(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	size_t ctrl_size = 0;
	char *buf = NULL;
	uint32_t session_handle = session;
	uint32_t obj_id = obj;

	/* Shm io0: (i/o) ctrl = [session-handle][object-handle] / [status] */
	ctrl_size = sizeof(session_handle) + sizeof(obj_id);

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl)
		return CKR_HOST_MEMORY;

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &obj_id, sizeof(obj_id));

	rv = ckteec_invoke_ctrl(PKCS11_CMD_DESTROY_OBJECT, ctrl);

	ckteec_free_shm(ctrl);

	return rv;
}
