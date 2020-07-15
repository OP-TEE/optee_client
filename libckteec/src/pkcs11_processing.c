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

CK_RV ck_encdecrypt_init(CK_SESSION_HANDLE session,
			 CK_MECHANISM_PTR mechanism,
			 CK_OBJECT_HANDLE key,
			 int decrypt)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	struct serializer obj = { };
	uint32_t session_handle = session;
	uint32_t key_handle = key;
	size_t ctrl_size = 0;
	char *buf = NULL;

	if (!mechanism)
		return CKR_ARGUMENTS_BAD;

	rv = serialize_ck_mecha_params(&obj, mechanism);
	if (rv)
		return rv;

	/*
	 * Shm io0: (in/out) ctrl
	 * (in) [session-handle][key-handle][serialized-mechanism-blob]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + sizeof(key_handle) + obj.size;

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &key_handle, sizeof(key_handle));
	buf += sizeof(key_handle);

	memcpy(buf, obj.buffer, obj.size);

	rv = ckteec_invoke_ctrl(decrypt ? PKCS11_CMD_DECRYPT_INIT :
				PKCS11_CMD_ENCRYPT_INIT, ctrl);

bail:
	ckteec_free_shm(ctrl);
	release_serial_object(&obj);

	return rv;
}

CK_RV ck_encdecrypt_update(CK_SESSION_HANDLE session,
			   CK_BYTE_PTR in,
			   CK_ULONG in_len,
			   CK_BYTE_PTR out,
			   CK_ULONG_PTR out_len,
			   int decrypt)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *in_shm = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	uint32_t session_handle = session;
	size_t out_size = 0;

	if ((out_len && *out_len && !out) || (in_len && !in))
		return CKR_ARGUMENTS_BAD;

	/* Shm io0: (in/out) ctrl = [session-handle] / [status] */
	ctrl = ckteec_alloc_shm(sizeof(session_handle), CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}
	memcpy(ctrl->buffer, &session_handle, sizeof(session_handle));

	/* Shm io1: input data buffer if any */
	if (in_len) {
		in_shm = ckteec_register_shm(in, in_len, CKTEEC_SHM_IN);
		if (!in_shm) {
			rv = CKR_HOST_MEMORY;
			goto bail;
		}
	}

	/* Shm io2: output data buffer */
	if (out_len && *out_len) {
		out_shm = ckteec_register_shm(out, *out_len, CKTEEC_SHM_OUT);
	} else {
		/* Query output data size */
		out_shm = ckteec_alloc_shm(0, CKTEEC_SHM_OUT);
	}

	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	/* Invoke */
	rv = ckteec_invoke_ta(decrypt ? PKCS11_CMD_DECRYPT_UPDATE :
			      PKCS11_CMD_ENCRYPT_UPDATE, ctrl,
			      in_shm, out_shm, &out_size, NULL, NULL);

	if (out_len && (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL))
		*out_len = out_size;

	if (rv == CKR_BUFFER_TOO_SMALL && out_size && !out)
		rv = CKR_OK;

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(in_shm);
	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_encdecrypt_oneshot(CK_SESSION_HANDLE session,
			    CK_BYTE_PTR in,
			    CK_ULONG in_len,
			    CK_BYTE_PTR out,
			    CK_ULONG_PTR out_len,
			    int decrypt)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *in_shm = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	uint32_t session_handle = session;
	size_t out_size = 0;

	if ((out_len && *out_len && !out) || (in_len && !in))
		return CKR_ARGUMENTS_BAD;

	/* Shm io0: (in/out) ctrl = [session-handle] / [status] */
	ctrl = ckteec_alloc_shm(sizeof(session_handle), CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}
	memcpy(ctrl->buffer, &session_handle, sizeof(session_handle));

	/* Shm io1: input data buffer */
	if (in_len) {
		in_shm = ckteec_register_shm(in, in_len, CKTEEC_SHM_IN);
		if (!in_shm) {
			rv = CKR_HOST_MEMORY;
			goto bail;
		}
	}

	/* Shm io2: output data buffer */
	if (out_len && *out_len) {
		out_shm = ckteec_register_shm(out, *out_len, CKTEEC_SHM_OUT);
	} else {
		/* Query output data size */
		out_shm = ckteec_alloc_shm(0, CKTEEC_SHM_OUT);
	}

	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ta(decrypt ? PKCS11_CMD_DECRYPT_ONESHOT :
			      PKCS11_CMD_ENCRYPT_ONESHOT, ctrl,
			      in_shm, out_shm, &out_size, NULL, NULL);

	if (out_len && (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL))
		*out_len = out_size;

	if (rv == CKR_BUFFER_TOO_SMALL && out_size && !out)
		rv = CKR_OK;

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(in_shm);
	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_encdecrypt_final(CK_SESSION_HANDLE session,
			  CK_BYTE_PTR out,
			  CK_ULONG_PTR out_len,
			  int decrypt)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	uint32_t session_handle = session;
	size_t out_size = 0;

	if (out_len && *out_len && !out)
		return CKR_ARGUMENTS_BAD;

	/* Shm io0: (in/out) ctrl = [session-handle] / [status] */
	ctrl = ckteec_alloc_shm(sizeof(session_handle), CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}
	memcpy(ctrl->buffer, &session_handle, sizeof(session_handle));

	/* Shm io2: output buffer reference */
	if (out_len && *out_len) {
		out_shm = ckteec_register_shm(out, *out_len, CKTEEC_SHM_OUT);
	} else {
		/* Query output data size */
		out_shm = ckteec_alloc_shm(0, CKTEEC_SHM_OUT);
	}

	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(decrypt ? PKCS11_CMD_DECRYPT_FINAL :
				    PKCS11_CMD_ENCRYPT_FINAL,
				    ctrl, out_shm, &out_size);

	if (out_len && (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL))
		*out_len = out_size;

	if (rv == CKR_BUFFER_TOO_SMALL && out_size && !out)
		rv = CKR_OK;

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);

	return rv;
}
