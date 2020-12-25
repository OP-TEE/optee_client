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
	struct serializer obj = { 0 };
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
	struct serializer obj = { 0 };
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

	if ((out_len && *out_len && !out) || (in_len && !in)) {
		rv = CKR_ARGUMENTS_BAD;
		goto bail;
	}

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

	goto bail_invoked;

bail:
	ck_release_active_processing(session, decrypt ?
				     PKCS11_CMD_DECRYPT_UPDATE :
				     PKCS11_CMD_ENCRYPT_UPDATE);
bail_invoked:
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

	if ((out_len && *out_len && !out) || (in_len && !in)) {
		rv = CKR_ARGUMENTS_BAD;
		goto bail;
	}

	/* Shm io0: (in/out) ctrl = [session-handle] / [status] */
	ctrl = ckteec_alloc_shm(sizeof(session_handle), CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}
	memcpy(ctrl->buffer, &session_handle, sizeof(session_handle));

	/* Shm io1: input data buffer */
	in_shm = ckteec_register_shm(in, in_len, CKTEEC_SHM_IN);
	if (!in_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
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

	goto bail_invoked;

bail:
	ck_release_active_processing(session, decrypt ?
				     PKCS11_CMD_DECRYPT_ONESHOT :
				     PKCS11_CMD_ENCRYPT_ONESHOT);
bail_invoked:
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

	if (out_len && *out_len && !out) {
		rv = CKR_ARGUMENTS_BAD;
		goto bail;
	}

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

	goto bail_invoked;

bail:
	ck_release_active_processing(session, decrypt ?
				     PKCS11_CMD_DECRYPT_FINAL :
				     PKCS11_CMD_ENCRYPT_FINAL);
bail_invoked:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_digest_init(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	struct serializer obj = { 0 };
	uint32_t session_handle = session;
	size_t ctrl_size = 0;
	uint8_t *buf = NULL;

	if (!mechanism)
		return CKR_ARGUMENTS_BAD;

	rv = serialize_ck_mecha_params(&obj, mechanism);
	if (rv)
		return rv;

	/*
	 * Shm io0: (in/out) ctrl
	 * (in) [session-handle][serialized-mechanism-blob]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + obj.size;
	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, obj.buffer, obj.size);

	rv = ckteec_invoke_ctrl(PKCS11_CMD_DIGEST_INIT, ctrl);

bail:
	ckteec_free_shm(ctrl);
	release_serial_object(&obj);

	return rv;
}

CK_RV ck_digest_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	uint32_t session_handle = session;
	uint32_t key_handle = key;
	size_t ctrl_size = 0;
	uint8_t *buf = NULL;

	/*
	 * Shm io0: (in/out) ctrl
	 * (in) [session-handle][key-handle]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + sizeof(key_handle);
	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl)
		return CKR_HOST_MEMORY;

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &key_handle, sizeof(key_handle));

	rv = ckteec_invoke_ctrl(PKCS11_CMD_DIGEST_KEY, ctrl);

	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_digest_update(CK_SESSION_HANDLE session, CK_BYTE_PTR in,
		       CK_ULONG in_len)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *io1 = NULL;
	uint32_t session_handle = session;
	uint8_t *buf = NULL;

	if (!in && in_len) {
		rv = CKR_ARGUMENTS_BAD;
		goto bail;
	}

	/*
	 * Shm io0: (in/out) ctrl = [session-handle] / [status]
	 */
	ctrl = ckteec_alloc_shm(sizeof(session_handle), CKTEEC_SHM_INOUT);
	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));

	/* Shm io1: input payload */
	if (in_len && in) {
		io1 = ckteec_register_shm(in, in_len, CKTEEC_SHM_IN);
		if (!io1) {
			rv = CKR_HOST_MEMORY;
			goto bail;
		}
	}

	rv = ckteec_invoke_ctrl_in(PKCS11_CMD_DIGEST_UPDATE, ctrl, io1);

	goto bail_invoked;

bail:
	ck_release_active_processing(session, PKCS11_CMD_DIGEST_UPDATE);
bail_invoked:
	ckteec_free_shm(io1);
	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_digest_oneshot(CK_SESSION_HANDLE session, CK_BYTE_PTR in,
			CK_ULONG in_len, CK_BYTE_PTR digest_ref,
			CK_ULONG_PTR digest_len)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *io1 = NULL;
	TEEC_SharedMemory *io2 = NULL;
	uint32_t session_handle = session;
	size_t out_size = 0;
	uint8_t *buf = NULL;

	if ((!in && in_len) || !digest_len) {
		rv = CKR_ARGUMENTS_BAD;
		goto bail;
	}

	/*
	 * Shm io0: (in/out) ctrl = [session-handle] / [status]
	 */
	ctrl = ckteec_alloc_shm(sizeof(session_handle), CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}
	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));

	/* Shm io1: input payload */
	if (in_len && in) {
		io1 = ckteec_register_shm(in, in_len, CKTEEC_SHM_IN);
		if (!io1) {
			rv = CKR_HOST_MEMORY;
			goto bail;
		}
	}

	/* Shm io2: output digest or null sized shm */
	if (digest_ref) {
		io2 = ckteec_register_shm(digest_ref, *digest_len,
					  CKTEEC_SHM_OUT);
	} else {
		/* Query size if output signature */
		io2 = ckteec_alloc_shm(0, CKTEEC_SHM_OUT);
	}

	if (!io2) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ta(PKCS11_CMD_DIGEST_ONESHOT, ctrl,
			      io1, io2, &out_size, NULL, NULL);

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
		*digest_len = out_size;

	if (rv == CKR_BUFFER_TOO_SMALL && out_size && !digest_ref)
		rv = CKR_OK;

	goto bail_invoked;

bail:
	ck_release_active_processing(session, PKCS11_CMD_DIGEST_ONESHOT);
bail_invoked:
	ckteec_free_shm(io1);
	ckteec_free_shm(io2);
	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_digest_final(CK_SESSION_HANDLE session, CK_BYTE_PTR digest_ref,
		      CK_ULONG_PTR digest_len)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *io2 = NULL;
	uint32_t session_handle = session;
	size_t io2_size = 0;
	uint8_t *buf = NULL;

	/*
	 * - If digest_ref == NULL AND digest_len == NULL -> need to call TA to
	 * terminate session.
	 * - If digest_len == NULL -> need to call to TA to terminate session.
	 * - If digest_ref == NULL BUT digest_len != NULL just operate normally
	 * to get size of the required buffer
	 */
	if (!digest_len) {
		rv = CKR_ARGUMENTS_BAD;
		goto bail;
	}

	/*
	 * Shm io0: (in/out) ctrl = [session-handle] / [status]
	 */
	ctrl = ckteec_alloc_shm(sizeof(session_handle),	CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}
	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));

	/* Shm io2: output digest or null sized shm */
	if (digest_ref)
		io2 = ckteec_register_shm(digest_ref, *digest_len,
					  CKTEEC_SHM_OUT);
	else
		io2 = ckteec_alloc_shm(0, CKTEEC_SHM_OUT);

	if (!io2) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ta(PKCS11_CMD_DIGEST_FINAL, ctrl, NULL, io2,
			      &io2_size, NULL, NULL);

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
		*digest_len = io2_size;

	if (rv == CKR_BUFFER_TOO_SMALL && io2_size && !digest_ref)
		rv = CKR_OK;

	goto bail_invoked;

bail:
	ck_release_active_processing(session, PKCS11_CMD_DIGEST_FINAL);
bail_invoked:
	ckteec_free_shm(io2);
	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_signverify_init(CK_SESSION_HANDLE session,
			 CK_MECHANISM_PTR mechanism,
			 CK_OBJECT_HANDLE key,
			 int sign)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	struct serializer obj = { 0 };
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

	rv = ckteec_invoke_ctrl(sign ? PKCS11_CMD_SIGN_INIT :
				PKCS11_CMD_VERIFY_INIT, ctrl);

bail:
	ckteec_free_shm(ctrl);
	release_serial_object(&obj);

	return rv;
}

CK_RV ck_signverify_update(CK_SESSION_HANDLE session,
			   CK_BYTE_PTR in,
			   CK_ULONG in_len,
			   int sign)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *in_shm = NULL;
	uint32_t session_handle = session;

	if (!in && in_len) {
		rv = CKR_ARGUMENTS_BAD;
		goto bail;
	}

	/* Shm io0: (in/out) ctrl = [session-handle] / [status] */
	ctrl = ckteec_alloc_shm(sizeof(session_handle), CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}
	memcpy(ctrl->buffer, &session_handle, sizeof(session_handle));

	/* Shm io1: input data */
	in_shm = ckteec_register_shm(in, in_len, CKTEEC_SHM_IN);
	if (!in_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_in(sign ? PKCS11_CMD_SIGN_UPDATE :
				   PKCS11_CMD_VERIFY_UPDATE, ctrl, in_shm);

	goto bail_invoked;

bail:
	ck_release_active_processing(session, sign ? PKCS11_CMD_SIGN_UPDATE :
				     PKCS11_CMD_VERIFY_UPDATE);
bail_invoked:
	ckteec_free_shm(in_shm);
	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_signverify_oneshot(CK_SESSION_HANDLE session,
			    CK_BYTE_PTR in,
			    CK_ULONG in_len,
			    CK_BYTE_PTR sign_ref,
			    CK_ULONG_PTR sign_len,
			    int sign)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *io1 = NULL;
	TEEC_SharedMemory *io2 = NULL;
	uint32_t session_handle = session;
	size_t out_size = 0;

	if ((in_len && !in) || (sign_len && *sign_len && !sign_ref) ||
	    (sign && !sign_len)) {
		rv = CKR_ARGUMENTS_BAD;
		goto bail;
	}

	/* Shm io0: (in/out) ctrl = [session-handle] / [status] */
	ctrl = ckteec_alloc_shm(sizeof(session_handle), CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}
	memcpy(ctrl->buffer, &session_handle, sizeof(session_handle));

	/* Shm io1: input payload */
	if (in_len) {
		io1 = ckteec_register_shm(in, in_len, CKTEEC_SHM_IN);
		if (!io1) {
			rv = CKR_HOST_MEMORY;
			goto bail;
		}
	}

	/*
	 * Shm io2: input signature (if verifying) or null sized shm
	 * or
	 * Shm io2: output signature (if signing) or null sized shm
	 */
	if (sign_len && *sign_len) {
		io2 = ckteec_register_shm(sign_ref, *sign_len,
					  sign ? CKTEEC_SHM_OUT : CKTEEC_SHM_IN);
	} else {
		/* Query size if output signature */
		io2 = ckteec_alloc_shm(0, sign ? CKTEEC_SHM_OUT : CKTEEC_SHM_IN);
	}

	if (!io2) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ta(sign ? PKCS11_CMD_SIGN_ONESHOT :
			      PKCS11_CMD_VERIFY_ONESHOT, ctrl,
			      io1, io2, &out_size, NULL, NULL);

	if (sign && (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL))
		*sign_len = out_size;

	if (rv == CKR_BUFFER_TOO_SMALL && out_size && !sign_ref)
		rv = CKR_OK;

	goto bail_invoked;

bail:
	ck_release_active_processing(session, sign ? PKCS11_CMD_SIGN_ONESHOT :
				     PKCS11_CMD_VERIFY_ONESHOT);
bail_invoked:
	ckteec_free_shm(io1);
	ckteec_free_shm(io2);
	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_signverify_final(CK_SESSION_HANDLE session,
			  CK_BYTE_PTR sign_ref,
			  CK_ULONG_PTR sign_len,
			  int sign)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *io = NULL;
	uint32_t session_handle = session;
	size_t io_size = 0;

	if ((sign_len && *sign_len && !sign_ref) || (sign && !sign_len)) {
		rv = CKR_ARGUMENTS_BAD;
		goto bail;
	}

	/* Shm io0: (in/out) ctrl = [session-handle] / [status] */
	ctrl = ckteec_alloc_shm(sizeof(session_handle), CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}
	memcpy(ctrl->buffer, &session_handle, sizeof(session_handle));

	/*
	 * Shm io1: input signature (if verifying) or null sized shm
	 * or
	 * Shm io1: output signature (if signing) or null sized shm
	 */
	if (sign_len && *sign_len)
		io = ckteec_register_shm(sign_ref, *sign_len,
					 sign ? CKTEEC_SHM_OUT : CKTEEC_SHM_IN);
	else
		io = ckteec_alloc_shm(0, sign ? CKTEEC_SHM_OUT : CKTEEC_SHM_IN);

	if (!io) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ta(sign ? PKCS11_CMD_SIGN_FINAL :
			      PKCS11_CMD_VERIFY_FINAL, ctrl, NULL, io,
			      &io_size, NULL, NULL);

	if (sign && sign_len && (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL))
		*sign_len = io_size;

	if (rv == CKR_BUFFER_TOO_SMALL && io_size && !sign_ref)
		rv = CKR_OK;

	goto bail_invoked;

bail:
	ck_release_active_processing(session, sign ? PKCS11_CMD_SIGN_FINAL :
				     PKCS11_CMD_VERIFY_FINAL);
bail_invoked:
	ckteec_free_shm(io);
	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_generate_key(CK_SESSION_HANDLE session,
		      CK_MECHANISM_PTR mechanism,
		      CK_ATTRIBUTE_PTR attribs,
		      CK_ULONG count,
		      CK_OBJECT_HANDLE_PTR handle)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	struct serializer smecha = { 0 };
	struct serializer sattr = { 0 };
	uint32_t session_handle = session;
	size_t ctrl_size = 0;
	uint32_t key_handle = 0;
	char *buf = NULL;
	size_t out_size = 0;

	if (!handle || !mechanism || (count && !attribs))
		return CKR_ARGUMENTS_BAD;

	rv = serialize_ck_mecha_params(&smecha, mechanism);
	if (rv)
		return rv;

	rv = serialize_ck_attributes(&sattr, attribs, count);
	if (rv)
		goto bail;

	/*
	 * Shm io0: (in/out) ctrl
	 * (in) [session-handle][serialized-mecha][serialized-attributes]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + smecha.size + sattr.size;

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, smecha.buffer, smecha.size);
	buf += smecha.size;

	memcpy(buf, sattr.buffer, sattr.size);

	/* Shm io2: (out) [object handle] */
	out_shm = ckteec_alloc_shm(sizeof(key_handle), CKTEEC_SHM_OUT);
	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_GENERATE_KEY,
				    ctrl, out_shm, &out_size);

	if (rv != CKR_OK || out_size != out_shm->size) {
		if (rv == CKR_OK)
			rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	memcpy(&key_handle, out_shm->buffer, sizeof(key_handle));
	*handle = key_handle;

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);
	release_serial_object(&sattr);
	release_serial_object(&smecha);

	return rv;
}

CK_RV ck_find_objects_init(CK_SESSION_HANDLE session,
			   CK_ATTRIBUTE_PTR attribs,
			   CK_ULONG count)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	uint32_t session_handle = session;
	struct serializer obj = { 0 };
	size_t ctrl_size = 0;
	char *buf = NULL;

	if (count && !attribs)
		return CKR_ARGUMENTS_BAD;

	rv = serialize_ck_attributes(&obj, attribs, count);
	if (rv)
		return rv;

	/* Shm io0: (in/out) ctrl
	 * (in) [session-handle][headed-serialized-attributes]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + obj.size;
	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, obj.buffer, obj.size);

	rv = ckteec_invoke_ctrl(PKCS11_CMD_FIND_OBJECTS_INIT, ctrl);

bail:
	ckteec_free_shm(ctrl);
	release_serial_object(&obj);

	return rv;
}

CK_RV ck_find_objects(CK_SESSION_HANDLE session,
		      CK_OBJECT_HANDLE_PTR obj,
		      CK_ULONG max_count,
		      CK_ULONG_PTR count)

{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	uint32_t session_handle = session;
	uint32_t *handles = NULL;
	size_t handles_size = max_count * sizeof(uint32_t);
	CK_ULONG n = 0;
	CK_ULONG last = 0;
	size_t out_size = 0;

	if (!count || (max_count && !obj))
		return CKR_ARGUMENTS_BAD;

	/* Shm io0: (in/out) ctrl = [session-handle] / [status] */
	ctrl = ckteec_alloc_shm(sizeof(session_handle), CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}
	memcpy(ctrl->buffer, &session_handle, sizeof(session_handle));

	/* Shm io2: (out) [object handle list] */
	out_shm = ckteec_alloc_shm(handles_size, CKTEEC_SHM_OUT);
	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_FIND_OBJECTS,
				    ctrl, out_shm, &out_size);

	if (rv || out_size > out_shm->size) {
		if (rv == CKR_OK)
			rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	handles = out_shm->buffer;
	last = out_size / sizeof(uint32_t);
	*count = last;

	for (n = 0; n < last; n++)
		obj[n] = handles[n];

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_find_objects_final(CK_SESSION_HANDLE session)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	uint32_t session_handle = session;

	/* Shm io0: (in/out) ctrl = [session-handle] / [status] */
	ctrl = ckteec_alloc_shm(sizeof(session_handle), CKTEEC_SHM_INOUT);
	if (!ctrl)
		return CKR_HOST_MEMORY;

	memcpy(ctrl->buffer, &session_handle, sizeof(session_handle));

	rv = ckteec_invoke_ctrl(PKCS11_CMD_FIND_OBJECTS_FINAL, ctrl);

	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_get_object_size(CK_SESSION_HANDLE session,
			 CK_OBJECT_HANDLE obj,
			 CK_ULONG_PTR p_size)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	size_t ctrl_size = 0;
	uint32_t session_handle = session;
	uint32_t obj_handle = obj;
	char *buf = NULL;
	size_t out_size = 0;
	uint32_t u32_sz = 0;

	if (!p_size)
		return CKR_ARGUMENTS_BAD;

	/* Shm io0: (in/out) [session][obj-handle] / [status] */
	ctrl_size = sizeof(session_handle) + sizeof(obj_handle);

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &obj_handle, sizeof(obj_handle));

	/* Shm io2: (out) [object size] */
	out_shm = ckteec_alloc_shm(sizeof(uint32_t), CKTEEC_SHM_OUT);
	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_GET_OBJECT_SIZE,
				    ctrl, out_shm, &out_size);
	if (rv)
		goto bail;

	if (out_shm->size != sizeof(uint32_t)) {
		rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	memcpy(&u32_sz, out_shm->buffer, out_shm->size);
	*p_size = u32_sz;

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_get_attribute_value(CK_SESSION_HANDLE session,
			     CK_OBJECT_HANDLE obj,
			     CK_ATTRIBUTE_PTR attribs,
			     CK_ULONG count)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_RV rv2 = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	struct serializer sattr = { 0 };
	size_t ctrl_size = 0;
	uint32_t session_handle = session;
	uint32_t obj_handle = obj;
	char *buf = NULL;
	size_t out_size = 0;

	if (count && !attribs)
		return CKR_ARGUMENTS_BAD;

	rv = serialize_ck_attributes(&sattr, attribs, count);
	if (rv)
		goto bail;

	/* Shm io0: (in/out) [session][obj-handle][attributes] / [status] */
	ctrl_size = sizeof(session_handle) + sizeof(obj_handle) + sattr.size;

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &obj_handle, sizeof(obj_handle));
	buf += sizeof(obj_handle);

	memcpy(buf, sattr.buffer, sattr.size);

	/* Shm io2: (out) [attributes] */
	out_shm = ckteec_alloc_shm(sattr.size, CKTEEC_SHM_OUT);
	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_GET_ATTRIBUTE_VALUE,
				    ctrl, out_shm, &out_size);

	if (rv == CKR_OK || rv == CKR_ATTRIBUTE_SENSITIVE ||
	    rv == CKR_ATTRIBUTE_TYPE_INVALID || rv == CKR_BUFFER_TOO_SMALL) {
		rv2 = deserialize_ck_attributes(out_shm->buffer, attribs,
						count);
		if (rv2)
			rv = CKR_GENERAL_ERROR;
	}

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);
	release_serial_object(&sattr);

	return rv;
}

CK_RV ck_set_attribute_value(CK_SESSION_HANDLE session,
			     CK_OBJECT_HANDLE obj,
			     CK_ATTRIBUTE_PTR attribs,
			     CK_ULONG count)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	struct serializer sattr = { 0 };
	size_t ctrl_size = 0;
	uint32_t session_handle = session;
	uint32_t obj_handle = obj;
	char *buf = NULL;

	if (count && !attribs)
		return CKR_ARGUMENTS_BAD;

	rv = serialize_ck_attributes(&sattr, attribs, count);
	if (rv)
		goto bail;

	/* Shm io0: (in/out) [session][obj-handle][attributes] / [status] */
	ctrl_size = sizeof(session_handle) + sizeof(obj_handle) + sattr.size;

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &obj_handle, sizeof(obj_handle));
	buf += sizeof(obj_handle);

	memcpy(buf, sattr.buffer, sattr.size);

	rv = ckteec_invoke_ctrl(PKCS11_CMD_SET_ATTRIBUTE_VALUE, ctrl);

bail:
	ckteec_free_shm(ctrl);
	release_serial_object(&sattr);

	return rv;
}

CK_RV ck_copy_object(CK_SESSION_HANDLE session,
		     CK_OBJECT_HANDLE obj,
		     CK_ATTRIBUTE_PTR attribs,
		     CK_ULONG count,
		     CK_OBJECT_HANDLE_PTR handle)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	struct serializer sattr = { 0 };
	size_t ctrl_size = 0;
	uint32_t session_handle = session;
	uint32_t obj_handle = obj;
	uint32_t key_handle = 0;
	char *buf = NULL;
	size_t out_size = 0;

	if (!handle || (count && !attribs))
		return CKR_ARGUMENTS_BAD;

	rv = serialize_ck_attributes(&sattr, attribs, count);
	if (rv)
		goto bail;

	/* Shm io0: (in/out) [session][obj-handle][attributes] / [status] */
	ctrl_size = sizeof(session_handle) + sizeof(obj_handle) + sattr.size;

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &obj_handle, sizeof(obj_handle));
	buf += sizeof(obj_handle);

	memcpy(buf, sattr.buffer, sattr.size);

	/* Shm io2: (out) [object handle] */
	out_shm = ckteec_alloc_shm(sizeof(key_handle), CKTEEC_SHM_OUT);
	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_COPY_OBJECT,
				    ctrl, out_shm, &out_size);
	if (rv != CKR_OK || out_size != out_shm->size) {
		if (rv == CKR_OK)
			rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	memcpy(&key_handle, out_shm->buffer, sizeof(key_handle));
	*handle = key_handle;

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);
	release_serial_object(&sattr);

	return rv;
}

CK_RV ck_derive_key(CK_SESSION_HANDLE session,
		    CK_MECHANISM_PTR mechanism,
		    CK_OBJECT_HANDLE parent_key,
		    CK_ATTRIBUTE_PTR attribs,
		    CK_ULONG count,
		    CK_OBJECT_HANDLE_PTR handle)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	struct serializer smecha = { 0 };
	struct serializer sattr = { 0 };
	uint32_t session_handle = session;
	uint32_t obj_handle = parent_key;
	size_t ctrl_size = 0;
	uint32_t key_handle = 0;
	char *buf = NULL;
	size_t out_size = 0;

	if (!handle || !mechanism || (count && !attribs))
		return CKR_ARGUMENTS_BAD;

	rv = serialize_ck_mecha_params(&smecha, mechanism);
	if (rv)
		return rv;

	rv = serialize_ck_attributes(&sattr, attribs, count);
	if (rv)
		goto bail;

	/*
	 * Shm io0: (in/out) ctrl
	 * (in) [session-handle][obj-handle][serialized-mecha][serialized-attributes]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + sizeof(obj_handle) + smecha.size +
		    sattr.size;

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &obj_handle, sizeof(obj_handle));
	buf += sizeof(obj_handle);

	memcpy(buf, smecha.buffer, smecha.size);
	buf += smecha.size;

	memcpy(buf, sattr.buffer, sattr.size);

	/* Shm io2: (out) [object handle] */
	out_shm = ckteec_alloc_shm(sizeof(key_handle), CKTEEC_SHM_OUT);
	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_DERIVE_KEY,
				    ctrl, out_shm, &out_size);

	if (rv != CKR_OK || out_size != out_shm->size) {
		if (rv == CKR_OK)
			rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	memcpy(&key_handle, out_shm->buffer, sizeof(key_handle));
	*handle = key_handle;

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);
	release_serial_object(&sattr);
	release_serial_object(&smecha);

	return rv;
}

CK_RV ck_release_active_processing(CK_SESSION_HANDLE session,
				   enum pkcs11_ta_cmd command)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	uint32_t session_handle = session;
	uint32_t cmd = command;
	size_t ctrl_size = 0;
	char *buf = NULL;

	/* Shm io0: (in/out) ctrl = [session-handle][command] / [status] */
	ctrl_size = sizeof(session_handle) + sizeof(cmd);

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl)
		return CKR_HOST_MEMORY;

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, &cmd, sizeof(cmd));

	rv = ckteec_invoke_ctrl(PKCS11_CMD_RELEASE_ACTIVE_PROCESSING, ctrl);

	ckteec_free_shm(ctrl);

	return rv;
}

CK_RV ck_generate_key_pair(CK_SESSION_HANDLE session,
			   CK_MECHANISM_PTR mechanism,
			   CK_ATTRIBUTE_PTR pub_attribs,
			   CK_ULONG pub_count,
			   CK_ATTRIBUTE_PTR priv_attribs,
			   CK_ULONG priv_count,
			   CK_OBJECT_HANDLE_PTR pub_key,
			   CK_OBJECT_HANDLE_PTR priv_key)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	TEEC_SharedMemory *ctrl = NULL;
	TEEC_SharedMemory *out_shm = NULL;
	struct serializer smecha = { 0 };
	struct serializer pub_sattr = { 0 };
	struct serializer priv_sattr = { 0 };
	uint32_t session_handle = session;
	size_t ctrl_size = 0;
	uint32_t *key_handle = NULL;
	size_t key_handle_size = 2 * sizeof(*key_handle);
	char *buf = NULL;
	size_t out_size = 0;

	if (!(mechanism && pub_attribs && priv_attribs && pub_key && priv_key))
		return CKR_ARGUMENTS_BAD;

	rv = serialize_ck_mecha_params(&smecha, mechanism);
	if (rv)
		return rv;

	rv = serialize_ck_attributes(&pub_sattr, pub_attribs, pub_count);
	if (rv)
		goto bail;

	rv = serialize_ck_attributes(&priv_sattr, priv_attribs, priv_count);
	if (rv)
		goto bail;

	/*
	 * Shm io0: (in/out) ctrl
	 * (in) [session-handle][serialized-mecha][serialized-pub_attribs]
	 *      [serialized-priv_attribs]
	 * (out) [status]
	 */
	ctrl_size = sizeof(session_handle) + smecha.size + pub_sattr.size +
		    priv_sattr.size;

	ctrl = ckteec_alloc_shm(ctrl_size, CKTEEC_SHM_INOUT);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	buf = ctrl->buffer;

	memcpy(buf, &session_handle, sizeof(session_handle));
	buf += sizeof(session_handle);

	memcpy(buf, smecha.buffer, smecha.size);
	buf += smecha.size;

	memcpy(buf, pub_sattr.buffer, pub_sattr.size);
	buf += pub_sattr.size;

	memcpy(buf, priv_sattr.buffer, priv_sattr.size);

	/*
	 * Shm io2: (out) public key object handle][private key object handle]
	 */
	out_shm = ckteec_alloc_shm(key_handle_size, CKTEEC_SHM_OUT);
	if (!out_shm) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = ckteec_invoke_ctrl_out(PKCS11_CMD_GENERATE_KEY_PAIR,
				    ctrl, out_shm, &out_size);

	if (rv != CKR_OK || out_size != out_shm->size) {
		if (rv == CKR_OK)
			rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	key_handle = out_shm->buffer;
	*pub_key = key_handle[0];
	*priv_key = key_handle[1];

bail:
	ckteec_free_shm(out_shm);
	ckteec_free_shm(ctrl);
	release_serial_object(&priv_sattr);
	release_serial_object(&pub_sattr);
	release_serial_object(&smecha);

	return rv;
}
