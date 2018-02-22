/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_ta.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>

#include "pkcs11_processing.h"
#include "invoke_ta.h"
#include "serializer.h"
#include "serialize_ck.h"

static struct sks_invoke *ck_session2sks_ctx(CK_SESSION_HANDLE session)
{
	(void)session;
	// TODO: find back the invocation context from the session handle
	// Until we do that, let's use the default invacation context.
	return NULL;
}

CK_RV ck_create_object(CK_SESSION_HANDLE session,
			CK_ATTRIBUTE_PTR attribs,
			CK_ULONG count,
			CK_OBJECT_HANDLE_PTR handle)
{
	CK_RV rv;
	struct serializer obj;
	char *ctrl = NULL;
	size_t ctrl_size;
	uint32_t key_handle;
	uint32_t session_handle = session;
	size_t key_handle_size = sizeof(key_handle);

	rv = serialize_ck_attributes(&obj, attribs, count);
	if (rv)
		goto out;

	/* ctrl = [session-handle][raw-head][serialized-attributes] */
	ctrl_size = sizeof(uint32_t) + obj.size;
	ctrl = malloc(ctrl_size);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}

	memcpy(ctrl, &session_handle, sizeof(uint32_t));
	memcpy(ctrl + sizeof(uint32_t), obj.buffer, obj.size);

	release_serial_object(&obj);

	rv = ck_invoke_ta(ck_session2sks_ctx(session),
			  SKS_CMD_IMPORT_OBJECT, ctrl, ctrl_size,
			  NULL, 0, &key_handle, &key_handle_size);
	if (rv)
		goto out;

	*handle = key_handle;

out:
	free(ctrl);
	return rv;
}

CK_RV ck_destroy_object(CK_SESSION_HANDLE session,
			CK_OBJECT_HANDLE obj)
{
	uint32_t ctrl[2] = { (uint32_t)session, (uint32_t)obj };

	return ck_invoke_ta(ck_session2sks_ctx(session),
			    SKS_CMD_DESTROY_OBJECT, ctrl, sizeof(ctrl),
			    NULL, 0, NULL, NULL);
}

CK_RV ck_encdecrypt_init(CK_SESSION_HANDLE session,
			 CK_MECHANISM_PTR mechanism,
			 CK_OBJECT_HANDLE key,
			 int decrypt)
{
	CK_RV rv;
	struct serializer obj;
	uint32_t session_handle = session;
	uint32_t key_handle = key;
	char *ctrl = NULL;
	size_t ctrl_size;

	rv = serialize_ck_mecha_params(&obj, mechanism);
	if (rv)
		return rv;

	/* params = [session-handle][key-handle][serialized-mechanism-blob] */
	ctrl_size = 2 * sizeof(uint32_t) + obj.size;
	ctrl = malloc(ctrl_size);
	if (!ctrl)
		return CKR_HOST_MEMORY;

	memcpy(ctrl, &session_handle, sizeof(uint32_t));
	memcpy(ctrl + sizeof(uint32_t), &key_handle, sizeof(uint32_t));
	memcpy(ctrl + 2 * sizeof(uint32_t), obj.buffer, obj.size);

	rv = ck_invoke_ta(ck_session2sks_ctx(session), decrypt ?
			  SKS_CMD_DECRYPT_INIT : SKS_CMD_ENCRYPT_INIT,
			  ctrl, ctrl_size, NULL, 0, NULL, NULL);

	free(ctrl);
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
	CK_RV rv;
	uint32_t ctrl;
	size_t ctrl_size;
	void *in_buf = in;
	size_t in_size = in_len;
	void *out_buf = out;
	size_t out_size;

	/* params = [session-handle] */
	ctrl = session;
	ctrl_size = sizeof(ctrl);

	if (!out_len)
		out_size = 0;
	else
		out_size = *out_len;

	rv = ck_invoke_ta(ck_session2sks_ctx(session), decrypt ?
			  SKS_CMD_DECRYPT_UPDATE : SKS_CMD_ENCRYPT_UPDATE,
			  &ctrl, ctrl_size, in_buf, in_size,
			  out_buf, &out_size);

	if (out_len && (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL))
		*out_len = out_size;

	return rv;
}

CK_RV ck_encdecrypt_final(CK_SESSION_HANDLE session,
			  CK_BYTE_PTR out,
			  CK_ULONG_PTR out_len,
			  int decrypt)
{
	CK_RV rv;
	uint32_t ctrl;
	size_t ctrl_size;
	void *out_buf = out;
	size_t out_size;

	/* params = [session-handle] */
	ctrl = session;
	ctrl_size = sizeof(ctrl);

	if (!out_len)
		out_size = 0;
	else
		out_size = *out_len;

	rv = ck_invoke_ta(ck_session2sks_ctx(session), decrypt ?
			  SKS_CMD_DECRYPT_FINAL : SKS_CMD_ENCRYPT_FINAL,
			  &ctrl, ctrl_size, NULL, 0, out_buf, &out_size);

	if (out_len && (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL))
		*out_len = out_size;

	return rv;
}

CK_RV ck_generate_key(CK_SESSION_HANDLE session,
		      CK_MECHANISM_PTR mechanism,
		      CK_ATTRIBUTE_PTR attribs,
		      CK_ULONG count,
		      CK_OBJECT_HANDLE_PTR handle)
{
	CK_RV rv;
	struct serializer smecha;
	struct serializer sattr;
	uint32_t session_handle = session;
	char *ctrl = NULL;
	size_t ctrl_size;
	uint32_t key_handle;
	size_t key_handle_size = sizeof(key_handle);

	rv = serialize_ck_mecha_params(&smecha, mechanism);
	if (rv)
		return rv;

	rv = serialize_ck_attributes(&sattr, attribs, count);
	if (rv)
		goto bail;

	/* ctrl = [session-handle][serialized-mecha][serialized-attributes] */
	ctrl_size = sizeof(uint32_t) + smecha.size + sattr.size;
	ctrl = malloc(ctrl_size);
	if (!ctrl) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	memcpy(ctrl, &session_handle, sizeof(uint32_t));
	memcpy(ctrl + sizeof(uint32_t), smecha.buffer, smecha.size);
	memcpy(ctrl + sizeof(uint32_t) + smecha.size, sattr.buffer, sattr.size);

	release_serial_object(&smecha);
	release_serial_object(&sattr);

	rv = ck_invoke_ta(ck_session2sks_ctx(session),
			  SKS_CMD_GENERATE_SYMM_KEY, ctrl, ctrl_size,
			  NULL, 0, &key_handle, &key_handle_size);
	if (rv)
		goto bail;

	*handle = key_handle;

bail:
	free(ctrl);
	release_serial_object(&smecha);
	release_serial_object(&sattr);

	return rv;
}

CK_RV ck_signverify_init(CK_SESSION_HANDLE session,
			 CK_MECHANISM_PTR mechanism,
			 CK_OBJECT_HANDLE key,
			 int sign)
{
	CK_RV rv;
	struct serializer obj;
	uint32_t session_handle = session;
	uint32_t key_handle = key;
	char *ctrl = NULL;
	size_t ctrl_size;

	rv = serialize_ck_mecha_params(&obj, mechanism);
	if (rv)
		return rv;

	/* params = [session-handle][key-handle][serialized-mechanism-blob] */
	ctrl_size = 2 * sizeof(uint32_t) + obj.size;
	ctrl = malloc(ctrl_size);
	if (!ctrl)
		return CKR_HOST_MEMORY;

	memcpy(ctrl, &session_handle, sizeof(uint32_t));
	memcpy(ctrl + sizeof(uint32_t), &key_handle, sizeof(uint32_t));
	memcpy(ctrl + 2 * sizeof(uint32_t), obj.buffer, obj.size);

	rv = ck_invoke_ta(ck_session2sks_ctx(session), sign ?
			  SKS_CMD_SIGN_INIT : SKS_CMD_VERIFY_INIT,
			  ctrl, ctrl_size, NULL, 0, NULL, NULL);

	free(ctrl);
	release_serial_object(&obj);

	return rv;
}

CK_RV ck_signverify_update(CK_SESSION_HANDLE session,
			   CK_BYTE_PTR in,
			   CK_ULONG in_len,
			   int sign)
{
	CK_RV rv;
	uint32_t ctrl;
	size_t ctrl_size;
	void *in_buf = in;
	size_t in_size = in_len;

	/* params = [session-handle] */
	ctrl = session;
	ctrl_size = sizeof(ctrl);

	rv = ck_invoke_ta(ck_session2sks_ctx(session), sign ?
			  SKS_CMD_SIGN_UPDATE : SKS_CMD_VERIFY_UPDATE,
			  &ctrl, ctrl_size, in_buf, in_size,
			  NULL, NULL);

	return rv;
}

CK_RV ck_signverify_final(CK_SESSION_HANDLE session,
			  CK_BYTE_PTR out,
			  CK_ULONG_PTR out_len,
			  int sign)
{
	CK_RV rv;
	uint32_t ctrl;
	size_t ctrl_size;
	void *out_buf = out;
	size_t out_size;

	/* params = [session-handle] */
	ctrl = session;
	ctrl_size = sizeof(ctrl);

	if (!out_len)
		out_size = 0;
	else
		out_size = *out_len;

	rv = ck_invoke_ta(ck_session2sks_ctx(session), sign ?
			  SKS_CMD_SIGN_FINAL : SKS_CMD_VERIFY_FINAL,
			  &ctrl, ctrl_size, NULL, 0, out_buf, &out_size);

	if (out_len && (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL))
		*out_len = out_size;

	return rv;
}
