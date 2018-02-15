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
