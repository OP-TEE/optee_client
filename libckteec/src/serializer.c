// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <pkcs11_ta.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ck_helpers.h"
#include "local_utils.h"
#include "serializer.h"

CK_RV init_serial_object(struct serializer *obj)
{
	struct pkcs11_object_head head = { 0 };

	memset(obj, 0, sizeof(*obj));

	return serialize_buffer(obj, &head, sizeof(head));
}

void finalize_serial_object(struct serializer *obj)
{
	struct pkcs11_object_head head = { 0 };

	head.attrs_size = obj->size - sizeof(head);
	head.attrs_count = obj->item_count;
	memcpy(obj->buffer, &head, sizeof(head));
}

void release_serial_object(struct serializer *obj)
{
	free(obj->buffer);
	obj->buffer = NULL;
}

/**
 * serialize - append data in a serialized buffer
 *
 * Serialize data in provided buffer.
 * Ensure 64byte alignment of appended data in the buffer.
 */
static CK_RV serialize(char **bstart, size_t *blen, void *data, size_t len)
{
	size_t nlen = *blen + len;
	char *buf = realloc(*bstart, nlen);

	if (!buf)
		return CKR_HOST_MEMORY;

	memcpy(buf + *blen, data, len);

	*blen = nlen;
	*bstart = buf;

	return CKR_OK;
}

CK_RV serialize_buffer(struct serializer *obj, void *data, size_t size)
{
	return serialize(&obj->buffer, &obj->size, data, size);
}

CK_RV serialize_32b(struct serializer *obj, uint32_t data)
{
	return serialize_buffer(obj, &data, sizeof(data));
}

CK_RV serialize_ck_ulong(struct serializer *obj, CK_ULONG data)
{
	uint32_t data32 = data;

	return serialize_buffer(obj, &data32, sizeof(data32));
}
