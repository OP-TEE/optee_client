/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sks_ta.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ck_helpers.h"
#include "local_utils.h"
#include "serializer.h"

CK_RV init_serial_object(struct serializer *obj)
{
	struct sks_object_head head;

	memset(obj, 0, sizeof(*obj));
	obj->object = SKS_UNDEFINED_ID;
	obj->type = SKS_UNDEFINED_ID;

	/* Init head to all ones, will be set at finalize_serial_object */
	memset(&head, 0xFF, sizeof(head));
	return serialize_buffer(obj, &head, sizeof(head));
}

void finalize_serial_object(struct serializer *obj)
{
	struct sks_object_head head;

	memset(&head, 0xFF, sizeof(head));

#ifdef SKS_WITH_GENERIC_ATTRIBS_IN_HEAD
fsdf fsd fsdf sdf
	head.object = obj->object;
	head.type = obj->type;
#ifdef SKS_WITH_BOOLPROP_ATTRIBS_IN_HEAD
	head.boolpropl = *((uint32_t *)obj->boolprop);
	head.boolproph = *((uint32_t *)obj->boolprop + 1);
#endif
#endif
	head.blobs_size = obj->size - sizeof(head);
	head.blobs_count = obj->item_count;
	memcpy(obj->buffer, &head, sizeof(head));

if(0)	{
		unsigned int n;
		printf("finalize %x %x:  ", (unsigned)head.blobs_size, (unsigned)head.blobs_count);
		for (n = 0; n < obj->size; n++)
			printf("%02x ", obj->buffer[n]);
		printf("\n");
	}
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
 * Ensure 64byte alignement of appended data in the buffer.
 */
static CK_RV serialize(char **bstart, size_t *blen, void *data, size_t len)
{
	char *buf;
	size_t nlen;

	nlen = *blen + len;

	buf = realloc(*bstart, nlen);
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
	uint32_t data32 = data;

	return serialize_buffer(obj, &data32, sizeof(uint32_t));
}

CK_RV serialize_ck_ulong(struct serializer *obj, CK_ULONG data)
{
	uint32_t data32 = data;

	return serialize_buffer(obj, &data32, sizeof(data32));
}
