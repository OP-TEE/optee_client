/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */
#ifndef LIBCKTEEC_SERIALIZER_H
#define LIBCKTEEC_SERIALIZER_H

#include <pkcs11.h>
#include <pkcs11_ta.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Struct used to create the buffer storing the serialized data.
 * Contains some fields to help parsing content (type/boolprops).
 */
struct serializer {
	char *buffer;		/* serial buffer base address */
	size_t size;		/* serial buffer current byte size */
	size_t item_count;	/* number of items in entry table */
	uint32_t object;
	uint32_t type;
};

/* Init/finalize/release a serializer object */
CK_RV init_serial_object(struct serializer *obj);
void finalize_serial_object(struct serializer *obj);
void release_serial_object(struct serializer *obj);

CK_RV serialize_buffer(struct serializer *obj, void *data, size_t size);
CK_RV serialize_32b(struct serializer *obj, uint32_t data);
CK_RV serialize_ck_ulong(struct serializer *obj, CK_ULONG data);

#endif /*LIBCKTEEC_SERIALIZER_H*/
