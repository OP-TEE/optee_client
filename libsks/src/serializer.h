/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SERIALIZER_H
#define __SERIALIZER_H

#include <pkcs11.h>
#include <sks_ta.h>
#include <stddef.h>
#include <stdint.h>

#define SKS_MAX_BOOLPROP_SHIFT	64
#define SKS_MAX_BOOLPROP_ARRAY	(SKS_MAX_BOOLPROP_SHIFT / sizeof(uint32_t))

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
	uint32_t boolprop[SKS_MAX_BOOLPROP_ARRAY];
};

size_t get_serial_object_size(struct serializer *obj);

/* Init/finalize/release a serializer object */
CK_RV init_serial_object(struct serializer *obj);
void finalize_serial_object(struct serializer *obj);
void release_serial_object(struct serializer *obj);

CK_RV serialize_buffer(struct serializer *obj, void *data, size_t size);
CK_RV serialize_32b(struct serializer *obj, uint32_t data);
CK_RV serialize_ck_ulong(struct serializer *obj, CK_ULONG data);

/*
 * Tools on already serialized object: input referenc is the serial object
 * head address.
 */

/* Return the size of the serial blob head or 0 on error */
size_t sizeof_serial_head(void *ref);

/* Return the size of a serial object (head + blobs size) */
size_t get_serial_size(void *ref);

/* Return the class of the object or the invalid ID if not found */
uint32_t serial_get_class(void *ref);

/* Return the type of the object or the invalid ID if not found */
uint32_t serial_get_type(void *ref);

/* Get the location of target the attribute data and size */
CK_RV serial_get_attribute_ptr(void *ref, uint32_t attribute,
			       void **attr, size_t *attr_size);

/* Get target the attribute data content */
CK_RV serial_get_attribute(void *ref, uint32_t attribute,
			   void *attr, size_t *attr_size);

/*
 * Same serial_get_attributes() in case an attribute is defined several
 * times in the object (i.e several string identifiers for a single object)
 * TODO.
 */
CK_RV serial_get_attribute_multi(void *ref, uint32_t attribute,
			   void *attr, size_t *attr_size);

#endif /*__SERIALIZER_H*/

