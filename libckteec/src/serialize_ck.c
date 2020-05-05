// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <ck_debug.h>
#include <inttypes.h>
#include <pkcs11.h>
#include <pkcs11_ta.h>
#include <stdlib.h>
#include <string.h>

#include "ck_helpers.h"
#include "local_utils.h"
#include "serializer.h"
#include "serialize_ck.h"

/*
 * Generic way of serializing CK keys, certificates, mechanism parameters, ...
 * In cryptoki 2.40 parameters are almost all packaged as structure below:
 */
struct ck_ref {
	CK_ULONG id;
	CK_BYTE_PTR ptr;
	CK_ULONG len;
};

/*
 * This is for attributes that contains data memory indirections.
 * In other words, an attributes that defines a list of attributes.
 * They are identified from the attribute type CKA_...
 *
 * @obj - ref used to track the serial object being created
 * @attribute - pointer to a structure aligned of the CK_ATTRIBUTE struct
 */
static CK_RV serialize_indirect_attribute(struct serializer *obj,
					  CK_ATTRIBUTE_PTR attribute)
{
	CK_ATTRIBUTE_PTR attr = NULL;
	CK_ULONG count = 0;
	CK_RV rv = CKR_GENERAL_ERROR;
	struct serializer obj2 = { };

	switch (attribute->type) {
	/* These are serialized each separately */
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
		count = attribute->ulValueLen / sizeof(CK_ATTRIBUTE);
		attr = (CK_ATTRIBUTE_PTR)attribute->pValue;
		break;
	default:
		return CKR_NO_EVENT;
	}

	/* Create a serialized object for the content */
	rv = serialize_ck_attributes(&obj2, attr, count);
	if (rv)
		return rv;

	/*
	 * Append the created serialized object into target object:
	 * [attrib-id][byte-size][attributes-data]
	 */
	rv = serialize_32b(obj, attribute->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, obj2.size);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, obj2.buffer, obj2.size);
	if (rv)
		return rv;

	obj->item_count++;

	return rv;
}

static int ck_attr_is_ulong(CK_ATTRIBUTE_TYPE attribute_id)
{
	switch (attribute_id) {
	case CKA_CLASS:
	case CKA_CERTIFICATE_TYPE:
	case CKA_KEY_TYPE:
	case CKA_HW_FEATURE_TYPE:
	case CKA_MECHANISM_TYPE:
	case CKA_KEY_GEN_MECHANISM:
	case CKA_VALUE_LEN:
	case CKA_MODULUS_BITS:
		return true;
	default:
		return false;
	}
}

static CK_RV serialize_ck_attribute(struct serializer *obj, CK_ATTRIBUTE *attr)
{
	CK_MECHANISM_TYPE *type = NULL;
	uint32_t pkcs11_size = 0;
	uint32_t pkcs11_data32 = 0;
	void *pkcs11_pdata = NULL;
	uint32_t *mech_buf = NULL;
	CK_RV rv = CKR_GENERAL_ERROR;
	unsigned int n = 0;
	unsigned int m = 0;

	if (attr->type == PKCS11_UNDEFINED_ID)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	switch (attr->type) {
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
		return serialize_indirect_attribute(obj, attr);
	case CKA_ALLOWED_MECHANISMS:
		n = attr->ulValueLen / sizeof(CK_ULONG);
		pkcs11_size = n * sizeof(uint32_t);
		mech_buf = malloc(pkcs11_size);
		if (!mech_buf)
			return CKR_HOST_MEMORY;

		type = attr->pValue;
		for (m = 0; m < n; m++) {
			mech_buf[m] = type[m];
			if (mech_buf[m] == PKCS11_UNDEFINED_ID) {
				rv = CKR_MECHANISM_INVALID;
				goto out;
			}
		}
		pkcs11_pdata = mech_buf;
		break;
	/* Attributes which data value do not need conversion (aside ulong) */
	default:
		if (ck_attr_is_ulong(attr->type)) {
			CK_ULONG ck_ulong = 0;

			if (attr->ulValueLen != sizeof(CK_ULONG))
				return CKR_ATTRIBUTE_TYPE_INVALID;

			memcpy(&ck_ulong, attr->pValue, sizeof(ck_ulong));
			pkcs11_data32 = ck_ulong;
			pkcs11_pdata = &pkcs11_data32;
			pkcs11_size = sizeof(uint32_t);
		} else {
			pkcs11_pdata = attr->pValue;
			pkcs11_size = attr->ulValueLen;
		}
		break;
	}

	rv = serialize_32b(obj, attr->type);
	if (rv)
		goto out;

	rv = serialize_32b(obj, pkcs11_size);
	if (rv)
		goto out;

	rv = serialize_buffer(obj, pkcs11_pdata, pkcs11_size);
	if (rv)
		goto out;

	obj->item_count++;
out:
	free(mech_buf);

	return rv;
}

/* CK attribute reference arguments are list of attribute item */
CK_RV serialize_ck_attributes(struct serializer *obj,
			      CK_ATTRIBUTE_PTR attributes, CK_ULONG count)
{
	CK_ULONG n = 0;
	CK_RV rv = CKR_OK;

	rv = init_serial_object(obj);
	if (rv)
		return rv;

	for (n = 0; n < count; n++) {
		rv = serialize_ck_attribute(obj, attributes + n);
		if (rv)
			break;
	}

	if (rv)
		release_serial_object(obj);
	else
		finalize_serial_object(obj);

	return rv;
}
