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

/*
 * Serialization of CK mechanism parameters
 *
 * Most mechanism have no parameters.
 * Some mechanism have a single 32bit parameter.
 * Some mechanism have a specific parameter structure which may contain
 * indirected data (data referred by a buffer pointer).
 *
 * Below are each structure specific mechanisms parameters.
 */

static CK_RV serialize_mecha_aes_ctr(struct serializer *obj,
				     CK_MECHANISM_PTR mecha)
{
	CK_AES_CTR_PARAMS_PTR param = mecha->pParameter;
	CK_RV rv = CKR_GENERAL_ERROR;
	uint32_t size = 0;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	size = sizeof(uint32_t) + sizeof(param->cb);
	rv = serialize_32b(obj, size);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulCounterBits);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->cb, sizeof(param->cb));
	if (rv)
		return rv;

	return rv;
}

static CK_RV serialize_mecha_aes_iv(struct serializer *obj,
				    CK_MECHANISM_PTR mecha)
{
	uint32_t iv_size = mecha->ulParameterLen;
	CK_RV rv = CKR_GENERAL_ERROR;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, iv_size);
	if (rv)
		return rv;

	return serialize_buffer(obj, mecha->pParameter, mecha->ulParameterLen);
}

/**
 * serialize_ck_mecha_params - serialize a mechanism type & params
 *
 * @obj - serializer used to track the serialization
 * @mechanism - pointer of the in structure aligned CK_MECHANISM.
 *
 * Serialized content:
 *	[mechanism-type][mechanism-param-blob]
 *
 * [mechanism-param-blob] depends on mechanism type ID, see
 * serialize_mecha_XXX().
 */
CK_RV serialize_ck_mecha_params(struct serializer *obj,
				CK_MECHANISM_PTR mechanism)
{
	CK_MECHANISM mecha = { };
	CK_RV rv = CKR_GENERAL_ERROR;

	memset(obj, 0, sizeof(*obj));

	obj->object = PKCS11_CKO_MECHANISM;

	mecha = *mechanism;
	obj->type = mecha.mechanism;
	if (obj->type == PKCS11_UNDEFINED_ID)
		return CKR_MECHANISM_INVALID;

	switch (mecha.mechanism) {
	case CKM_AES_ECB:
	case CKM_AES_CMAC:
		/* No parameter expected, size shall be 0 */
		if (mechanism->ulParameterLen)
			return CKR_MECHANISM_PARAM_INVALID;

		rv = serialize_32b(obj, obj->type);
		if (rv)
			return rv;

		return serialize_32b(obj, 0);

	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_CTS:
		return serialize_mecha_aes_iv(obj, &mecha);

	case CKM_AES_CTR:
		return serialize_mecha_aes_ctr(obj, &mecha);

	default:
		return CKR_MECHANISM_INVALID;
	}
}
