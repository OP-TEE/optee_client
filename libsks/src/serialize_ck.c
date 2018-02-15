/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <pkcs11.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sks_ck_debug.h>
#include <sks_ta.h>

#include "ck_helpers.h"
#include "local_utils.h"
#include "serializer.h"
#include "serialize_ck.h"

/*
 * Generic way of serializing CK keys, certif, mechanism parameters, ...
 * In cryptoki 2.40 parameters are almost all packaged as struture below:
 */
struct ck_ref {
	CK_ULONG id;
	CK_BYTE_PTR ptr;
	CK_ULONG len;
};

#if 0
/*
 * Append cryptoki generic buffer reference structure into a sks serial
 * object.
 *
 * ck_ref points to a structure aligned CK reference (attributes or else)
 */
static CK_RV serialize_ck_ref(struct serializer *obj, void *ck_ref)
{
	struct ck_ref *ref = ck_ref;
	CK_RV rv;

	rv = serialize_ck_ulong(obj, ref->id);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, ref->len);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, ref->ptr, ref->len);
	if (rv)
		return rv;

	obj->item_count++;

	return rv;
}

/*
 * ck_ref points to a structure aligned CK reference (attributes or else)
 *
 * Same as serialize_ck_ref but reference is a ULONG so the blob size
 * to be set accoring to the 32bit/64bit configuration of target CK ABI.
 */
static CK_RV serialize_ulong_ck_ref(struct serializer *obj, void *ck_ref)
{
	struct ck_ref *ref = ck_ref;
	CK_ULONG ck_value;
	uint32_t sks_value;
	CK_RV rv;

	rv = serialize_ck_ulong(obj, ref->id);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, sizeof(sks_value));
	if (rv)
		return rv;

	memcpy(&ck_value, ref->ptr, sizeof(CK_ULONG));
	sks_value = ck_value;

	rv = serialize_buffer(obj, &sks_value, sizeof(sks_value));
	if (rv)
		return rv;

	obj->item_count++;

	return rv;
}
#endif

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
	CK_ATTRIBUTE_PTR attr;
	CK_ULONG count;
	CK_RV rv;
	struct serializer obj2;

	switch (attribute->type) {
	/* These are serialized each seperately */
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
	case CKA_DERIVE_TEMPLATE:
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
	rv = serialize_32b(obj, ck2sks_attribute_id(attribute->type));
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
	return (ck_attr_is_class(attribute_id) ||
		ck_attr_is_type(attribute_id) ||
		attribute_id == CKA_VALUE_LEN);
}

static CK_RV serialize_ck_attribute(struct serializer *obj, CK_ATTRIBUTE *attr)
{
	uint32_t sks_id = SKS_UNDEFINED_ID;
	uint32_t sks_size = 0;
	uint32_t sks_data32;
	void *sks_pdata;
	int sks_pdata_alloced = 0;
	CK_ULONG ck_ulong;
	CK_RV rv;
	unsigned int n;
	unsigned int m;

	/* Expect only those from the identification table */
	sks_id = ck2sks_attribute_id(attr->type);
	if (sks_id == SKS_UNDEFINED_ID)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	if (ck_attr_is_ulong(attr->type)) {
		/* PKCS#11 CK_ULONG are use */
		if (attr->ulValueLen != sizeof(CK_ULONG))
			return CKR_ATTRIBUTE_TYPE_INVALID;

		memcpy(&ck_ulong, attr->pValue, sizeof(ck_ulong));
	}

	switch (attr->type) {
	case CKA_CLASS:
		sks_data32 = ck2sks_class(ck_ulong);
		sks_pdata = &sks_data32;
		sks_size = sizeof(uint32_t);
		break;

	case CKA_KEY_TYPE:
		sks_data32 = ck2sks_key_type(ck_ulong);
		sks_pdata = &sks_data32;
		sks_size = sizeof(uint32_t);
		break;

	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
	case CKA_DERIVE_TEMPLATE:
		return serialize_indirect_attribute(obj, attr);

	case CKA_ALLOWED_MECHANISMS:
		n = attr->ulValueLen / sizeof(CK_ULONG);
		sks_size = n * sizeof(uint32_t);
		sks_pdata = malloc(sks_size);
		if (!sks_pdata)
			return CKR_HOST_MEMORY;

		sks_pdata_alloced = 1;

		for (m = 0; m < n; m++) {
			CK_MECHANISM_TYPE *type = attr->pValue;

			sks_data32 = ck2sks_mechanism_type(type[m]);
			if (sks_data32 == SKS_UNDEFINED_ID) {
				free(sks_pdata);
				return CKR_MECHANISM_INVALID;
			}

			((uint32_t *)sks_pdata)[m] = sks_data32;
		}
		break;

	/* Attributes which data value do not need conversion (aside ulong) */
	default:
		if (ck_attr_is_ulong(attr->type)) {
			sks_data32 = (uint32_t)ck_ulong;
			sks_pdata = &sks_data32;
			sks_size = sizeof(uint32_t);
		} else {
			sks_pdata = attr->pValue;
			sks_size = attr->ulValueLen;
		}
		break;
	}

	rv = serialize_32b(obj, sks_id);
	if (rv)
		goto bail;

	rv = serialize_32b(obj, sks_size);
	if (rv)
		goto bail;

	rv = serialize_buffer(obj, sks_pdata, sks_size);
	if (rv)
		goto bail;

	obj->item_count++;

bail:
	if (sks_pdata_alloced)
		free(sks_pdata);

	return rv;
}

#ifdef SKS_WITH_GENERIC_ATTRIBS_IN_HEAD
static CK_RV get_class(struct serializer *obj, struct ck_ref *ref)
{
	CK_ULONG ck_value;
	uint32_t sks_value;

	if (ref->len != sizeof(ck_value))
		return CKR_TEMPLATE_INCONSISTENT;

	memcpy(&ck_value, ref->ptr, sizeof(ck_value));

	sks_value = ck2sks_class(ck_value);

	if (sks_value == SKS_UNDEFINED_ID)
		return CKR_TEMPLATE_INCONSISTENT; // TODO: errno

	if (obj->object == SKS_UNDEFINED_ID)
		obj->object = sks_value;

	if (obj->object != sks_value) {
		printf("Attribute %s redefined\n", cka2str(ref->id));
		return CKR_TEMPLATE_INCONSISTENT;
	}

	return CKR_OK;
}

static CK_RV get_type(struct serializer *obj, struct ck_ref *ref,
		      CK_ULONG class)
{
	CK_ULONG ck_value;
	uint32_t sks_value;

	if (ref->len != sizeof(ck_value))
		return CKR_TEMPLATE_INCONSISTENT;

	memcpy(&ck_value, ref->ptr, sizeof(ck_value));

	sks_value = ck2sks_type_in_class(ck_value, class);

	if (sks_value == SKS_UNDEFINED_ID)
		return CKR_TEMPLATE_INCONSISTENT; // TODO: errno

	if (obj->type == SKS_UNDEFINED_ID)
		obj->type = sks_value;

	if (obj->type != sks_value) {
		printf("Attribute %s redefined\n",
			cktype2str(ck_value, class));
		return CKR_TEMPLATE_INCONSISTENT;
	}

	return CKR_OK;
}

#ifdef /* SKS_WITH_BOOLPROP_ATTRIBS_IN_HEAD */
static CK_RV get_boolprop(struct serializer *obj,
			  struct ck_ref *ref, uint32_t *sanity)
{
	int shift;
	uint32_t mask;
	uint32_t value;
	uint32_t *boolprop_ptr;
	uint32_t *sanity_ptr;
	CK_BBOOL bbool;

	/* Get the boolean property shift position and value */
	shift = ck_attr2boolprop_shift(ref->id);
	if (shift < 0)
		return CKR_NO_EVENT;

	if (shift >= SKS_MAX_BOOLPROP_SHIFT)
		return CKR_FUNCTION_FAILED;

	memcpy(&bbool, ref->ptr, sizeof(bbool));

	mask = 1 << (shift % 32);
	if (bbool == CK_TRUE)
		value = mask;
	else
		value = 0;

	/* Locate the current config value for the boolean property */
	boolprop_ptr = obj->boolprop + (shift / 32);
	sanity_ptr = sanity + (shift / 32);

	/* Error if already set to a different boolean value */
	if ((*sanity_ptr & mask) && value != (*boolprop_ptr & mask)) {
		printf("Attribute %s redefined\n", cka2str(ref->id));
		return CKR_TEMPLATE_INCONSISTENT;
	}

	*sanity_ptr |= mask;
	if (value)
		*boolprop_ptr |= mask;
	else
		*boolprop_ptr &= ~mask;

	return CKR_OK;
}
#endif /* SKS_WITH_BOOLPROP_ATTRIBS_IN_HEAD */

/*
 * Extract object generic attributes
 * - all objects must provide at least a class
 * - some classes expect a type
 * - some classes can define generic boolean attributes (boolprops)
 */
static CK_RV serialize_generic_attributes(struct serializer *obj,
					  CK_ATTRIBUTE_PTR attributes,
					  CK_ULONG count)
{
	struct ck_ref *ref;
	size_t n;
	uint32_t sanity[SKS_MAX_BOOLPROP_ARRAY] = { 0 };
	CK_RV rv = CKR_OK;
	CK_ULONG class;

	for (ref = (struct ck_ref *)attributes, n = 0; n < count; n++, ref++) {
		if (ck_attr_is_class(ref->id))
			rv = get_class(obj, ref);
		if (rv)
			return rv;
	}

	rv = sks2ck_class(&class, obj->object);
	if (rv)
		return rv;

	for (ref = (struct ck_ref *)attributes, n = 0; n < count; n++, ref++) {
		if (ck_attr_is_type(ref->id)) {
			rv = get_type(obj, ref, class);
			if (rv)
				return rv;

			continue;
		}

#ifdef SKS_WITH_BOOLPROP_ATTRIBS_IN_HEAD
		if (sks_object_has_boolprop(obj->object) &&
		    ck_attr2boolprop_shift(ref->id) >= 0) {
			rv = get_boolprop(obj, ref, sanity);
			if (rv == CKR_NO_EVENT)
				rv = CKR_OK;

			if (rv)
				return rv;

			continue;
		}
#endif
	}

	return rv;
}

static int ck_attr_is_generic(CK_ULONG attribute_id)
{
	return (ck_attr_is_class(attribute_id) ||
#ifdef SKS_WITH_BOOLPROP_ATTRIBS_IN_HEAD
		(ck_attr2boolprop_shift(attribute_id) >= 0) ||
#endif
		ck_attr_is_type(attribute_id));
}
#endif /* SKS_WITH_GENERIC_ATTRIBS_IN_HEAD */

/* CK attribute reference arguments are list of attribute item */
CK_RV serialize_ck_attributes(struct serializer *obj,
				CK_ATTRIBUTE_PTR attributes, CK_ULONG count)
{
	CK_ATTRIBUTE_PTR cur_attr = attributes;
	CK_ULONG n = count;
	CK_RV rv = CKR_OK;

	rv = init_serial_object(obj);
	if (rv)
		return rv;

#ifdef SKS_WITH_GENERIC_ATTRIBS_IN_HEAD
	rv = serialize_generic_attributes(obj, attributes, count);
	if (rv)
		goto out;
#endif

	for (; n; n--, cur_attr++) {
		CK_ATTRIBUTE attr;

		memcpy(&attr, cur_attr, sizeof(attr));

#ifdef SKS_WITH_GENERIC_ATTRIBS_IN_HEAD
		if (ck_attr_is_generic(attr.type))
			continue;
#endif

		rv = serialize_ck_attribute(obj, &attr);
		if (rv)
			goto out;
	}

out:
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
 *
 * Be careful that CK_ULONG based types translate to 32bit sks ulong fields.
 */

/*
 * typedef struct CK_AES_CTR_PARAMS {
 *	CK_ULONG ulCounterBits;
 *	CK_BYTE cb[16];
 * } CK_AES_CTR_PARAMS;
 */
static CK_RV serialize_mecha_aes_ctr(struct serializer *obj,
				     CK_MECHANISM_PTR mecha)
{
	CK_AES_CTR_PARAMS_PTR param = mecha->pParameter;
	CK_RV rv;
	uint32_t size;

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

/*
 * typedef struct CK_GCM_PARAMS {
 *	CK_BYTE_PTR       pIv;
 *	CK_ULONG          ulIvLen;
 *	CK_ULONG          ulIvBits;
 *	CK_BYTE_PTR       pAAD;
 *	CK_ULONG          ulAADLen;
 *	CK_ULONG          ulTagBits;
 * } CK_GCM_PARAMS;
 */
static CK_RV serialize_mecha_aes_gcm(struct serializer *obj,
				     CK_MECHANISM_PTR mecha)
{
	CK_GCM_PARAMS_PTR param = mecha->pParameter;
	CK_RV rv;

	rv = serialize_buffer(obj, param->pIv, param->ulIvLen);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulIvBits);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->pAAD, param->ulAADLen);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulTagBits);
	if (rv)
		return rv;

	return rv;
}

/*
 * typedef struct CK_CCM_PARAMS {
 *	CK_ULONG          ulDataLen;
 *	CK_BYTE_PTR       pNonce;
 *	CK_ULONG          ulNonceLen;
 *	CK_BYTE_PTR       pAAD;
 *	CK_ULONG          ulAADLen;
 *	CK_ULONG          ulMACLen;
 *} CK_CCM_PARAMS;
 */
static CK_RV serialize_mecha_aes_ccm(struct serializer *obj,
				     CK_MECHANISM_PTR mecha)
{
	CK_CCM_PARAMS_PTR param = mecha->pParameter;
	CK_RV rv;

	rv = serialize_ck_ulong(obj, param->ulDataLen);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->pNonce, param->ulNonceLen);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->pAAD, param->ulAADLen);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulMACLen);
	if (rv)
		return rv;

	return rv;
}

static CK_RV serialize_mecha_aes_iv(struct serializer *obj,
				    CK_MECHANISM_PTR mecha)
{
	uint32_t iv_size = mecha->ulParameterLen;
	CK_RV rv;

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
 *	[sks-mechanism-type][sks-mechanism-param-blob]
 *
 * [sks-mechanism-param-blob] depends on mechanism type ID, see
 * serialize_mecha_XXX().
 */
CK_RV serialize_ck_mecha_params(struct serializer *obj,
				CK_MECHANISM_PTR mechanism)
{
	CK_MECHANISM mecha;
	CK_RV rv;

	memset(obj, 0, sizeof(*obj));

	obj->object = SKS_OBJ_CK_MECHANISM;

	memcpy(&mecha, mechanism, sizeof(mecha));
	obj->type = ck2sks_mechanism_type(mecha.mechanism);
	if (obj->type == SKS_UNDEFINED_ID)
		return CKR_MECHANISM_INVALID;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	switch (mecha.mechanism) {
	case CKM_GENERIC_SECRET_KEY_GEN:
	case CKM_AES_KEY_GEN:
	case CKM_AES_ECB:
		/* No parameter expected, size shall be 0 */
		if (mechanism->ulParameterLen)
			return CKR_MECHANISM_PARAM_INVALID;
		return serialize_32b(obj, 0);
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_CTS:
		return serialize_mecha_aes_iv(obj, &mecha);
	case CKM_AES_CTR:
		return serialize_mecha_aes_ctr(obj, &mecha);
	case CKM_AES_CCM:
		return serialize_mecha_aes_ccm(obj, &mecha);
	case CKM_AES_GCM:
		return serialize_mecha_aes_gcm(obj, &mecha);
	default:
		return CKR_MECHANISM_INVALID;
	}
}

/*
 * Debug: dump CK attribute array to output trace
 */

static CK_RV trace_attributes(char *prefix, void *src, void *end)
{
	size_t next = 0;
	char *prefix2;
	size_t prefix_len = strlen(prefix);
	char *cur = src;

	/* append 4 spaces to the prefix */
	prefix2 = malloc(prefix_len + 1 + 4) ;
	memcpy(prefix2, prefix, prefix_len + 1);
	memset(prefix2 + prefix_len, ' ', 4);
	*(prefix2 + prefix_len + 1 + 4) = '\0';

	for (; cur < (char *)end; cur += next) {
		struct sks_reference ref;

		memcpy(&ref, cur, sizeof(ref));
		next = sizeof(ref) + ref.size;

		LOG_DEBUG("%s attr 0x%" PRIx32 " (%" PRIu32" byte) : %02x %02x %02x %02x ...\n",
			prefix, ref.id, ref.size,
			*((char *)cur + sizeof(ref) + 0),
			*((char *)cur + sizeof(ref) + 1),
			*((char *)cur + sizeof(ref) + 2),
			*((char *)cur + sizeof(ref) + 3));

		switch (ref.id) {
		case SKS_WRAP_ATTRIBS:
		case SKS_UNWRAP_ATTRIBS:
		case SKS_DERIVE_ATTRIBS:
			serial_trace_attributes_from_head(prefix2,
							  cur + sizeof(ref));
			break;
		default:
			break;
		}
	}

	/* sanity */
	if (cur != (char *)end) {
		LOG_ERROR("unexpected none alignement\n");
	}

	free(prefix2);
	return CKR_OK;
}

CK_RV serial_trace_attributes_from_head(char *prefix, void *ref)
{
	struct sks_object_head head;
	char *pre;
	CK_RV rv;

	memcpy(&head, ref, sizeof(head));

	pre = calloc(1, prefix ? strlen(prefix) + 2 : 2) ;
	if (!pre)
		return CKR_HOST_MEMORY;
	if (prefix)
		memcpy(pre, prefix, strlen(prefix));

	LOG_INFO("%s,--- (serial object) Attributes list --------\n", pre);
	LOG_INFO("%s| %" PRIu32 " item(s) - %" PRIu32 " bytes\n", pre,
		 head.blobs_count, head.blobs_size);

	pre[prefix ? strlen(prefix) + 1 : 0] = '|';

	rv = trace_attributes(pre, (char *)ref + sizeof(head),
			      (char *)ref + sizeof(head) + head.blobs_size);
	if (rv)
		goto bail;

	LOG_INFO("%s`-----------------------\n", prefix ? prefix : "");

bail:
	free(pre);
	return rv;
}

CK_RV serial_trace_attributes(char *prefix, struct serializer *obj)
{
	return serial_trace_attributes_from_head(prefix, obj->buffer);
}
