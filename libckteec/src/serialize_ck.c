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
 * Serialization and de-serialization logic
 *
 * Cryptoki API works in a way that user application uses memory references
 * in object attributes description. TA can be invoked with only a small set
 * of possible references to caller memory. Thus a Cryptoki object, made of
 * data and pointers to data, is reassembled into a byte array where each
 * attribute info (ID, value size, value) is appended with byte alignment. This
 * so-called serialized object can be passed through the TA API.
 *
 * Initial entry to PKCS11 TA uses serialize_ck_attributes(). When TA
 * returns with updated serialized data to be passed back to caller, we call
 * deserialize_ck_attributes().
 *
 * Special handling is performed for CK_ULONG passing which may be either 32
 * bits or 64 bits depending on target device architecture. In TA interface
 * this is handled as unsigned 32 bit data type.
 *
 * When user application is querying attributes in example with
 * C_GetAttributeValue() user may allocate larger value buffers. During entry
 * to TA shared buffer is allocated in serialize_ck_attributes() based on
 * caller's arguments. For each attribute TA verifies if value fits in
 * the buffer and if it does, value is returned. Value size in buffer is
 * updated to indicate real size of the value. When call is returned back to
 * REE deserialize_ck_attributes() is invoked and then both input arguments and
 * serialization buffer are used to return values to caller. Provided input
 * arguments from caller are used to determine serialization buffer structure
 * and then actual values and value sizes are then decoded from serialization
 * buffer and returned to caller in caller's allocated memory.
 */

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
	struct serializer obj2 = { 0 };

	switch (attribute->type) {
	/* These are serialized each separately */
	case CKA_DERIVE_TEMPLATE:
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
		goto out;

	rv = serialize_32b(obj, obj2.size);
	if (rv)
		goto out;

	rv = serialize_buffer(obj, obj2.buffer, obj2.size);
	if (rv)
		goto out;

	obj->item_count++;
out:
	release_serial_object(&obj2);

	return rv;
}

static CK_RV deserialize_indirect_attribute(struct pkcs11_attribute_head *obj,
					    CK_ATTRIBUTE_PTR attribute)
{
	CK_ULONG count = 0;
	CK_ATTRIBUTE_PTR attr = NULL;

	switch (attribute->type) {
	/* These are serialized each separately */
	case CKA_DERIVE_TEMPLATE:
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
		count = attribute->ulValueLen / sizeof(CK_ATTRIBUTE);
		attr = (CK_ATTRIBUTE_PTR)attribute->pValue;
		break;
	default:
		return CKR_GENERAL_ERROR;
	}

	return deserialize_ck_attributes(obj->data, attr, count);
}

static int ck_attr_is_ulong(CK_ATTRIBUTE_TYPE attribute_id)
{
	switch (attribute_id) {
	case CKA_CLASS:
	case CKA_CERTIFICATE_TYPE:
	case CKA_CERTIFICATE_CATEGORY:
	case CKA_NAME_HASH_ALGORITHM:
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
	case CKA_DERIVE_TEMPLATE:
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
		pkcs11_pdata = attr->pValue;
		if (!attr->pValue) {
			pkcs11_size = 0;
		} else if (ck_attr_is_ulong(attr->type)) {
			CK_ULONG ck_ulong = 0;

			if (attr->ulValueLen < sizeof(CK_ULONG))
				return CKR_ATTRIBUTE_VALUE_INVALID;

			memcpy(&ck_ulong, attr->pValue, sizeof(ck_ulong));
			pkcs11_data32 = ck_ulong;
			pkcs11_pdata = &pkcs11_data32;
			pkcs11_size = sizeof(uint32_t);
		} else {
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

static CK_RV deserialize_mecha_list(CK_MECHANISM_TYPE *dst, void *src,
				    size_t count)
{
	char *ta_src = src;
	size_t n = 0;
	uint32_t mecha_id = 0;

	for (n = 0; n < count; n++) {
		memcpy(&mecha_id, ta_src + n * sizeof(mecha_id),
		       sizeof(mecha_id));
		dst[n] = mecha_id;
	}

	return CKR_OK;
}

static CK_RV deserialize_ck_attribute(struct pkcs11_attribute_head *in,
				      uint8_t *data, CK_ATTRIBUTE_PTR out)
{
	CK_ULONG ck_ulong = 0;
	uint32_t pkcs11_data32 = 0;
	CK_RV rv = CKR_OK;

	out->type = in->id;

	if (in->size == PKCS11_CK_UNAVAILABLE_INFORMATION) {
		out->ulValueLen = CK_UNAVAILABLE_INFORMATION;
		return CKR_OK;
	}

	if (!out->pValue && ck_attr_is_ulong(out->type)) {
		out->ulValueLen = sizeof(CK_ULONG);
		return CKR_OK;
	}

	if (out->ulValueLen < in->size) {
		out->ulValueLen = in->size;
		return CKR_OK;
	}

	if (!out->pValue)
		return CKR_OK;

	/* Specific ulong encoded as 32bit in PKCS11 TA API */
	if (ck_attr_is_ulong(out->type)) {
		if (out->ulValueLen < sizeof(CK_ULONG))
			return CKR_ATTRIBUTE_VALUE_INVALID;

		memcpy(&pkcs11_data32, data, sizeof(uint32_t));
		if (out->type == CKA_KEY_GEN_MECHANISM &&
		    pkcs11_data32 == PKCS11_CK_UNAVAILABLE_INFORMATION)
			ck_ulong = CK_UNAVAILABLE_INFORMATION;
		else
			ck_ulong = pkcs11_data32;

		memcpy(out->pValue, &ck_ulong, sizeof(CK_ULONG));
		out->ulValueLen = sizeof(CK_ULONG);
		return CKR_OK;
	}

	switch (out->type) {
	case CKA_DERIVE_TEMPLATE:
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
		rv = deserialize_indirect_attribute(in, out->pValue);
		break;
	case CKA_ALLOWED_MECHANISMS:
		rv = deserialize_mecha_list(out->pValue, data,
					    in->size / sizeof(uint32_t));
		out->ulValueLen = in->size / sizeof(uint32_t) *
				  sizeof(CK_ULONG);
		break;
	/* Attributes which data value do not need conversion (aside ulong) */
	default:
		memcpy(out->pValue, data, in->size);
		out->ulValueLen = in->size;
		break;
	}

	return rv;
}

CK_RV deserialize_ck_attributes(uint8_t *in, CK_ATTRIBUTE_PTR attributes,
				CK_ULONG count)
{
	CK_ATTRIBUTE_PTR cur_attr = attributes;
	CK_ULONG n = 0;
	CK_RV rv = CKR_OK;
	uint8_t *curr_head = in;
	size_t len = 0;

	curr_head += sizeof(struct pkcs11_object_head);

	for (n = count; n > 0; n--, cur_attr++, curr_head += len) {
		struct pkcs11_attribute_head *cli_ref = (void *)curr_head;
		struct pkcs11_attribute_head cli_head = { 0 };
		void *data_ptr = NULL;

		/* Make copy if header so that is aligned properly. */
		memcpy(&cli_head, cli_ref, sizeof(cli_head));

		/* Get real data pointer from template data */
		data_ptr = cli_ref->data;

		len = sizeof(cli_head);

		/* Advance by size provisioned in input serialized buffer */
		if (cur_attr->pValue) {
			if (ck_attr_is_ulong(cur_attr->type))
				len += sizeof(uint32_t);
			else
				len += cur_attr->ulValueLen;
		}

		rv = deserialize_ck_attribute(&cli_head, data_ptr, cur_attr);
		if (rv)
			return rv;
	}

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

static CK_RV serialize_mecha_aes_gcm(struct serializer *obj,
				     CK_MECHANISM_PTR mecha)
{
	CK_GCM_PARAMS_PTR param = mecha->pParameter;
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_ULONG aad_len = 0;

	/* AAD is not manadatory */
	if (param->pAAD)
		aad_len = param->ulAADLen;

	if (!param->pIv)
		return CKR_MECHANISM_PARAM_INVALID;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, 3 * sizeof(uint32_t) +
				param->ulIvLen + aad_len);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulIvLen);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->pIv, param->ulIvLen);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, aad_len);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->pAAD, aad_len);
	if (rv)
		return rv;

	return serialize_ck_ulong(obj, param->ulTagBits);
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

static CK_RV serialize_mecha_key_deriv_str(struct serializer *obj,
					   CK_MECHANISM_PTR mecha)
{
	CK_KEY_DERIVATION_STRING_DATA_PTR param = mecha->pParameter;
	CK_RV rv = CKR_GENERAL_ERROR;
	uint32_t size = 0;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	size = sizeof(uint32_t) + param->ulLen;
	rv = serialize_32b(obj, size);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulLen);
	if (rv)
		return rv;

	return serialize_buffer(obj, param->pData, param->ulLen);
}

static CK_RV serialize_mecha_ecdh1_derive_param(struct serializer *obj,
						CK_MECHANISM_PTR mecha)
{
	CK_ECDH1_DERIVE_PARAMS *params = mecha->pParameter;
	CK_RV rv = CKR_GENERAL_ERROR;
	size_t params_size = 3 * sizeof(uint32_t) + params->ulSharedDataLen +
			     params->ulPublicDataLen;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params_size);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params->kdf);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params->ulSharedDataLen);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, params->pSharedData,
			      params->ulSharedDataLen);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params->ulPublicDataLen);
	if (rv)
		return rv;

	return serialize_buffer(obj, params->pPublicData,
				params->ulPublicDataLen);
}

static CK_RV serialize_mecha_aes_cbc_encrypt_data(struct serializer *obj,
						  CK_MECHANISM_PTR mecha)
{
	CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR param = mecha->pParameter;
	CK_RV rv = CKR_GENERAL_ERROR;
	uint32_t size = 0;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	size = sizeof(param->iv) + sizeof(uint32_t) + param->length;
	rv = serialize_32b(obj, size);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->iv, sizeof(param->iv));
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->length);
	if (rv)
		return rv;

	return serialize_buffer(obj, param->pData, param->length);
}

static CK_RV serialize_mecha_rsa_pss_param(struct serializer *obj,
					   CK_MECHANISM_PTR mecha)
{
	CK_RSA_PKCS_PSS_PARAMS *params = mecha->pParameter;
	CK_RV rv = CKR_GENERAL_ERROR;
	uint32_t params_size = 3 * sizeof(uint32_t);

	if (mecha->ulParameterLen != sizeof(*params))
		return CKR_ARGUMENTS_BAD;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params_size);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, params->hashAlg);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, params->mgf);
	if (rv)
		return rv;

	return serialize_ck_ulong(obj, params->sLen);
}

static CK_RV serialize_mecha_rsa_oaep_param(struct serializer *obj,
					    CK_MECHANISM_PTR mecha)
{
	CK_RSA_PKCS_OAEP_PARAMS *params = mecha->pParameter;
	CK_RV rv = CKR_GENERAL_ERROR;
	size_t params_size = 4 * sizeof(uint32_t) + params->ulSourceDataLen;

	if (mecha->ulParameterLen != sizeof(*params))
		return CKR_ARGUMENTS_BAD;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params_size);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, params->hashAlg);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, params->mgf);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, params->source);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, params->ulSourceDataLen);
	if (rv)
		return rv;

	return serialize_buffer(obj, params->pSourceData,
				params->ulSourceDataLen);
}

static CK_RV serialize_mecha_rsa_aes_key_wrap(struct serializer *obj,
					      CK_MECHANISM_PTR mecha)
{
	CK_RSA_AES_KEY_WRAP_PARAMS *params = mecha->pParameter;
	CK_RSA_PKCS_OAEP_PARAMS *aes_params = params->pOAEPParams;
	CK_RV rv = CKR_GENERAL_ERROR;
	size_t params_size = 5 * sizeof(uint32_t) + aes_params->ulSourceDataLen;

	if (mecha->ulParameterLen != sizeof(*params))
		return CKR_ARGUMENTS_BAD;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params_size);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, params->ulAESKeyBits);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, aes_params->hashAlg);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, aes_params->mgf);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, aes_params->source);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, aes_params->ulSourceDataLen);
	if (rv)
		return rv;

	return serialize_buffer(obj, aes_params->pSourceData,
				aes_params->ulSourceDataLen);
}

static CK_RV serialize_mecha_eddsa(struct serializer *obj,
				   CK_MECHANISM_PTR mecha)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_EDDSA_PARAMS *params = mecha->pParameter;
	CK_ULONG params_len = mecha->ulParameterLen;
	/*
	 * When no parameter is provided, the expected operation is
	 * no-prehash and no-context.
	 */
	CK_EDDSA_PARAMS default_params = {
		.phFlag = 0,
		.ulContextDataLen = 0,
	};

	if (params_len == 0) {
		params = &default_params;
		params_len = sizeof(*params);
	}

	if (params_len != sizeof(*params))
		return CKR_ARGUMENTS_BAD;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, 2 * sizeof(uint32_t) + params->ulContextDataLen);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params->phFlag);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params->ulContextDataLen);
	if (rv)
		return rv;

	return serialize_buffer(obj, params->pContextData, params->ulContextDataLen);
}

static CK_RV serialize_mecha_mac_general_param(struct serializer *obj,
					       CK_MECHANISM_PTR mecha)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_ULONG ck_data = 0;

	if (mecha->ulParameterLen != sizeof(ck_data))
		return CKR_ARGUMENTS_BAD;

	memcpy(&ck_data, mecha->pParameter, mecha->ulParameterLen);

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, sizeof(uint32_t));
	if (rv)
		return rv;

	return serialize_ck_ulong(obj, ck_data);
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
	CK_MECHANISM mecha = { 0 };
	CK_RV rv = CKR_GENERAL_ERROR;

	memset(obj, 0, sizeof(*obj));

	obj->object = PKCS11_CKO_MECHANISM;

	mecha = *mechanism;
	obj->type = mecha.mechanism;
	if (obj->type == PKCS11_UNDEFINED_ID)
		return CKR_MECHANISM_INVALID;

	switch (mecha.mechanism) {
	case CKM_GENERIC_SECRET_KEY_GEN:
	case CKM_AES_KEY_GEN:
	case CKM_AES_ECB:
	case CKM_AES_CMAC:
	case CKM_MD5:
	case CKM_SHA_1:
	case CKM_SHA224:
	case CKM_SHA256:
	case CKM_SHA384:
	case CKM_SHA512:
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC:
	case CKM_SHA224_HMAC:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC:
	case CKM_EC_KEY_PAIR_GEN:
	case CKM_EC_EDWARDS_KEY_PAIR_GEN:
	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA224_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
		/* No parameter expected, size shall be 0 */
		if (mechanism->ulParameterLen)
			return CKR_MECHANISM_PARAM_INVALID;

		rv = serialize_32b(obj, obj->type);
		if (rv)
			return rv;

		return serialize_32b(obj, 0);

	case CKM_EDDSA:
		return serialize_mecha_eddsa(obj, &mecha);

	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_CTS:
		return serialize_mecha_aes_iv(obj, &mecha);

	case CKM_AES_CTR:
		return serialize_mecha_aes_ctr(obj, &mecha);

	case CKM_AES_GCM:
		return serialize_mecha_aes_gcm(obj, &mecha);

	case CKM_AES_ECB_ENCRYPT_DATA:
		return serialize_mecha_key_deriv_str(obj, &mecha);

	case CKM_AES_CBC_ENCRYPT_DATA:
		return serialize_mecha_aes_cbc_encrypt_data(obj, &mecha);

	case CKM_ECDH1_DERIVE:
	case CKM_ECDH1_COFACTOR_DERIVE:
		return serialize_mecha_ecdh1_derive_param(obj, &mecha);

	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
	case CKM_SHA224_RSA_PKCS_PSS:
		return serialize_mecha_rsa_pss_param(obj, &mecha);

	case CKM_RSA_PKCS_OAEP:
		return serialize_mecha_rsa_oaep_param(obj, &mecha);

	case CKM_AES_CMAC_GENERAL:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA224_HMAC_GENERAL:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512_HMAC_GENERAL:
		return serialize_mecha_mac_general_param(obj, &mecha);
	case CKM_RSA_AES_KEY_WRAP:
		return serialize_mecha_rsa_aes_key_wrap(obj, &mecha);

	default:
		return CKR_MECHANISM_INVALID;
	}
}
