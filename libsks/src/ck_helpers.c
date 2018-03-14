/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>

#include "ck_helpers.h"

/*
 * SKS TA returns Cryptoki like information structure.
 * These routine convert the SKS format structure and bit flags
 * from/into Cryptoki format structures and bit flags.
 */
#define MEMCPY_FIELD(_dst, _src, _f) \
	do { \
		memcpy((_dst)->_f, (_src)->_f, sizeof((_dst)->_f)); \
		if (sizeof((_dst)->_f) != sizeof((_src)->_f)) \
			return CKR_GENERAL_ERROR; \
	} while (0)

#define MEMCPY_VERSION(_dst, _src, _f) \
	do { \
		memcpy(&(_dst)->_f, (_src)->_f, sizeof(CK_VERSION)); \
		if (sizeof(CK_VERSION) != sizeof((_src)->_f)) \
			return CKR_GENERAL_ERROR; \
	} while (0)


CK_RV sks2ck_slot_info(CK_SLOT_INFO_PTR ck_info,
			struct sks_ck_slot_info *sks_info)
{
	MEMCPY_FIELD(ck_info, sks_info, slotDescription);
	MEMCPY_FIELD(ck_info, sks_info, manufacturerID);
	ck_info->flags = sks_info->flags;
	MEMCPY_VERSION(ck_info, sks_info, hardwareVersion);
	MEMCPY_VERSION(ck_info, sks_info, firmwareVersion);

	return CKR_OK;
}

static CK_RV sks2ck_token_flags(CK_TOKEN_INFO_PTR ck_info,
				struct sks_ck_token_info *sks_info)
{
	CK_FLAGS ck_flag;
	uint32_t sks_mask;

	ck_info->flags = 0;
	for (sks_mask = 1; sks_mask; sks_mask <<= 1) {

		/* Skip sks token flags without a CK equilavent */
		if (sks2ck_token_flag(&ck_flag, sks_mask))
			continue;

		if (sks_info->flags & sks_mask)
			ck_info->flags |= ck_flag;
	}

	return CKR_OK;
}

CK_RV sks2ck_token_info(CK_TOKEN_INFO_PTR ck_info,
			struct sks_ck_token_info *sks_info)
{
	CK_RV rv;

	MEMCPY_FIELD(ck_info, sks_info, label);
	MEMCPY_FIELD(ck_info, sks_info, manufacturerID);
	MEMCPY_FIELD(ck_info, sks_info, model);
	MEMCPY_FIELD(ck_info, sks_info, serialNumber);

	rv = sks2ck_token_flags(ck_info, sks_info);
	if (rv)
		return rv;

	ck_info->ulMaxSessionCount = sks_info->ulMaxSessionCount;
	ck_info->ulSessionCount = sks_info->ulSessionCount;
	ck_info->ulMaxRwSessionCount = sks_info->ulMaxRwSessionCount;
	ck_info->ulRwSessionCount = sks_info->ulRwSessionCount;
	ck_info->ulMaxPinLen = sks_info->ulMaxPinLen;
	ck_info->ulMinPinLen = sks_info->ulMinPinLen;
	ck_info->ulTotalPublicMemory = sks_info->ulTotalPublicMemory;
	ck_info->ulFreePublicMemory = sks_info->ulFreePublicMemory;
	ck_info->ulTotalPrivateMemory = sks_info->ulTotalPrivateMemory;
	ck_info->ulFreePrivateMemory = sks_info->ulFreePrivateMemory;
	MEMCPY_VERSION(ck_info, sks_info, hardwareVersion);
	MEMCPY_VERSION(ck_info, sks_info, firmwareVersion);
	MEMCPY_FIELD(ck_info, sks_info, utcTime);

	return CKR_OK;
}

#undef CK_SKS_ID
#define CK_SKS_ID(ck_id, sks_id)	case ck_id: return sks_id;

uint32_t ck2sks_token_flag(CK_FLAGS ck)
{
	switch (ck) {
	CK_SKS_TOKEN_FLAG_MASKS
	default:
		return SKS_UNDEFINED_ID;
	}
}

#undef CK_SKS_ID
#define CK_SKS_ID(ck_id, sks_id)	case sks_id: *ck = ck_id; break;

CK_RV sks2ck_token_flag(CK_FLAGS *ck, uint32_t sks)
{
	switch (sks) {
	CK_SKS_TOKEN_FLAG_MASKS
	default:
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

#undef CK_SKS_ID
#define CK_SKS_ID(ck_id, sks_id)	case ck_id: return sks_id;

uint32_t ck2sks_attribute_id(CK_ULONG ck)
{
	switch (ck) {
	CK_SKS_ATTRIBS_ID
	default:
		return SKS_UNDEFINED_ID;
	}
}

#undef CK_SKS_ID
#define CK_SKS_ID(ck_id, sks_id)	case sks_id: *ck = ck_id; break;

CK_RV sks2ck_attribute_id(CK_ULONG *ck, uint32_t sks)
{
	switch (sks) {
	CK_SKS_ATTRIBS_ID
	default:
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

#undef CK_SKS_ID
#define CK_SKS_ID(ck_id, sks_id)	case ck_id: return sks_id;

uint32_t ck2sks_mechanism_type(CK_MECHANISM_TYPE ck)
{
	switch (ck) {
	CK_SKS_PROCESSING_IDS
	default:
		return SKS_UNDEFINED_ID;
	}
}

#undef CK_SKS_ID
#define CK_SKS_ID(ck_id, sks_id)	case sks_id: *ck = ck_id; break;

CK_RV sks2ck_mechanism_type(CK_MECHANISM_TYPE *ck, uint32_t sks)
{
	switch (sks) {
	CK_SKS_PROCESSING_IDS
	default:
		return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}

#undef CK_SKS_ID
#define CK_SKS_ID(ck_id, sks_id)	case sks_id: return ck_id;

CK_RV sks2ck_rv(uint32_t sks)
{
	switch (sks) {
	CK_SKS_ERROR_CODES
	default:
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

#define CK_TEEC_ERROR_CODES \
	CK_TEEC_ID(CKR_OK,			TEEC_SUCCESS) \
	CK_TEEC_ID(CKR_DEVICE_MEMORY,		TEEC_ERROR_OUT_OF_MEMORY) \
	CK_TEEC_ID(CKR_ARGUMENTS_BAD,		TEEC_ERROR_BAD_PARAMETERS) \
	CK_TEEC_ID(CKR_BUFFER_TOO_SMALL,	TEEC_ERROR_SHORT_BUFFER)

#undef CK_TEEC_ID
#define CK_TEEC_ID(ck_id, teec_id)	case teec_id: return ck_id;

CK_RV teec2ck_rv(TEEC_Result res)
{
	switch (res) {
	CK_TEEC_ERROR_CODES
	default:
		break;
	}

	return CKR_FUNCTION_FAILED;
}

/* Convert a array of mechanism type from sks into CK_MECHANIMS_TYPE */
CK_RV sks2ck_mechanism_type_list(CK_MECHANISM_TYPE *dst,
				 void *src, size_t count)
{
	CK_MECHANISM_TYPE *ck = dst;
	char *sks = src;
	size_t n;
	uint32_t proc;

	for (n = 0; n < count; n++, sks += sizeof(uint32_t), ck++) {
		memcpy(&proc, src, sizeof(proc));
		if (sks2ck_mechanism_type(ck, proc))
			return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}


#undef CK_SKS_ID
#define CK_SKS_ID(ck_id, sks_id)	case sks_id: *ck = ck_id; break;

CK_RV sks2ck_mechanism_flag(CK_FLAGS *ck, uint32_t sks)
{
	switch (sks) {
	CK_SKS_MECHANISM_FLAG_IDS
	default:
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}


#undef CK_SKS_ID
#define CK_SKS_ID(ck_id, sks_id)	case ck_id: return sks_id;

uint32_t ck2sks_class(CK_ULONG ck)
{
	switch (ck) {
	CK_SKS_OBJECT_CLASS_IDS
	default:
		return SKS_UNDEFINED_ID;
	}
}

#undef CK_SKS_ID
#define CK_SKS_ID(ck_id, sks_id)	case sks_id: *ck = ck_id; break;

CK_RV sks2ck_class(CK_ULONG *ck, uint32_t sks)
{
	switch (sks) {
	CK_SKS_OBJECT_CLASS_IDS
	default:
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

#undef CK_SKS_ID
#define CK_SKS_ID(ck_id, sks_id)	case ck_id: return sks_id;

uint32_t ck2sks_key_type(CK_ULONG ck)
{
	switch (ck) {
	CK_SKS_KEY_TYPE_IDS
	default:
		return SKS_UNDEFINED_ID;
	}
}

#undef CK_SKS_ID
#define CK_SKS_ID(ck_id, sks_id)	case sks_id: *ck = ck_id; break;

CK_RV sks2ck_key_type(CK_ULONG *ck, uint32_t sks)
{
	switch (sks) {
	CK_SKS_KEY_TYPE_IDS
	default:
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

#include <stdio.h>

/* Convert structure CK_MECHANIMS_INFO from sks to ck (3 ulong fields) */
CK_RV sks2ck_mechanism_info(CK_MECHANISM_INFO *info, void *src)
{
	struct sks_ck_mecha_info sks;
	CK_FLAGS ck_flag;
	uint32_t mask;
	CK_RV rv;

	memcpy(&sks, src, sizeof(sks));

	info->ulMinKeySize = sks.min_key_size;
	info->ulMaxKeySize = sks.max_key_size;

	info->flags = 0;
	for (mask = 1; mask; mask <<= 1) {
		if (!(sks.flags & mask))
			continue;

		rv = sks2ck_mechanism_flag(&ck_flag, mask);
		if (rv)
			return rv;

		info->flags |= ck_flag;
	}

	return CKR_OK;
}

/*
 * Helper functions to analyse CK fields
 */
size_t ck_attr_is_class(uint32_t attribute_id)
{
	if (attribute_id == CKA_CLASS)
		return sizeof(CK_ULONG);
	else
		return 0;
}

size_t ck_attr_is_type(uint32_t attribute_id)
{
	switch (attribute_id) {
	case CKA_CERTIFICATE_TYPE:
	case CKA_KEY_TYPE:
	case CKA_HW_FEATURE_TYPE:
	case CKA_MECHANISM_TYPE:
		return sizeof(CK_ULONG);
	default:
		return 0;
	}
}
int sks_object_has_boolprop(uint32_t class)
{
	switch (class) {
	case SKS_OBJ_RAW_DATA:
	case SKS_OBJ_CERTIFICATE:
	case SKS_OBJ_PUB_KEY:
	case SKS_OBJ_PRIV_KEY:
	case SKS_OBJ_SYM_KEY:
	case SKS_OBJ_CK_DOMAIN_PARAMS:
		return 1;
	default:
		return 0;
	}
}
int sks_class_has_type(uint32_t class)
{
	switch (class) {
	case SKS_OBJ_CERTIFICATE:
	case SKS_OBJ_PUB_KEY:
	case SKS_OBJ_PRIV_KEY:
	case SKS_OBJ_SYM_KEY:
	case SKS_OBJ_CK_MECHANISM:
	case SKS_OBJ_CK_HW_FEATURES:
		return 1;
	default:
		return 0;
	}
}

uint32_t ck2sks_type_in_class(CK_ULONG ck, CK_ULONG class)
{
	switch (class) {
	case CKO_DATA:
		return 0;
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
	case CKO_OTP_KEY:
		return ck2sks_key_type(ck);
	case CKO_MECHANISM:
		return ck2sks_mechanism_type(ck);
	case CKO_CERTIFICATE: // TODO
	default:
		return SKS_UNDEFINED_ID;
	}
}

CK_RV sks2ck_type_in_class(CK_ULONG *ck, uint32_t sks, CK_ULONG class)
{
	switch (class) {
	case SKS_OBJ_RAW_DATA:
		return CKR_NO_EVENT;
	case SKS_OBJ_SYM_KEY:
	case SKS_OBJ_PUB_KEY:
	case SKS_OBJ_PRIV_KEY:
	case SKS_OBJ_OTP_KEY:
		return sks2ck_key_type(ck, sks);
	case SKS_OBJ_CK_MECHANISM:
		return sks2ck_mechanism_type(ck, sks);
	case SKS_OBJ_CERTIFICATE: // TODO
	default:
		return CKR_GENERAL_ERROR;
	}
}

