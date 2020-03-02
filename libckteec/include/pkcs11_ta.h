/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#ifndef PKCS11_TA_H
#define PKCS11_TA_H

#include <stdbool.h>
#include <stdint.h>

#define PKCS11_TA_UUID { 0xfd02c9da, 0x306c, 0x48c7, \
			 { 0xa4, 0x9c, 0xbb, 0xd8, 0x27, 0xae, 0x86, 0xee } }

/* PKCS11 trusted application version information */
#define PKCS11_TA_VERSION_MAJOR			0
#define PKCS11_TA_VERSION_MINOR			1
#define PKCS11_TA_VERSION_PATCH			0

/* Attribute specific values */
#define PKCS11_UNAVAILABLE_INFORMATION		UINT32_C(0xFFFFFFFF)
#define PKCS11_UNDEFINED_ID			PKCS11_UNAVAILABLE_INFORMATION
#define PKCS11_FALSE				false
#define PKCS11_TRUE				true

/*
 * Note on PKCS#11 TA commands ABI
 *
 * For evolution of the TA API and to not mess with the GPD TEE 4 parameters
 * constraint, all the PKCS11 TA invocation commands use a subset of available
 * the GPD TEE invocation parameter types.
 *
 * Param#0 is used for the so-called control arguments of the invoked command
 * and for providing a PKCS#11 compliant status code for the request command.
 * Param#0 is an in/out memory reference (aka memref[0]). The input buffer
 * stores serialized arguments for the command. The output buffer store the
 * 32bit TA return code for the command. As a consequence, param#0 shall
 * always be an input/output memory reference of at least 32bit, more if
 * the command expects more input arguments.
 *
 * When the TA returns with TEE_SUCCESS result, client shall always get the
 * 32bit value stored in param#0 output buffer and use the value as TA
 * return code for the invoked command.
 *
 * Param#1 can be used for input data arguments of the invoked command.
 * It is unused or is a input memory reference, aka memref[1].
 * Evolution of the API may use memref[1] for output data as well.
 *
 * Param#2 is mostly used for output data arguments of the invoked command
 * and for output handles generated from invoked commands.
 * Few commands uses it for a secondary input data buffer argument.
 * It is unused or is a input/output/in-out memory reference, aka memref[2].
 *
 * Param#3 is currently unused and reserved for evolution of the API.
 */

enum pkcs11_ta_cmd {
	/*
	 * PKCS11_CMD_PING		Ack TA presence and return version info
	 *
	 * [in]  memref[0] = 32bit, unused, must be 0
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = [
	 *              32bit version major value,
	 *              32bit version minor value
	 *              32bit version patch value
	 *       ]
	 */
	PKCS11_CMD_PING = 0,

	/*
	 * PKCS11_CMD_SLOT_LIST - Get the table of the valid slot IDs
	 *
	 * [in]  memref[0] = 32bit, unused, must be 0
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = 32bit array slot_ids[slot counts]
	 *
	 * The TA instance may represent several PKCS#11 slots and
	 * associated tokens. This commadn reports the IDs of embedded tokens.
	 * This command relates the PKCS#11 API function C_GetSlotList().
	 */
	PKCS11_CMD_SLOT_LIST = 1,

	/*
	 * PKCS11_CMD_SLOT_INFO - Get cryptoki structured slot information
	 *
	 * [in]	 memref[0] = 32bit slot ID
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = (struct pkcs11_slot_info)info
	 *
	 * The TA instance may represent several PKCS#11 slots/tokens.
	 * This command relates the PKCS#11 API function C_GetSlotInfo().
	 */
	PKCS11_CMD_SLOT_INFO = 2,

	/*
	 * PKCS11_CMD_TOKEN_INFO - Get cryptoki structured token information
	 *
	 * [in]	 memref[0] = 32bit slot ID
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = (struct pkcs11_token_info)info
	 *
	 * The TA instance may represent several PKCS#11 slots/tokens.
	 * This command relates the PKCS#11 API function C_GetTokenInfo().
	 */
	PKCS11_CMD_TOKEN_INFO = 3,

	/*
	 * PKCS11_CMD_MECHANISM_IDS - Get list of the supported mechanisms
	 *
	 * [in]	 memref[0] = 32bit slot ID
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = 32bit array mechanism IDs
	 *
	 * This command relates to the PKCS#11 API function
	 * C_GetMechanismList().
	 */
	PKCS11_CMD_MECHANISM_IDS = 4,

	/*
	 * PKCS11_CMD_MECHANISM_INFO - Get information on a specific mechanism
	 *
	 * [in]  memref[0] = [
	 *              32bit slot ID,
	 *              32bit mechanism ID (PKCS11_CKM_*)
	 *       ]
	 * [out] memref[0] = 32bit return code, enum pkcs11_rc
	 * [out] memref[2] = (struct pkcs11_mechanism_info)info
	 *
	 * This command relates to the PKCS#11 API function
	 * C_GetMechanismInfo().
	 */
	PKCS11_CMD_MECHANISM_INFO = 5,
};

/*
 * Command return codes
 * PKCS11_<x> relates CryptoKi client API CKR_<x>
 */
enum pkcs11_rc {
	PKCS11_CKR_OK				= 0,
	PKCS11_CKR_CANCEL			= 0x0001,
	PKCS11_CKR_SLOT_ID_INVALID		= 0x0003,
	PKCS11_CKR_GENERAL_ERROR		= 0x0005,
	PKCS11_CKR_FUNCTION_FAILED		= 0x0006,
	PKCS11_CKR_ARGUMENTS_BAD		= 0x0007,
	PKCS11_CKR_ATTRIBUTE_READ_ONLY		= 0x0010,
	PKCS11_CKR_ATTRIBUTE_SENSITIVE		= 0x0011,
	PKCS11_CKR_ATTRIBUTE_TYPE_INVALID	= 0x0012,
	PKCS11_CKR_ATTRIBUTE_VALUE_INVALID	= 0x0013,
	PKCS11_CKR_ACTION_PROHIBITED		= 0x001b,
	PKCS11_CKR_DATA_INVALID			= 0x0020,
	PKCS11_CKR_DATA_LEN_RANGE		= 0x0021,
	PKCS11_CKR_DEVICE_ERROR			= 0x0030,
	PKCS11_CKR_DEVICE_MEMORY		= 0x0031,
	PKCS11_CKR_DEVICE_REMOVED		= 0x0032,
	PKCS11_CKR_ENCRYPTED_DATA_INVALID	= 0x0040,
	PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE	= 0x0041,
	PKCS11_CKR_KEY_HANDLE_INVALID		= 0x0060,
	PKCS11_CKR_KEY_SIZE_RANGE		= 0x0062,
	PKCS11_CKR_KEY_TYPE_INCONSISTENT	= 0x0063,
	PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED	= 0x0068,
	PKCS11_CKR_KEY_NOT_WRAPPABLE		= 0x0069,
	PKCS11_CKR_KEY_UNEXTRACTABLE		= 0x006a,
	PKCS11_CKR_MECHANISM_INVALID		= 0x0070,
	PKCS11_CKR_MECHANISM_PARAM_INVALID	= 0x0071,
	PKCS11_CKR_OBJECT_HANDLE_INVALID	= 0x0082,
	PKCS11_CKR_OPERATION_ACTIVE		= 0x0090,
	PKCS11_CKR_OPERATION_NOT_INITIALIZED	= 0x0091,
	PKCS11_CKR_PIN_INCORRECT		= 0x00a0,
	PKCS11_CKR_PIN_INVALID			= 0x00a1,
	PKCS11_CKR_PIN_LEN_RANGE		= 0x00a2,
	PKCS11_CKR_PIN_EXPIRED			= 0x00a3,
	PKCS11_CKR_PIN_LOCKED			= 0x00a4,
	PKCS11_CKR_SESSION_CLOSED		= 0x00b0,
	PKCS11_CKR_SESSION_COUNT		= 0x00b1,
	PKCS11_CKR_SESSION_HANDLE_INVALID	= 0x00b3,
	PKCS11_CKR_SESSION_READ_ONLY		= 0x00b5,
	PKCS11_CKR_SESSION_EXISTS		= 0x00b6,
	PKCS11_CKR_SESSION_READ_ONLY_EXISTS	= 0x00b7,
	PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS	= 0x00b8,
	PKCS11_CKR_SIGNATURE_INVALID		= 0x00c0,
	PKCS11_CKR_SIGNATURE_LEN_RANGE		= 0x00c1,
	PKCS11_CKR_TEMPLATE_INCOMPLETE		= 0x00d0,
	PKCS11_CKR_TEMPLATE_INCONSISTENT	= 0x00d1,
	PKCS11_CKR_TOKEN_NOT_PRESENT		= 0x00e0,
	PKCS11_CKR_TOKEN_NOT_RECOGNIZED		= 0x00e1,
	PKCS11_CKR_TOKEN_WRITE_PROTECTED	= 0x00e2,
	PKCS11_CKR_USER_ALREADY_LOGGED_IN	= 0x0100,
	PKCS11_CKR_USER_NOT_LOGGED_IN		= 0x0101,
	PKCS11_CKR_USER_PIN_NOT_INITIALIZED	= 0x0102,
	PKCS11_CKR_USER_TYPE_INVALID		= 0x0103,
	PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x0104,
	PKCS11_CKR_USER_TOO_MANY_TYPES		= 0x0105,
	PKCS11_CKR_DOMAIN_PARAMS_INVALID	= 0x0130,
	PKCS11_CKR_CURVE_NOT_SUPPORTED		= 0x0140,
	PKCS11_CKR_BUFFER_TOO_SMALL		= 0x0150,
	PKCS11_CKR_SAVED_STATE_INVALID		= 0x0160,
	PKCS11_CKR_INFORMATION_SENSITIVE	= 0x0170,
	PKCS11_CKR_STATE_UNSAVEABLE		= 0x0180,
	PKCS11_CKR_PIN_TOO_WEAK			= 0x01b8,
	PKCS11_CKR_PUBLIC_KEY_INVALID		= 0x01b9,
	PKCS11_CKR_FUNCTION_REJECTED		= 0x0200,
	/* Vendor specific IDs not returned to client */
	PKCS11_RV_NOT_FOUND			= 0x80000000,
	PKCS11_RV_NOT_IMPLEMENTED		= 0x80000001,
};

/*
 * Arguments for PKCS11_CMD_SLOT_INFO
 */
#define PKCS11_SLOT_DESC_SIZE			64
#define PKCS11_SLOT_MANUFACTURER_SIZE		32
#define PKCS11_SLOT_VERSION_SIZE		2

struct pkcs11_slot_info {
	uint8_t slot_description[PKCS11_SLOT_DESC_SIZE];
	uint8_t manufacturer_id[PKCS11_SLOT_MANUFACTURER_SIZE];
	uint32_t flags;
	uint8_t hardware_version[PKCS11_SLOT_VERSION_SIZE];
	uint8_t firmware_version[PKCS11_SLOT_VERSION_SIZE];
};

/*
 * Values for pkcs11_slot_info::flags.
 * PKCS11_CKFS_<x> reflects CryptoKi client API slot flags CKF_<x>.
 */
#define PKCS11_CKFS_TOKEN_PRESENT		(1U << 0)
#define PKCS11_CKFS_REMOVABLE_DEVICE		(1U << 1)
#define PKCS11_CKFS_HW_SLOT			(1U << 2)

/*
 * Arguments for PKCS11_CMD_TOKEN_INFO
 */
#define PKCS11_TOKEN_LABEL_SIZE			32
#define PKCS11_TOKEN_MANUFACTURER_SIZE		32
#define PKCS11_TOKEN_MODEL_SIZE			16
#define PKCS11_TOKEN_SERIALNUM_SIZE		16

struct pkcs11_token_info {
	uint8_t label[PKCS11_TOKEN_LABEL_SIZE];
	uint8_t manufacturer_id[PKCS11_TOKEN_MANUFACTURER_SIZE];
	uint8_t model[PKCS11_TOKEN_MODEL_SIZE];
	uint8_t serial_number[PKCS11_TOKEN_SERIALNUM_SIZE];
	uint32_t flags;
	uint32_t max_session_count;
	uint32_t session_count;
	uint32_t max_rw_session_count;
	uint32_t rw_session_count;
	uint32_t max_pin_len;
	uint32_t min_pin_len;
	uint32_t total_public_memory;
	uint32_t free_public_memory;
	uint32_t total_private_memory;
	uint32_t free_private_memory;
	uint8_t hardware_version[2];
	uint8_t firmware_version[2];
	uint8_t utc_time[16];
};

/*
 * Values for pkcs11_token_info::flags.
 * PKCS11_CKFT_<x> reflects CryptoKi client API token flags CKF_<x>.
 */
#define PKCS11_CKFT_RNG					(1U << 0)
#define PKCS11_CKFT_WRITE_PROTECTED			(1U << 1)
#define PKCS11_CKFT_LOGIN_REQUIRED			(1U << 2)
#define PKCS11_CKFT_USER_PIN_INITIALIZED		(1U << 3)
#define PKCS11_CKFT_RESTORE_KEY_NOT_NEEDED		(1U << 4)
#define PKCS11_CKFT_CLOCK_ON_TOKEN			(1U << 5)
#define PKCS11_CKFT_PROTECTED_AUTHENTICATION_PATH	(1U << 6)
#define PKCS11_CKFT_DUAL_CRYPTO_OPERATIONS		(1U << 7)
#define PKCS11_CKFT_TOKEN_INITIALIZED			(1U << 8)
#define PKCS11_CKFT_USER_PIN_COUNT_LOW			(1U << 9)
#define PKCS11_CKFT_USER_PIN_FINAL_TRY			(1U << 10)
#define PKCS11_CKFT_USER_PIN_LOCKED			(1U << 11)
#define PKCS11_CKFT_USER_PIN_TO_BE_CHANGED		(1U << 12)
#define PKCS11_CKFT_SO_PIN_COUNT_LOW			(1U << 13)
#define PKCS11_CKFT_SO_PIN_FINAL_TRY			(1U << 14)
#define PKCS11_CKFT_SO_PIN_LOCKED			(1U << 15)
#define PKCS11_CKFT_SO_PIN_TO_BE_CHANGED		(1U << 16)
#define PKCS11_CKFT_ERROR_STATE				(1U << 17)

/*
 * Arguments for PKCS11_CMD_MECHANISM_INFO
 */

struct pkcs11_mechanism_info {
	uint32_t min_key_size;
	uint32_t max_key_size;
	uint32_t flags;
};

/*
 * Values for pkcs11_mechanism_info::flags.
 * PKCS11_CKFM_<x> reflects CryptoKi client API mechanism flags CKF_<x>.
 */
#define PKCS11_CKFM_HW				(1U << 0)
#define PKCS11_CKFM_ENCRYPT			(1U << 8)
#define PKCS11_CKFM_DECRYPT			(1U << 9)
#define PKCS11_CKFM_DIGEST			(1U << 10)
#define PKCS11_CKFM_SIGN			(1U << 11)
#define PKCS11_CKFM_SIGN_RECOVER		(1U << 12)
#define PKCS11_CKFM_VERIFY			(1U << 13)
#define PKCS11_CKFM_VERIFY_RECOVER		(1U << 14)
#define PKCS11_CKFM_GENERATE			(1U << 15)
#define PKCS11_CKFM_GENERATE_KEY_PAIR		(1U << 16)
#define PKCS11_CKFM_WRAP			(1U << 17)
#define PKCS11_CKFM_UNWRAP			(1U << 18)
#define PKCS11_CKFM_DERIVE			(1U << 19)
#define PKCS11_CKFM_EC_F_P			(1U << 20)
#define PKCS11_CKFM_EC_F_2M			(1U << 21)
#define PKCS11_CKFM_EC_ECPARAMETERS		(1U << 22)
#define PKCS11_CKFM_EC_NAMEDCURVE		(1U << 23)
#define PKCS11_CKFM_EC_UNCOMPRESS		(1U << 24)
#define PKCS11_CKFM_EC_COMPRESS			(1U << 25)

/*
 * Valid values for mechanism IDs
 * PKCS11_CKM_<x> reflects CryptoKi client API mechanism IDs CKM_<x>.
 */
enum pkcs11_mechanism_id {
	PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN	= 0x00000,
	PKCS11_CKM_RSA_PKCS			= 0x00001,
	PKCS11_CKM_RSA_9796			= 0x00002,
	PKCS11_CKM_RSA_X_509			= 0x00003,
	PKCS11_CKM_RSA_PKCS_OAEP		= 0x00009,
	PKCS11_CKM_SHA256_RSA_PKCS		= 0x00040,
	PKCS11_CKM_SHA384_RSA_PKCS		= 0x00041,
	PKCS11_CKM_SHA512_RSA_PKCS		= 0x00042,
	PKCS11_CKM_SHA256_RSA_PKCS_PSS		= 0x00043,
	PKCS11_CKM_SHA384_RSA_PKCS_PSS		= 0x00044,
	PKCS11_CKM_SHA512_RSA_PKCS_PSS		= 0x00045,
	PKCS11_CKM_SHA224_RSA_PKCS		= 0x00046,
	PKCS11_CKM_SHA224_RSA_PKCS_PSS		= 0x00047,
	PKCS11_CKM_SHA512_224			= 0x00048,
	PKCS11_CKM_SHA512_224_HMAC		= 0x00049,
	PKCS11_CKM_SHA512_224_HMAC_GENERAL	= 0x0004a,
	PKCS11_CKM_SHA512_224_KEY_DERIVATION	= 0x0004b,
	PKCS11_CKM_SHA512_256			= 0x0004c,
	PKCS11_CKM_SHA512_256_HMAC		= 0x0004d,
	PKCS11_CKM_SHA512_256_HMAC_GENERAL	= 0x0004e,
	PKCS11_CKM_SHA512_256_KEY_DERIVATION	= 0x0004f,
	PKCS11_CKM_DES3_ECB			= 0x00132,
	PKCS11_CKM_DES3_CBC			= 0x00133,
	PKCS11_CKM_DES3_MAC			= 0x00134,
	PKCS11_CKM_DES3_MAC_GENERAL		= 0x00135,
	PKCS11_CKM_DES3_CBC_PAD			= 0x00136,
	PKCS11_CKM_DES3_CMAC_GENERAL		= 0x00137,
	PKCS11_CKM_DES3_CMAC			= 0x00138,
	PKCS11_CKM_MD5				= 0x00210,
	PKCS11_CKM_MD5_HMAC			= 0x00211,
	PKCS11_CKM_MD5_HMAC_GENERAL		= 0x00212,
	PKCS11_CKM_SHA_1			= 0x00220,
	PKCS11_CKM_SHA_1_HMAC			= 0x00221,
	PKCS11_CKM_SHA_1_HMAC_GENERAL		= 0x00222,
	PKCS11_CKM_SHA256			= 0x00250,
	PKCS11_CKM_SHA256_HMAC			= 0x00251,
	PKCS11_CKM_SHA256_HMAC_GENERAL		= 0x00252,
	PKCS11_CKM_SHA224			= 0x00255,
	PKCS11_CKM_SHA224_HMAC			= 0x00256,
	PKCS11_CKM_SHA224_HMAC_GENERAL		= 0x00257,
	PKCS11_CKM_SHA384			= 0x00260,
	PKCS11_CKM_SHA384_HMAC			= 0x00261,
	PKCS11_CKM_SHA384_HMAC_GENERAL		= 0x00262,
	PKCS11_CKM_SHA512			= 0x00270,
	PKCS11_CKM_SHA512_HMAC			= 0x00271,
	PKCS11_CKM_SHA512_HMAC_GENERAL		= 0x00272,
	PKCS11_CKM_HOTP_KEY_GEN			= 0x00290,
	PKCS11_CKM_HOTP				= 0x00291,
	PKCS11_CKM_GENERIC_SECRET_KEY_GEN	= 0x00350,
	PKCS11_CKM_MD5_KEY_DERIVATION		= 0x00390,
	PKCS11_CKM_MD2_KEY_DERIVATION		= 0x00391,
	PKCS11_CKM_SHA1_KEY_DERIVATION		= 0x00392,
	PKCS11_CKM_SHA256_KEY_DERIVATION	= 0x00393,
	PKCS11_CKM_SHA384_KEY_DERIVATION	= 0x00394,
	PKCS11_CKM_SHA512_KEY_DERIVATION	= 0x00395,
	PKCS11_CKM_SHA224_KEY_DERIVATION	= 0x00396,
	PKCS11_CKM_EC_KEY_PAIR_GEN		= 0x01040,
	PKCS11_CKM_ECDSA			= 0x01041,
	PKCS11_CKM_ECDSA_SHA1			= 0x01042,
	PKCS11_CKM_ECDSA_SHA224			= 0x01043,
	PKCS11_CKM_ECDSA_SHA256			= 0x01044,
	PKCS11_CKM_ECDSA_SHA384			= 0x01045,
	PKCS11_CKM_ECDSA_SHA512			= 0x01046,
	PKCS11_CKM_ECDH1_DERIVE			= 0x01050,
	PKCS11_CKM_ECDH1_COFACTOR_DERIVE	= 0x01051,
	PKCS11_CKM_ECMQV_DERIVE			= 0x01052,
	PKCS11_CKM_ECDH_AES_KEY_WRAP		= 0x01053,
	PKCS11_CKM_RSA_AES_KEY_WRAP		= 0x01054,
	PKCS11_CKM_AES_KEY_GEN			= 0x01080,
	PKCS11_CKM_AES_ECB			= 0x01081,
	PKCS11_CKM_AES_CBC			= 0x01082,
	PKCS11_CKM_AES_MAC			= 0x01083,
	PKCS11_CKM_AES_MAC_GENERAL		= 0x01084,
	PKCS11_CKM_AES_CBC_PAD			= 0x01085,
	PKCS11_CKM_AES_CTR			= 0x01086,
	PKCS11_CKM_AES_GCM			= 0x01087,
	PKCS11_CKM_AES_CCM			= 0x01088,
	PKCS11_CKM_AES_CTS			= 0x01089,
	PKCS11_CKM_AES_CMAC			= 0x0108a,
	PKCS11_CKM_AES_CMAC_GENERAL		= 0x0108b,
	PKCS11_CKM_AES_XCBC_MAC			= 0x0108c,
	PKCS11_CKM_AES_XCBC_MAC_96		= 0x0108d,
	PKCS11_CKM_AES_GMAC			= 0x0108e,
	PKCS11_CKM_DES3_ECB_ENCRYPT_DATA	= 0x01102,
	PKCS11_CKM_DES3_CBC_ENCRYPT_DATA	= 0x01103,
	PKCS11_CKM_AES_ECB_ENCRYPT_DATA		= 0x01104,
	PKCS11_CKM_AES_CBC_ENCRYPT_DATA		= 0x01105,
	PKCS11_CKM_AES_KEY_WRAP			= 0x02109,
	PKCS11_CKM_AES_KEY_WRAP_PAD		= 0x0210a,
};
#endif /*PKCS11_TA_H*/
