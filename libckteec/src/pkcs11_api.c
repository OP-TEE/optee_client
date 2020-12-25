// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <pkcs11.h>
#include <stdbool.h>
#include <stddef.h>

#include "ck_helpers.h"
#include "invoke_ta.h"
#include "pkcs11_processing.h"
#include "pkcs11_token.h"

static const CK_FUNCTION_LIST libckteec_function_list = {
	.version = {
		.major = CK_PKCS11_VERSION_MAJOR,
		.minor = CK_PKCS11_VERSION_MINOR,
	},
	.C_Initialize = C_Initialize,
	.C_Finalize = C_Finalize,
	.C_GetInfo = C_GetInfo,
	.C_GetFunctionList = C_GetFunctionList,
	.C_GetSlotList = C_GetSlotList,
	.C_GetSlotInfo = C_GetSlotInfo,
	.C_GetTokenInfo = C_GetTokenInfo,
	.C_GetMechanismList = C_GetMechanismList,
	.C_GetMechanismInfo = C_GetMechanismInfo,
	.C_InitToken = C_InitToken,
	.C_InitPIN = C_InitPIN,
	.C_SetPIN = C_SetPIN,
	.C_OpenSession = C_OpenSession,
	.C_CloseSession = C_CloseSession,
	.C_CloseAllSessions = C_CloseAllSessions,
	.C_GetSessionInfo = C_GetSessionInfo,
	.C_GetOperationState = C_GetOperationState,
	.C_SetOperationState = C_SetOperationState,
	.C_Login = C_Login,
	.C_Logout = C_Logout,
	.C_CreateObject = C_CreateObject,
	.C_CopyObject = C_CopyObject,
	.C_DestroyObject = C_DestroyObject,
	.C_GetObjectSize = C_GetObjectSize,
	.C_GetAttributeValue = C_GetAttributeValue,
	.C_SetAttributeValue = C_SetAttributeValue,
	.C_FindObjectsInit = C_FindObjectsInit,
	.C_FindObjects = C_FindObjects,
	.C_FindObjectsFinal = C_FindObjectsFinal,
	.C_EncryptInit = C_EncryptInit,
	.C_Encrypt = C_Encrypt,
	.C_EncryptUpdate = C_EncryptUpdate,
	.C_EncryptFinal = C_EncryptFinal,
	.C_DecryptInit = C_DecryptInit,
	.C_Decrypt = C_Decrypt,
	.C_DecryptUpdate = C_DecryptUpdate,
	.C_DecryptFinal = C_DecryptFinal,
	.C_DigestInit = C_DigestInit,
	.C_Digest = C_Digest,
	.C_DigestUpdate = C_DigestUpdate,
	.C_DigestKey = C_DigestKey,
	.C_DigestFinal = C_DigestFinal,
	.C_SignInit = C_SignInit,
	.C_Sign = C_Sign,
	.C_SignUpdate = C_SignUpdate,
	.C_SignFinal = C_SignFinal,
	.C_SignRecoverInit = C_SignRecoverInit,
	.C_SignRecover = C_SignRecover,
	.C_VerifyInit = C_VerifyInit,
	.C_Verify = C_Verify,
	.C_VerifyUpdate = C_VerifyUpdate,
	.C_VerifyFinal = C_VerifyFinal,
	.C_VerifyRecoverInit = C_VerifyRecoverInit,
	.C_VerifyRecover = C_VerifyRecover,
	.C_DigestEncryptUpdate = C_DigestEncryptUpdate,
	.C_DecryptDigestUpdate = C_DecryptDigestUpdate,
	.C_SignEncryptUpdate = C_SignEncryptUpdate,
	.C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
	.C_GenerateKey = C_GenerateKey,
	.C_GenerateKeyPair = C_GenerateKeyPair,
	.C_WrapKey = C_WrapKey,
	.C_UnwrapKey = C_UnwrapKey,
	.C_DeriveKey = C_DeriveKey,
	.C_SeedRandom = C_SeedRandom,
	.C_GenerateRandom = C_GenerateRandom,
	.C_GetFunctionStatus = C_GetFunctionStatus,
	.C_CancelFunction = C_CancelFunction,
	.C_WaitForSlotEvent = C_WaitForSlotEvent,
};

static bool lib_initiated(void)
{
	return ckteec_invoke_initiated();
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_C_INITIALIZE_ARGS_PTR args = NULL;
	CK_RV rv = 0;

	if (pInitArgs) {
		args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

		/* Reserved must be set to NULL in this version of PKCS#11 */
		if (args->reserved)
			return CKR_ARGUMENTS_BAD;
	}

	rv = ckteec_invoke_init();

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CANT_LOCK,
		     CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_NEED_TO_CREATE_THREADS, CKR_OK,
		     CKR_MUTEX_BAD);

	return rv;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	CK_RV rv = 0;

	/* Reserved must be set to NULL in this version of PKCS#11 */
	if (pReserved)
		return CKR_ARGUMENTS_BAD;

	rv = ckteec_invoke_terminate();

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OK);

	return rv;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_get_info(pInfo);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OK);

	return rv;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (!ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	/* Discard the const attribute when exporting the list address */
	*ppFunctionList = (void *)&libckteec_function_list;

	return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
		    CK_SLOT_ID_PTR pSlotList,
		    CK_ULONG_PTR pulCount)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_slot_get_list(tokenPresent, pSlotList, pulCount);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK);

	return rv;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID,
		    CK_SLOT_INFO_PTR pInfo)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_slot_get_info(slotID, pInfo);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR,
		     CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID);

	return rv;
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
		  CK_UTF8CHAR_PTR pPin,
		  CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pLabel)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_init_token(slotID, pPin, ulPinLen, pLabel);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SESSION_EXISTS,
		     CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT,
		     CKR_TOKEN_NOT_RECOGNIZED, CKR_TOKEN_WRITE_PROTECTED);

	return rv;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID,
		     CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_token_get_info(slotID, pInfo);

	ASSERT_CK_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT,
		     CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD);

	return rv;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_token_mechanism_ids(slotID, pMechanismList, pulCount);

	ASSERT_CK_RV(rv, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT,
		     CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD);

	return rv;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_token_mechanism_info(slotID, type, pInfo);

	ASSERT_CK_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID,
		     CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT,
		     CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD);

	return rv;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID,
		    CK_FLAGS flags,
		    CK_VOID_PTR pApplication,
		    CK_NOTIFY Notify,
		    CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_open_session(slotID, flags, pApplication, Notify,
				     phSession);

	ASSERT_CK_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_SESSION_COUNT, CKR_SESSION_PARALLEL_NOT_SUPPORTED,
		     CKR_SESSION_READ_WRITE_SO_EXISTS, CKR_SLOT_ID_INVALID,
		     CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED,
		     CKR_TOKEN_WRITE_PROTECTED, CKR_ARGUMENTS_BAD);

	return rv;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_close_session(hSession);

	ASSERT_CK_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_close_all_sessions(slotID);

	ASSERT_CK_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT);

	return rv;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,
		       CK_SESSION_INFO_PTR pInfo)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_get_session_info(hSession, pInfo);

	ASSERT_CK_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID,
		     CKR_ARGUMENTS_BAD);

	return rv;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession,
		CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_init_pin(hSession, pPin, ulPinLen);

	ASSERT_CK_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_PIN_INVALID, CKR_PIN_LEN_RANGE, CKR_SESSION_CLOSED,
		     CKR_SESSION_READ_ONLY, CKR_SESSION_HANDLE_INVALID,
		     CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN,
		     CKR_ARGUMENTS_BAD);

	return rv;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
	       CK_UTF8CHAR_PTR pOldPin,
	       CK_ULONG ulOldLen,
	       CK_UTF8CHAR_PTR pNewPin,
	       CK_ULONG ulNewLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_set_pin(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);

	ASSERT_CK_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OK, CKR_PIN_INCORRECT, CKR_PIN_INVALID,
		     CKR_PIN_LEN_RANGE, CKR_PIN_LOCKED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY,
		     CKR_TOKEN_WRITE_PROTECTED, CKR_ARGUMENTS_BAD);

	return rv;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession,
	      CK_USER_TYPE userType,
	      CK_UTF8CHAR_PTR pPin,
	      CK_ULONG ulPinLen)

{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_login(hSession, userType, pPin, ulPinLen);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_PIN_INCORRECT,
		     CKR_PIN_LOCKED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY_EXISTS,
		     CKR_USER_ALREADY_LOGGED_IN,
		     CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
		     CKR_USER_PIN_NOT_INITIALIZED, CKR_USER_TOO_MANY_TYPES,
		     CKR_USER_TYPE_INVALID);

	return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_logout(hSession);

	ASSERT_CK_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID,
		     CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG_PTR pulOperationStateLen)
{
	(void)hSession;
	(void)pOperationState;
	(void)pulOperationStateLen;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG ulOperationStateLen,
			  CK_OBJECT_HANDLE hEncryptionKey,
			  CK_OBJECT_HANDLE hAuthenticationKey)
{
	(void)hSession;
	(void)pOperationState;
	(void)ulOperationStateLen;
	(void)hEncryptionKey;
	(void)hAuthenticationKey;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
		     CK_ATTRIBUTE_PTR pTemplate,
		     CK_ULONG ulCount,
		     CK_OBJECT_HANDLE_PTR phObject)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_create_object(hSession, pTemplate, ulCount, phObject);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY,
		     CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_DOMAIN_PARAMS_INVALID, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OK, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY,
		     CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT,
		     CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession,
		   CK_OBJECT_HANDLE hObject,
		   CK_ATTRIBUTE_PTR pTemplate,
		   CK_ULONG ulCount,
		   CK_OBJECT_HANDLE_PTR phNewObject)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_copy_object(hSession, hObject, pTemplate, ulCount,
				    phNewObject);

	ASSERT_CK_RV(rv, CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD,
		     CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID,
		     CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_PIN_EXPIRED,
		     CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID,
		     CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCONSISTENT,
		     CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
		      CK_OBJECT_HANDLE hObject)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_destroy_object(hSession, hObject);

	ASSERT_CK_RV(rv, CKR_ACTION_PROHIBITED, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_PIN_EXPIRED,
		     CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID,
		     CKR_SESSION_READ_ONLY, CKR_TOKEN_WRITE_PROTECTED);

	return rv;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession,
		      CK_OBJECT_HANDLE hObject,
		      CK_ULONG_PTR pulSize)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_get_object_size(hSession, hObject, pulSize);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_INFORMATION_SENSITIVE, CKR_OBJECT_HANDLE_INVALID,
		     CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
			  CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG ulCount)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_get_attribute_value(hSession, hObject, pTemplate, ulCount);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_SENSITIVE,
		     CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
			  CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG ulCount)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_set_attribute_value(hSession, hObject, pTemplate, ulCount);

	ASSERT_CK_RV(rv, CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD,
		     CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID,
		     CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY,
		     CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED,
		     CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
			CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_find_objects_init(hSession, pTemplate, ulCount);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_TYPE_INVALID,
		     CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED,
		     CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
		    CK_OBJECT_HANDLE_PTR phObject,
		    CK_ULONG ulMaxObjectCount,
		    CK_ULONG_PTR pulObjectCount)

{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_find_objects(hSession, phObject,
				     ulMaxObjectCount, pulObjectCount);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_find_objects_final(hSession);

	ASSERT_CK_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_encdecrypt_init(hSession, pMechanism, hKey, CK_FALSE);

	ASSERT_CK_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID,
		     CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT,
		     CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID,
		     CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED,
		     CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID,
		     CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_encdecrypt_oneshot(hSession, pData, ulDataLen,
					   pEncryptedData, pulEncryptedDataLen,
					   CK_FALSE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pPart,
		      CK_ULONG ulPartLen,
		      CK_BYTE_PTR pEncryptedData,
		      CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_encdecrypt_update(hSession, pPart, ulPartLen,
					  pEncryptedData,
					  pulEncryptedDataLen, CK_FALSE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pLastEncryptedPart,
		     CK_ULONG_PTR pulLastEncryptedPartLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_encdecrypt_final(hSession, pLastEncryptedPart,
					 pulLastEncryptedPartLen, CK_FALSE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_encdecrypt_init(hSession, pMechanism, hKey, CK_TRUE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID,
		     CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT,
		     CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID,
		     CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED,
		     CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID,
		     CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_encdecrypt_oneshot(hSession, pEncryptedData,
					   ulEncryptedDataLen,
					   pData, pulDataLen, CK_TRUE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG ulEncryptedPartLen,
		      CK_BYTE_PTR pPart,
		      CK_ULONG_PTR pulPartLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_encdecrypt_update(hSession, pEncryptedPart,
					  ulEncryptedPartLen,
					  pPart, pulPartLen, CK_TRUE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pLastPart,
		     CK_ULONG_PTR pulLastPartLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_encdecrypt_final(hSession, pLastPart, pulLastPartLen,
					 CK_TRUE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession,
		   CK_MECHANISM_PTR pMechanism)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_digest_init(hSession, pMechanism);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID,
		     CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE,
		     CKR_PIN_EXPIRED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen,
	       CK_BYTE_PTR pDigest,
	       CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_digest_oneshot(hSession, pData, ulDataLen, pDigest,
				       pulDigestLen);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_digest_update(hSession, pPart, ulPartLen);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession,
		  CK_OBJECT_HANDLE hKey)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_digest_key(hSession, hKey);

	ASSERT_CK_RV(rv, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_KEY_HANDLE_INVALID, CKR_KEY_INDIGESTIBLE,
		     CKR_KEY_SIZE_RANGE, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pDigest,
		    CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_digest_final(hSession, pDigest, pulDigestLen);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession,
		 CK_MECHANISM_PTR pMechanism,
		 CK_OBJECT_HANDLE hKey)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_signverify_init(hSession, pMechanism, hKey, CK_TRUE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID,
		     CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT,
		     CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID,
		     CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED,
		     CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID,
		     CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession,
	     CK_BYTE_PTR pData,
	     CK_ULONG ulDataLen,
	     CK_BYTE_PTR pSignature,
	     CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_signverify_oneshot(hSession, pData, ulDataLen,
					   pSignature, pulSignatureLen,
					   CK_TRUE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_INVALID,
		     CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY,
		     CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGG_IN,
		     CKR_FUNCTION_REJECTED);

	return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,
		   CK_BYTE_PTR pPart,
		   CK_ULONG ulPartLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_signverify_update(hSession, pPart, ulPartLen, CK_TRUE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY,
		     CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,
		  CK_BYTE_PTR pSignature,
		  CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_signverify_final(hSession, pSignature, pulSignatureLen,
					 CK_TRUE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN,
		     CKR_FUNCTION_REJECTED);

	return rv;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
			CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen,
		    CK_BYTE_PTR pSignature,
		    CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)pulSignatureLen;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
		   CK_MECHANISM_PTR pMechanism,
		   CK_OBJECT_HANDLE hKey)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_signverify_init(hSession, pMechanism, hKey, CK_FALSE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID,
		     CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT,
		     CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID,
		     CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED,
		     CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID,
		     CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen,
	       CK_BYTE_PTR pSignature,
	       CK_ULONG ulSignatureLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	CK_ULONG out_size = ulSignatureLen;

	if (lib_initiated())
		rv = ck_signverify_oneshot(hSession, pData, ulDataLen,
					   pSignature, &out_size,
					   CK_FALSE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR,
		     CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_INVALID,
		     CKR_SIGNATURE_LEN_RANGE);

	return rv;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_signverify_update(hSession, pPart, ulPartLen, CK_FALSE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY,
		     CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID);

	return rv;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pSignature,
		    CK_ULONG ulSignatureLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_signverify_final(hSession, pSignature, &ulSignatureLen,
					 CK_FALSE);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY,
		     CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_INVALID,
		     CKR_SIGNATURE_LEN_RANGE);

	return rv;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism,
			  CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pSignature,
		      CK_ULONG ulSignatureLen,
		      CK_BYTE_PTR pData,
		      CK_ULONG_PTR pulDataLen)
{
	(void)hSession;
	(void)pSignature;
	(void)ulSignatureLen;
	(void)pData;
	(void)pulDataLen;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pPart,
			    CK_ULONG ulPartLen,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG_PTR pulEncryptedPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	(void)pEncryptedPart;
	(void)pulEncryptedPartLen;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen,
			    CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{
	(void)hSession;
	(void)pEncryptedPart;
	(void)ulEncryptedPartLen;
	(void)pPart;
	(void)pulPartLen;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pPart,
			  CK_ULONG ulPartLen,
			  CK_BYTE_PTR pEncryptedPart,
			  CK_ULONG_PTR pulEncryptedPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	(void)pEncryptedPart;
	(void)pulEncryptedPartLen;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen,
			    CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{
	(void)hSession;
	(void)pEncryptedPart;
	(void)ulEncryptedPartLen;
	(void)pPart;
	(void)pulPartLen;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_ATTRIBUTE_PTR pTemplate,
		    CK_ULONG ulCount,
		    CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_generate_key(hSession, pMechanism, pTemplate, ulCount,
				     phKey);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY,
		     CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID,
		     CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE,
		     CKR_PIN_EXPIRED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY,
		     CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT,
		     CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
			CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPublicKeyTemplate,
			CK_ULONG ulPublicKeyAttributeCount,
			CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
			CK_ULONG ulPrivateKeyAttributeCount,
			CK_OBJECT_HANDLE_PTR phPublicKey,
			CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_generate_key_pair(hSession, pMechanism,
					  pPublicKeyTemplate,
					  ulPublicKeyAttributeCount,
					  pPrivateKeyTemplate,
					  ulPrivateKeyAttributeCount,
					  phPublicKey, phPrivateKey);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY,
		     CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_DOMAIN_PARAMS_INVALID, CKR_FUNCTION_CANCELED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID,
		     CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED,
		     CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID,
		     CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCOMPLETE,
		     CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED,
		     CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey,
		CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pWrappedKey,
		CK_ULONG_PTR pulWrappedKeyLen)
{
	(void)hSession;
	(void)pMechanism;
	(void)hWrappingKey;
	(void)hKey;
	(void)pWrappedKey;
	(void)pulWrappedKeyLen;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hUnwrappingKey,
		  CK_BYTE_PTR pWrappedKey,
		  CK_ULONG ulWrappedKeyLen,
		  CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulCount,
		  CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hUnwrappingKey;
	(void)pWrappedKey;
	(void)ulWrappedKeyLen;
	(void)pTemplate;
	(void)ulCount;
	(void)phKey;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hBaseKey,
		  CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulCount,
		  CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_derive_key(hSession, pMechanism, hBaseKey, pTemplate,
				   ulCount, phKey);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY,
		     CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID,
		     CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_DOMAIN_PARAMS_INVALID, CKR_FUNCTION_CANCELED,
		     CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
		     CKR_KEY_HANDLE_INVALID, CKR_KEY_SIZE_RANGE,
		     CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID,
		     CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE,
		     CKR_PIN_EXPIRED, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY,
		     CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT,
		     CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN,
		     CKR_DATA_LEN_RANGE);

	return rv;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession,
		   CK_BYTE_PTR pSeed,
		   CK_ULONG ulSeedLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_seed_random(hSession, pSeed, ulSeedLen);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_ACTIVE, CKR_RANDOM_SEED_NOT_SUPPORTED,
		     CKR_RANDOM_NO_RNG, CKR_SESSION_CLOSED,
		     CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
		       CK_BYTE_PTR pRandomData,
		       CK_ULONG ulRandomLen)
{
	CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (lib_initiated())
		rv = ck_generate_random(hSession, pRandomData, ulRandomLen);

	ASSERT_CK_RV(rv, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED,
		     CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
		     CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
		     CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
		     CKR_OPERATION_ACTIVE, CKR_RANDOM_NO_RNG,
		     CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID,
		     CKR_USER_NOT_LOGGED_IN);

	return rv;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags,
			 CK_SLOT_ID_PTR slotID,
			 CK_VOID_PTR pReserved)
{
	(void)flags;
	(void)slotID;
	(void)pReserved;

	if (!lib_initiated())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
