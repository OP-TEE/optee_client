// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <pkcs11.h>
#include <stddef.h>

static const CK_FUNCTION_LIST libckteec_function_list = {
	.version = {
		.major = CK_PKCS11_VERSION_MAJOR,
		.minor = CK_PKCS11_VERSION_MINOR,
	},
	.C_Initialize = C_Initialize,
	.C_Finalize = C_Finalize,
	.C_GetFunctionList = C_GetFunctionList,
};

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	/* Argument currently unused as per the PKCS#11 specification */
	(void)pInitArgs;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	/* Argument currently unused as per the PKCS#11 specification */
	(void)pReserved;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	(void)pInfo;

	return CKR_FUNCTION_NOT_SUPPORTED;
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
	(void)tokenPresent;
	(void)pSlotList;
	(void)pulCount;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID,
		    CK_SLOT_INFO_PTR pInfo)
{
	(void)slotID;
	(void)pInfo;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
		  CK_UTF8CHAR_PTR pPin,
		  CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pLabel)
{
	(void)slotID;
	(void)pPin;
	(void)ulPinLen;
	(void)pLabel;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID,
		     CK_TOKEN_INFO_PTR pInfo)
{
	(void)slotID;
	(void)pInfo;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount)
{
	(void)slotID;
	(void)pMechanismList;
	(void)pulCount;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR pInfo)
{
	(void)slotID;
	(void)type;
	(void)pInfo;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID,
		    CK_FLAGS flags,
		    CK_VOID_PTR pApplication,
		    CK_NOTIFY Notify,
		    CK_SESSION_HANDLE_PTR phSession)
{
	(void)slotID;
	(void)flags;
	(void)pApplication;
	(void)Notify;
	(void)phSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	(void)slotID;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,
		       CK_SESSION_INFO_PTR pInfo)
{
	(void)hSession;
	(void)pInfo;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession,
		CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen)
{
	(void)hSession;
	(void)pPin;
	(void)ulPinLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
	       CK_UTF8CHAR_PTR pOldPin,
	       CK_ULONG ulOldLen,
	       CK_UTF8CHAR_PTR pNewPin,
	       CK_ULONG ulNewLen)
{
	(void)hSession;
	(void)pOldPin;
	(void)ulOldLen;
	(void)pNewPin;
	(void)ulNewLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession,
	      CK_USER_TYPE userType,
	      CK_UTF8CHAR_PTR pPin,
	      CK_ULONG ulPinLen)

{
	(void)hSession;
	(void)userType;
	(void)pPin;
	(void)ulPinLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG_PTR pulOperationStateLen)
{
	(void)hSession;
	(void)pOperationState;
	(void)pulOperationStateLen;

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

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
		     CK_ATTRIBUTE_PTR pTemplate,
		     CK_ULONG ulCount,
		     CK_OBJECT_HANDLE_PTR phObject)
{
	(void)hSession;
	(void)pTemplate;
	(void)ulCount;
	(void)phObject;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession,
		   CK_OBJECT_HANDLE hObject,
		   CK_ATTRIBUTE_PTR pTemplate,
		   CK_ULONG ulCount,
		   CK_OBJECT_HANDLE_PTR phNewObject)
{
	(void)hSession;
	(void)hObject;
	(void)pTemplate;
	(void)ulCount;
	(void)phNewObject;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
		      CK_OBJECT_HANDLE hObject)
{
	(void)hSession;
	(void)hObject;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession,
		      CK_OBJECT_HANDLE hObject,
		      CK_ULONG_PTR pulSize)
{
	(void)hSession;
	(void)hObject;
	(void)pulSize;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
			  CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG ulCount)
{
	(void)hSession;
	(void)hObject;
	(void)pTemplate;
	(void)ulCount;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
			  CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG ulCount)
{
	(void)hSession;
	(void)hObject;
	(void)pTemplate;
	(void)ulCount;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
			CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount)
{
	(void)hSession;
	(void)pTemplate;
	(void)ulCount;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
		    CK_OBJECT_HANDLE_PTR phObject,
		    CK_ULONG ulMaxObjectCount,
		    CK_ULONG_PTR pulObjectCount)

{
	(void)hSession;
	(void)phObject;
	(void)ulMaxObjectCount;
	(void)pulObjectCount;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pEncryptedData;
	(void)pulEncryptedDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pPart,
		      CK_ULONG ulPartLen,
		      CK_BYTE_PTR pEncryptedData,
		      CK_ULONG_PTR pulEncryptedDataLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	(void)pEncryptedData;
	(void)pulEncryptedDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pLastEncryptedPart,
		     CK_ULONG_PTR pulLastEncryptedPartLen)
{
	(void)hSession;
	(void)pLastEncryptedPart;
	(void)pulLastEncryptedPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	(void)hSession;
	(void)pEncryptedData;
	(void)ulEncryptedDataLen;
	(void)pData;
	(void)pulDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
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

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pLastPart,
		     CK_ULONG_PTR pulLastPartLen)
{
	(void)hSession;
	(void)pLastPart;
	(void)pulLastPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession,
		   CK_MECHANISM_PTR pMechanism)
{
	(void)hSession;
	(void)pMechanism;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen,
	       CK_BYTE_PTR pDigest,
	       CK_ULONG_PTR pulDigestLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pDigest;
	(void)pulDigestLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession,
		  CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pDigest,
		    CK_ULONG_PTR pulDigestLen)
{
	(void)hSession;
	(void)pDigest;
	(void)pulDigestLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession,
		 CK_MECHANISM_PTR pMechanism,
		 CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession,
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

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,
		   CK_BYTE_PTR pPart,
		   CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,
		  CK_BYTE_PTR pSignature,
		  CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession;
	(void)pSignature;
	(void)pulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
			CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

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

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
		   CK_MECHANISM_PTR pMechanism,
		   CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen,
	       CK_BYTE_PTR pSignature,
	       CK_ULONG ulSignatureLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)ulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pSignature,
		    CK_ULONG ulSignatureLen)
{
	(void)hSession;
	(void)pSignature;
	(void)ulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism,
			  CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

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

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_ATTRIBUTE_PTR pTemplate,
		    CK_ULONG ulCount,
		    CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)pTemplate;
	(void)ulCount;
	(void)phKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
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
	(void)hSession;
	(void)pMechanism;
	(void)pPublicKeyTemplate;
	(void)ulPublicKeyAttributeCount;
	(void)pPrivateKeyTemplate;
	(void)ulPrivateKeyAttributeCount;
	(void)phPublicKey;
	(void)phPrivateKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
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

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hBaseKey,
		  CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulCount,
		  CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hBaseKey;
	(void)pTemplate;
	(void)ulCount;
	(void)phKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession,
		   CK_BYTE_PTR pSeed,
		   CK_ULONG ulSeedLen)
{
	(void)hSession;
	(void)pSeed;
	(void)ulSeedLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
		       CK_BYTE_PTR pRandomData,
		       CK_ULONG ulRandomLen)
{
	(void)hSession;
	(void)pRandomData;
	(void)ulRandomLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags,
			 CK_SLOT_ID_PTR slotID,
			 CK_VOID_PTR pReserved)
{
	(void)flags;
	(void)slotID;
	(void)pReserved;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
