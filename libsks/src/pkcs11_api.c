/*
 * Copyright (c) 2017, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <pkcs11.h>
#include "invoke_ta.h"
#include "local_utils.h"

static int inited;

#define SANITY_LIB_INIT	\
	do { \
		if (!inited) \
			return CKR_CRYPTOKI_NOT_INITIALIZED; \
	} while (0)

#define SANITY_NONNULL_PTR(ptr) \
	do { \
		if (!ptr) \
			return CKR_ARGUMENTS_BAD; \
	} while (0)

#define REGISTER_CK_FUNCTION(_function)		._function = _function
#define DO_NOT_REGISTER_CK_FUNCTION(_function)	._function = NULL

static const CK_FUNCTION_LIST libsks_function_list = {
	REGISTER_CK_FUNCTION(C_Initialize),
	REGISTER_CK_FUNCTION(C_Finalize),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetInfo),
	REGISTER_CK_FUNCTION(C_GetFunctionList),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetSlotList),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetSlotInfo),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetTokenInfo),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetMechanismList),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetMechanismInfo),
	DO_NOT_REGISTER_CK_FUNCTION(C_InitToken),
	DO_NOT_REGISTER_CK_FUNCTION(C_InitPIN),
	DO_NOT_REGISTER_CK_FUNCTION(C_SetPIN),
	DO_NOT_REGISTER_CK_FUNCTION(C_OpenSession),
	DO_NOT_REGISTER_CK_FUNCTION(C_CloseSession),
	DO_NOT_REGISTER_CK_FUNCTION(C_CloseAllSessions),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetSessionInfo),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetOperationState),
	DO_NOT_REGISTER_CK_FUNCTION(C_SetOperationState),
	DO_NOT_REGISTER_CK_FUNCTION(C_Login),
	DO_NOT_REGISTER_CK_FUNCTION(C_Logout),
	DO_NOT_REGISTER_CK_FUNCTION(C_CreateObject),
	DO_NOT_REGISTER_CK_FUNCTION(C_CopyObject),
	DO_NOT_REGISTER_CK_FUNCTION(C_DestroyObject),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetObjectSize),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetAttributeValue),
	DO_NOT_REGISTER_CK_FUNCTION(C_SetAttributeValue),
	DO_NOT_REGISTER_CK_FUNCTION(C_FindObjectsInit),
	DO_NOT_REGISTER_CK_FUNCTION(C_FindObjects),
	DO_NOT_REGISTER_CK_FUNCTION(C_FindObjectsFinal),
	DO_NOT_REGISTER_CK_FUNCTION(C_EncryptInit),
	DO_NOT_REGISTER_CK_FUNCTION(C_Encrypt),
	DO_NOT_REGISTER_CK_FUNCTION(C_EncryptUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_EncryptFinal),
	DO_NOT_REGISTER_CK_FUNCTION(C_DecryptInit),
	DO_NOT_REGISTER_CK_FUNCTION(C_Decrypt),
	DO_NOT_REGISTER_CK_FUNCTION(C_DecryptUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_DecryptFinal),
	DO_NOT_REGISTER_CK_FUNCTION(C_DigestInit),
	DO_NOT_REGISTER_CK_FUNCTION(C_Digest),
	DO_NOT_REGISTER_CK_FUNCTION(C_DigestUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_DigestKey),
	DO_NOT_REGISTER_CK_FUNCTION(C_DigestFinal),
	DO_NOT_REGISTER_CK_FUNCTION(C_SignInit),
	DO_NOT_REGISTER_CK_FUNCTION(C_Sign),
	DO_NOT_REGISTER_CK_FUNCTION(C_SignUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_SignFinal),
	DO_NOT_REGISTER_CK_FUNCTION(C_SignRecoverInit),
	DO_NOT_REGISTER_CK_FUNCTION(C_SignRecover),
	DO_NOT_REGISTER_CK_FUNCTION(C_VerifyInit),
	DO_NOT_REGISTER_CK_FUNCTION(C_Verify),
	DO_NOT_REGISTER_CK_FUNCTION(C_VerifyUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_VerifyFinal),
	DO_NOT_REGISTER_CK_FUNCTION(C_VerifyRecoverInit),
	DO_NOT_REGISTER_CK_FUNCTION(C_VerifyRecover),
	DO_NOT_REGISTER_CK_FUNCTION(C_DigestEncryptUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_DecryptDigestUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_SignEncryptUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_DecryptVerifyUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_GenerateKey),
	DO_NOT_REGISTER_CK_FUNCTION(C_GenerateKeyPair),
	DO_NOT_REGISTER_CK_FUNCTION(C_WrapKey),
	DO_NOT_REGISTER_CK_FUNCTION(C_UnwrapKey),
	DO_NOT_REGISTER_CK_FUNCTION(C_DeriveKey),
	DO_NOT_REGISTER_CK_FUNCTION(C_SeedRandom),
	DO_NOT_REGISTER_CK_FUNCTION(C_GenerateRandom),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetFunctionStatus),
	DO_NOT_REGISTER_CK_FUNCTION(C_CancelFunction),
	DO_NOT_REGISTER_CK_FUNCTION(C_WaitForSlotEvent),
};

/*
 * List of all PKCS#11 cryptoki API functions implemented
 */

CK_RV C_Initialize(CK_VOID_PTR init_args)
{
	(void)init_args;
	CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)init_args;

	/* Argument currently unused */
	(void)args;

	if (inited)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	/*
	 * TODO
	 */

	inited = 1;
	return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR res)
{
	(void)res;
	SANITY_LIB_INIT;

	sks_invoke_terminate();
	inited = 0;

	return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR info)
{
	(void)info;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	/* Note: no SANITY_LIB_INIT needed here */
	SANITY_NONNULL_PTR(ppFunctionList);

	/* Discard the const attribute when exporting the list address */
	*ppFunctionList = (void *)&libsks_function_list;

	return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL token_present,
		    CK_SLOT_ID_PTR slots,
		    CK_ULONG_PTR count)
{
	(void)token_present;
	(void)slots;
	(void)count;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slot,
		    CK_SLOT_INFO_PTR info)
{
	(void)slot;
	(void)info;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID slot,
		  CK_UTF8CHAR_PTR pin,
		  CK_ULONG pin_len,
		  CK_UTF8CHAR_PTR label)
{
	(void)slot;
	(void)pin;
	(void)pin_len;
	(void)label;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slot,
		     CK_TOKEN_INFO_PTR info)
{
	(void)slot;
	(void)info;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slot,
			 CK_MECHANISM_TYPE_PTR mechanisms,
			 CK_ULONG_PTR count)
{
	(void)slot;
	(void)mechanisms;
	(void)count;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slot,
			 CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR info)
{
	(void)slot;
	(void)type;
	(void)info;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_OpenSession(CK_SLOT_ID slot,
		    CK_FLAGS flags,
		    CK_VOID_PTR cookie,
		    CK_NOTIFY callback,
		    CK_SESSION_HANDLE_PTR session)
{
	(void)slot;
	(void)flags;
	(void)cookie;
	(void)callback;
	(void)session;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;

}

CK_RV C_CloseSession(CK_SESSION_HANDLE session)
{
	(void)session;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slot)
{
	(void)slot;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE session,
		       CK_SESSION_INFO_PTR info)
{
	(void)session;
	(void)info;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE session,
		CK_UTF8CHAR_PTR pin,
		CK_ULONG pin_len)
{
	(void)session;
	(void)pin;
	(void)pin_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE session,
	       CK_UTF8CHAR_PTR old,
	       CK_ULONG old_len,
	       CK_UTF8CHAR_PTR   new,
	       CK_ULONG new_len)
{
	(void)session;
	(void)old;
	(void)old_len;
	(void)new;
	(void)new_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE session,
	      CK_USER_TYPE user_type,
	      CK_UTF8CHAR_PTR pin,
	      CK_ULONG pin_len)

{
	(void)session;
	(void)user_type;
	(void)pin;
	(void)pin_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Logout(CK_SESSION_HANDLE session)
{
	(void)session;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE session,
			  CK_BYTE_PTR state,
			  CK_ULONG_PTR state_len)
{
	(void)session;
	(void)state;
	(void)state_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE session,
			  CK_BYTE_PTR state,
			  CK_ULONG state_len,
			  CK_OBJECT_HANDLE ciph_key,
			  CK_OBJECT_HANDLE auth_key)
{
	(void)session;
	(void)state;
	(void)state_len;
	(void)ciph_key;
	(void)auth_key;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE session,
		     CK_ATTRIBUTE_PTR attribs,
		     CK_ULONG count,
		     CK_OBJECT_HANDLE_PTR phObject)
{
	(void)session;
	(void)attribs;
	(void)count;
	(void)phObject;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE session,
		   CK_OBJECT_HANDLE obj,
		   CK_ATTRIBUTE_PTR attribs,
		   CK_ULONG count,
		   CK_OBJECT_HANDLE_PTR new_obj)
{
	(void)session;
	(void)obj;
	(void)attribs;
	(void)count;
	(void)new_obj;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE session,
		      CK_OBJECT_HANDLE obj)
{
	(void)session;
	(void)obj;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE session,
		      CK_OBJECT_HANDLE obj,
		      CK_ULONG_PTR out_size)
{
	(void)session;
	(void)obj;
	(void)out_size;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE session,
			  CK_OBJECT_HANDLE obj,
			  CK_ATTRIBUTE_PTR attribs,
			  CK_ULONG count)
{
	(void)session;
	(void)obj;
	(void)attribs;
	(void)count;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE session,
			  CK_OBJECT_HANDLE obj,
			  CK_ATTRIBUTE_PTR attribs,
			  CK_ULONG count)
{
	(void)session;
	(void)obj;
	(void)attribs;
	(void)count;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session,
			CK_ATTRIBUTE_PTR attribs,
			CK_ULONG count)
{
	(void)session;
	(void)attribs;
	(void)count;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE session,
		    CK_OBJECT_HANDLE_PTR obj,
		    CK_ULONG max_count,
		    CK_ULONG_PTR count)

{
	(void)session;
	(void)obj;
	(void)max_count;
	(void)count;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE session)
{
	(void)session;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE session,
		    CK_MECHANISM_PTR mechanism,
		    CK_OBJECT_HANDLE key)
{
	(void)session;
	(void)mechanism;
	(void)key;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE session,
		CK_BYTE_PTR in,
		CK_ULONG in_len,
		CK_BYTE_PTR out,
		CK_ULONG_PTR out_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE session,
		      CK_BYTE_PTR in,
		      CK_ULONG in_len,
		      CK_BYTE_PTR out,
		      CK_ULONG_PTR out_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE session,
		     CK_BYTE_PTR out,
		     CK_ULONG_PTR out_len)
{
	(void)session;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE session,
		    CK_MECHANISM_PTR  mechanism,
		    CK_OBJECT_HANDLE  key)
{
	(void)session;
	(void)mechanism;
	(void)key;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE session,
		CK_BYTE_PTR in,
		CK_ULONG in_len,
		CK_BYTE_PTR out,
		CK_ULONG_PTR out_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE session,
		      CK_BYTE_PTR in,
		      CK_ULONG in_len,
		      CK_BYTE_PTR out,
		      CK_ULONG_PTR out_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE session,
		     CK_BYTE_PTR out,
		     CK_ULONG_PTR out_len)
{
	(void)session;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_DigestInit(CK_SESSION_HANDLE session,
		   CK_MECHANISM_PTR  mechanism)
{
	(void)session;
	(void)mechanism;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE session,
	       CK_BYTE_PTR in,
	       CK_ULONG in_len,
	       CK_BYTE_PTR out,
	       CK_ULONG_PTR out_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE session,
		     CK_BYTE_PTR in,
		     CK_ULONG in_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE session,
		  CK_OBJECT_HANDLE  key)
{
	(void)session;
	(void)key;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE session,
		    CK_BYTE_PTR digest,
		    CK_ULONG_PTR len)
{
	(void)session;
	(void)digest;
	(void)len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignInit(CK_SESSION_HANDLE session,
		 CK_MECHANISM_PTR mechanism,
		 CK_OBJECT_HANDLE key)
{
	(void)session;
	(void)mechanism;
	(void)key;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Sign(CK_SESSION_HANDLE session,
	     CK_BYTE_PTR       in,
	     CK_ULONG          in_len,
	     CK_BYTE_PTR       out,
	     CK_ULONG_PTR      out_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE session,
		   CK_BYTE_PTR in,
		   CK_ULONG in_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE session,
		  CK_BYTE_PTR out,
		  CK_ULONG_PTR out_len)
{
	(void)session;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE session,
			CK_MECHANISM_PTR  mechanism,
			CK_OBJECT_HANDLE  key)
{
	(void)session;
	(void)mechanism;
	(void)key;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE session,
		    CK_BYTE_PTR in,
		    CK_ULONG in_len,
		    CK_BYTE_PTR out,
		    CK_ULONG_PTR out_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE session,
		   CK_MECHANISM_PTR  mechanism,
		   CK_OBJECT_HANDLE  key)
{
	(void)session;
	(void)mechanism;
	(void)key;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE session,
	       CK_BYTE_PTR in,
	       CK_ULONG in_len,
	       CK_BYTE_PTR sign,
	       CK_ULONG sign_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)sign;
	(void)sign_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE session,
		     CK_BYTE_PTR in,
		     CK_ULONG in_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE session,
		    CK_BYTE_PTR sign,
		    CK_ULONG sign_len)
{
	(void)session;
	(void)sign;
	(void)sign_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE session,
			  CK_MECHANISM_PTR mechanism,
			  CK_OBJECT_HANDLE key)
{
	(void)session;
	(void)mechanism;
	(void)key;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE session,
		      CK_BYTE_PTR in,
		      CK_ULONG in_len,
		      CK_BYTE_PTR out,
		      CK_ULONG_PTR out_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE session,
			    CK_BYTE_PTR in,
			    CK_ULONG in_len,
			    CK_BYTE_PTR out,
			    CK_ULONG_PTR out_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE session,
			    CK_BYTE_PTR in,
			    CK_ULONG in_len,
			    CK_BYTE_PTR out,
			    CK_ULONG_PTR out_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE session,
			  CK_BYTE_PTR in,
			  CK_ULONG in_len,
			  CK_BYTE_PTR out,
			  CK_ULONG_PTR out_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE session,
			    CK_BYTE_PTR in,
			    CK_ULONG in_len,
			    CK_BYTE_PTR out,
			    CK_ULONG_PTR out_len)
{
	(void)session;
	(void)in;
	(void)in_len;
	(void)out;
	(void)out_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE session,
		    CK_MECHANISM_PTR mechanism,
		    CK_ATTRIBUTE_PTR attribs,
		    CK_ULONG count,
		    CK_OBJECT_HANDLE_PTR new_key)
{
	(void)session;
	(void)mechanism;
	(void)attribs;
	(void)count;
	(void)new_key;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE session,
			CK_MECHANISM_PTR mechanism,
			CK_ATTRIBUTE_PTR pub_attribs,
			CK_ULONG pub_count,
			CK_ATTRIBUTE_PTR priv_attribs,
			CK_ULONG priv_count,
			CK_OBJECT_HANDLE_PTR pub_key,
			CK_OBJECT_HANDLE_PTR priv_key)
{
	(void)session;
	(void)mechanism;
	(void)pub_attribs;
	(void)pub_count;
	(void)priv_attribs;
	(void)priv_count;
	(void)pub_key;
	(void)priv_key;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE session,
		CK_MECHANISM_PTR  mechanism,
		CK_OBJECT_HANDLE wrap_key,
		CK_OBJECT_HANDLE key,
		CK_BYTE_PTR wrapped_key,
		CK_ULONG_PTR wrapped_key_len)
{
	(void)session;
	(void)mechanism;
	(void)wrap_key;
	(void)key;
	(void)wrapped_key;
	(void)wrapped_key_len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE session,
		  CK_MECHANISM_PTR mechanism,
		  CK_OBJECT_HANDLE unwrap_key,
		  CK_BYTE_PTR wrapped_key,
		  CK_ULONG wrapped_key_len,
		  CK_ATTRIBUTE_PTR attribs,
		  CK_ULONG count,
		  CK_OBJECT_HANDLE_PTR new_key)
{
	(void)session;
	(void)mechanism;
	(void)unwrap_key;
	(void)wrapped_key;
	(void)wrapped_key_len;
	(void)attribs;
	(void)count;
	(void)new_key;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE session,
		  CK_MECHANISM_PTR mechanism,
		  CK_OBJECT_HANDLE derived_key,
		  CK_ATTRIBUTE_PTR attribs,
		  CK_ULONG count,
		  CK_OBJECT_HANDLE_PTR new_key)
{
	(void)session;
	(void)mechanism;
	(void)derived_key;
	(void)attribs;
	(void)count;
	(void)new_key;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE session,
		   CK_BYTE_PTR seed,
		   CK_ULONG len)
{
	(void)session;
	(void)seed;
	(void)len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE session,
		       CK_BYTE_PTR out,
		       CK_ULONG len)
{
	(void)session;
	(void)out;
	(void)len;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE session)
{
	(void)session;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE session)
{
	(void)session;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_WaitForSlotEvent(CK_FLAGS flags,
			 CK_SLOT_ID_PTR slot,
			 CK_VOID_PTR rsv)
{
	(void)flags;
	(void)slot;
	(void)rsv;
	SANITY_LIB_INIT;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
