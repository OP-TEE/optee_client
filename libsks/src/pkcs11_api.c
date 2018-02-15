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
	/* Note: no SANITY_LIB_INIT here */
	(void)ppFunctionList;
	return CKR_FUNCTION_NOT_SUPPORTED;
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
