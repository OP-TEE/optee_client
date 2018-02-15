/*
 * Copyright (c) 2017, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __PKCS11_TOKEN_H
#define __PKCS11_TOKEN_H

#include <pkcs11.h>

#include "invoke_ta.h"

int sks_ck_get_info(CK_INFO_PTR info);
CK_RV sks_ck_slot_get_list(CK_BBOOL present,
			   CK_SLOT_ID_PTR slots, CK_ULONG_PTR count);
int sks_ck_slot_get_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info);
CK_RV sks_ck_token_get_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info);

CK_RV sks_ck_token_mechanism_ids(CK_SLOT_ID slot,
				 CK_MECHANISM_TYPE_PTR mechanisms,
				 CK_ULONG_PTR count);

CK_RV sks_ck_token_mechanism_info(CK_SLOT_ID slot,
				  CK_MECHANISM_TYPE type,
				  CK_MECHANISM_INFO_PTR info);

CK_RV sks_ck_init_token(CK_SLOT_ID slot,
			CK_UTF8CHAR_PTR pin,
			CK_ULONG pin_len,
			CK_UTF8CHAR_PTR label);

CK_RV sks_ck_open_session(CK_SLOT_ID slot,
		          CK_FLAGS flags,
		          CK_VOID_PTR cookie,
		          CK_NOTIFY callback,
		          CK_SESSION_HANDLE_PTR session);
CK_RV sks_ck_close_session(CK_SESSION_HANDLE session);
CK_RV sks_ck_close_all_sessions(CK_SLOT_ID slot);
CK_RV sks_ck_get_session_info(CK_SESSION_HANDLE session,
			      CK_SESSION_INFO_PTR info);

#endif /*__PKCS11_TOKEN_H*/
