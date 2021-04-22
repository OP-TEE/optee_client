/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEECPP_GROUPPKCS11LOGIN_HPP
#define CKTEECPP_GROUPPKCS11LOGIN_HPP

#include <ckteecpp/PKCS11Login.hpp>

#include <string>

namespace cktee {

/**
 * @brief Group based login
 */
class GroupPKCS11Login : public PKCS11Login {
public:
	/**
	 * Try to login as userType user.
	 *
	 * @param pkcs11Session existing PKCS11Session
	 * @param userType usually CK_USER or CKU_SO
	 */
	GroupPKCS11Login(GroupLoginPKCS11Session &pkcs11Session,
			 const CK_USER_TYPE userType) :
		GroupPKCS11Login{pkcs11Session.getHandle(), userType} {}

	/**
	 * Try to login as userType user.
	 *
	 * @param pkcs11Session existing PKCS11Session
	 * @param userType usually CK_USER or CKU_SO
	 * @param logoutRv where to store C_Logout return value.
	 */
	GroupPKCS11Login(GroupLoginPKCS11Session &pkcs11Session,
			 const CK_USER_TYPE userType,
			 CK_RV &logoutRv) :
		GroupPKCS11Login{pkcs11Session.getHandle(), userType, logoutRv} {}

	/**
	 * Try to login as userType user.
	 *
	 * @param sessionHandle existing session
	 * @param userType usually CK_USER or CKU_SO
	 */
	GroupPKCS11Login(const CK_SESSION_HANDLE sessionHandle,
			 const CK_USER_TYPE userType) :
		GroupPKCS11Login{sessionHandle, userType, nullptr} {}

	/**
	 * Try to login as userType user.
	 *
	 * @param sessionHandle existing session
	 * @param userType usually CK_USER or CKU_SO
	 * @param logoutRv where to store C_Logout return value.
	 */
	GroupPKCS11Login(const CK_SESSION_HANDLE sessionHandle,
			 const CK_USER_TYPE userType,
			 CK_RV &logoutRv) :
		GroupPKCS11Login{sessionHandle, userType, &logoutRv}
	{
	}

private:
	GroupPKCS11Login(const CK_SESSION_HANDLE sessionHandle,
			 const CK_USER_TYPE userType,
			 CK_RV *logoutRv) :
		PKCS11Login{userType, sessionHandle, logoutRv}
	{
		CK_UTF8CHAR_PTR pPin = nullptr;
		CK_ULONG pin_len  = 0;
		if (C_Login(m_session, m_userType, pPin, pin_len) != CKR_OK)
			throw std::runtime_error("Failed to login in PKCS11 session");
	}
};

} // namespace cktee

#endif //CKTEECPP_GROUPPKCS11LOGIN_HPP
