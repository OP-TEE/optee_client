/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEECPP_DEFAULTPKCS11LOGIN_HPP
#define CKTEECPP_DEFAULTPKCS11LOGIN_HPP

#include <ckteecpp/PKCS11Login.hpp>

#include <string>

namespace cktee {

/**
 * @brief Pin based login
 */
class DefaultPKCS11Login : public PKCS11Login {
public:
	/**
	 * Try to login as userType user.
	 *
	 * @param pkcs11Session existing PKCS11Session
	 * @param userType usually CK_USER or CKU_SO
	 * @param loginPin pin code in UTF-8 encoding
	 */
	DefaultPKCS11Login(const DefaultPKCS11Session &pkcs11Session,
			   const CK_USER_TYPE userType,
			   const std::string &loginPin) :
		DefaultPKCS11Login{pkcs11Session.getHandle(), userType,
				   loginPin} {}

	/**
	 * Try to login as userType user.
	 *
	 * @param pkcs11Session existing PKCS11Session
	 * @param userType usually CK_USER or CKU_SO
	 * @param loginPin pin code in UTF-8 encoding
	 * @param logoutRv where to store C_Logout return value.
	 */
	DefaultPKCS11Login(const DefaultPKCS11Session &pkcs11Session,
			   const CK_USER_TYPE userType,
			   const std::string &loginPin,
			   CK_RV &logoutRv) :
		DefaultPKCS11Login{pkcs11Session.getHandle(), userType,
				   loginPin, logoutRv} {}

	/**
	 * Try to login as userType user.
	 *
	 * @param sessionHandle existing session
	 * @param userType usually CK_USER or CKU_SO
	 * @param loginPin pin code in UTF-8 encoding
	 */
	DefaultPKCS11Login(const CK_SESSION_HANDLE sessionHandle,
			   const CK_USER_TYPE userType,
			   const std::string &loginPin) :
		DefaultPKCS11Login{sessionHandle, userType,
				   loginPin, nullptr} {}

	/**
	 * Try to login as userType user.
	 *
	 * @param sessionHandle existing session
	 * @param userType usually CK_USER or CKU_SO
	 * @param loginPin pin code in UTF-8 encoding
	 * @param logoutRv where to store C_Logout return value.
	 */
	DefaultPKCS11Login(const CK_SESSION_HANDLE sessionHandle,
			   const CK_USER_TYPE userType,
			   const std::string &loginPin,
			   CK_RV &logoutRv) :
		DefaultPKCS11Login{sessionHandle, userType,
				   loginPin, &logoutRv} {}

private:
	DefaultPKCS11Login(const CK_SESSION_HANDLE sessionHandle,
			   const CK_USER_TYPE userType,
			   const std::string &loginPin,
			   CK_RV *logoutRv) :
		PKCS11Login{userType, sessionHandle, logoutRv}
	{
		CK_UTF8CHAR_PTR pPin = (CK_UTF8CHAR_PTR) loginPin.c_str();
		CK_ULONG pin_len  = loginPin.size();
		if (C_Login(m_session, m_userType, pPin, pin_len) != CKR_OK)
			throw std::runtime_error("Failed to login in PKCS11 session");
	}
};

} // namespace cktee

#endif //CKTEECPP_DEFAULTPKCS11LOGIN_HPP
