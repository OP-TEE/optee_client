/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEECPP_PKCS11LOGIN_HPP
#define CKTEECPP_PKCS11LOGIN_HPP

#include <ckteecpp/CkteeCall.hpp>

namespace cktee {

/**
 * @brief Log in as a user and logout after use.
 *
 * The used login method determines the type of arguments required.
 */
class PKCS11Login : protected CkteeCall {
public:
	PKCS11Login(const PKCS11Login&) = delete;
	PKCS11Login& operator= (const PKCS11Login&) = delete;
protected:
	PKCS11Login(const CK_SESSION_HANDLE sessionHandle, const CK_USER_TYPE userType) :
		m_session{sessionHandle}, m_userType{userType} {}
	PKCS11Login(CK_USER_TYPE userType, CK_SESSION_HANDLE sessionHandle, CK_RV *logoutRv) :
		CkteeCall{logoutRv}, m_session{sessionHandle}, m_userType{userType} {}

	~PKCS11Login()
	{
		store_rv(C_Logout(m_session));
	}

	const CK_SESSION_HANDLE m_session;
	const CK_USER_TYPE m_userType;
};

} // namespace cktee

#endif //CKTEECPP_PKCS11LOGIN_HPP
