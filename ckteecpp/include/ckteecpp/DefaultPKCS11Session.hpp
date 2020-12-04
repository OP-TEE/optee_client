/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEECPP_DEFAULTPKCS11SESSION_HPP
#define CKTEECPP_DEFAULTPKCS11SESSION_HPP

#include <ckteecpp/DefaultCryptoki.hpp>
#include <ckteecpp/PKCS11Session.hpp>

namespace cktee {

class DefaultPKCS11Session : public PKCS11Session {
public:
	CK_SESSION_HANDLE getHandle() const override
	{
		return m_session;
	}
protected:
	explicit DefaultPKCS11Session(CK_SLOT_ID slot_id) : PKCS11Session{slot_id} {}

	DefaultPKCS11Session(CK_SLOT_ID slot_id, CK_RV &closeSessionRv) : PKCS11Session{slot_id, &closeSessionRv} {}

	friend class DefaultCryptoki;
};

} // namespace cktee

#endif //CKTEECPP_DEFAULTPKCS11SESSION_HPP
