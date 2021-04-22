/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEECPP_GROUPLOGINPKCS11SESSION_HPP
#define CKTEECPP_GROUPLOGINPKCS11SESSION_HPP

#include <ckteecpp/PKCS11Session.hpp>

namespace cktee {

class GroupLoginPKCS11Session : public PKCS11Session {
public:
	CK_SESSION_HANDLE getHandle() const override
	{
		return m_session;
	}
protected:
	explicit GroupLoginPKCS11Session(CK_SLOT_ID slot_id) : PKCS11Session{slot_id} {}

	GroupLoginPKCS11Session(CK_SLOT_ID slot_id, CK_RV &closeSessionRv) : PKCS11Session{slot_id, &closeSessionRv} {}

	friend class GroupLoginCryptoki;
};

} // namespace cktee

#endif //CKTEECPP_GROUPLOGINPKCS11SESSION_HPP
