/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEECPP_PKCS11SESSION_HPP
#define CKTEECPP_PKCS11SESSION_HPP

#include <ckteecpp/CkteeCall.hpp>

namespace cktee {

/**
 * @brief Open and close a session for a given token.
 */
class PKCS11Session : protected CkteeCall {
public:
	PKCS11Session(const PKCS11Session&) = delete;
	virtual CK_SESSION_HANDLE getHandle() const = 0;
	// make virtual to prevent mix-up
protected:
	explicit PKCS11Session(CK_SLOT_ID slot_id) :
		PKCS11Session{slot_id, nullptr} {}

	PKCS11Session(CK_SLOT_ID slot_id, CK_RV &closeSessionRv) :
		PKCS11Session{slot_id, &closeSessionRv} {}

	PKCS11Session(PKCS11Session &&right) noexcept :
		CkteeCall{nullptr}, m_session{0}, moved{false}
	{
		*this = std::move(right);
	}
	PKCS11Session& operator=(PKCS11Session &&right) noexcept
	{
		m_dest_rv = right.m_dest_rv;
		m_session = right.m_session;
		moved = false;
		right.moved = true;
		return *this;
	}

	~PKCS11Session()
	{
		if (!moved)
			store_rv(C_CloseSession(m_session));
	}

	PKCS11Session(CK_SLOT_ID slot_id, CK_RV *closeSessionRv) :
		CkteeCall{closeSessionRv}, m_session{0}, moved{false}
	{
		CK_RV rv = C_OpenSession(slot_id, (CKF_SERIAL_SESSION | CKF_RW_SESSION),
					 nullptr, nullptr, &m_session);
		if (rv != CKR_OK)
			throw std::runtime_error("Failed to open PKCS11 Session");
	}
	CK_SESSION_HANDLE m_session{};

	/**
	 * Set when this object has been moved.
	 */
	bool moved{};
};

} // namespace cktee

#endif //CKTEECPP_PKCS11SESSION_HPP
