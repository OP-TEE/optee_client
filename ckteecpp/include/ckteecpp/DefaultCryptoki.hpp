/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEECPP_DEFAULTCRYPTOKI_HPP
#define CKTEECPP_DEFAULTCRYPTOKI_HPP

#include <ckteecpp/Cryptoki.hpp>
#include <ckteecpp/DefaultPKCS11Session.hpp>

namespace cktee {

/**
 * @brief Initialize the Cryptoki library for the standard PIN code based login.
 */
class DefaultCryptoki : public Cryptoki {
public:
	DefaultCryptoki() : DefaultCryptoki{nullptr} {}

	explicit DefaultCryptoki(CK_RV &finalizeRv) : DefaultCryptoki{&finalizeRv} {}

	~DefaultCryptoki()
	{
		store_rv(C_Finalize(nullptr));
	}

	/**
	 * Open a session to slot number slot_id.
	 *
	 * @param slot_id slot number
	 * @return PKCS11Session object
	 */
	DefaultPKCS11Session openSession(CK_SLOT_ID slot_id)
	{
		return std::move(DefaultPKCS11Session(slot_id));
	}

	/**
	 * Open a session to slot number slot_id.
	 *
	 * @param slot_id slot number
	 * @param closeSessionRv where to store C_CloseSession return value.
	 * @return PKCS11Session object
	 */
	DefaultPKCS11Session openSession(CK_SLOT_ID slot_id, CK_RV &closeSessionRv)
	{
		return DefaultPKCS11Session(slot_id, closeSessionRv);
	}

private:
	explicit DefaultCryptoki(CK_RV *dest) : Cryptoki{dest}
	{
		if (C_Initialize(nullptr) != CKR_OK)
			throw std::runtime_error("Failed to initialize Cryptoki");
	}
};

} // namespace cktee

#endif //CKTEECPP_DEFAULTCRYPTOKI_HPP
