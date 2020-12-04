/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEECPP_GROUPLOGINCRYPTOKI_HPP
#define CKTEECPP_GROUPLOGINCRYPTOKI_HPP

#include <ckteecpp/GroupLoginPKCS11Session.hpp>
#include <ckteecpp/BadLoginGroupArgument.hpp>
#include <ckteecpp/Cryptoki.hpp>
#include <ckteeaclc.h>
#include <ckteec_extensions.h>

#include <cinttypes>

namespace cktee {

/**
 * @brief Initialize the Cryptoki library for group based login.
 */
class GroupLoginCryptoki : public Cryptoki {
public:
	explicit GroupLoginCryptoki(gid_t loginGroup) : GroupLoginCryptoki{loginGroup, nullptr} {}

	explicit GroupLoginCryptoki(gid_t loginGroup, CK_RV &finalizeRv) :
	GroupLoginCryptoki{loginGroup, &finalizeRv} {}

	~GroupLoginCryptoki()
	{
		store_rv(C_Finalize(nullptr));
	}

	/**
	 * Open a session to slot number slot_id.
	 *
	 * @param slot_id slot number
	 * @return PKCS11Session object
	 */
	GroupLoginPKCS11Session openSession(CK_SLOT_ID slot_id)
	{
		return GroupLoginPKCS11Session(slot_id);
	}

	/**
	 * Open a session to slot number slot_id.
	 *
	 * @param slot_id slot number
	 * @param closeSessionRv where to store C_CloseSession return value.
	 * @return PKCS11Session object
	 */
	GroupLoginPKCS11Session openSession(CK_SLOT_ID slot_id, CK_RV &closeSessionRv)
	{
		return GroupLoginPKCS11Session(slot_id, closeSessionRv);
	}

private:
	GroupLoginCryptoki(gid_t loginGroup, CK_RV *finalizeRv) : Cryptoki{finalizeRv}
	{
		char username[L_cuserid] = { 0 };

		switch (ckteeaclc_current_user_is_member_of(loginGroup)) {
			case NOT_MEMBER:
				cuserid(username);
				throw BadLoginGroupArgument(username, loginGroup);
				break;
			case IS_MEMBER:
				if (ckteec_invoke_init_login_group(loginGroup) != CKR_OK)
					throw std::runtime_error("Failed to initialize Cryptoki");
				break;
			default:
				throw std::runtime_error("Error in checking group membership");
				break;
		}
	}
};

} // namespace cktee

#endif //CKTEECPP_GROUPLOGINCRYPTOKI_HPP
