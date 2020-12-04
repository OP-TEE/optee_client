/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEECPP_CKTEECALL_HPP
#define CKTEECPP_CKTEECALL_HPP

#include <pkcs11.h>

namespace cktee {

/**
 * Utility class to report back CK_RV values in destructor calls.
 *
 * if CK_RV reference is provided, store_rv will store it
 */
class CkteeCall {
protected:
	CkteeCall() : m_dest_rv(nullptr) {}
	explicit CkteeCall(CK_RV *dest) : m_dest_rv{dest} {}

	CK_RV *m_dest_rv;

	void store_rv(CK_RV rv)
	{
		if (m_dest_rv)
			*m_dest_rv = rv;
	}
};

} // namespace cktee

#endif //CKTEECPP_CKTEECALL_HPP
