/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEECPP_CRYPTOKI_HPP
#define CKTEECPP_CRYPTOKI_HPP

#include <ckteecpp/CkteeCall.hpp>

#include <pkcs11.h>

namespace cktee {

/**
 * @brief Initializes the Cryptoki library and finalizes after use.
 *
 * The used login method determines the type of arguments required.
 */
class Cryptoki : protected CkteeCall {
public:
	Cryptoki(const Cryptoki&) = delete;
	Cryptoki& operator= (const Cryptoki&) = delete;
protected:
	Cryptoki() = default;
	explicit Cryptoki(CK_RV *dest) : CkteeCall{dest} {}
};

} // namespace cktee

#endif //CKTEECPP_CRYPTOKI_HPP
