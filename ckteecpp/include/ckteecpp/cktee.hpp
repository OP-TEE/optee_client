/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEECPP_CKTEE_HPP
#define CKTEECPP_CKTEE_HPP

#include <ckteecpp/BadLoginGroupArgument.hpp>
#include <ckteecpp/CkteeCall.hpp>
#include <ckteecpp/Cryptoki.hpp>
#include <ckteecpp/DefaultCryptoki.hpp>
#include <ckteecpp/DefaultPKCS11Login.hpp>
#include <ckteecpp/DefaultPKCS11Session.hpp>
#include <ckteecpp/GroupLoginCryptoki.hpp>
#include <ckteecpp/GroupLoginPKCS11Session.hpp>
#include <ckteecpp/GroupPKCS11Login.hpp>
#include <ckteecpp/PKCS11Login.hpp>
#include <ckteecpp/PKCS11Session.hpp>

/**
 * @brief A C++ interface for the ckteec PKCS#11 library
 *
 * This namespace provides C++ interfaces for ckteec functions which require
 * a cleanup call after use.
 *
 * The below classes are provided for session and state management:
 * <ul>
 * <li> Cryptoki
 * <li> PKCS11Session
 * <li> PKCS11Login
 * </ul>
 * Two variants of each are provided for PIN based login (Default) and
 * group based login.
 */
namespace cktee {
} // namespace cktee

#endif //CKTEECPP_CKTEE_HPP
