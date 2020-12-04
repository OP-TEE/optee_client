/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEECPP_BADLOGINGROUPARGUMENT_HPP
#define CKTEECPP_BADLOGINGROUPARGUMENT_HPP

#include <stdexcept>
#include <string>
#include <sstream>

namespace cktee {

/**
 * @brief User was not member of specified group
 */
class BadLoginGroupArgument : std::runtime_error {
public:
	BadLoginGroupArgument(std::string username, gid_t group) :
		std::runtime_error(errStr(username, group)) {}
private:
	std::string errStr(std::string username, gid_t group)
	{
		std::stringstream ss;
		ss << "User " << username << " is not a member of group " << group;
		return ss.str();
	}
};

} // namespace cktee

#endif //CKTEECPP_BADLOGINGROUPARGUMENT_HPP
