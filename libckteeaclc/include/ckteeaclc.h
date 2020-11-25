/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

/*
 * Definitions for configuring and using Access Control List (ACL)
 * authentication on PKCS#11 tokens provided by OP-TEE PKCS11
 * Trusted Application (TA).
 */

#ifndef CKTEEACLC_H
#define CKTEEACLC_H

#include <grp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CKTEEACLC_NO_GROUP ((gid_t)0xFFFFFFFFFFFFFFFF)

/**
 * The possible return values of the *_user_is_member_of functions.
 */
enum rv_groupmember {
	NOT_MEMBER,
	IS_MEMBER,
	E_MEMORY, /**< Failed to allocate memory. */
	E_GROUPLIST /**< Failed to read group listing. */
};

/**
 * ckteeaclc_current_user_is_member_of() - Check if the effective user ID of
 * the process is a member in `group`.
 *
 * @param group Group id to check membership of.
 * @return enum rv_groupmember form result.
 */
enum rv_groupmember ckteeaclc_current_user_is_member_of(gid_t group);

/**
 * ckteeaclc_user_is_member_of() - Check if `user` is a member in `group`.
 *
 * @param user Username string.
 * @param group Group id to check membership of.
 * @return enum rv_groupmember form result.
 */
enum rv_groupmember ckteeaclc_user_is_member_of(const char *user, gid_t group);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* CKTEEACLC_H */
