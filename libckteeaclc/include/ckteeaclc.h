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
#include <uuid/uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CKTEEACLC_NO_GROUP ((gid_t)0xFFFFFFFFFFFFFFFF)
#define KERNEL_NAMESPACE "58ac9ca0-2086-4683-a1b8-ec4bc08e01b6"

/**
 * TEE Client UUID name space identifier in Linux kernel.
 *
 * Remember to call ckteeaclc_lib_init before use.
 */
extern uuid_t kernel_namespace_uuid;
/*
 * making kernel_namespace_uuid const would probably require initializing with
 * a magic byte array. The non const version can be initialized with
 * `uuid_parse`.
 */

/**
 * ckteeaclc_lib_init() - Initialize the ckteeaclc library.
 * Must be called before use.
 */
int ckteeaclc_lib_init(void);

/*
 * len UUID = 36 characters
 *
 * Prefixes:
 *   public
 *   user:
 *   group:
 *
 * + '\0' character totals 43, roundup.
 */

/**
 * Required length for UUID char buffers
 */
#define CKTEEACLC_L_UUID 48

/**
 * ckteeaclc_try_resolve_group - Try to resolve gid_t for a given `group_name`.
 *
 * @param gid_out Ptr to gid result. After the call the value will be either
 * - Group id or
 * - CKTEEACLC_NO_GROUP
 * @param group_name Name of group to resolve.
 * @return Zero on success, errno otherwise.
 */
int ckteeaclc_try_resolve_group(gid_t *gid_out, const char *group_name);

/**
 * ckteeaclc_group_acl_uuid() - Encode a group login ACL string to the
 * provided uuid_buf
 *
 * @param uuid_buf A buffer of length CKTEEACLC_L_UUID.
 * @param group Group id to encode for login.
 * @return 0 on success, otherwise a negative number is returned in case of failure.
 */
int ckteeaclc_group_acl_uuid(char uuid_buf[CKTEEACLC_L_UUID], gid_t group);

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
