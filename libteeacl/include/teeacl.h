/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Vaisala Oyj.
 */

/*
 * Definitions for configuring and using Access Control List (ACL)
 * based login methods.
 */

#ifndef TEEACL_H
#define TEEACL_H

#include <grp.h>
#include <uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

// TEE Client UUID name space identifier (UUIDv4)
// same as `tee_client_uuid_ns` in linux kernel drivers/tee/tee_core.c
#define KERNEL_NAMESPACE "58ac9ca0-2086-4683-a1b8-ec4bc08e01b6"

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
#define TEEACL_L_UUID 48

/**
 * teeacl_gid_from_name - Try to resolve gid_t for a given `group_name`.
 *
 * If a matching group is found, zero is returned and `gid_out` will be set to
 * the found value.
 * If no group is found, -ENOENT is returned.
 * If memory allocation fails, -ENOMEM is returned.
 * For other failures, errno is returned.
 *
 * @param gid_out Ptr to gid result. Will be set to group id if a matching
 * group is found.
 * @param group_name Name of group to resolve.
 * @return 0 if a matching group is found, see detailed description for other
 * cases.
 */
int teeacl_gid_from_name(gid_t *gid_out, const char *group_name);

/**
 * teeacl_group_acl_uuid() - Encode a group login ACL string to the
 * provided uuid_buf
 *
 * @param uuid_buf A buffer of length TEEACL_L_UUID.
 * @param group Group id to encode for login.
 * @return 0 on success, otherwise a negative number is returned in case of failure.
 */
int teeacl_group_acl_uuid(char uuid_buf[TEEACL_L_UUID], gid_t group);
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
 * teeacl_current_user_is_member_of() - Check if the effective user ID of
 * the process is a member in `group`.
 *
 * @param group Group id to check membership of.
 * @return enum rv_groupmember form result.
 */
enum rv_groupmember teeacl_current_user_is_member_of(gid_t group);

/**
 * teeacl_user_is_member_of() - Check if `user` is a member in `group`.
 *
 * @param user Username string.
 * @param group Group id to check membership of.
 * @return enum rv_groupmember form result.
 */
enum rv_groupmember teeacl_user_is_member_of(const char *user, gid_t group);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* TEEACL_H */
