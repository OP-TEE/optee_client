// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Vaisala Oyj.
 */

#include <teeacl.h>

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static long teeacl_getgr_r_size_max(void)
{
	long s = sysconf(_SC_GETGR_R_SIZE_MAX);

	if (s == -1)
		return 1024;
	return s;
};

int teeacl_gid_from_name(gid_t *gid_out, const char *group_name)
{
	struct group grp = { 0 };
	char *buffer = NULL;
	struct group *result = NULL;
	size_t b_size = 0;
	int rv = 0;

	b_size = teeacl_getgr_r_size_max();
	buffer = calloc(1, b_size);
	if (!buffer)
		return -ENOMEM;

	rv = getgrnam_r(group_name, &grp, buffer, b_size, &result);

	free(buffer);
	if (!result) {
		if (rv == 0)
			return -ENOENT;
		else
			return rv;
	} else {
		*gid_out = grp.gr_gid;
		return 0;
	}
}

enum rv_groupmember teeacl_current_user_is_member_of(gid_t group)
{
	char username[L_cuserid] = { 0 };

	cuserid(username);
	return teeacl_user_is_member_of(username, group);
}

enum rv_groupmember teeacl_user_is_member_of(const char *user, gid_t group)
{
	enum rv_groupmember result = E_MEMORY;
	int ret = 0;
	int i = 0;
	int grouplistsize = 8; /* initial guess */
	gid_t *p_groups = NULL;
	gid_t *groups = calloc(grouplistsize, sizeof(gid_t));

	if (!groups)
		return E_MEMORY;
	ret = getgrouplist(user, group, groups, &grouplistsize);

	if (ret == -1) {
		p_groups = groups;

		/* we use realloc, since uClibc does not implement reallocarray */
		groups = realloc(groups, grouplistsize * sizeof(gid_t));
		if (!groups) {
			free(p_groups);
			return E_MEMORY;
		}
		ret = getgrouplist(user, group, groups, &grouplistsize);
		if (ret == -1) {
			result = E_GROUPLIST;
			goto out;
		}
	}

	for (i = 0; i < grouplistsize; ++i) {
		if (group == groups[i]) {
			result = IS_MEMBER;
			goto out;
		}
	}
	result = NOT_MEMBER;
out:
	free(groups);
	return result;
}
