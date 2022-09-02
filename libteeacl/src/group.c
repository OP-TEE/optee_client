// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Vaisala Oyj.
 */

#include <teeacl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

		groups = reallocarray(groups, grouplistsize, sizeof(gid_t));
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
