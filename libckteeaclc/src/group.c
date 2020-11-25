// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Vaisala Oyj.
 */

#include <ckteeaclc.h>

#include <stdio.h>
#include <stdlib.h>

enum rv_groupmember ckteeaclc_current_user_is_member_of(gid_t group)
{
	char username[L_cuserid] = { 0 };

	cuserid(username);
	return ckteeaclc_user_is_member_of(username, group);
}

enum rv_groupmember ckteeaclc_user_is_member_of(const char *username, gid_t group)
{
	enum rv_groupmember result = E_MEMORY;
	int i = 0;
	int grouplistsize = 8; /* initial guess */
	gid_t *groups = (gid_t *)calloc(grouplistsize, sizeof(gid_t));
	int ret = getgrouplist(username, group, groups, &grouplistsize);

	if (ret == -1) {
		gid_t *p_groups = groups;

		if ((groups = reallocarray(groups, grouplistsize, sizeof(gid_t))) == NULL) {
			free(p_groups);
			return E_MEMORY;
		}
		ret = getgrouplist(username, group, groups, &grouplistsize);
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
