// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Vaisala Oyj.
 */

#include <ckteeaclc.h>
#include <stdio.h>
#include <string.h>

uuid_t kernel_namespace_uuid;

int ckteeaclc_lib_init(void)
{
	return uuid_parse(KERNEL_NAMESPACE, kernel_namespace_uuid);
}

int ckteeaclc_group_acl_uuid(char uuid_buf[CKTEEACLC_L_UUID], gid_t group)
{
	char gid_buf[CKTEEACLC_L_UUID];
	int rv = snprintf(gid_buf, CKTEEACLC_L_UUID, "gid=%x", group);

	if (rv < 0)
		return rv;
	if (rv >= CKTEEACLC_L_UUID)
		return -1;

	uuid_t g_uuid = { 0 };
	size_t gid_buf_len = strnlen(gid_buf, CKTEEACLC_L_UUID);

	uuid_generate_sha1(g_uuid, kernel_namespace_uuid, gid_buf, gid_buf_len);
	uint len = 6;

	memcpy(uuid_buf, "group:", len);
	uuid_unparse(g_uuid, uuid_buf + len);
	return 0;
}
