// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Vaisala Oyj.
 */

#include <ckteeaclc.h>
#include <stdio.h>
#include <string.h>
#include <uuid.h>

int ckteeaclc_group_acl_uuid(char uuid_buf[CKTEEACLC_L_UUID], gid_t group)
{
	uuid_t g_uuid = { 0 };
	uuid_t k_uuid = { 0 };
	char gid_buf[CKTEEACLC_L_UUID] = { 0 };
	size_t gid_buf_len = 0;
	int rv = snprintf(gid_buf, CKTEEACLC_L_UUID, "gid=%x", group);

	if (rv < 0)
		return rv;
	if (rv >= CKTEEACLC_L_UUID)
		return -1;
	rv = uuid_parse(KERNEL_NAMESPACE, k_uuid);
	if (rv < 0)
		return rv;

	gid_buf_len = strnlen(gid_buf, CKTEEACLC_L_UUID);

	uuid_generate_sha1(g_uuid, k_uuid, gid_buf, gid_buf_len);
	uint len = 6;

	memcpy(uuid_buf, "group:", len);
	uuid_unparse(g_uuid, uuid_buf + len);
	return 0;
}
