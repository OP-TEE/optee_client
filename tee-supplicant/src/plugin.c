// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <dirent.h>
#include <plugin.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include <teec_trace.h>
#include <tee_supplicant.h>

#include "optee_msg_supplicant.h"

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

/* internal possible returned values */
enum plugin_err {
	PLUGIN_OK = 0,
	PLUGIN_DL_OPEN_ERR = -1,
	PLUGIN_DL_SYM_ERR = -2,
};

static struct plugin *plugin_list_head;

/* returns 0, if u1 and u2 are equal */
static int uuid_cmp(TEEC_UUID *u1, TEEC_UUID *u2)
{
	if (!memcmp(u1, u2, sizeof(TEEC_UUID)))
		return 0;

	return 1;
}

static void uuid_from_octets(TEEC_UUID *d, const uint8_t s[TEE_IOCTL_UUID_LEN])
{
	d->timeLow = ((uint32_t)s[0] << 24) | ((uint32_t)s[1] << 16) |
		((uint32_t)s[2] << 8) | s[3];
	d->timeMid = ((uint32_t)s[4] << 8) | s[5];
	d->timeHiAndVersion = ((uint32_t)s[6] << 8) | s[7];
	memcpy(d->clockSeqAndNode, s + 8, sizeof(d->clockSeqAndNode));
}

static void push_plugin(struct plugin *p)
{
	p->next = plugin_list_head;
	plugin_list_head = p;
}

static struct plugin *find_plugin(TEEC_UUID *u)
{
	struct plugin *p = plugin_list_head;

	while (p) {
		if (!uuid_cmp(&p->method->uuid, u))
			return p;

		p = p->next;
	}

	return NULL;
}

static enum plugin_err load_plugin(const char *name, struct plugin *p)
{
	void *handle = NULL;
	struct plugin_method *m = NULL;

	handle = dlopen(name, RTLD_LAZY);
	if (!handle)
		return PLUGIN_DL_OPEN_ERR;

	p->handle = handle;

	m = (struct plugin_method *)dlsym(handle, "plugin_method");
	if (!m || !m->name || !m->invoke)
		return PLUGIN_DL_SYM_ERR;

	p->method = m;

	return PLUGIN_OK;
}

static TEEC_Result plugin_invoke(TEEC_UUID *u, unsigned int cmd,
				 unsigned int sub_cmd, void *data,
				 size_t in_len, size_t *out_len)
{
	struct plugin *p = NULL;

	p = find_plugin(u);
	if (!p)
		return TEEC_ERROR_ITEM_NOT_FOUND;

	assert(p->method->invoke);

	return p->method->invoke(cmd, sub_cmd, data, in_len, out_len);
}

TEEC_Result plugin_load_all(void)
{
	DIR *dir = NULL;
	enum plugin_err res = PLUGIN_OK;
	TEEC_Result teec_res = TEEC_SUCCESS;
	struct dirent *entry = NULL;

	dir = opendir(TEE_PLUGIN_LOAD_PATH);
	if (!dir) {
		IMSG("could not open directory %s", TEE_PLUGIN_LOAD_PATH);

		/* don't generate error if there is no the dir */
		return TEEC_SUCCESS;
	}

	while ((entry = readdir(dir))) {
		if (entry->d_type == DT_REG) {
			struct plugin *p;

			p = calloc(1, sizeof(struct plugin));
			if (!p) {
				EMSG("allocate mem for plugin <%s> failed",
				     entry->d_name);
				closedir(dir);
				return TEEC_ERROR_OUT_OF_MEMORY;
			}

			res = load_plugin((const char *)entry->d_name, p);
			switch (res) {
			case PLUGIN_DL_OPEN_ERR:
				EMSG("open plugin <%s> failed: %s",
				     entry->d_name, dlerror());
				free(p);
				continue;
			case PLUGIN_DL_SYM_ERR:
				EMSG("find 'plugin_method' sym in <%s> failed: %s",
				     entry->d_name, dlerror());
				free(p);
				continue;
			default:
				DMSG("loading the <%s> plugin were successful",
				     p->method->name);
				break;
			}

			/* Init the plugin */
			if (p->method->init) {
				teec_res = p->method->init();
				if (teec_res) {
					EMSG("init the <%s> plugin failed with 0x%x",
					     p->method->name, teec_res);
					free(p);
					continue;
				}
			}

			push_plugin(p);
		}
	}

	closedir(dir);
	return TEEC_SUCCESS;
}

TEEC_Result plugin_process(size_t num_params, struct tee_ioctl_param *params)
{
	unsigned int cmd = 0;
	unsigned int sub_cmd = 0;
	void *data = NULL;
	uint32_t data_len = 0;
	TEEC_UUID uuid = { };
	uint32_t uuid_words[4] = { };
	size_t outlen = 0;
	TEEC_Result res = TEEC_ERROR_NOT_SUPPORTED;

	if (num_params != 4 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
		    TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
		    TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[2].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
		    TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT ||
	    (params[3].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
		    TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	uuid_words[0] = params[0].b;
	uuid_words[1] = params[0].c;
	uuid_words[2] = params[1].a;
	uuid_words[3] = params[1].b;

	uuid_from_octets(&uuid, (const uint8_t *)uuid_words);

	cmd = params[1].c;
	sub_cmd = params[2].a;

	data = tee_supp_param_to_va(params + 3);
	data_len = MEMREF_SIZE(params + 3);

	if (data_len && !data)
		return TEEC_ERROR_BAD_PARAMETERS;

	switch (params[0].a) {
	case OPTEE_INVOKE_PLUGIN:
		res = plugin_invoke(&uuid, cmd, sub_cmd, data, data_len,
				    &outlen);
		params[2].b = outlen;
	default:
		break;
	}

	return res;
}
