/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#ifndef PLUGIN_H
#define PLUGIN_H

#include <stdint.h>
#include <tee_client_api.h>
#include <tee_plugin_method.h>

struct tee_ioctl_param;

/* This structure describes one plugin for the supplicant */
struct plugin {
	void *handle;
	struct plugin_method *method; /* Implemented in the plugin */
	struct plugin *next;
};

/*
 * Loads all shared objects from 'CFG_TEE_PLUGIN_LOAD_PATH'
 * and binds all functions.
 *
 * @return 'TEEC_SUCCESS' if all plugins were successfully loaded.
 */
TEEC_Result plugin_load_all(void);

/* Plugin RPC handler */
TEEC_Result plugin_process(size_t num_params, struct tee_ioctl_param *params);

#endif /* PLUGIN_H */

