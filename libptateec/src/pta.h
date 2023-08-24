/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, Foundries.io Ltd
 */
#ifndef PTATEEC_PTA_H
#define PTATEEC_PTA_H

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <pta_tee.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <teec_trace.h>

struct pta_context {
	pthread_mutex_t lock; /* Serialize session creation/deletion */
	TEEC_Context context;
	TEEC_Session session;
	TEEC_UUID uuid; /* PTA Unique Identifier */
	bool open; /* PTA session state */
	atomic_int count; /* PTA session number of users */
};

/**
 * This set of wrappers aims at protecting PTA access in a multithreaded
 * environment.
 *
 * Each call to the PTA expects balanced open/invoke operations
 *
 * pta_xxxx_foo()
 * {
 *	pta_open_session();
 *	[...]
 *	pta_invoke_cmd();
 *	[...]
 * }
 */

/**
 * pta_open_session() - Opens a session with the PTA uuid in the pta_context.
 * If the session is already open it will increment a session counter.
 *
 * @ctx:	PTA context information.
 *		@ctx->uuid defines the target PTA.
 *
 */
TEEC_Result pta_open_session(struct pta_context *ctx);

/**
 * pta_invoke_cmd() - Invokes a command in the PTA
 *
 * @ctx:		Opened PTA context information.
 * @cmd_id:		Command passed to target PTA.
 * @operation:		TEE operation arguments passed to target PTA.
 * @error_origin:	Output TEE_ORIGIN_* emitter of the result code.
 */
TEEC_Result pta_invoke_cmd(struct pta_context *ctx, uint32_t cmd_id,
			   TEEC_Operation *operation, uint32_t *error_origin);
/**
 * pta_final() - Attempts to close the session with the PTA.
 * The session will not be closed while there are active users.
 *
 * @ctx:	Opened PTA context information.
 */
TEEC_Result pta_final(struct pta_context *ctx);

#endif
