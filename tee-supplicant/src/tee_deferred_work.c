// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <teec_trace.h>
#include <tee_client_api.h>

#include "tee_deferred_work.h"

#define DW_TRIGGER_CNT_ATTEMPTS 100
#define DW_TRIGGER_ATTEMPTS_LATENCY_SEC 1

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define PTA_DEFERRED_WORK_UUID \
	{ 0x77383949, 0x5627, 0x49b0, \
		{ 0xa0, 0x81, 0x1f, 0xd1, 0x2e, 0xff, 0x7c, 0xf0} }

/* TA command ID */
#define DW_PTA_EXEC_ALL_DW 0

static void *dw_poller_thread(void *a)
{
	(void)a;

	int cnt_attempts = 0;
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = PTA_DEFERRED_WORK_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		EMSG("TEEC_InitializeContext failed with code 0x%x", res);
		return NULL;
	}

	/*
	 * FIXME: restrict access to the PTA by the tee-supplicant only.
	 * TEEC_LOGIN_APPLICATION method should be used in future.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		EMSG("TEEC_Opensession failed with code 0x%x origin 0x%x", res,
		     err_origin);
		goto open_ses_err;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	while (true) {
		res = TEEC_InvokeCommand(&sess, DW_PTA_EXEC_ALL_DW, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS) {
			EMSG("Attempts #%d: TEEC_InvokeCommand failed with code=0x%x, orig=0x%x",
			     ++cnt_attempts, res, err_origin);

			if (cnt_attempts >= DW_TRIGGER_CNT_ATTEMPTS) {
				EMSG("Trigger deferred works failed: attempts ended");
				break;
			}
			sleep(DW_TRIGGER_ATTEMPTS_LATENCY_SEC);
		} else {
			IMSG("All deferred works in OP-TEE have been executed");
			break;
		}
	}

	TEEC_CloseSession(&sess);

open_ses_err:
	TEEC_FinalizeContext(&ctx);

	return NULL;
}

int tee_dw_poller_start(void)
{
	int e;
	pthread_t tid;

	memset(&tid, 0, sizeof(tid));

	e = pthread_create(&tid, NULL, dw_poller_thread, NULL);
	if (e) {
		EMSG("pthread_create: %s", strerror(e));
		return -1;
	}

	e = pthread_detach(tid);
	if (e)
		EMSG("pthread_detach: %s", strerror(e));

	return 0;
}
