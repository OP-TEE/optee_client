/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#ifndef __REE_SERVICE_H__
#define __REE_SERVICE_H__

#include <inttypes.h>
#include <tee_client_api.h>

/*
 * Attributes for struct tee_ioctl_param, selects field in the union
 */
#define TEE_PARAM_ATTR_TYPE_NONE		0 /* parameter not used */

/*
 * These defines value parameters (struct tee_ioctl_param_value)
 */
#define TEE_PARAM_ATTR_TYPE_VALUE_INPUT		1
#define TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT	2
#define TEE_PARAM_ATTR_TYPE_VALUE_INOUT		3 /* input and output */

/*
 * These defines shared memory reference parameters (struct
 * tee_ioctl_param_memref)
 */
#define TEE_PARAM_ATTR_TYPE_MEMREF_INPUT	5
#define TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT	6
#define TEE_PARAM_ATTR_TYPE_MEMREF_INOUT	7 /* input and output */

/*
 * struct tee_param_memref
 * @buffer: pointer to buffer (contains data based on type (IN/OUT/INOUT)
 * @size  : size of @buffer
 */
struct tee_param_memref {
	void *buffer;
	uint64_t size;
};

/*
 * struct tee_param_value
 */
struct tee_param_value {
	uint64_t a;
	uint64_t b;
	uint64_t c;
};

/*
 * struct tee_params
 * @attr  : MEMREF/INPUT type. It decides what to use from union
 * @memref: See struct tee_param_memref
 * @vaue  : See struct tee_param_value
 */
struct tee_params {
	uint64_t attr;
	union {
		struct tee_param_memref memref;
		struct tee_param_value value;
	} u;
};

TEEC_Result uuid_to_str(TEEC_UUID *uuid, char *uuid_str, size_t size);

TEEC_Result ree_service_init(TEEC_UUID *uuid, void **service);
void ree_service_exit(void *service);

TEEC_Result ree_service_rcv(void *service, size_t *num_params,
					struct tee_params *params);
TEEC_Result ree_service_snd(void *service, size_t num_params,
				struct tee_params *params, int32_t error);

/*
 * Start REE Service
 *
 * [in]     param[0].u.value.a  OPTEE_MRC_REE_SERVICE_START
 */
#define OPTEE_MRC_REE_SERVICE_START		0xFFFFFFF2

/*
 * Stop REE Service
 *
 * [in]     param[0].u.value.a  OPTEE_MRC_REE_SERVICE_STOP
 */
#define OPTEE_MRC_REE_SERVICE_STOP		0xFFFFFFF3

/*
 * mtype for message queue message exchange. Internal defines for
 * service handling.
 */
#define OPTEE_MRC_MSG_SEND		1 /* send params to service */
#define OPTEE_MRC_MSG_RCV		2 /* receive params from service */

#endif
