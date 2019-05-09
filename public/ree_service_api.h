#ifndef __REE_SERVICE_H__
#define __REE_SERVICE_H__

/*
 * Attributes for struct tee_ioctl_param, selects field in the union
 */
#define TEE_PARAM_ATTR_TYPE_NONE		0	/* parameter not used */

/*
 * These defines value parameters (struct tee_ioctl_param_value)
 */
#define TEE_PARAM_ATTR_TYPE_VALUE_INPUT	1
#define TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT	2
#define TEE_PARAM_ATTR_TYPE_VALUE_INOUT	3	/* input and output */

/*
 * These defines shared memory reference parameters (struct
 * tee_ioctl_param_memref)
 */
#define TEE_PARAM_ATTR_TYPE_MEMREF_INPUT	5
#define TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT	6
#define TEE_PARAM_ATTR_TYPE_MEMREF_INOUT	7	/* input and output */
struct tee_param_memref {
	void *buffer;
	uint64_t size;
};

struct tee_param_value {
	uint64_t a;
	uint64_t b;
	uint64_t c;
};

struct tee_params {
	uint64_t attr;
	union {
		struct tee_param_memref memref;
		struct tee_param_value value;
	} u;
};

TEEC_Result uuid_to_str(REEC_UUID *uuid, char *uuid_str, size_t size);
TEEC_Result ree_service_init(REEC_UUID *uuid, void **service);
void ree_service_exit(void *service);
TEEC_Result ree_rcv_params(void *service, size_t *num_params,
					struct tee_params *params);
TEEC_Result ree_snd_params(void *service, size_t num_params,
				struct tee_params *params, int32_t error);

/*
 * Define protocol for messages with .cmd == OPTEE_MSG_RPC_CMD_GENERIC
 */

/*
 * Open REE Service
 *
 * [in]     param[0].u.value.a  OPTEE_MRC_GENERIC_OPEN
 * [in]     param[0].u.value.b  TA instance id
 * [out]    param[1].u.value.c  service handle
 */
#define OPTEE_MRC_GENERIC_SERVICE_START		3

/*
 * Close REE Service
 *
 * [in]     param[0].u.value.a  OPTEE_MRC_GENERIC_CLOSE
 * [in]     param[0].u.value.b  TA instance id
 */
#define OPTEE_MRC_GENERIC_SERVICE_STOP		4

/* mtype for message queue message exchange */
#define OPTEE_MRC_MSG_SEND		1 /* send params to service */
#define OPTEE_MRC_MSG_RCV		2 /* receive params from service */


#endif
