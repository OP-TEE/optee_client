/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdlib.h>

#include <ree_service_api.h>
#include <teec_trace.h>
#include <tee_client_api.h>

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

/*
 * Internal structure to represent Message Queue Service.
 * struct msgq_service
 * @msgqid: Message Queue received from system
 * @buf   : Buffer associated with service
 * @buf_sz: Size of @buf
 */
struct msgq_service {
	int msgqid;
	void *buf;
	size_t buf_sz;
};

/**
 * param_type_is_value() - returns true if param type is value
 */
static bool param_type_is_value(uint64_t param_type)
{
	switch(param_type) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
		return true;
	default:
		return false;
	}
}

/**
 * param_type_is_memref() - returns true if param type is memory reference
 */
static bool param_type_is_memref(uint64_t param_type)
{
	switch (param_type) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
		return true;
	default:
		return false;
	}
}

/**
 * uuid_to_str() - convert uuid structure to string
 *
 * Example uuid: 2aa2685c-fba3-44be-a218-fbdafebd639a
 * Convert the structure to the string form as above
 */
TEEC_Result uuid_to_str(TEEC_UUID *uuid, char *uuid_str, size_t size)
{
	uint32_t idx;

	if (!uuid || !uuid_str || !size)
		return TEEC_ERROR_BAD_PARAMETERS;

	/* Convert to the uuid string */
	snprintf(uuid_str, size, "%08x-%04x-%04x-",
		uuid->timeLow, uuid->timeMid, uuid->timeHiAndVersion);
	idx = strlen(uuid_str);
	snprintf(uuid_str + idx, size - idx,
		"%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid->clockSeqAndNode[0], uuid->clockSeqAndNode[1],
		uuid->clockSeqAndNode[2], uuid->clockSeqAndNode[3],
		uuid->clockSeqAndNode[4], uuid->clockSeqAndNode[5],
		uuid->clockSeqAndNode[6], uuid->clockSeqAndNode[7]);

	return TEEC_SUCCESS;
}

/**
 * ree_service_init() - Initiliaze the Message Queue service
 * A Client Application(CA) which wants to service TEE requests
 * within its context, can use this API. This API internally
 * creates a Message Queue which will listen for data coming
 * from tee-supplicant.
 *
 * Return Value:
 *  fills in a service handle to uniquely identify this service
 *  returns TEE_SUCCESS on success, else TEEC_ERROR_<Code>
 */
TEEC_Result ree_service_init(TEEC_UUID *uuid, void **service_hdl)
{
	char filename[64];
	char uuid_str[48];
	FILE *fp = NULL;
	key_t msgqkey = 0;
	size_t size;
	struct msgq_service *s = NULL;
	TEEC_Result result;

	/* Convert UUID structure to string as given by uuidgen */
	result = uuid_to_str(uuid, uuid_str, sizeof(uuid_str));
	if (result != TEEC_SUCCESS)
		goto err;

	/*
	 * Allocate the service context. This will uniquely identify
	 * this service context
	 */
	s = malloc(sizeof(struct msgq_service));
	if (!s) {
		result = TEEC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/* Set the error code for next file operations */
	result = TEEC_ERROR_ACCESS_DENIED;

	/*
	 * Create a file in /data/<uuid>. tee-supplicant must be having
	 * access to /data folder, otherwise, servicing by REE will fail
	 */
	snprintf(filename, sizeof(filename), "/data/%s", uuid_str);
	fp = fopen(filename, "w");
	if (!fp) {
		EMSG("Failed to create a file for token");
		goto err;
	}

	/* Write the same uuid to the file */
	size = fwrite(uuid_str, 1, strlen(uuid_str), fp);
	if (size != strlen(uuid_str)) {
		EMSG("Failed to write to %s", filename);
		goto err;
	}

	/* Flush out the data to filesystem */
	if (fclose(fp)) {
		EMSG("Failed to commit data to storage");
		goto err;
	}
	fp = NULL;

	/* Create a message queue and wait for the msg */
	msgqkey = ftok(filename, 'O');
	if (msgqkey == -1) {
		EMSG("Failed to create a msg queue key (%d: %s)",
							errno, strerror(errno));
		goto err;
	}

	s->msgqid = msgget(msgqkey, 0600 | IPC_CREAT);
	if (s->msgqid == -1) {
		EMSG("Failed to get the msg queue");
		goto err;
	}

	*service_hdl = s;
	result = TEEC_SUCCESS; /* All good, mark as success */

err:
	if (fp)
		fclose(fp);
	if (s && result != TEEC_SUCCESS)
		free(s);
	return result;
}

/**
 * ree_service_exit() - release the service context
 * Cleanup the Posix Message Queue from the system
 */
void ree_service_exit(void *service_hdl)
{
	struct msgq_service *s = service_hdl;

	if (!s)
		return;

	if (s->msgqid != -1) {
		if (msgctl(s->msgqid, IPC_RMID, NULL) == -1)
			EMSG("Failed to delete msgq, try using ipcrm");
	}

	free(s->buf);
	free(s);
}


/**
 * ree_service_rcv() - receive the parameters sent by UTA
 */
TEEC_Result ree_service_rcv(void *service_hdl, size_t *num_params,
					struct tee_params *params)
{
	char *buf = NULL;
	int idx = 0;
	char *ptr;
	int ret;
	long msg_size[2] = {0};
	size_t attr_sz;
	size_t mtype_sz = sizeof(long);
	size_t size;
	size_t value_sz;
	struct msgq_service *s = service_hdl;

	if (!s || !num_params || !params)
		return TEEC_ERROR_BAD_PARAMETERS;

	attr_sz = sizeof(params->attr);
	value_sz = sizeof(params->u.value);

	/* The first message will tell the size of buffer */
	ret = msgrcv(s->msgqid, &msg_size,
				sizeof(msg_size[1]), OPTEE_MRC_MSG_SEND, 0);
	if (ret == -1) {
		EMSG("Failed to get the size of buffer");
		goto err;
	}
	size = msg_size[1];
	s->buf_sz = size;

	buf = calloc(size, 1);
	if (!buf) {
		EMSG("Out of memory to receive message");
		goto err;
	}

	/* The second message will retrive full contents */
	ret = msgrcv(s->msgqid, buf, size - mtype_sz, OPTEE_MRC_MSG_SEND, 0);
	if (ret == -1) {
		EMSG("Failed to receive msg");
		goto err;
	}

	/* Real params start from here: buf + mtype_sz */
	for (ptr = buf + mtype_sz; ptr < buf + size - sizeof(TEEC_Result);) {

		if (param_type_is_value(*(long *)ptr)) {

			memcpy(&params[idx].attr, ptr, attr_sz);
			ptr += attr_sz;

			memcpy(&params[idx].u.value, ptr, value_sz);
			ptr += value_sz;

		} else if (param_type_is_memref(*(long *)ptr)) {

			memcpy(&params[idx].attr, ptr, attr_sz);
			ptr += attr_sz;

			params[idx].u.memref.size = *(size_t *)ptr;
			params[idx].u.memref.buffer = ptr +
					sizeof(params[idx].u.memref.size);
			ptr = (char *)params[idx].u.memref.buffer +
					params[idx].u.memref.size;
		}
		idx++;
		if (idx == TEEC_CONFIG_PAYLOAD_REF_COUNT)
			break;
	}

	s->buf = buf;
	*num_params = idx;
	return 0;

err:
	if (buf)
		free(buf);
	return TEEC_ERROR_GENERIC;
}

/**
 * ree_service_snd() - send the response back to UTA
 */
TEEC_Result ree_service_snd(void *service_hdl, size_t num_params,
				struct tee_params *params, int32_t error)
{
	struct msgq_service *s = service_hdl;
	size_t mtype_sz = sizeof(long);

	(void)num_params;
	(void)params;
	(void)error;

	*(TEEC_Result *)((uint8_t *)s->buf
			+ s->buf_sz - sizeof(TEEC_Result)) = error;

	*((long *)s->buf) = OPTEE_MRC_MSG_RCV;
	if (msgsnd(s->msgqid, s->buf, s->buf_sz - mtype_sz, 0) == -1)
		EMSG("Failed to send the response");

	free(s->buf);
	s->buf = NULL;

	return 0;
}
