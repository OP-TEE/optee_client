
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdlib.h>
#include <errno.h>

#include <tee_client_api.h>
#include <teec_trace.h>
#include <ree_service_api.h>

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

struct service {
	int msgqid;
	void *buf;
	size_t buf_sz;
};

static bool is_param_type_value(uint64_t param_type)
{
	if (param_type == TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT ||
			param_type == TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT ||
			param_type == TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT)
		return true;
	return false;
}

static bool is_param_type_memref(uint64_t param_type)
{
	if (param_type == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT ||
			param_type == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT ||
			param_type == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT)
		return true;
	return false;
}

/**
 * uuid_to_str() - convert uuid structure to string
 *
 * Example uuid: 2aa2685c-fba3-44be-a218-fbdafebd639a
 * Convert the structure to the string form as above
 */
TEEC_Result uuid_to_str(REEC_UUID *uuid, char *uuid_str, size_t size)
{
	uint32_t i, idx;

	if (!uuid || !uuid_str)
		return TEEC_ERROR_BAD_PARAMETERS;

	/* Convert to the uuid string */
	snprintf(uuid_str, size, "%08x-", uuid->timeLow);
	idx = strlen(uuid_str);

	snprintf(uuid_str + idx, size - idx, "%04x-", uuid->timeMid);
	idx = strlen(uuid_str);

	snprintf(uuid_str + idx, size - idx,
				"%04x-", uuid->timeHiAndVersion);
	idx = strlen(uuid_str);

	snprintf(uuid_str + idx, size,
				"%02x%02x-", uuid->clockSeqAndNode[0],
				uuid->clockSeqAndNode[1]);
	idx = strlen(uuid_str);

	for (i = 2; i < 8; i++) {
		snprintf(uuid_str + idx, size - idx,
				"%02x", uuid->clockSeqAndNode[i]);
		idx = strlen(uuid_str);
	}

	return TEEC_SUCCESS;
}

TEEC_Result ree_service_init(REEC_UUID *uuid, void **service)
{
	int ret = -1;
	size_t size;
	FILE *fp = NULL;
	char filename[64];
	key_t msgqkey = 0;
	TEEC_Result result;
	char uuid_str[48];

	result = uuid_to_str(uuid, uuid_str, sizeof(uuid_str));
	if (result != TEEC_SUCCESS)
		return result;

	struct service *s = malloc(sizeof(struct service));
	if (!s)
		return -ENOMEM;

	/* Create a file in /data/<uuid> */
	snprintf(filename, sizeof(filename), "/data/%s", uuid_str);
	fp = fopen(filename, "w");
	if (!fp) {
		printf("Failed to create a file for token\n");
		goto err;
	}

	size = fwrite(uuid_str, 1, strlen(uuid_str), fp);
	if (size != strlen(uuid_str)) {
		printf("Failed to write to %s\n", filename);
		result = TEEC_ERROR_GENERIC;
		goto err;
	}

	if (fclose(fp)) {
		printf("Failed to commit data to storage\n");
		result = TEEC_ERROR_GENERIC;
		goto err;
	}

	/* Create a message queue and wait for the msg */
	msgqkey = ftok(filename, 'O');
	if (msgqkey == -1) {
		printf("Failed to create a msg queue key (%d: %s)\n",
							errno, strerror(errno));
		result = TEEC_ERROR_GENERIC;
		goto err;
	}

	s->msgqid = msgget(msgqkey, 0600 | IPC_CREAT);
	if (s->msgqid == -1) {
		printf("Failed to get the msg queue\n");
		result = TEEC_ERROR_GENERIC;
		goto err;
	}

	*service = s;

	return 0;

err:
	if (s)
		free(s);

	return ret;
}

void ree_service_exit(void *service)
{
	struct service *s = service;

	if (!s)
		return;

	if (s->msgqid != -1) {
		if (msgctl(s->msgqid, IPC_RMID, NULL) == -1)
			printf("Failed to delete msgq, try using ipcrm\n");
	}

	if (s->buf)
		free(s->buf);

	free(s);
}

TEEC_Result ree_rcv_params(void *service, size_t *num_params,
					struct tee_params *params)
{
	int ret, idx = 0;
	char *buf = NULL, *ptr;
	struct service *s = service;
	long msg_size[2] = {0};
	size_t size, attr_sz, value_sz, mtype_sz = sizeof(long);

	if (!s || !num_params || !params)
		return TEEC_ERROR_BAD_PARAMETERS;

	attr_sz = sizeof(params->attr);
	value_sz = sizeof(params->u.value);

	/* The first message will tell the size of buffer */
	ret = msgrcv(s->msgqid, &msg_size,
				sizeof(msg_size[1]), OPTEE_MRC_MSG_SEND, 0);
	if (ret == -1) {
		printf("Failed to get the size of buffer\n");
		goto err;
	}
	size = msg_size[1];
	s->buf_sz = size;

	buf = calloc(size, 1);
	if (!buf) {
		printf("Out of memory to receive message\n");
		goto err;
	}

	/* The second message will retrive full contents */
	ret = msgrcv(s->msgqid, buf, size - mtype_sz, OPTEE_MRC_MSG_SEND, 0);
	if (ret == -1) {
		printf("Failed to receive msg\n");
		goto err;
	}

	/* Real params start from here: buf + mtype_sz */
	for (ptr = buf + mtype_sz; ptr < buf + size - sizeof(TEEC_Result);) {

		if (is_param_type_value(*(long *)ptr)) {

			memcpy(&params[idx].attr, ptr, attr_sz);
			ptr += attr_sz;

			memcpy(&params[idx].u.value, ptr, value_sz);
			ptr += value_sz;

		} else if (is_param_type_memref(*(long *)ptr)) {

			memcpy(&params[idx].attr, ptr, attr_sz);
			ptr += attr_sz;

			params[idx].u.memref.size = *(size_t *)ptr;
			params[idx].u.memref.buffer = ptr +
					sizeof(params[idx].u.memref.size);
			ptr = (char *)params[idx].u.memref.buffer +
					params[idx].u.memref.size;
		}
		idx++;
		if (idx == 4)
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

TEEC_Result ree_snd_params(void *service, size_t num_params,
				struct tee_params *params, int32_t error)
{
	struct service *s = service;
	size_t mtype_sz = sizeof(long);

	(void)num_params;
	(void)params;
	(void)error;

	*(TEEC_Result *)((uint8_t *)s->buf + s->buf_sz - sizeof(TEEC_Result)) = error;

	*((long *)s->buf) = OPTEE_MRC_MSG_RCV;
	if (msgsnd(s->msgqid, s->buf, s->buf_sz - mtype_sz, 0) == -1)
		printf("Failed to send the response\n");

	return 0;
}
