/* FIXME: Copyright */
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <errno.h>
#include <dlfcn.h>

#include <tee_client_api.h>
#include <teec_trace.h>
#include <tee_supplicant.h>
#include <optee_msg_supplicant.h>
#include <ree_service_api.h>

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>
#include <tee_service.h>
#include <tee_service_handle.h>

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
static bool is_param_type_value_out(uint64_t param_type)
{
	if (param_type == TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT ||
			param_type == TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT)
		return true;
	return false;
}

static bool is_param_type_memref_out(uint64_t param_type)
{
	if (param_type == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT ||
			param_type == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT)
		return true;
	return false;
}

/**
 * params_to_buffer() - serialize params before send
 */
static TEEC_Result params_to_buffer(size_t num_params,
				struct tee_ioctl_param *params,
				void **buf, size_t *size)
{
	uint8_t i;
	char *buffer;
	size_t buf_sz = sizeof(long) + sizeof(TEEC_Result), ctr = sizeof(long);
	size_t attr_sz = sizeof(params->attr);
	size_t value_sz = sizeof(params->u.value);

	/* Calculate the total size of parameters */
	for (i = 0; i < num_params; i++) {
		if (tee_supp_param_is_value(&params[i]))
			buf_sz += attr_sz + value_sz;
		else if (tee_supp_param_is_memref(&params[i]))
			buf_sz += attr_sz + sizeof(params[i].u.memref.size) +
							params[i].u.memref.size;
	}

	/*
	 *  Allocate a buffer and fill in the buffer like:
	 *  ------------------------------------------------------
	 * | type                                                 |
	 *  ------------------------------------------------------
	 * | size (in case of memref)                             |
	 *  -----------------------------------------------------
	 * | contents (values, or buffer in case of memref)       |
	 *  -----------------------------------------------------
	 * | All all params, reserve space to receive TEEC_Result |
	 *  ------------------------------------------------------
	 */
	buffer = calloc(buf_sz, 1);
	if (!buffer)
		return TEEC_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < num_params; i++) {
		if (is_param_type_value(params[i].attr)) {
			memcpy(buffer + ctr, &params[i].attr, attr_sz);
			ctr += attr_sz;

			memcpy(buffer + ctr, &params[i].u.value, value_sz);
			ctr += value_sz;
		} else if (tee_supp_param_is_memref(&params[i])) {
			memcpy(buffer + ctr, &params[i].attr, attr_sz);
			ctr += attr_sz;

			memcpy(buffer + ctr, &params[i].u.memref.size,
					sizeof(params[i].u.memref.size));
			ctr += sizeof(params[i].u.memref.size);

			memcpy(buffer + ctr, tee_supp_param_to_va(params + i),
						params[i].u.memref.size);
			ctr += params[i].u.memref.size;
		}
	}

	*buf = buffer;
	*size = buf_sz;
	return TEEC_SUCCESS;
}

static TEEC_Result send_msg(size_t num_params,
			struct tee_ioctl_param *params, int msgqid,
			void **buffer, size_t *sent)
{
	void *buf = NULL;
	size_t size;
	TEEC_Result result;
	long msg_size[2];

	if (params->attr != TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	result = params_to_buffer(num_params, params, &buf, &size);
	if (result != TEEC_SUCCESS)
		return result;


	/* Send the complete message size */
	msg_size[0] = OPTEE_MRC_MSG_SEND;
	msg_size[1] = size;
	if (msgsnd(msgqid, &msg_size, sizeof(msg_size[1]), 0) == -1)  {
		EMSG("Failed to send msg with size: %lu\n", size);
		result = TEEC_ERROR_GENERIC;
		goto err;
	}

	/* Send the complete msg */
	*(long *)buf =  OPTEE_MRC_MSG_SEND;
	if (msgsnd(msgqid, buf, size - sizeof(long), 0) == -1) {
		EMSG("Failed to send msg with size: %lu\n", size);
		result = TEEC_ERROR_GENERIC;
		goto err;
	}

	*buffer = buf;
	*sent = size;

	return TEEC_SUCCESS;

err:
	if (buf)
		free(buf);
	return result;
}

/**
 * fill_param() - deserialize buffer to params
 */
static TEEC_Result fill_param(size_t num_params,
		struct tee_ioctl_param *params,
		void *buf, size_t size)
{
	char *ptr = (char *)buf + sizeof(long);
	size_t attr_sz = sizeof(params->attr);
	size_t value_sz = sizeof(params->u.value);
	size_t idx = 1;
	TEEC_Result err = TEEC_SUCCESS;

	if (!is_param_type_value(*ptr))
		return TEEC_ERROR_BAD_PARAMETERS;

	/* If the command processing results in error, send back the same */
	err = *(TEEC_Result *)((uint8_t *)buf + size - sizeof(TEEC_Result));
	if (err != TEEC_SUCCESS)
		return err;

	ptr += attr_sz + value_sz;

	for (; ptr < (char*)buf + size && idx < num_params;) {
		if (is_param_type_memref_out(*ptr)) {
			ptr += attr_sz + sizeof(params[idx].u.memref.size);
			memcpy(tee_supp_param_to_va(params + idx), ptr,
						params[idx].u.memref.size);
			ptr += params[idx].u.memref.size;
		} else if (is_param_type_value_out(*ptr)) {
			ptr += attr_sz;
			memcpy(&params[idx].u.value, ptr, value_sz);
			ptr += value_sz;
		}
		else if (is_param_type_memref(*ptr) &&
				!is_param_type_memref_out(*ptr)) {
			ptr += attr_sz;
			ptr += (*(uint64_t *)ptr);
		   	ptr += sizeof(params[idx].u.memref.size);
		} else if (is_param_type_value(*ptr) &&
				!is_param_type_value_out(*ptr)) {
			ptr += attr_sz + value_sz;
		}
		idx++;
	}

	return TEEC_SUCCESS;
}

static TEEC_Result rcv_msg(void *buf, size_t size, int msgqid,
			size_t num_params, struct tee_ioctl_param *params)
{
	size_t rcvd;
	TEEC_Result result = TEEC_SUCCESS;

	/* We just need to fill in the OUT params from the buffer */
	rcvd = msgrcv(msgqid, buf, size - sizeof(long), OPTEE_MRC_MSG_RCV, 0);
	if (rcvd == (size_t)-1) {
		EMSG("Failed to retrieve message from ree service (%d, %s)\n",
							errno, strerror(errno));
		result = TEEC_ERROR_GENERIC;
		goto err;
	}

	result = fill_param(num_params, params, buf, size);

err:
	if (buf)
		free(buf);

	return result;
}

static TEEC_Result process_dlib_params(void *dl, size_t num_params,
									struct tee_ioctl_param *params)
{
	size_t i;
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Result (*process_tee_params)(size_t num_params, struct tee_params *params);
	struct tee_params tee_params[4];

	process_tee_params = dlsym(dl, "process_tee_params");
	if (dlerror() != NULL) {
		EMSG("no params handling implementation found");
		res = TEEC_ERROR_NOT_IMPLEMENTED;
		goto err;
	}

	for (i = 0; i < num_params; i++) {
		if (is_param_type_value(params[i].attr) & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
			switch (params[i].attr) {
			case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
				tee_params[i].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
				break;
			case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
				tee_params[i].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT;
				break;
			case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
				tee_params[i].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT;
				break;
			default:
				break;
			}
			memcpy(&tee_params[i].u.value, &params[i].u.value, sizeof(tee_params[i].u.value));
		} else if (is_param_type_memref(params[i].attr)) {
			switch (params[i].attr) {
			case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
				tee_params[i].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
				break;
			case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
				tee_params[i].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
				break;
			case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
				tee_params[i].attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT;
				break;
			default:
				break;
			}
			tee_params[i].u.memref.buffer = tee_supp_param_to_va(params + i);
			tee_params[i].u.memref.size = params[i].u.memref.size;
		}
	}

	res = process_tee_params(num_params, tee_params);
	if (res != TEEC_SUCCESS) {
		EMSG("failed to handle the tee params\n");
		res = TEEC_ERROR_GENERIC;
	}

	/* Fill back all the values */
	for (i = 0; i < num_params; i++) {
		if (is_param_type_value_out(params[i].attr))
			memcpy(&params[i].u.value, &tee_params[i].u.value, sizeof(params[i].u.value));
	}

err:
	return res;
}

static TEEC_Result open_service_msg_queue(struct tee_ioctl_param *params)
{
	key_t msgqkey;
	int msgqid, handle;
	TEEC_Result res = TEEC_SUCCESS;
	char filename[64], uuid_str[48];
	struct service_handle *hdl = NULL;
	uint32_t instance_id = params[0].u.value.b;
	REEC_UUID *uuid = tee_supp_param_to_va(params + 1);

	DMSG("===== OPTEE_MRC_GENERIC_OPEN === \n");

	/* Convert to the uuid string */
	res = uuid_to_str(uuid, uuid_str, sizeof(uuid_str));
	if (res != TEEC_SUCCESS) {
		EMSG("failed to convert UUID to string");
		goto err;
	}

	/* Open the message queue */
	snprintf(filename, sizeof(filename), "/data/%s", uuid_str);
	msgqkey = ftok(filename, 'O');
	if (msgqkey == -1) {
		EMSG("failed to create a msg queue key");
		res = TEEC_ERROR_GENERIC;
		goto err;
	}

	msgqid = msgget(msgqkey, 0600);
	if (msgqid == -1) {
		EMSG("failed to get the msg queue id");
		res = TEEC_ERROR_GENERIC;
		goto err;
	}

	/* Allocate service info */
	hdl = calloc(1, sizeof(struct service_handle));
	if (!hdl) {
		EMSG("out of memory for msgq service info");
		res = TEEC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	hdl->type = MSGQ_HANDLE;
	hdl->u.msgqid = msgqid;

	/* Convert the msgqid to handle */
	handle = service_handle_new(instance_id, hdl);
	if (handle < 0) {
		EMSG("failed to get msgq service handle");
		res = TEEC_ERROR_GENERIC;
		goto err;
	}
	params[2].u.value.a = handle;

	return res;

err:
	if (hdl)
		free(hdl);
	return res;
}

static TEEC_Result open_service_dlib(struct tee_ioctl_param *params)
{
	void *dl_handle;
	TEEC_Result res = TEEC_SUCCESS;
	char libname[64], uuid_str[48];
	struct service_handle *hdl = NULL;
	REEC_UUID *uuid = tee_supp_param_to_va(params + 1);

	printf("========== generic open ======== \n");
	res = uuid_to_str(uuid, uuid_str, sizeof(uuid_str));
	if (res != TEEC_SUCCESS)
		return TEEC_ERROR_GENERIC;

	snprintf(libname, sizeof(libname), "/usr/lib/lib%s.so", uuid_str);
	dl_handle = dlopen(libname, RTLD_LAZY);
	if (!dl_handle) {
		printf("Failed to open %s (%s)\n", libname, dlerror());
		return TEEC_ERROR_GENERIC;
	}

	/* Allocate service info */
	hdl = calloc(1, sizeof(struct service_handle));
	if (!hdl) {
		EMSG("out of memory for dl service info");
		res = TEEC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	hdl->type = DLIB_HANDLE;
	hdl->u.dl = dl_handle;

	/* Get the handle to the service */
	params[2].u.value.a = service_handle_new(params[0].u.value.b, hdl);
	printf("========= generic open done (%p) ========== \n", dl_handle);

err:
	return res;
}

/**
 * tee_service_process() - called from tee-supplicant
 * This functions finds the service for tee based on UUID
 * based on either message queue or dynamic lib.
 * o Message queue is useful when we want to directly pass
 *   some date to CA.
 * o Dynamic library interface is useful when we want some
 *   non-CA specific functionality like network library,
 *   which is likely not relevant for the TA/CA state machine.
 */
TEEC_Result tee_service_process(size_t num_params,
			       struct tee_ioctl_param *params)
{
	uint32_t instance_id = params[0].u.value.b;

	switch (params[0].u.value.a) {
	case OPTEE_MRC_GENERIC_OPEN:
	{
		TEEC_Result res = TEEC_SUCCESS;

		/*
		 * Find if the service is present as message queue
		 * or as a dynamic library.
		 * a. Open the uuid as a message queue in r-x mode.
		 *    It will fail if the message queue is not present.
		 * b. Open the dl with the pre-defined symbols
		 * One of will pass.
		 */
		res = open_service_msg_queue(params);
		if (res != TEEC_SUCCESS)
			res = open_service_dlib(params);

		break;
	}

	case OPTEE_MRC_GENERIC_CLOSE:
	{
		struct service_handle *hdl = NULL;

		DMSG("===== OPTEE_MRC_GENERIC_CLOSE === \n");

		hdl = service_handle_get(instance_id, params->u.value.c);
		if (!hdl) {
			EMSG("unregistered handle, no such handle");
			return TEEC_ERROR_GENERIC;
		}

		if (hdl->type == DLIB_HANDLE)
			dlclose(hdl->u.dl);

		service_handle_put(instance_id, params->u.value.c);
		free(hdl);
		break;
	}

	/*
	 * Anyother command will be handled by the service
	 * mtype = 1 (OPTEE_MRC_SEND) - send params to service
	 * mtype = 2 (OPTEE_MRC_RCV) - receive params from service
	 */
	default:
	{
		TEEC_Result result;
		size_t sent;
		void *buf;
		struct service_handle *hdl = NULL;

		DMSG("===== Routing to service === \n");

		/*
		 * Get the handle from the instance and route to either
		 * message queue or to dynamic lib.
		 */
		hdl = service_handle_get(instance_id, params->u.value.c);
		if (!hdl) {
			EMSG("unregistered handle, no such handle");
			return TEEC_ERROR_GENERIC;
		}

		if (hdl->type == MSGQ_HANDLE) {
			result = send_msg(num_params, params, hdl->u.msgqid, &buf, &sent);
			if (result != TEEC_SUCCESS) {
				EMSG("Failed to send message to the service\n");
				return TEEC_ERROR_GENERIC;
			}

			result = rcv_msg(buf, sent, hdl->u.msgqid, num_params, params);
			if (result != TEEC_SUCCESS) {
				EMSG("Failed to receive response from the service\n");
				return TEEC_ERROR_GENERIC;
			}
		} else if (hdl->type == DLIB_HANDLE) {
			result = process_dlib_params(hdl->u.dl, num_params, params);
		}

		break;
	}
	}

	return TEEC_SUCCESS;
}
