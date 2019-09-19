/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#ifndef __TEE_SERVICE_HANDLE_H_
#define __TEE_SERVICE_HANDLE_H__

typedef enum {
	MSGQ_HANDLE = 1,
	DLL_HANDLE = 2,
} service_type_t;

/* Service information to determine which type to invoke */
struct service_handle {
	service_type_t type;
	union {
		int msgqid;
		void *dll;
	}u;
};

int service_handle_new(uint32_t instance_id, void *ptr);
void *service_handle_get(uint32_t instance_id, uint32_t handle);
void service_handle_put(uint32_t instance_id, uint32_t handle);

#endif
