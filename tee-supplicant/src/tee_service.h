/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#ifndef __TEE_SERVICE_H__
#define __TEE_SERVICE_H__

TEEC_Result tee_service_process(size_t num_params,
			       struct tee_ioctl_param *params);
#endif
