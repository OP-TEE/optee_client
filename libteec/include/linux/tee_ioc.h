/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _TEE_IOC_H
#define _TEE_IOC_H

#include <tee_client_api.h>

#ifndef __KERNEL__
#define __user
#endif

/**
 * struct tee_cmd_io - The command sent to an open tee device.
 * @err: Error code (as in Global Platform TEE Client API spec)
 * @origin: Origin for the error code (also from spec).
 * @cmd: The command to be executed in the trusted application.
 * @uuid: The uuid for the trusted application.
 * @data: The trusted application or memory block.
 * @data_size: The size of the trusted application or memory block.
 * @op: The cmd payload operation for the trusted application.
 *
 * This structure is mainly used in the Linux kernel for communication
 * with the user space.
 */
struct tee_cmd_io {
	TEEC_Result err;
	uint32_t origin;
	uint32_t cmd;
	int fd_sess;
	/*
	 * Here fd_sess is 32-bit variable. Since TEEC_Result also is defined as
	 * "uint32_t", this structure is aligned.
	 */
	union {
		TEEC_UUID __user *uuid;
		uint64_t padding_uuid;
	};
	union {
		void __user *data;
		uint64_t padding_data;
	};
	union {
		TEEC_Operation __user *op;
		uint64_t padding_op;
	};
	uint32_t data_size;
	int32_t reserved;
};

struct tee_shm_io {
	union {
		void __user *buffer;
		uint64_t padding_buf;
	};
	uint32_t size;
	uint32_t flags;
	/*
	 * Here fd_shm is 32-bit. To be compliant with the convention of file
	 * descriptor definition, fd_shm is defined as "int" type other
	 * than "int32_t". Even though using "int32_t" is more obvious to
	 * indicate that we intend to keep this structure aligned.
	 */
	int fd_shm;
	uint32_t registered;
};

#define TEE_OPEN_SESSION_IOC		_IOWR('t', 161, struct tee_cmd_io)
#define TEE_INVOKE_COMMAND_IOC		_IOWR('t', 163, struct tee_cmd_io)
#define TEE_REQUEST_CANCELLATION_IOC	_IOWR('t', 164, struct tee_cmd_io)
#define TEE_ALLOC_SHM_IOC		_IOWR('t', 165, struct tee_shm_io)
#define TEE_GET_FD_FOR_RPC_SHM_IOC	_IOWR('t', 167, struct tee_shm_io)

#endif /* _TEE_IOC_H */
