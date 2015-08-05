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
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include <teec_trace.h>
#include <teec.h>
#include <tee_client_api.h>
#include <malloc.h>

#define TEE_TZ_DEVICE_NAME "opteearmtz00"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

/*
 * Maximum size of the device name
 */
#define TEEC_MAX_DEVNAME_SIZE 256

#ifdef _GNU_SOURCE
static pthread_mutex_t mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
#else
static pthread_mutex_t mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER;
#endif

static void teec_mutex_lock(pthread_mutex_t *mu)
{
	int e = pthread_mutex_lock(mu);

	if (e != 0)
		EMSG("pthread_mutex_lock failed: %d\n", e);
}

static void teec_mutex_unlock(pthread_mutex_t *mu)
{
	int e = pthread_mutex_unlock(mu);

	if (e != 0)
		EMSG("pthread_mutex_unlock failed: %d\n", e);
}

static void teec_resetTeeCmd(struct tee_cmd_io *cmd)
{
	memset((void *)cmd, 0, sizeof(struct tee_cmd_io));

	cmd->fd_sess	= -1;
	cmd->cmd	= 0;
	cmd->uuid	= NULL;
	cmd->origin	= TEEC_ORIGIN_API;
	cmd->err	= TEEC_SUCCESS;
	cmd->data	= NULL;
	cmd->data_size	= 0;
	cmd->op		= NULL;
}



/*
 * This function initializes a new TEE Context, connecting this Client
 * application to the TEE identified by the name name.
 *
 * name == NULL will give the default TEE.
 */
TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	int name_size = 0;
	const char* _name = name;

	INMSG("%s", name);

	if (context == NULL)
		return TEEC_ERROR_BAD_PARAMETERS;

	/*
	 * Specification says that when no name is provided it should fall back
	 * on a predefined TEE.
	 */
	if (name == NULL)
		_name = TEE_TZ_DEVICE_NAME;

	name_size = snprintf(context->devname, TEEC_MAX_DEVNAME_SIZE,
			     "/dev/%s", _name);

	if (name_size >= TEEC_MAX_DEVNAME_SIZE)
		return TEEC_ERROR_BAD_PARAMETERS; /* Device name truncated */

	context->fd = open(context->devname, O_RDWR);
	if (context->fd == -1)
		return TEEC_ERROR_ITEM_NOT_FOUND;

	pthread_mutex_init(&mutex, NULL);

	OUTMSG("");
	return TEEC_SUCCESS;
}

/*
 * This function destroys an initialized TEE Context, closing the connection
 * between the Client and the TEE.
 * The function implementation MUST do nothing if context is NULL
 */
void TEEC_FinalizeContext(TEEC_Context *context)
{
	if (context)
		close(context->fd);
}

/*
 * Allocates or registers shared memory.
 */
TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context,
				      TEEC_SharedMemory *shared_memory)
{
	struct tee_shm_io shm;
	size_t size;
	uint32_t flags;

	if (context == NULL || shared_memory == NULL)
		return TEEC_ERROR_BAD_PARAMETERS;

	size = shared_memory->size;
	flags = shared_memory->flags;
	memset(shared_memory, 0, sizeof(TEEC_SharedMemory));
	shared_memory->size = size;
	shared_memory->flags = flags;

	memset((void *)&shm, 0, sizeof(shm));
	shm.buffer = NULL;
	shm.size   = size;
	shm.registered = 0;
	shm.fd_shm = 0;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (ioctl(context->fd, TEE_ALLOC_SHM_IOC, &shm) != 0) {
		EMSG("Ioctl(TEE_ALLOC_SHM_IOC) failed! (%s)\n",
		     strerror(errno));
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	DMSG("fd %d size %d flags %08x", shared_memory->d.fd,
		(int)shared_memory->size, shared_memory->flags);

	shared_memory->size = size;
	shared_memory->d.fd = shm.fd_shm;

	/*
	 * Map memory to current user space process.
	 *
	 * Adjust the size in case it is 0 as, from the spec:
	 *      The size is allowed to be zero. In this case memory is
	 *      allocated and the pointer written in to the buffer field
	 *      on return MUST not be NULL but MUST never be de-referenced
	 *      by the Client Application. In this case however, the
	 *      Shared Memory block can be used in Registered Memory References
	 */
	shared_memory->buffer = mmap(NULL,
				    (shared_memory->size ==
				     0) ? 8 : shared_memory->size,
				    PROT_READ | PROT_WRITE, MAP_SHARED,
				    shared_memory->d.fd, 0);
	if (shared_memory->buffer == (void *)MAP_FAILED) {
		EMSG("Mmap failed (%s)\n", strerror(errno));
		shared_memory->buffer = NULL;
		close(shared_memory->d.fd);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	shared_memory->registered = 0;
	return TEEC_SUCCESS;
}

/*
 * Releases shared memory.
 */
void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *shared_memory)
{
	if (!shared_memory)
		return;

	if (shared_memory->registered)
		return;

	if (shared_memory->d.fd != 0) {
		munmap(shared_memory->buffer, (shared_memory->size ==
			     0) ? 8 : shared_memory->size);
		close(shared_memory->d.fd);
		shared_memory->d.fd = 0;
	}

	shared_memory->buffer = NULL;
}

/*
 * Register shared memory
 */
TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context,
				      TEEC_SharedMemory *shared_memory)
{
	if (!context || !shared_memory)
		return TEEC_ERROR_BAD_PARAMETERS;

	shared_memory->registered = 1;

	/* Use a default fd when not using the dma_buf framework */
	if (!(shared_memory->flags & TEEC_MEM_DMABUF))
		shared_memory->d.fd = 0;

	return TEEC_SUCCESS;
}

/*
 * This function opens a new Session between the Client application and the
 * specified TEE application.
 *
 * Only connection_method == TEEC_LOGIN_PUBLIC is supported connection_data and
 * operation shall be set to NULL.
 */
TEEC_Result TEEC_OpenSession(TEEC_Context *context,
			     TEEC_Session *session,
			     const TEEC_UUID *destination,
			     uint32_t connection_method,
			     const void *connection_data,
			     TEEC_Operation *operation, uint32_t *error_origin)
{
	TEEC_Operation dummy_op;
	uint32_t origin = TEEC_ORIGIN_API;
	TEEC_Result res = TEEC_SUCCESS;
	(void)connection_data;
	struct tee_cmd_io cmd;

	if (session != NULL)
		session->fd = -1;

	if ((context == NULL) || (session == NULL)) {
		res = TEEC_ERROR_BAD_PARAMETERS;
		goto error;
	}

	if (connection_method != TEEC_LOGIN_PUBLIC) {
		res = TEEC_ERROR_NOT_SUPPORTED;
		goto error;
	}

	teec_resetTeeCmd(&cmd);
	cmd.uuid = (TEEC_UUID *)destination;

	if (operation == NULL) {
		/*
		 * The code here exist because Global Platform API states that
		 * it is allowed to give operation as a NULL pointer. In kernel
		 * and secure world we in most cases don't want this to be NULL,
		 * hence we use this dummy operation when a client doesn't
		 * provide any operation.
		 */
		memset(&dummy_op, 0, sizeof(TEEC_Operation));
		operation = &dummy_op;
	}

	cmd.op = operation;

	errno = 0;
	if (ioctl(context->fd, TEE_OPEN_SESSION_IOC, &cmd) != 0) {
		EMSG("Ioctl(TEE_OPEN_SESSION_IOC) failed! (%s) err %08x ori %08x\n",
		     strerror(errno), cmd.err, cmd.origin);
		if (cmd.origin)
			origin = cmd.origin;
		else
			origin = TEEC_ORIGIN_COMMS;
		if (cmd.err)
			res = cmd.err;
		else
			res = TEEC_ERROR_COMMUNICATION;
		goto error;
	}
	session->fd = cmd.fd_sess;

	if (cmd.err != 0) {
		EMSG("open session to TA UUID %x %x %x failed\n",
		     destination->timeLow,
		     destination->timeMid, destination->timeHiAndVersion);
	}
	origin = cmd.origin;
	res = cmd.err;

error:
	// printf("**** res=0x%08x, org=%d, seeid=%d ***\n", res, origin, cmd.fd_sess)

	/*
	 * We do this check at the end instead of checking on every place where
	 * we set the error origin.
	 */
	if (res != TEEC_SUCCESS) {
		if (session != NULL && session->fd != -1) {
			close(session->fd);
			session->fd = -1;
		}
	}

	if (error_origin != NULL)
		*error_origin = origin;

	return res;
}

/*
 * This function closes a session which has been opened with a TEE
 * application.
 */
void TEEC_CloseSession(TEEC_Session *session)
{
	if (session == NULL)
		return;

	close(session->fd);
}

/*
 * Invokes a TEE command (secure service, sub-PA or whatever).
 */
TEEC_Result TEEC_InvokeCommand(TEEC_Session *session,
			       uint32_t cmd_id,
			       TEEC_Operation *operation,
			       uint32_t *error_origin)
{
	INMSG("session: [%p], cmd_id: [%d]", session, cmd_id);
	struct tee_cmd_io cmd;
	TEEC_Operation dummy_op;
	TEEC_Result result = TEEC_SUCCESS;
	uint32_t origin = TEEC_ORIGIN_API;

	if (session == NULL) {
		origin = TEEC_ORIGIN_API;
		result = TEEC_ERROR_BAD_PARAMETERS;
		goto error;
	}

	if (operation == NULL) {
		/*
		 * The code here exist because Global Platform API states that
		 * it is allowed to give operation as a NULL pointer. In kernel
		 * and secure world we in most cases don't want this to be NULL,
		 * hence we use this dummy operation when a client doesn't
		 * provide any operation.
		 */
		memset(&dummy_op, 0, sizeof(TEEC_Operation));
		operation = &dummy_op;
	}

	teec_mutex_lock(&mutex);
	operation->session = session;
	teec_mutex_unlock(&mutex);

	teec_resetTeeCmd(&cmd);

	cmd.cmd = cmd_id;
	cmd.op = operation;

	if (ioctl(session->fd, TEE_INVOKE_COMMAND_IOC, &cmd) != 0)
		EMSG("Ioctl(TEE_INVOKE_COMMAND_IOC) failed! (%s)\n",
		     strerror(errno));

	if (operation != NULL) {
		teec_mutex_lock(&mutex);

		operation->session = NULL;

		teec_mutex_unlock(&mutex);
	}

	origin = cmd.origin;
	result = cmd.err;

error:

	if (error_origin != NULL)
		*error_origin = origin;

	OUTRMSG(result);
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
	struct tee_cmd_io cmd;
	TEEC_Session *session;

	if (operation == NULL)
		return;

	teec_mutex_lock(&mutex);
	session = operation->session;
	teec_mutex_unlock(&mutex);

	if (session == NULL)
		return;

	teec_resetTeeCmd(&cmd);

	cmd.op = operation;

	if (ioctl(session->fd, TEE_REQUEST_CANCELLATION_IOC, &cmd) != 0)
		EMSG("Ioctl(TEE_REQUEST_CANCELLATION_IOC) failed! (%s)\n",
		     strerror(errno));
}
