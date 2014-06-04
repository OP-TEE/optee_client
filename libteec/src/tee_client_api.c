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
#include <teec_ta_load.h>
#include <malloc.h>

#ifndef TEEC_DEV_PATH
#define TEEC_DEV_PATH "/dev/teetz"
#endif

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#ifdef _GNU_SOURCE
static pthread_mutex_t mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
#else
static pthread_mutex_t mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER;
#endif

static enum tee_target get_tee_target(TEEC_Context *context)
{
	if ((strlen(context->devname) == 10) &&
	    (strncmp(context->devname, "/dev/teetz", 10) == 0))
		return TEE_TARGET_TZ;
	return TEE_TARGET_UNKNOWN;
}

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

/*
 * This function initializes a new TEE Context, connecting this Client
 * application to the TEE indentified by the name name.
 *
 * name == NULL will give the default TEE.
 */
TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
	int name_size = 0;

	if (context == NULL)
		return TEEC_ERROR_BAD_PARAMETERS;

	/*
	 * Specification says that when no name is provided it should fall back
	 * on a predefined TEE.
	 */
	if (name == NULL)
		name_size = strlcpy(context->devname, TEEC_DEV_PATH,
				    TEEC_MAX_DEVNAME_SIZE);
	else {
		name_size = snprintf(context->devname, TEEC_MAX_DEVNAME_SIZE,
				     "/dev/%s", name);
	}

	if (name_size >= TEEC_MAX_DEVNAME_SIZE)
		return TEEC_ERROR_BAD_PARAMETERS; /* Device name truncated */

	context->fd = open(context->devname, O_RDWR);
	if (context->fd == -1)
		return TEEC_ERROR_ITEM_NOT_FOUND;

	return TEEC_SUCCESS;
}

/*
 * This function destroys an initialized TEE Context, closing the connection
 * between the Client and the TEE.
 * The function implementation MUST do nothing if context is NULL
 */
TEEC_Result TEEC_FinalizeContext(TEEC_Context *context)
{
	if (context)
		close(context->fd);

	return TEEC_SUCCESS;
}

/*
 * Allocates or registers shared memory.
 */
TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context,
				      TEEC_SharedMemory *shared_memory)
{
	size_t size;
	uint32_t flags;

	if (context == NULL || shared_memory == NULL)
		return TEEC_ERROR_BAD_PARAMETERS;

	size = shared_memory->size;
	flags = shared_memory->flags;
	memset(shared_memory, 0, sizeof(TEEC_SharedMemory));
	shared_memory->size = size;
	shared_memory->flags = flags;

	if (ioctl(context->fd, TEE_ALLOC_SHM_IOC, shared_memory) != 0) {
		EMSG("Ioctl(TEE_ALLOC_SHM_IOC) failed! (%s)\n",
		     strerror(errno));
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

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
	if (shared_memory == NULL)
		return;

	if (shared_memory->d.fd != 0) {
		if (shared_memory->registered == 0)
			munmap(shared_memory->buffer, shared_memory->size);

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
	if (context == NULL || shared_memory == NULL || shared_memory->buffer
	    == NULL)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (ioctl(context->fd, TEE_ALLOC_SHM_IOC, shared_memory) != 0)
		/*
		 * The buffer not repect platform constraints (not continuous)
		 * and thus can't be used with zero-copy.
		 */
		shared_memory->d.fd = 0;

	shared_memory->registered = 1;
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
	size_t ta_size = 0;
	struct tee_cmd tc;
	uint32_t origin = TEEC_ORIGIN_API;
	TEEC_Result res = TEEC_SUCCESS;
	void *ta = NULL;
	(void)connection_data;

	if (session != NULL)
		session->fd = -1;

	if ((context == NULL) || (session == NULL)) {
		res = TEEC_ERROR_BAD_PARAMETERS;
		goto error;
	}

	/* Check that context->fd is a valid file descriptor */
	session->fd = dup(context->fd);
	if (session->fd == -1) {
		res = TEEC_ERROR_BAD_PARAMETERS;
		goto error;
	}
	close(session->fd);
	session->fd = -1;

	if (connection_method != TEEC_LOGIN_PUBLIC) {
		res = TEEC_ERROR_NOT_SUPPORTED;
		goto error;
	}

	memset(&tc, 0, sizeof(struct tee_cmd));

	/*
	 * Save the fd in the session for later use when invoke command and
	 * close the session.
	 */
	session->fd = open(context->devname, O_RDWR);
	if (session->fd == -1) {
		res = TEEC_ERROR_BAD_PARAMETERS;
		goto error;
	}

	/*
	 * Check if the TA binary is found on the filesystem.
	 * If no, assume it is a static TA.
	 */
	if (TEECI_LoadSecureModule
	    (get_tee_target(context), destination, &ta,
	     &ta_size) == TA_BINARY_FOUND) {
		tc.uuid = (TEEC_UUID *)destination;
		tc.data = ta;
		tc.data_size = ta_size;
	} else {
		tc.uuid = (TEEC_UUID *)destination;
		tc.data = NULL;
		tc.data_size = 0;
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

	tc.op = operation;

	if (ioctl(session->fd, TEE_OPEN_SESSION_IOC, &tc) != 0) {
		EMSG("Ioctl(TEE_OPEN_SESSION_IOC) failed! (%s)\n",
		     strerror(errno));
		origin = TEEC_ORIGIN_COMMS;
		res = TEEC_ERROR_COMMUNICATION;
		goto error;
	}

	if (tc.err != 0) {
		EMSG("UUID %x %x %x can't be loaded !!!\n",
		     destination->timeLow,
		     destination->timeMid, destination->timeHiAndVersion);
	}
	origin = tc.origin;
	res = tc.err;

error:
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

	if (ta)
		free(ta);

	return res;
}

/*
 * This function closes a session which has been opened with a TEE
 * application.
 */
void TEEC_CloseSession(TEEC_Session *session)
{
	uint32_t dummyvalue = 0;

	if (session == NULL)
		return;

	if (ioctl(session->fd, TEE_CLOSE_SESSION_IOC, &dummyvalue) != 0)
		EMSG("Ioctl(TEE_CLOSE_SESSION_IOC) failed! (%s)\n",
		     strerror(errno));

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
	struct tee_cmd tc;
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

	memset(&tc, 0, sizeof(struct tee_cmd));

	tc.cmd = cmd_id;
	tc.op = operation;

	if (ioctl(session->fd, TEE_INVOKE_COMMAND_IOC, &tc) != 0)
		EMSG("Ioctl(TEE_INVOKE_COMMAND_IOC) failed! (%s)\n",
		     strerror(errno));

	if (operation != NULL) {
		teec_mutex_lock(&mutex);

		operation->session = NULL;

		teec_mutex_unlock(&mutex);
	}

	origin = tc.origin;
	result = tc.err;

error:

	if (error_origin != NULL)
		*error_origin = origin;

	OUTRMSG(result);
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
	struct tee_cmd tc;
	TEEC_Session *session;

	if (operation == NULL)
		return;

	teec_mutex_lock(&mutex);
	session = operation->session;
	teec_mutex_unlock(&mutex);

	if (session == NULL)
		return;

	memset(&tc, 0, sizeof(struct tee_cmd));

	tc.op = operation;

	if (ioctl(session->fd, TEE_REQUEST_CANCELLATION_IOC, &tc) != 0)
		EMSG("Ioctl(TEE_REQUEST_CANCELLATION_IOC) failed! (%s)\n",
		     strerror(errno));
}
