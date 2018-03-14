/*
 * Copyright (c) 2017, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __INVOKE_TA_H
#define __INVOKE_TA_H

#include <pkcs11.h>
#include <tee_client_api.h>

/*
 * structure stored in CK session so it calls through the right
 * GPD TEE session. TEEC type as abstract through void pointers
 * to prevent CK messing with TEEC API.
 *
 * The structure must be reset to zero prior being used.
 */
struct sks_invoke {
	void *context;
	void *session;
};

/**
 * alloc_shm - Allocate memory in the TEE SHM (in, out or in/out)
 *
 * @owner - Supplied TEE session or NULL
 * @size - allocated size in byte
 *
 * Return a shm reference or NULL on failure.
 *
 * Allocate input SHM on behalf of supplied TEE context.
 * If the supplied context is not initialized, init it through
 * the primary TEE context.
 * If there is no supplied context (ctx is NULL), allocate
 * on behalf of the primary TEE session context.
 */
TEEC_SharedMemory *sks_alloc_shm(struct sks_invoke *ctx,
				 size_t size, int in, int out);

static inline TEEC_SharedMemory *sks_alloc_shm_in(struct sks_invoke *ctx,
						  size_t size)
{
	return sks_alloc_shm(ctx, size, 1, 0);
}
static inline TEEC_SharedMemory *sks_alloc_shm_out(struct sks_invoke *ctx,
						   size_t size)
{
	return sks_alloc_shm(ctx, size, 0, 1);
}
static inline TEEC_SharedMemory *sks_alloc_shm_inout(struct sks_invoke *ctx,
						     size_t size)
{
	return sks_alloc_shm(ctx, size, 1, 1);
}

/**
 * register_shm - Register buffer as TEE SHM memory (in, out or in/out)
 *
 * @owner - Supplied TEE session or NULL
 * @buffer - pointer to the buffer to be registered
 * @size - allocated size in byte
 *
 * Return a shm reference or NULL on failure.
 *
 * Allocate input SHM on behalf of supplied TEE context.
 * If the supplied context is not initialized, init it through
 * the primary TEE context.
 * If there is no supplied context (ctx is NULL), allocate
 * on behalf of the primary TEE session context.
 */
TEEC_SharedMemory *sks_register_shm(struct sks_invoke *ctx, void *buf,
				    size_t size, int in, int out);

static inline TEEC_SharedMemory *sks_register_shm_in(struct sks_invoke *ctx,
						     void *buf, size_t size)
{
	return sks_register_shm(ctx, buf, size, 1, 0);
}
static inline TEEC_SharedMemory *sks_register_shm_out(struct sks_invoke *ctx,
						      void *buf, size_t size)
{
	return sks_register_shm(ctx, buf, size, 0, 1);
}
static inline TEEC_SharedMemory *sks_register_shm_inout(struct sks_invoke *ctx,
							void *buf, size_t size)
{
	return sks_register_shm(ctx, buf, size, 1, 1);
}

/**
 * free_shm - Release allocated or registered emory in the TEE SHM
 *
 * @shm - memory reference
 */
void sks_free_shm(TEEC_SharedMemory *shm);

/**
 * invoke_sks_ta - Invoke a SKS request to the TEE
 *
 * @ctx - supplied TEE session context
 * @cmd - SKS TA command ID
 * @ctrl - command serialized input arguments. Shm, buffer or NULL pointer.
 * @ctrl_sz - byte size of ctrl if ctrl is a buffer pointer
 * @in - input to-be-processed data. shm pointer.Shm, buffer or NULL pointer.
 * @in_sz - byte size of ctrl if ctrl is a buffer pointer
 * @out - output to-be-processed data. shm pointer.Shm, buffer or NULL pointer.
 * @out_sz - byte size of ctrl if ctrl is a buffer pointer
 *
 * Allocate input SHM on behalf of supplied TEE context.
 * If the supplied context is not initialized, init it through
 * the primary TEE context.
 * If there is no supplied context (ctx is NULL), allocate
 * on behalf of the primary TEE session context.
 *
 * ctrl, in and out can be NULL pointer (no related data), buffer pointer
 * (related data are stored in a memory buffer not registered as TEE SHM)
 * or a SHM reference (related data are stored in a buffer registered as
 * TEE SHM).
 * ctrl_sz, in_sz and out_sz are null if the related reference is a SHM buffer
 * and are not null if the related reference is a non SHM buffer. Note that
 * out_sz is a pointer.
 *
 * Function return values versus TA invocation statuses:
 * - CKR_OK on invocation success (TEEC_SUCCESS)
 * - CKR_BUFFER_TOO_SMALL on TEEC_ERROR_SHORT_BUFFER. This affect only the
 *   output data buffer.
 * - CKR_DEVICE_MEMORY on TEEC_ERROR_OUT_OF_MEMORY.
 * - TODO...
 */
CK_RV ck_invoke_ta(struct sks_invoke *sks_ctx,
		   unsigned long cmd,
		   void *ctrl, size_t ctrl_sz,
		   void *in, size_t in_sz,
		   void *out, size_t *out_sz);

/* sks_invoke_terminate - Release all allocated invocation resources */
void sks_invoke_terminate(void);

#endif /*__INVOKE_TA_H*/
