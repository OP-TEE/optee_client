/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 20187-2020, Linaro Limited
 */

#ifndef LIBCKTEEC_INVOKE_TA_H
#define LIBCKTEEC_INVOKE_TA_H

#include <pkcs11.h>
#include <tee_client_api.h>

enum ckteec_shm_dir {
	CKTEEC_SHM_IN,
	CKTEEC_SHM_OUT,
	CKTEEC_SHM_INOUT,
};

/**
 * ckteec_alloc_shm - Allocate memory in the TEE SHM (in, out or in/out)
 *
 * @size - Allocated size in byte
 * @dir - Data direction used for the shared memory
 *
 * Return a shm reference or NULL on failure.
 */
TEEC_SharedMemory *ckteec_alloc_shm(size_t size, enum ckteec_shm_dir dir);

/**
 * ckteec_free_shm - Release allocated or registered emory in the TEE SHM
 *
 * @shm - memory reference
 */
void ckteec_free_shm(TEEC_SharedMemory *shm);

/**
 * ckteec_invoke_ta - Invoke PKCS11 TA for a target request through the TEE
 *
 * @cmd - PKCS11 TA command ID
 * @ctrl - shared memory with serialized request input arguments or NULL
 * @io1 - In and/or out memory buffer argument #1 for the command or NULL
 * @io2 - In and/or out memory buffer argument #2 for the command or NULL
 * @io3 - In and/or out memory buffer argument #3 for the command or NULL
 *
 * Return a CR_RV compliant return value
 */
CK_RV ckteec_invoke_ta(unsigned long cmd, TEEC_SharedMemory *ctrl,
		       TEEC_SharedMemory *io1, TEEC_SharedMemory *io2,
		       TEEC_SharedMemory *io3);

/*
 * ckteec_invoke_init - Initialize TEE session with the PKCS11 TA
 *
 * Return a CR_RV compliant return value
 */
CK_RV ckteec_invoke_init(void);

/*
 * ckteec_invoke_terminate - Release all allocated invocation resources
 *
 * Return a CR_RV compliant return value
 */
CK_RV ckteec_invoke_terminate(void);

/* Return true if and only if the PKCS11 TA invocation context is initiated */
bool ckteec_invoke_initiated(void);

#endif /*LIBCKTEEC_INVOKE_TA_H*/
