/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Vaisala Oyj.
 */

#ifndef ASTEEC_H
#define ASTEEC_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <tee_client_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * asteec_seal() - Seal secret using hardware unique TA specific key
 *
 * @param login_method  Login method such as TEEC_LOGIN_PUBLIC or TEEC_LOGIN_GROUP
 * @param login_gid     Group ID, used with TEEC_LOGIN_GROUP and
 *                      TEEC_LOGIN_GROUP_APPLICATION methods
 * @param plain         Pointer to plain secret
 * @param plain_len     Byte length of plain secret
 * @param sealed        Pointer to buffer to receive sealed secret datablob.
 *                      May be NULL when *sealed_len is 0 to query the
 *                      required output size.
 * @param sealed_len    On input, byte length of buffer @sealed. On output,
 *                      updated with the actual size on success or the required
 *                      size when TEEC_ERROR_SHORT_BUFFER is returned.
 *
 * @return TEEC_SUCCESS on success, TEEC_ERROR_* on failure
 */
TEEC_Result asteec_seal(uint32_t login_method, gid_t login_gid,
			const void *plain, size_t plain_len,
			void *sealed, size_t *sealed_len);

/**
 * asteec_unseal() - Unseal secret using hardware unique TA specific key
 *
 * @param login_method  Login method such as TEEC_LOGIN_PUBLIC or TEEC_LOGIN_GROUP
 * @param login_gid     Group ID, used with TEEC_LOGIN_GROUP and
 *                      TEEC_LOGIN_GROUP_APPLICATION methods
 * @param sealed        Pointer to sealed secret datablob
 * @param sealed_len    Byte length of sealed secret datablob
 * @param plain         Pointer to buffer to receive plain secret.
 *                      May be NULL when *plain_len is 0 to query the
 *                      required output size.
 * @param plain_len     On input, byte length of buffer @plain. On output,
 *                      updated with the actual size on success or the required
 *                      size when TEEC_ERROR_SHORT_BUFFER is returned.
 *
 * @return TEEC_SUCCESS on success, TEEC_ERROR_* on failure
 */
TEEC_Result asteec_unseal(uint32_t login_method, gid_t login_gid,
			  const void *sealed, size_t sealed_len,
			  void *plain, size_t *plain_len);

#ifdef __cplusplus
}
#endif

#endif /* ASTEEC_H */
