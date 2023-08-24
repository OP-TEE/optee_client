/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, Foundries.io
 */

#ifndef PTA_TEE_H
#define PTA_TEE_H

#include <tee_client_api.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * pta_imx_mprotect_get_key() - Retrieves the iMX CAAM Manufacturing Protection
 * EC public key. The components x,y are retrieved in RAW format and should
 * be converted to DER or PEM as required.
 *
 * For the 256 bit curve, this will generate two 32 byte components therefore
 * requiring at least a 64 byte buffer.
 *
 * @key: [out] Public key in RAW format.
 * @len: [in/out] Key length in bytes.
 *
 * @return TEEC_ERROR_BAD_PARAMETERS	Invalid parameters provided on input.
 * @return TEEC_ERROR_ACCESS_DENIED	Error opening the TEE session.
 * @return TEEC_ERROR_OUT_OF_MEMORY	Memory exhaustion.
 * @return TEEC_ERROR_GENERIC		Error unspecified.
 * @return TEEC_ERROR_SHORT_BUFFER	Error small buffer provided.
 * @return TEEC_ERROR_COMMUNICATION	Some other thread closed the connection.
 * @return TEEC_SUCCESS			On success.
 *
 */
TEEC_Result pta_imx_mprotect_get_key(char *key, size_t *len);

/**
 * pta_imx_mprotect_sign() - Signs a message using the Manufacturing Protection
 * EC private key.
 *
 * This function takes message data as input and outputs a signature over a
 * message composed of the content of the MPMR, followed by the input-data
 * message.
 *
 * @message:	[in] Message to sign.
 * @mlen:	[in] Message length in bytes.
 * @signature:	[out] Generated signature.
 * @slen:	[in/out] Signature length in bytes.
 * @mpmr:	[out] MPMR data.
 * @len:	[in/out] MPMR length in bytes.
 *
 * @return TEEC_ERROR_BAD_PARAMETERS	Invalid parameters provided on input.
 * @return TEEC_ERROR_ACCESS_DENIED	Error opening the TEE session.
 * @return TEEC_ERROR_OUT_OF_MEMORY	Memory exhaustion.
 * @return TEEC_ERROR_GENERIC		Error unspecified.
 * @return TEEC_ERROR_COMMUNICATION	Some other thread closed the connection.
 * @return TEEC_ERROR_SHORT_BUFFER	Error small buffer provided.
 * @return TEEC_SUCCESS			On success.
 *
 */
TEEC_Result pta_imx_mprotect_sign(char *message, size_t mlen, char *signature,
				  size_t *slen, char *mpmr, size_t *len);

/**
 * pta_imx_mprotect_final() - Closes the OP-TEE session
 *
 * This function may fail with TEEC_ERROR_BUSY if there are unfulfilled calls
 * pending.
 *
 * @return TEEC_ERROR_BUSY		PTA is still in use.
 * @return TEEC_SUCCESS			On success.
 *
 */
TEEC_Result pta_imx_mprotect_final(void);

#ifdef __cplusplus
}
#endif

#endif /*PTA_TEE_H*/
