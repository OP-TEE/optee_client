/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Foundries.io
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#ifndef SE_TEE_H
#define SE_TEE_H

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long SE_ULONG;
typedef SE_ULONG SE_RV;

/* Values for type SR_RV */
#define SER_OK					0x0000
#define SER_CANT_OPEN_SESSION			0x0001
#define SER_ERROR_GENERIC			0x0002

/*
 * Type identifier for the APDU message as described by Smart Card Standard ISO7816-4
 * about ADPU message bodies decoding convention:
 *
 * https://cardwerk.com/smart-card-standard-iso7816-4-section-5-basic-organizations/#chap5_3_2
 */
enum se_apdu_type {
	SE_APDU_NO_HINT,
	SE_APDU_CASE_1,
	SE_APDU_CASE_2,
	SE_APDU_CASE_2E,
	SE_APDU_CASE_3,
	SE_APDU_CASE_3E,
	SE_APDU_CASE_4,
	SE_APDU_CASE_4E,
};

/**
 * se_apdu_request() - Send an APDU message and get response.
 *
 * @param type		Type of the APDU command.
 * @param hdr		Pointer to APDU message header.
 * @param hdr_len	Byte length of message header @hdr.
 * @param src		Pointer to APDU message payload.
 * @param src_len	Byte length of message payload @src.
 * @param dst		Pointer to APDU message reponse buffer.
 * @param dst_len	Byte length of reponse buffer @dst.
 *
 * @return SER_CANT_OPEN_SESSION	Error opening the TEE session.
 * @return SER_ERROR_GENERIC		Error unspecified.
 * @return SER_OK			On success.
 */
SE_RV se_apdu_request(enum se_apdu_type type,
		    unsigned char *hdr, size_t hdr_len,
		    unsigned char *src, size_t src_len,
		    unsigned char *dst, size_t *dst_len);

/**
 * se_scp03_enable() - Enable the SCP03 protocol using the keys active in the
 * Secure Element.
 *
 * Enables the SCP03 session with the Secure Element.
 *
 * @return SER_CANT_OPEN_SESSION	Error opening the TEE session.
 * @return SER_ERROR_GENERIC		Error unspecified.
 * @return SER_OK			On success.
 */
SE_RV se_scp03_enable(void);

/**
 * se_scp03_rotate_keys_and_enable() - Attempt to replace the active SCP03 keys
 * and enable the SCP03 session.
 *
 * Generates secure keys for the board and writes them in the Secure Element non
 * volatile memory. Then re-enables the session.
 *
 * @return SER_CANT_OPEN_SESSION	Error opening the TEE session.
 * @return SER_ERROR_GENERIC		Error unspecified.
 * @return SER_OK			On success.
 */
SE_RV se_scp03_rotate_keys_and_enable(void);

#ifdef __cplusplus
}
#endif

#endif /*SE_TEE_H*/
