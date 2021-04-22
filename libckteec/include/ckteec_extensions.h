/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Vaisala Oyj.
 */

#ifndef CKTEEC_EXTENSIONS_H
#define CKTEEC_EXTENSIONS_H

#include <pkcs11.h>
#include <sys/types.h>
#include <tee_client_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
* ckteec_invoke_init_with_login - Invoke init with an alternative login method.
*
* TEE MUST be initiated at this point.
*
* @param login_method such as TEEC_LOGIN_USER or TEEC_LOGIN_GROUP.
* @param login_gid [optional] used with TEEC_LOGIN_GROUP method.
*/
CK_RV ckteec_invoke_init_with_login(uint32_t login_method, gid_t login_gid);

/**
 * ckteec_invoke_init_login_group - Initialize TEE session with the PKCS11 TA
 * using group login method.
 *
 * TEE MUST be initiated at this point.
 *
 * @param login_gid gid of group to login with.
 * @return a CR_RV compliant return value
 */
static inline CK_RV ckteec_invoke_init_login_group(gid_t login_gid)
{
	return ckteec_invoke_init_with_login(TEEC_LOGIN_GROUP, login_gid);
}

/**
 * ckteec_invoke_init_login_group - Initialize TEE session with the PKCS11 TA
 * using user login method.
 *
 * TEE MUST be initiated at this point.
 *
 * @return a CR_RV compliant return value
 */
static inline CK_RV ckteec_invoke_init_login_user(void)
{
	return ckteec_invoke_init_with_login(TEEC_LOGIN_USER, 0);
}

/**
 * ckteec_invoke_init_login_group - Initialize TEE session with the PKCS11 TA
 * using public login method (no login data).
 *
 * TEE MUST be initiated at this point.
 *
 * @return a CR_RV compliant return value
 */
static inline CK_RV ckteec_invoke_init_login_public(void)
{
	return ckteec_invoke_init_with_login(TEEC_LOGIN_PUBLIC, 0);
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* CKTEEC_EXTENSIONS_H */
