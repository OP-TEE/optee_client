/*
 * Copyright (c) 2016, Linaro Limited
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
#ifndef TEE_CLIENT_API_EXTENSIONS_H
#define TEE_CLIENT_API_EXTENSIONS_H

#include <tee_client_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * TEEC_RegisterMemoryFileDescriptor() - Register a block of existing memory as
 * a shared block within the scope of the specified context.
 *
 * @param context    The initialized TEE context structure in which scope to
 *                   open the session.
 * @param sharedMem  pointer to the shared memory structure to register.
 * @param fd         file descriptor of the target memory.
 *
 * @return TEEC_SUCCESS              The registration was successful.
 * @return TEEC_ERROR_OUT_OF_MEMORY  Memory exhaustion.
 * @return TEEC_Result               Something failed.
 */
TEEC_Result TEEC_RegisterSharedMemoryFileDescriptor(TEEC_Context *context,
						    TEEC_SharedMemory *sharedMem,
						    int fd);

/**
 * TEEC_InitializeContext2() - Behaves the same way as TEEC_InitializeContext
 * allowing the caller to attach the specified settings to the resulting
 * context.
 *
 * @param name         A zero-terminated string identifying the TEE to connect
 *                     to. If name is set to NULL, the default TEE is connected
 *                     to. NULL is the only supported value in this version of
 *                     the API implementation.
 * @param context      The context structure which is to be initialized.
 * @param settings     A list of settings to use to configure the new
 *                     context, or NULL.
 * @param numSettings  The number of settings, if any.
 *
 * @return TEEC_SUCCESS               The initialization was successful.
 * @return TEEC_ERROR_BAD_PARAMETERS  One or more parameters are wrong.
 * @return TEEC_ERROR_NOT_SUPPORTED   One or more settings are not supported.
 * @return TEEC_Result                Something else failed.
 */
TEEC_Result TEEC_InitializeContext2(const char *name, TEEC_Context *context,
				    const TEEC_ContextSetting *settings,
				    uint32_t numSettings);

/**
 * TEEC_OpenSession2() - Behaves the same way as TEEC_OpenSession allowing the
 * caller to attach the specified settings to the resulting session.
 *
 * @param context           The initialized TEE context structure in which scope
 *                          to open the session.
 * @param session           The session to initialize.
 * @param destination       A structure identifying the trusted application with
 *                          which to open a session.
 * @param connectionMethod  The connection method to use.
 * @param connectionData    Any data necessary to connect with the chosen
 *                          connection method. Not supported, should be set to
 *                          NULL.
 * @param operation         An operation structure to use in the session. May be
 *                          set to NULL to signify no operation structure
 *                          needed.
 * @param returnOrigin      A parameter which will hold the error origin if this
 *                          function returns any value other than TEEC_SUCCESS.
 * @param settings          A list of settings to use to configure the new
 *                          session, or NULL.
 * @param numSettings       The number of settings, if any.
 *
 * @return TEEC_SUCCESS               Successfully opened a new session.
 * @return TEEC_ERROR_BAD_PARAMETERS  One or more parameters are wrong.
 * @return TEEC_Result                Something else failed.
 */
TEEC_Result TEEC_OpenSession2(TEEC_Context *context,
			      TEEC_Session *session,
			      const TEEC_UUID *destination,
			      uint32_t connectionMethod,
			      const void *connectionData,
			      TEEC_Operation *operation,
			      uint32_t *returnOrigin,
			      const TEEC_SessionSetting *settings,
			      uint32_t numSettings);

#ifdef __cplusplus
}
#endif

#endif /* TEE_CLIENT_API_EXTENSIONS_H */
