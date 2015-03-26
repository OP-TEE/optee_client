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
#ifndef _TEEC_TA_LOAD_H
#define _TEEC_TA_LOAD_H
#include <tee_client_api.h>

#define TA_BINARY_FOUND 0
#define TA_BINARY_NOT_FOUND -1

/**
 * Based on the uuid this function will try to find a TA-binary on the
 * filesystem and return it back to the caller in the parameter ta.
 *
 * @param: destination  The uuid of the TA we are searching for.
 * @param: ta           A pointer which this function will copy
 *                      the TA from the filesystem to if *@ta_size i large
 *                      enough.
 * @param: ta_size      The size of the TA found on file system. It will be 0
 *                      if no TA was not found.
 *
 * @return              0 if TA was found, otherwise -1.
 */
int TEECI_LoadSecureModule(const char *name,
			   const TEEC_UUID *destination, void *ta,
			   size_t *ta_size);
#endif
