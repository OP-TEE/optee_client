/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#ifndef LIBCKTEEC_PKCS11_PROCESSING_H
#define LIBCKTEEC_PKCS11_PROCESSING_H

#include <pkcs11.h>

CK_RV ck_create_object(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attribs,
		       CK_ULONG count, CK_OBJECT_HANDLE_PTR phObject);

CK_RV ck_destroy_object(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj);
#endif /*LIBCKTEEC_PKCS11_PROCESSING_H*/
