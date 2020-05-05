/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */
#ifndef LIBCKTEEC_SERIALIZE_CK_H
#define LIBCKTEEC_SERIALIZE_CK_H

#include <pkcs11.h>

#include "serializer.h"

/* Create (and allocate) a serial object for CK_ATTRIBUTE array */
CK_RV serialize_ck_attributes(struct serializer *obj,
			      CK_ATTRIBUTE_PTR attributes, CK_ULONG count);

#endif /*LIBCKTEEC_SERIALIZE_CK_H*/
