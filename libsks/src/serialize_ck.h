/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __SERIALIZE_CK_H
#define __SERIALIZE_CK_H

#include <pkcs11.h>
#include "serializer.h"

/* Create (and allocate) a serial object for CK_ATTRIBUTE array */
CK_RV serialize_ck_attributes(struct serializer *obj,
				CK_ATTRIBUTE_PTR attributes, CK_ULONG count);

/* Create (and allocate) a serial object for CK_MECHANISM array */
CK_RV serialize_ck_mecha_params(struct serializer *obj,
				CK_MECHANISM_PTR mechanisms);

/* Log content of a serialized object */
CK_RV serial_trace_attributes(char *prefix, struct serializer *obj);
CK_RV serial_trace_attributes_from_head(char *prefix, void *ref);

#endif /*__SERIALIZE_CK_H*/
