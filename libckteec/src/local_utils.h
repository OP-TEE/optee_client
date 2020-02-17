/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Linaro Limited
 */

#ifndef LIBCKTEEC_LOCAL_UTILS_H
#define LIBCKTEEC_LOCAL_UTILS_H

#define ARRAY_SIZE(array)	(sizeof(array) / sizeof(array[0]))

#define COMPILE_TIME_ASSERT(x) \
	do { \
		switch (0) { case 0: case ((x) ? 1: 0) : default : break; } \
	} while (0)

#endif /*LIBCKTEEC_LOCAL_UTILS_H*/
