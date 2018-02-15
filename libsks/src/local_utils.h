/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __LOCAL_UTILS_H
#define __LOCAL_UTILS_H

#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond) \
	do { \
		if (!(cond)) { \
			LOG_ERROR("Assert failed in %s, %s:%d\n", \
				  __func__, __FILE__, __LINE__); \
			exit(2); \
		} \
	} while (0)

#define LOG_ERROR(...)	printf(__VA_ARGS__)
#define LOG_INFO(...)	printf(__VA_ARGS__)
#define LOG_DEBUG(...)	printf(__VA_ARGS__)

#endif /*__LOCAL_UTILS_H*/
