/*
 * Copyright 2020 NXP
 */

#ifndef COVERAGE_H
#define COVERAGE_H

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

#include <tee_client_api.h>

#include <teec_trace.h>

#if defined(CFG_GCOV_SUPPORT)

TEEC_Result coverage_process(size_t num_params, struct tee_ioctl_param *params);

#else

static inline TEEC_Result coverage_process(size_t num_params,
					   struct tee_ioctl_param *params)
{
	(void)num_params;
	(void)params;

	return TEEC_ERROR_NOT_SUPPORTED;
}

#endif /* CFG_GCOV_SUPPORT */

#endif /* COVERAGE_H */
