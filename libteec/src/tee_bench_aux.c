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

#include <linux/tee_bench_aux.h>

const char *bench_str_src(uint64_t source)
{
	switch (source) {
	case TEE_BENCH_CORE:
		return "CORE";
	case TEE_BENCH_KMOD:
		return "KMOD";
	case TEE_BENCH_CLIENT:
		return "CLIENT";
	case TEE_BENCH_UTEE:
		return "UTEE";
	case TEE_BENCH_DUMB_TA:
		return "DUMB_TA";
	default:
		return "???";
	}
}

void print_latency_info(void *timebuffer)
{
	struct tee_time_buf *timeb = (struct tee_time_buf *)timebuffer;
	uint64_t start = 0;

	printf("Latency information:\n");
	printf("================================");
	printf("================================\n");
	for (uint32_t ts_i = 0; ts_i < timeb->tm_ind; ts_i++) {
		if (!ts_i)
			start = timeb->stamps[ts_i].cnt;

		if (timeb->stamps[ts_i].cnt < start)
			printf("| CCNT=overflow occured | SRC=%-8s | PC=0x%016"
				PRIx64 " |\n",
				bench_str_src(timeb->stamps[ts_i].src),
				(timeb->stamps[ts_i].addr));
		else
			printf("| CCNT=%16" PRIu64 " | SRC=%-8s | PC=0x%016"
				PRIx64 " |\n",
				(timeb->stamps[ts_i].cnt - start) *
				BENCH_DIVIDER,
				bench_str_src(timeb->stamps[ts_i].src),
				(timeb->stamps[ts_i].addr));
	}
	printf("================================");
	printf("================================\n");
}
