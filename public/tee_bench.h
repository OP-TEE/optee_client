/*
 * Copyright (c) 2016, Linaro Limited
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef TEE_BENCH_H
#define TEE_BENCH_H

#include <inttypes.h>
#include <tee_client_api.h>

#define UNUSED(x) (void)(x)

/* max amount of timestamps */
#define TEE_BENCH_MAX_STAMPS	10
#define TEE_BENCH_RB_SIZE (sizeof(struct tee_time_buf) + \
		sizeof(struct tee_time_st) * TEE_BENCH_MAX_STAMPS)
#define TEE_BENCH_DEF_PARAM		4

/* OP-TEE susbsystems ids */
#define TEE_BENCH_CLIENT	0x10000000
#define TEE_BENCH_KMOD		0x20000000
#define TEE_BENCH_CORE		0x30000000
#define TEE_BENCH_UTEE		0x40000000
#define TEE_BENCH_DUMB_TA	0xF0000001

/* storing timestamps */
struct tee_time_st {
	uint64_t cnt;	/* stores value from CNTPCT register */
	uint64_t addr;	/* stores value from program counter register */
	uint64_t src;	/* OP-TEE subsystem id */
};

/* memory layout for shared memory, where timestamps will be stored */
struct tee_time_buf {
	uint64_t tm_ind; /* index of the next unfilled timestamp in stamps[] */
	struct tee_time_st stamps[];
};

#ifdef CFG_TEE_BENCHMARK
/* Reading program counter */
static inline __attribute__((always_inline)) uintptr_t read_pc(void)
{
	uintptr_t pc;
#ifdef __aarch64__
	asm volatile("adr %0, ." : "=r"(pc));
#else
	asm volatile("mov %0, r15" : "=r"(pc));
#endif
	return pc;
}

/* Cycle counter */
static inline uint64_t read_ccounter(void)
{
	uint64_t ccounter = 0;
#ifdef __aarch64__
	asm volatile("mrs %0, PMCCNTR_EL0" : "=r"(ccounter));
#else
	asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(ccounter));
#endif
	return ccounter;
}

/* Adding timestamp to buffer */
static inline __attribute__((always_inline)) void bm_timestamp
				(TEEC_Parameter
				 params[TEEC_CONFIG_PAYLOAD_REF_COUNT],
				 uint32_t source)
{
	struct tee_time_buf *timeb = (struct tee_time_buf *)
			params[TEE_BENCH_DEF_PARAM].memref.parent->buffer;
	uint64_t ts_i;

	if (!timeb)
		return;
	if (timeb->tm_ind >= TEE_BENCH_MAX_STAMPS)
		return;

	ts_i = timeb->tm_ind++;
	timeb->stamps[ts_i].cnt = read_ccounter();
	timeb->stamps[ts_i].addr = read_pc();
	timeb->stamps[ts_i].src = source;
}
#else /* CFG_TEE_BENCHMARK */
static inline void bm_timestamp(TEEC_Parameter
				params[TEEC_CONFIG_PAYLOAD_REF_COUNT],
				uint32_t source)
{
	UNUSED(params);
	UNUSED(source);
}

#endif /* CFG_TEE_BENCHMARK */
#endif /* TEE_BENCH_H */