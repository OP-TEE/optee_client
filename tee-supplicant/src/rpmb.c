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

#include <fcntl.h>
#include <linux/types.h>
#include <linux/mmc/ioctl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <rpmb.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <teec_trace.h>
#include <tee_supplicant.h>
#include <unistd.h>

#ifdef RPMB_EMU
#include <stdarg.h>
#include "hmac_sha2.h"
#else
#include <errno.h>
#endif

/*
 * Request and response definitions must be in sync with the secure side
 */

/* Request */
struct rpmb_req {
	uint16_t cmd;
#define RPMB_CMD_DATA_REQ      0x00
#define RPMB_CMD_GET_DEV_INFO  0x01
	uint16_t dev_id;
	uint16_t block_count;
	/* Optional data frames (rpmb_data_frame) follow */
};
#define RPMB_REQ_DATA(req) ((void *)((struct rpmb_req *)(req) + 1))

/* Response to device info request */
struct rpmb_dev_info {
	uint8_t cid[16];
	uint8_t rpmb_size_mult;	/* EXT CSD-slice 168: RPMB Size */
	uint8_t rel_wr_sec_c;	/* EXT CSD-slice 222: Reliable Write Sector */
				/*                    Count */
	uint8_t ret_code;
#define RPMB_CMD_GET_DEV_INFO_RET_OK     0x00
#define RPMB_CMD_GET_DEV_INFO_RET_ERROR  0x01
};

/*
 * This structure is shared with OP-TEE and the MMC ioctl layer.
 * It is the "data frame for RPMB access" defined by JEDEC, minus the
 * start and stop bits.
 */
struct rpmb_data_frame {
	uint8_t stuff_bytes[196];
	uint8_t key_mac[32];
	uint8_t data[256];
	uint8_t nonce[16];
	uint32_t write_counter;
	uint16_t address;
	uint16_t block_count;
	uint16_t op_result;
#define RPMB_RESULT_OK				0x00
#define RPMB_RESULT_GENERAL_FAILURE		0x01
#define RPMB_RESULT_AUTH_FAILURE		0x02
#define RPMB_RESULT_ADDRESS_FAILURE		0x04
	uint16_t msg_type;
#define RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM		0x0001
#define RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ	0x0002
#define RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE		0x0003
#define RPMB_MSG_TYPE_REQ_AUTH_DATA_READ		0x0004
#define RPMB_MSG_TYPE_REQ_RESULT_READ			0x0005
#define RPMB_MSG_TYPE_RESP_AUTH_KEY_PROGRAM		0x0100
#define RPMB_MSG_TYPE_RESP_WRITE_COUNTER_VAL_READ	0x0200
#define RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE		0x0300
#define RPMB_MSG_TYPE_RESP_AUTH_DATA_READ		0x0400
};


static pthread_mutex_t rpmb_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * ioctl() interface
 * Comes from: uapi/linux/major.h, linux/mmc/core.h
 */

#define MMC_BLOCK_MAJOR	179

/* mmc_ioc_cmd.opcode */
#define MMC_SEND_EXT_CSD		 8
#define MMC_READ_MULTIPLE_BLOCK		18
#define MMC_WRITE_MULTIPLE_BLOCK	25

/* mmc_ioc_cmd.flags */
#define MMC_RSP_PRESENT	(1 << 0)
#define MMC_RSP_136     (1 << 1)	/* 136 bit response */
#define MMC_RSP_CRC	(1 << 2)	/* Expect valid CRC */
#define MMC_RSP_OPCODE	(1 << 4)	/* Response contains opcode */

#define MMC_RSP_R1      (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)

#define MMC_CMD_ADTC	(1 << 5)	/* Addressed data transfer command */

/* mmc_ioc_cmd.write_flag */
#define MMC_CMD23_ARG_REL_WR	(1 << 31) /* CMD23 reliable write */

#ifndef RPMB_EMU

#define IOCTL(fd, request, ...)					   \
	({							   \
		int ret;					   \
		ret = ioctl((fd), (request), ##__VA_ARGS__);	   \
		if (ret < 0)					   \
			EMSG("ioctl ret=%d errno=%d", ret, errno); \
		ret;						   \
	})


/* Open and/or return file descriptor to RPMB partition of device dev_id */
static int mmc_rpmb_fd(uint16_t dev_id)
{
	static int id;
	static int fd = -1;
	char path[PATH_MAX];

	if (fd < 0) {
#ifdef __ANDROID__
		snprintf(path, sizeof(path), "/dev/block/mmcblk%urpmb", dev_id);
#else
		snprintf(path, sizeof(path), "/dev/mmcblk%urpmb", dev_id);
#endif
		fd = open(path, O_RDWR);
		if (fd < 0) {
			EMSG("Could not open %s (%s)", path, strerror(errno));
			return -1;
		}
		id = dev_id;
	}
	if (id != dev_id) {
		EMSG("Only one MMC device is supported");
		return -1;
	}
	return fd;
}

/* Open eMMC device dev_id */
static int mmc_fd(uint16_t dev_id)
{
	int fd;
	char path[PATH_MAX];

#ifdef __ANDROID__
	snprintf(path, sizeof(path), "/dev/block/mmcblk%u", dev_id);
#else
	snprintf(path, sizeof(path), "/dev/mmcblk%u", dev_id);
#endif
	fd = open(path, O_RDONLY);
	if (fd < 0)
		EMSG("Could not open %s (%s)", path, strerror(errno));

	return fd;
}

static void close_mmc_fd(int fd)
{
	close(fd);
}

/* Device Identification (CID) register is 16 bytes. It is read from sysfs. */
static uint32_t read_cid(uint16_t dev_id, uint8_t *cid)
{
	TEEC_Result res;
	char path[48];
	char hex[3] = { 0, };
	int st;
	int fd;
	int i;

	snprintf(path, sizeof(path),
		 "/sys/class/mmc_host/mmc%u/mmc%u:0001/cid", dev_id, dev_id);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		EMSG("Could not open %s (%s)", path, strerror(errno));
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	for (i = 0; i < 16; i++) {
		st = read(fd, hex, 2);
		if (st < 0) {
			EMSG("Read CID error (%s)", strerror(errno));
			res = TEEC_ERROR_NO_DATA;
			goto err;
		}
		cid[i] = (uint8_t)strtol(hex, NULL, 16);
	}
	res = TEEC_SUCCESS;
err:
	close(fd);
	return res;
}

#else /* RPMB_EMU */

#define IOCTL(fd, request, ...) ioctl_emu((fd), (request), ##__VA_ARGS__)

/* Emulated rel_wr_sec_c value (reliable write size, *256 bytes) */
#define EMU_RPMB_REL_WR_SEC_C	1
/* Emulated rpmb_size_mult value (RPMB size, *128 kB) */
#define EMU_RPMB_SIZE_MULT	1

#define EMU_RPMB_SIZE_BYTES	(EMU_RPMB_SIZE_MULT * 128 * 1024)

/* Emulated eMMC device state */
struct rpmb_emu {
	uint8_t buf[EMU_RPMB_SIZE_BYTES];
	size_t size;
	uint8_t key[32];
	bool key_set;
	uint8_t nonce[16];
	uint32_t write_counter;
	struct {
		uint16_t msg_type;
		uint16_t op_result;
		uint16_t address;
	} last_op;
};
static struct rpmb_emu rpmb_emu = {
	.size = EMU_RPMB_SIZE_BYTES
};

static struct rpmb_emu *mem_for_fd(int fd)
{
	static int sfd = -1;

	if (sfd == -1)
		sfd = fd;
	if (sfd != fd) {
		EMSG("Emulating more than 1 RPMB partition is not supported");
		return NULL;
	}

	return &rpmb_emu;
}

#if (DEBUGLEVEL >= TRACE_FLOW)
static void dump_blocks(size_t startblk, size_t numblk, uint8_t *ptr,
			bool to_mmc)
{
	char msg[100];
	size_t i;

	for (i = 0; i < numblk; i++) {
		snprintf(msg, sizeof(msg), "%s MMC block %zu",
			 to_mmc ? "Write" : "Read", startblk + i);
		dump_buffer(msg, ptr, 256);
		ptr += 256;
	}
}
#else
static void dump_blocks(size_t startblk, size_t numblk, uint8_t *ptr,
			bool to_mmc)
{
	(void)startblk;
	(void)numblk;
	(void)ptr;
	(void)to_mmc;
}
#endif

#define CUC(x) ((const unsigned char *)(x))
static void hmac_update_frm(hmac_sha256_ctx *ctx, struct rpmb_data_frame *frm)
{
	hmac_sha256_update(ctx, CUC(frm->data), 256);
	hmac_sha256_update(ctx, CUC(frm->nonce), 16);
	hmac_sha256_update(ctx, CUC(&frm->write_counter), 4);
	hmac_sha256_update(ctx, CUC(&frm->address), 2);
	hmac_sha256_update(ctx, CUC(&frm->block_count), 2);
	hmac_sha256_update(ctx, CUC(&frm->op_result), 2);
	hmac_sha256_update(ctx, CUC(&frm->msg_type), 2);
}

static bool is_hmac_valid(struct rpmb_emu *mem, struct rpmb_data_frame *frm,
		   size_t nfrm)
{
	hmac_sha256_ctx ctx;
	uint8_t mac[32];
	size_t i;

	if (!mem->key_set) {
		EMSG("Cannot check MAC (key not set)");
		return false;
	}

	hmac_sha256_init(&ctx, mem->key, sizeof(mem->key));
	for (i = 0; i < nfrm; i++, frm++)
		hmac_update_frm(&ctx, frm);
	frm--;
	hmac_sha256_final(&ctx, mac, 32);

	if (memcmp(mac, frm->key_mac, 32)) {
		EMSG("Invalid MAC");
		return false;
	}
	return true;
}

static uint16_t compute_hmac(struct rpmb_emu *mem, struct rpmb_data_frame *frm,
			     size_t nfrm)
{
	hmac_sha256_ctx ctx;
	size_t i;

	if (!mem->key_set) {
		EMSG("Cannot compute MAC (key not set)");
		return RPMB_RESULT_GENERAL_FAILURE;
	}

	hmac_sha256_init(&ctx, mem->key, sizeof(mem->key));
	for (i = 0; i < nfrm; i++, frm++)
		hmac_update_frm(&ctx, frm);
	frm--;
	hmac_sha256_final(&ctx, frm->key_mac, 32);

	return RPMB_RESULT_OK;
}

static uint16_t ioctl_emu_mem_transfer(struct rpmb_emu *mem,
				       struct rpmb_data_frame *frm,
				       size_t nfrm, int to_mmc)
{
	size_t start = mem->last_op.address * 256;
	size_t size = nfrm * 256;
	size_t i;
	uint8_t *memptr;

	if (start > mem->size || start + size > mem->size) {
		EMSG("Transfer bounds exceeed emulated memory");
		return RPMB_RESULT_ADDRESS_FAILURE;
	}
	if (to_mmc && !is_hmac_valid(mem, frm, nfrm))
		return RPMB_RESULT_AUTH_FAILURE;

	DMSG("Transferring %zu 256-byte data block%s %s MMC (block offset=%zu)",
	     nfrm, (nfrm > 1) ? "s" : "", to_mmc ? "to" : "from", start / 256);
	for (i = 0; i < nfrm; i++) {
		memptr = mem->buf + start + i * 256;
		if (to_mmc) {
			memcpy(memptr, frm[i].data, 256);
			mem->write_counter++;
			frm[i].write_counter = htonl(mem->write_counter);
			frm[i].msg_type =
				htons(RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE);
		} else {
			memcpy(frm[i].data, memptr, 256);
			frm[i].msg_type =
				htons(RPMB_MSG_TYPE_RESP_AUTH_DATA_READ);
			frm[i].address = htons(mem->last_op.address);
			frm[i].block_count = nfrm;
			memcpy(frm[i].nonce, mem->nonce, 16);
		}
		frm[i].op_result = RPMB_RESULT_OK;
	}
	dump_blocks(mem->last_op.address, nfrm, mem->buf + start, to_mmc);

	if (!to_mmc)
		compute_hmac(mem, frm, nfrm);

	return RPMB_RESULT_OK;
}

static void ioctl_emu_get_write_result(struct rpmb_emu *mem,
				       struct rpmb_data_frame *frm)
{
	frm->msg_type =	htons(RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE);
	frm->op_result = mem->last_op.op_result;
	frm->address = htons(mem->last_op.address);
	frm->write_counter = htonl(mem->write_counter);
	compute_hmac(mem, frm, 1);
}

static uint16_t ioctl_emu_setkey(struct rpmb_emu *mem,
				 struct rpmb_data_frame *frm)
{
	if (mem->key_set) {
		EMSG("Key already set");
		return RPMB_RESULT_GENERAL_FAILURE;
	}
	dump_buffer("Setting key", frm->key_mac, 32);
	memcpy(mem->key, frm->key_mac, 32);
	mem->key_set = true;

	return RPMB_RESULT_OK;
}

static void ioctl_emu_get_keyprog_result(struct rpmb_emu *mem,
					 struct rpmb_data_frame *frm)
{
	frm->msg_type =
		htons(RPMB_MSG_TYPE_RESP_AUTH_KEY_PROGRAM);
	frm->op_result = mem->last_op.op_result;
}

static void ioctl_emu_read_ctr(struct rpmb_emu *mem,
			       struct rpmb_data_frame *frm)
{
	DMSG("Reading counter");
	frm->msg_type = htons(RPMB_MSG_TYPE_RESP_WRITE_COUNTER_VAL_READ);
	frm->write_counter = htonl(mem->write_counter);
	memcpy(frm->nonce, mem->nonce, 16);
	frm->op_result = compute_hmac(mem, frm, 1);
}

static uint32_t read_cid(uint16_t dev_id, uint8_t *cid)
{
	/* Taken from an actual eMMC chip */
	static const uint8_t test_cid[] = {
		/* MID (Manufacturer ID): Micron */
		0xfe,
		/* CBX (Device/BGA): BGA */
		0x01,
		/* OID (OEM/Application ID) */
		0x4e,
		/* PNM (Product name) "MMC04G" */
		0x4d, 0x4d, 0x43, 0x30, 0x34, 0x47,
		/* PRV (Product revision): 4.2 */
		0x42,
		/* PSN (Product serial number) */
		0xc8, 0xf6, 0x55, 0x2a,
		/*
		 * MDT (Manufacturing date):
		 * June, 2014
		 */
		0x61,
		/* (CRC7 (0xA) << 1) | 0x1 */
		0x15
	};

	(void)dev_id;
	memcpy(cid, test_cid, sizeof(test_cid));

	return TEEC_SUCCESS;
}

static void ioctl_emu_set_ext_csd(uint8_t *ext_csd)
{
	ext_csd[168] = EMU_RPMB_SIZE_MULT;
	ext_csd[222] = EMU_RPMB_REL_WR_SEC_C;
}

/* A crude emulation of the MMC ioctls we need for RPMB */
static int ioctl_emu(int fd, unsigned long request, ...)
{
	struct mmc_ioc_cmd *cmd;
	struct rpmb_data_frame *frm;
	uint16_t msg_type;
	struct rpmb_emu *mem = mem_for_fd(fd);
	va_list ap;

	if (request != MMC_IOC_CMD) {
		EMSG("Unsupported ioctl: 0x%lx", request);
		return -1;
	}
	if (!mem)
		return -1;

	va_start(ap, request);
	cmd = va_arg(ap, struct mmc_ioc_cmd *);
	va_end(ap);

	switch (cmd->opcode) {
	case MMC_SEND_EXT_CSD:
		ioctl_emu_set_ext_csd((uint8_t *)(uintptr_t)cmd->data_ptr);
		break;

	case MMC_WRITE_MULTIPLE_BLOCK:
		frm = (struct rpmb_data_frame *)(uintptr_t)cmd->data_ptr;
		msg_type = ntohs(frm->msg_type);

		switch (msg_type) {
		case RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM:
			mem->last_op.msg_type = msg_type;
			mem->last_op.op_result = ioctl_emu_setkey(mem, frm);
			break;

		case RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE:
			mem->last_op.msg_type = msg_type;
			mem->last_op.address = ntohs(frm->address);
			mem->last_op.op_result =
					ioctl_emu_mem_transfer(mem, frm,
							       cmd->blocks, 1);
			break;

		case RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ:
		case RPMB_MSG_TYPE_REQ_AUTH_DATA_READ:
			memcpy(mem->nonce, frm->nonce, 16);
			mem->last_op.msg_type = msg_type;
			mem->last_op.address = ntohs(frm->address);
			break;
		default:
			break;
		}
		break;

	case MMC_READ_MULTIPLE_BLOCK:
		frm = (struct rpmb_data_frame *)(uintptr_t)cmd->data_ptr;
		msg_type = ntohs(frm->msg_type);

		switch (mem->last_op.msg_type) {
		case RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM:
			ioctl_emu_get_keyprog_result(mem, frm);
			break;

		case RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE:
			ioctl_emu_get_write_result(mem, frm);
			break;

		case RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ:
			ioctl_emu_read_ctr(mem, frm);
			break;

		case RPMB_MSG_TYPE_REQ_AUTH_DATA_READ:
			ioctl_emu_mem_transfer(mem, frm, cmd->blocks, 0);
			break;

		default:
			EMSG("Unexpected");
			break;
		}
		break;

	default:
		EMSG("Unsupported ioctl opcode 0x%08x", cmd->opcode);
		return -1;
	}

	return 0;
}

static int mmc_rpmb_fd(uint16_t dev_id)
{
	(void)dev_id;

	/* Any value != -1 will do in test mode */
	return 0;
}

static int mmc_fd(uint16_t dev_id)
{
	(void)dev_id;

	return 0;
}

static void close_mmc_fd(int fd)
{
	(void)fd;
}

#endif /* RPMB_EMU */

/*
 * Extended CSD Register is 512 bytes and defines device properties
 * and selected modes.
 */
static uint32_t read_ext_csd(int fd, uint8_t *ext_csd)
{
	int st;
	struct mmc_ioc_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.blksz = 512;
	cmd.blocks = 1;
	cmd.flags = MMC_RSP_R1 | MMC_CMD_ADTC;
	cmd.opcode = MMC_SEND_EXT_CSD;
	mmc_ioc_cmd_set_data(cmd, ext_csd);

	st = IOCTL(fd, MMC_IOC_CMD, &cmd);
	if (st < 0)
		return TEEC_ERROR_GENERIC;

	return TEEC_SUCCESS;
}

static uint32_t rpmb_data_req(int fd, struct rpmb_data_frame *req_frm,
			      size_t req_nfrm, struct rpmb_data_frame *rsp_frm,
			      size_t rsp_nfrm)
{
	int st;
	size_t i;
	uint16_t msg_type = ntohs(req_frm->msg_type);
	struct mmc_ioc_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.blksz = 512;
	cmd.blocks = req_nfrm;
	cmd.data_ptr = (uintptr_t)req_frm;
	cmd.flags = MMC_RSP_R1 | MMC_CMD_ADTC;
	cmd.opcode = MMC_WRITE_MULTIPLE_BLOCK;
	cmd.write_flag = 1;

	for (i = 1; i < req_nfrm; i++) {
		if (req_frm[i].msg_type != msg_type) {
			EMSG("All request frames shall be of the same type");
			return TEEC_ERROR_BAD_PARAMETERS;
		}
	}

	DMSG("Req: %zu frame(s) of type 0x%04x", req_nfrm, msg_type);
	DMSG("Rsp: %zu frame(s)", rsp_nfrm);

	switch(msg_type) {
	case RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM:
	case RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE:
		if (rsp_nfrm != 1) {
			EMSG("Expected only one response frame");
			return TEEC_ERROR_BAD_PARAMETERS;
		}

		/* Send write request frame(s) */
		cmd.write_flag |= MMC_CMD23_ARG_REL_WR;
		/*
		 * Black magic: tested on a HiKey board with a HardKernel eMMC
		 * module. When postsleep values are zero, the kernel logs
		 * random errors: "mmc_blk_ioctl_cmd: Card Status=0x00000E00"
		 * and ioctl() fails.
		 */
		cmd.postsleep_min_us = 20000;
		cmd.postsleep_max_us = 50000;
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEEC_ERROR_GENERIC;
		cmd.postsleep_min_us = 0;
		cmd.postsleep_max_us = 0;

		/* Send result request frame */
		memset(rsp_frm, 0, 1);
		rsp_frm->msg_type = htons(RPMB_MSG_TYPE_REQ_RESULT_READ);
		cmd.data_ptr = (uintptr_t)rsp_frm;
		cmd.write_flag &= ~MMC_CMD23_ARG_REL_WR;
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEEC_ERROR_GENERIC;

		/* Read response frame */
		cmd.opcode = MMC_READ_MULTIPLE_BLOCK;
		cmd.write_flag = 0;
		cmd.blocks = rsp_nfrm;
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEEC_ERROR_GENERIC;
		break;

	case RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ:
		if (rsp_nfrm != 1) {
			EMSG("Expected only one response frame");
			return TEEC_ERROR_BAD_PARAMETERS;
		}
#if __GNUC__ > 6
		__attribute__((fallthrough));
#endif

	case RPMB_MSG_TYPE_REQ_AUTH_DATA_READ:
		if (req_nfrm != 1) {
			EMSG("Expected only one request frame");
			return TEEC_ERROR_BAD_PARAMETERS;
		}

		/* Send request frame */
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEEC_ERROR_GENERIC;

		/* Read response frames */
		cmd.data_ptr = (uintptr_t)rsp_frm;
		cmd.opcode = MMC_READ_MULTIPLE_BLOCK;
		cmd.write_flag = 0;
		cmd.blocks = rsp_nfrm;
		st = IOCTL(fd, MMC_IOC_CMD, &cmd);
		if (st < 0)
			return TEEC_ERROR_GENERIC;
		break;

	default:
		EMSG("Unsupported message type: %d", msg_type);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static uint32_t rpmb_get_dev_info(uint16_t dev_id, struct rpmb_dev_info *info)
{
	int fd;
	uint32_t res;
	uint8_t ext_csd[512];

	res = read_cid(dev_id, info->cid);
	if (res != TEEC_SUCCESS)
		return res;

	fd = mmc_fd(dev_id);
	if (fd < 0)
		return TEEC_ERROR_BAD_PARAMETERS;

	res = read_ext_csd(fd, ext_csd);
	if (res != TEEC_SUCCESS)
		goto err;

	info->rel_wr_sec_c = ext_csd[222];
	info->rpmb_size_mult = ext_csd[168];
	info->ret_code = RPMB_CMD_GET_DEV_INFO_RET_OK;

err:
	close_mmc_fd(fd);
	return res;
}


/*
 * req is one struct rpmb_req followed by one or more struct rpmb_data_frame
 * rsp is either one struct rpmb_dev_info or one or more struct rpmb_data_frame
 */
static uint32_t rpmb_process_request_unlocked(void *req, size_t req_size,
					      void *rsp, size_t rsp_size)
{
	struct rpmb_req *sreq = req;
	size_t req_nfrm;
	size_t rsp_nfrm;
	uint32_t res;
	int fd;

	if (req_size < sizeof(*sreq))
		return TEEC_ERROR_BAD_PARAMETERS;

	switch (sreq->cmd) {
	case RPMB_CMD_DATA_REQ:
		req_nfrm = (req_size - sizeof(struct rpmb_req)) / 512;
		rsp_nfrm = rsp_size / 512;
		fd = mmc_rpmb_fd(sreq->dev_id);
		if (fd < 0)
			return TEEC_ERROR_BAD_PARAMETERS;
		res = rpmb_data_req(fd, RPMB_REQ_DATA(req), req_nfrm, rsp,
				    rsp_nfrm);
		break;

	case RPMB_CMD_GET_DEV_INFO:
		if (req_size != sizeof(struct rpmb_req) ||
		    rsp_size != sizeof(struct rpmb_dev_info)) {
			EMSG("Invalid req/rsp size");
			return TEEC_ERROR_BAD_PARAMETERS;
		}
		res = rpmb_get_dev_info(sreq->dev_id,
					(struct rpmb_dev_info *)rsp);
		break;

	default:
		EMSG("Unsupported RPMB command: %d", sreq->cmd);
		res = TEEC_ERROR_BAD_PARAMETERS;
		break;
	}

	return res;
}


uint32_t rpmb_process_request(void *req, size_t req_size, void *rsp,
			      size_t rsp_size)
{
	uint32_t res;

	tee_supp_mutex_lock(&rpmb_mutex);
	res = rpmb_process_request_unlocked(req, req_size, rsp, rsp_size);
	tee_supp_mutex_unlock(&rpmb_mutex);

	return res;
}
