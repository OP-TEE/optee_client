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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <unistd.h>

#include <teec_trace.h>
#include <teec_rpc.h>
#include <teec_ta_load.h>
#include <tee_supp_fs.h>
#include <teec.h>

#define TEE_RPC_BUFFER_NUMBER 5

/* Flags of the shared memory. Also defined in tee_service.h in the kernel. */
/*
 * Maximum size of the device name
 */
#define TEEC_MAX_DEVNAME_SIZE 256

char devname1[TEEC_MAX_DEVNAME_SIZE];
char devname2[TEEC_MAX_DEVNAME_SIZE];

struct tee_rpc_cmd {
	union {
		void	*buffer;
		uint64_t padding_buf;
	};
	uint32_t size;
	uint32_t type;
	int fd;
	int reserved;
};

struct tee_rpc_invoke {
	uint32_t cmd;
	uint32_t res;
	uint32_t nbr_bf;
	uint32_t reserved;
	struct tee_rpc_cmd cmds[TEE_RPC_BUFFER_NUMBER];
};

struct tee_rpc_ta {
	TEEC_UUID uuid;
	uint32_t supp_ta_handle;
};

static int read_request(int fd, struct tee_rpc_invoke *request);
static void write_response(int fd, struct tee_rpc_invoke *request);
static void free_param(TEEC_SharedMemory *shared_mem);

struct share_mem_entry {
	TEEC_SharedMemory shared_mem;
	TAILQ_ENTRY(share_mem_entry) link;
};
static TAILQ_HEAD(, share_mem_entry) shared_memory_list =
	TAILQ_HEAD_INITIALIZER(shared_memory_list);

static void free_all_shared_memory(void)
{
	struct share_mem_entry *entry;

	DMSG(">");
	while (!TAILQ_EMPTY(&shared_memory_list)) {
		entry = TAILQ_FIRST(&shared_memory_list);
		TAILQ_REMOVE(&shared_memory_list, entry, link);
		free_param(&entry->shared_mem);
		free(entry);
	}
	DMSG("<");
}

static void free_shared_memory(int fd)
{
	struct share_mem_entry *entry;

	TAILQ_FOREACH(entry, &shared_memory_list, link)
		if (entry->shared_mem.d.fd == fd)
			break;

	if (!entry) {
		EMSG("Cannot find fd=%d\n", fd);
		return;
	}

	free_param(&entry->shared_mem);

	TAILQ_REMOVE(&shared_memory_list, entry, link);
	free(entry);
}

static TEEC_SharedMemory *add_shared_memory(int fd, size_t size)
{
	struct tee_shm_io shm;
	TEEC_SharedMemory *shared_mem;
	struct share_mem_entry *entry;

	entry = calloc(1, sizeof(struct share_mem_entry));
	if (!entry)
		return NULL;

	shared_mem = &entry->shared_mem;

	memset((void *)&shm, 0, sizeof(shm));
	shm.buffer = NULL;
	shm.size   = size;
	shm.registered = 0;
	shm.fd_shm = 0;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (ioctl(fd, TEE_ALLOC_SHM_IOC, &shm) != 0) {
		EMSG("Ioctl(TEE_ALLOC_SHM_IOC) failed! (%s)", strerror(errno));
		shared_mem = NULL;
		goto out;
	}

	shared_mem->size = size;
	shared_mem->d.fd = shm.fd_shm;

	shared_mem->buffer = mmap(NULL, size,
				  PROT_READ | PROT_WRITE, MAP_SHARED,
				  shared_mem->d.fd, 0);

	if (shared_mem->buffer == (void *)MAP_FAILED) {
		EMSG("mmap(%zu) failed - Error = %s", size, strerror(errno));
		close(shared_mem->d.fd);
		shared_mem = NULL;
		goto out;
	}

	TAILQ_INSERT_TAIL(&shared_memory_list, entry, link);
out:
	if (!shared_mem)
		free(entry);

	return shared_mem;
}

/* Get parameter allocated by secure world */
static int get_param(int fd, struct tee_rpc_invoke *inv, const uint32_t idx,
		     TEEC_SharedMemory *shared_mem)
{
	struct tee_shm_io shm;

	if (idx >= inv->nbr_bf)
		return -1;

	memset((void *)&shm, 0, sizeof(shm));

	shm.buffer = inv->cmds[idx].buffer;
	shm.size   = inv->cmds[idx].size;
	shm.registered = 0;
	shm.fd_shm = 0;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	if (ioctl(fd, TEE_GET_FD_FOR_RPC_SHM_IOC, &shm) != 0) {
		EMSG("Ioctl(TEE_ALLOC_SHM_IOC) failed! (%s)", strerror(errno));
		return -1;
	}

	memset(shared_mem, 0, sizeof(TEEC_SharedMemory));
	shared_mem->size = shm.size;
	shared_mem->flags = shm.flags;
	shared_mem->d.fd = shm.fd_shm;

	DMSG("size %u fd_shm %d", (int)shared_mem->size, shared_mem->d.fd);

	shared_mem->buffer = mmap(NULL, shared_mem->size,
				     PROT_READ | PROT_WRITE, MAP_SHARED,
				     shared_mem->d.fd, 0);

	if (shared_mem->buffer == (void *)MAP_FAILED) {
		dprintf(TRACE_ERROR, "mmap(%d, %p) failed - Error = %s\n",
			inv->cmds[idx].size, inv->cmds[idx].buffer,
			strerror(errno));
		close(shared_mem->d.fd);
		return -1;
	}
	/* Erase value, since we don't want to send back input memory to TEE. */
	inv->cmds[idx].buffer = 0;

	return 0;
}

/* Allocate new parameter to be used in RPC communication */
static TEEC_SharedMemory *alloc_param(int fd, struct tee_rpc_invoke *inv,
				      const uint32_t idx, size_t size)
{
	TEEC_SharedMemory *shared_mem;

	if (idx >= inv->nbr_bf) {
		EMSG("idx %d >= inv->nbr_bf %d", idx, inv->nbr_bf);
		return NULL;
	}

	if (inv->cmds[idx].buffer != NULL) {
		EMSG("cmd[idx].buffer != NULL");
		return NULL;
	}

	shared_mem = add_shared_memory(fd, size);
	if (shared_mem == 0) {
		EMSG("add_shared_memory() returned NULL");
		return NULL;
	}

	inv->cmds[idx].buffer = shared_mem->buffer;
	inv->cmds[idx].size = size;
	inv->cmds[idx].type = TEE_RPC_BUFFER;
	inv->cmds[idx].fd = shared_mem->d.fd;

	return shared_mem;
}

/* Release parameter recieved from get_param or alloc_param */
static void free_param(TEEC_SharedMemory *shared_mem)
{
	INMSG("%p %u (%p)", shared_mem->buffer,
	      (int)shared_mem->size, shared_mem);
	if (munmap(shared_mem->buffer, shared_mem->size) != 0)
		EMSG("munmap(%p, %u) failed - Error = %s",
		     shared_mem->buffer, (int)shared_mem->size,
		     strerror(errno));
	close(shared_mem->d.fd);
	OUTMSG();
}

static void process_fs(int fd, struct tee_rpc_invoke *inv)
{
	TEEC_SharedMemory shared_mem;

	INMSG();
	if (get_param(fd, inv, 0, &shared_mem)) {
		inv->res = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	tee_supp_fs_process(shared_mem.buffer, shared_mem.size);
	inv->res = TEEC_SUCCESS;;

	free_param(&shared_mem);
	OUTMSG();
}

static void load_ta(int fd, struct tee_rpc_invoke *inv)
{
	void *ta = NULL;
	int ta_found = 0;
	size_t size = 0;
	struct tee_rpc_ta *cmd;
	TEEC_SharedMemory shared_mem;

	INMSG();
	if (get_param(fd, inv, 0, &shared_mem)) {
		inv->res = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}
	cmd = (struct tee_rpc_ta *)shared_mem.buffer;

	ta_found = TEECI_LoadSecureModule(devname1, &cmd->uuid, &ta, &size);
	/* Tracked by 6408 */
	if (ta_found != TA_BINARY_FOUND)
		ta_found = TEECI_LoadSecureModule(devname2, &cmd->uuid, &ta, &size);

	if (ta_found == TA_BINARY_FOUND) {
		TEEC_SharedMemory *ta_shm = alloc_param(fd, inv, 1, size);

		if (!ta_shm) {
			inv->res = TEEC_ERROR_OUT_OF_MEMORY;
		} else {
			inv->res = TEEC_SUCCESS;

			memcpy(ta_shm->buffer, ta, size);

			/* Fd will come back from TEE for unload. */
			cmd->supp_ta_handle = ta_shm->d.fd;
		}

		free(ta);
	} else {
		EMSG("  TA not found");
		inv->res = TEEC_ERROR_ITEM_NOT_FOUND;
	}

	free_param(&shared_mem);
	OUTMSG();
}

static void free_ta(struct tee_rpc_invoke *inv)
{
	INMSG();
	free_shared_memory(inv->cmds[0].fd);
	inv->nbr_bf = 0;
	inv->res = TEEC_SUCCESS;
	OUTMSG();
}

static void get_ree_time(int fd, struct tee_rpc_invoke *inv)
{
	struct TEE_Time {
		uint32_t seconds;
		uint32_t millis;
	};
	struct timeval tv;

	TEEC_SharedMemory shared_mem;
	struct TEE_Time *tee_time;

	INMSG();
	if (get_param(fd, inv, 0, &shared_mem)) {
		inv->res = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	tee_time = (struct TEE_Time *)shared_mem.buffer;
	gettimeofday(&tv, NULL);

	tee_time->seconds = tv.tv_sec;
	tee_time->millis = tv.tv_usec / 1000;

	DMSG("%ds:%dms", tee_time->seconds, tee_time->millis);

	inv->res = TEEC_SUCCESS;

	/* Unmap the memory. */
	free_param(&shared_mem);
	OUTMSG();
}

int main(int argc, char *argv[])
{
	int fd;
	int n = 0;
	char devpath[TEEC_MAX_DEVNAME_SIZE];
	struct tee_rpc_invoke request;
	int ret;

	sprintf(devpath, "/dev/opteearmtz00");
	sprintf(devname1, "optee_armtz");
	sprintf(devname2, "teetz");

	while (--argc) {
		n++;
		if (strncmp(argv[n], "opteearmtz00", 12) == 0) {
			snprintf(devpath, TEEC_MAX_DEVNAME_SIZE, "%s", "/dev/opteearmtz00");
			snprintf(devname1, TEEC_MAX_DEVNAME_SIZE, "%s", "optee_armtz");
			snprintf(devname2, TEEC_MAX_DEVNAME_SIZE, "%s", "teetz");
		} else {
			EMSG("Invalid argument #%d", n);
			exit(EXIT_FAILURE);
		}
	}

	fd = open(devpath, O_RDWR);
	if (fd < 0) {
		EMSG("error opening [%s]", devpath);
		exit(EXIT_FAILURE);
	}

	if (tee_supp_fs_init() != 0) {
		EMSG("error tee_supp_fs_init");
		exit(EXIT_FAILURE);
	}

	IMSG("tee-supplicant running on %s", devpath);

	/* major failure on read kills supplicant, malformed data will not */
	do {
		DMSG("looping");
		ret = read_request(fd, &request);
		if (ret == 0) {
			switch (request.cmd) {
			case TEE_RPC_LOAD_TA:
				load_ta(fd, &request);
				break;

			case TEE_RPC_FREE_TA:
				free_ta(&request);
				break;

			case TEE_RPC_GET_TIME:
				get_ree_time(fd, &request);
				break;

			case TEE_RPC_FS:
				process_fs(fd, &request);
				break;
			default:
				EMSG("Cmd [0x%" PRIx32 "] not supported",
				     request.cmd);
				/* Not supported. */
				break;
			}

			write_response(fd, &request);
		}
	} while (ret >= 0);

	free_all_shared_memory();
	close(fd);

	return EXIT_SUCCESS;
}

static int read_request(int fd, struct tee_rpc_invoke *request)
{
	ssize_t res = 0;

	if (fd < 0) {
		EMSG("invalid fd");
		return -1;
	}

	res = read(fd, request, sizeof(*request));
	if (res < 0)
		return -1;

	if ((size_t)res < sizeof(*request) - sizeof(request->cmds)) {
		EMSG("error reading from driver");
		return 1;
	}

	if (sizeof(*request) - sizeof(request->cmds) +
	    sizeof(request->cmds[0]) * request->nbr_bf != (size_t)res) {
		DMSG("length read does not equal expected length");
		return 1;
	}

	return 0;
}

static void write_response(int fd, struct tee_rpc_invoke *request)
{
	size_t writesize;
	size_t res;

	if (fd < 0) {
		EMSG("invalid fd");
		return;
	}

	writesize = sizeof(*request) - sizeof(request->cmds) +
		sizeof(request->cmds[0]) * request->nbr_bf;

	res = write(fd, request, writesize);
	if (res != writesize)
		EMSG("error writing to device (%zu)", res);
}
