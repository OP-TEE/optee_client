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

#include <assert.h>

#define BUFFER_LENGTH 0x100
#define TEE_RPC_BUFFER_NUMBER 5

/* Flags of the shared memory. Also defined in tee_service.h in the kernel. */
#define SHM_ALLOCATE_FROM_PHYSICAL 0x100

struct tee_rpc_cmd {
	void *buffer;
	uint32_t size;
	uint32_t type;
	int fd;
};

struct tee_rpc_invoke {
	uint32_t cmd;
	uint32_t res;
	uint32_t nbr_bf;
	struct tee_rpc_cmd cmds[TEE_RPC_BUFFER_NUMBER];
};

struct tee_rpc_ta {
	TEEC_UUID uuid;
	uint32_t supp_ta_handle;
};

static enum tee_target tee_target = TEE_TARGET_UNKNOWN;

static bool read_request(int fd, struct tee_rpc_invoke *request);
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

static void free_shared_memory(struct share_mem_entry *entry)
{
	free_param(&entry->shared_mem);

	TAILQ_REMOVE(&shared_memory_list, entry, link);
	free(entry);
}

static void free_shared_memory_with_fd(int fd)
{
	struct share_mem_entry *entry;

	TAILQ_FOREACH(entry, &shared_memory_list, link)
		if (entry->shared_mem.d.fd == fd)
			break;

	if (!entry) {
		EMSG("Cannot find fd=%d\n", fd);
		return;
	}

	free_shared_memory(entry);
}

static TEEC_SharedMemory *add_shared_memory(int fd, size_t size)
{
	TEEC_SharedMemory *shared_mem;
	struct share_mem_entry *entry;

	entry = calloc(1, sizeof(struct share_mem_entry));
	if (!entry)
		return NULL;

	shared_mem = &entry->shared_mem;
	shared_mem->size = size;

	if (ioctl(fd, TEE_ALLOC_SHM_IOC, shared_mem) != 0) {
		EMSG("Ioctl(TEE_ALLOC_SHM_IOC) failed! (%s)", strerror(errno));
		shared_mem = NULL;
		goto out;
	}

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
	if (idx >= inv->nbr_bf)
		return -1;

	memset(shared_mem, 0, sizeof(TEEC_SharedMemory));
	shared_mem->size = inv->cmds[idx].size;
	shared_mem->flags |= SHM_ALLOCATE_FROM_PHYSICAL;
	shared_mem->buffer = inv->cmds[idx].buffer;
	if (ioctl(fd, TEE_ALLOC_SHM_IOC, shared_mem) != 0) {
		EMSG("Ioctl(TEE_ALLOC_SHM_IOC) failed! (%s)", strerror(errno));
		return -1;
	}

	shared_mem->buffer = mmap(NULL, shared_mem->size,
				     PROT_READ | PROT_WRITE, MAP_SHARED,
				     shared_mem->d.fd, 0);
	shared_mem->flags &= (~SHM_ALLOCATE_FROM_PHYSICAL);

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
	INMSG("%p %zu (%p)", shared_mem->buffer,
	      shared_mem->size, shared_mem);
	if (munmap(shared_mem->buffer, shared_mem->size) != 0)
		EMSG("munmap(%p, %zu) failed - Error = %s",
		     shared_mem->buffer, shared_mem->size,
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

	ta_found = TEECI_LoadSecureModule(tee_target, &cmd->uuid, &ta, &size);

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
	int fd;

	INMSG();
	/* TODO This parameter should come as a value parameter instead. */
	fd = (int)(uintptr_t)inv->cmds[0].buffer;
	free_shared_memory_with_fd(fd);
	inv->res = TEEC_SUCCESS;
	OUTMSG();
}

static void free_ta_with_fd(struct tee_rpc_invoke *inv)
{
	INMSG();
	free_shared_memory_with_fd(inv->cmds[0].fd);
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
	char devname[TEEC_MAX_DEVNAME_SIZE];
	memset(&devname, 0, sizeof(devname));

	while (--argc) {
		n++;
		if ((strlen(argv[n]) == 5) &&
		    (strncmp(argv[n], "teetz", 5) == 0)) {
			tee_target = TEE_TARGET_TZ;
			snprintf(devname, TEEC_MAX_DEVNAME_SIZE, "%s",
				 "/dev/teetz");
		} else {
			EMSG("Invalid argument #%d", n);
			exit(EXIT_FAILURE);
		}
	}

	/* If no arguments have been given, then we default to LX. */
	if (tee_target == TEE_TARGET_UNKNOWN) {
		tee_target = TEE_TARGET_TZ;
		sprintf(devname, "/dev/teetz");
	}

	fd = open(devname, O_RDWR);
	if (fd < 0) {
		EMSG("error opening [%s]", devname);
		exit(EXIT_FAILURE);
	}

	if (tee_supp_fs_init() != 0) {
		EMSG("error tee_supp_fs_init");
		exit(EXIT_FAILURE);
	}

	IMSG("tee-supplicant running on %s", devname);

	while (true) {
		struct tee_rpc_invoke request;
		DMSG("looping");

		if (read_request(fd, &request)) {
			switch (request.cmd) {
			case TEE_RPC_LOAD_TA:
				load_ta(fd, &request);
				break;

			case TEE_RPC_FREE_TA:
				free_ta(&request);
				break;

			case TEE_RPC_FREE_TA_WITH_FD:
				free_ta_with_fd(&request);
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
	}

	free_all_shared_memory();
	close(fd);

	return EXIT_SUCCESS;
}

static bool read_request(int fd, struct tee_rpc_invoke *request)
{
	size_t res = 0;

	if (fd < 0) {
		EMSG("invalid fd");
		return false;
	}

	res = read(fd, request, BUFFER_LENGTH);
	if (res < sizeof(*request) - sizeof(request->cmds)) {
		EMSG("error reading from driver");
		return false;
	}

	if (sizeof(*request) - sizeof(request->cmds) +
	    sizeof(request->cmds[0]) * request->nbr_bf != res) {
		DMSG("length read does not equal expected length");
		return false;
	}

	return true;
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
