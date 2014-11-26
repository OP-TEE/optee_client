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
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdint.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <tee_supp_fs.h>
#include <pthread.h>
#include "handle.h"

/*
 * Operations and defines shared with TEE.
 */
#define TEE_FS_OPEN       1
#define TEE_FS_CLOSE      2
#define TEE_FS_READ       3
#define TEE_FS_WRITE      4
#define TEE_FS_SEEK       5
#define TEE_FS_UNLINK     6
#define TEE_FS_RENAME     7
#define TEE_FS_TRUNC      8
#define TEE_FS_MKDIR      9
#define TEE_FS_OPENDIR   10
#define TEE_FS_CLOSEDIR  11
#define TEE_FS_READDIR   12
#define TEE_FS_RMDIR     13
#define TEE_FS_ACCESS    14

/*
 * Open flags, defines shared with TEE.
 */
#define TEE_FS_O_RDONLY 0x1
#define TEE_FS_O_WRONLY 0x2
#define TEE_FS_O_RDWR   0x4
#define TEE_FS_O_CREAT  0x8
#define TEE_FS_O_EXCL   0x10
#define TEE_FS_O_APPEND 0x20

/*
 * Seek flags, defines shared with TEE.
 */
#define TEE_FS_SEEK_SET 0x1
#define TEE_FS_SEEK_END 0x2
#define TEE_FS_SEEK_CUR 0x4

/*
 * Mkdir flags, defines shared with TEE.
 */
#define TEE_FS_S_IWUSR 0x1
#define TEE_FS_S_IRUSR 0x2

/*
 * Access flags, X_OK not supported, defines shared with TEE.
 */
#define TEE_FS_R_OK    0x1
#define TEE_FS_W_OK    0x2
#define TEE_FS_F_OK    0x4

/* Path to all secure storage files. */
#define TEE_FS_SUBPATH "/data"
#define TEE_FS_PATH "/data/tee/"

#ifndef PATH_MAX
#define PATH_MAX 255
#endif

#define TEE_FS_FILENAME_MAX_LENGTH 150

/*
 * Structure for file related RPC calls
 *
 * @op     The operation like open, close, read, write etc
 * @flags  Flags to the operation shared with secure world
 * @arg    Argument to operation
 * @fd     NW file descriptor
 * @len    Length of buffer at the end of this struct
 * @res    Result of the operation
 */
struct tee_fs_rpc {
	int op;
	int flags;
	int arg;
	int fd;
	uint32_t len;
	int res;
};

static pthread_mutex_t dir_handle_db_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct handle_db dir_handle_db =
		HANDLE_DB_INITIALIZER_WITH_MUTEX(&dir_handle_db_mutex);

/* Function to convert TEE open flags to UNIX IO */
static int tee_supp_fs_conv_oflags(int in)
{
	int flags = 0;

	if (in & TEE_FS_O_RDONLY)
		flags |= O_RDONLY;

	if (in & TEE_FS_O_WRONLY)
		flags |= O_WRONLY;

	if (in & TEE_FS_O_RDWR)
		flags |= O_RDWR;

	if (in & TEE_FS_O_CREAT)
		flags |= O_CREAT;

	if (in & TEE_FS_O_EXCL)
		flags |= O_EXCL;

	if (in & TEE_FS_O_APPEND)
		flags |= O_APPEND;

	return flags;
}

/* Function to convert TEE seek flags to UNIX IO */
static int tee_supp_fs_conv_whence(int in)
{
	int flags = 0;

	if (in & TEE_FS_SEEK_SET)
		flags |= SEEK_SET;

	if (in & TEE_FS_SEEK_END)
		flags |= SEEK_END;

	if (in & TEE_FS_SEEK_CUR)
		flags |= SEEK_CUR;

	return flags;
}

/* Function to convert TEE open flags to UNIX IO */
static mode_t tee_supp_fs_conv_mkdflags(int in)
{
	int flags = 0;

	if (in & TEE_FS_S_IWUSR)
		flags |= S_IWUSR;

	if (in & TEE_FS_S_IRUSR)
		flags |= S_IRUSR;

	return flags;
}

static int tee_supp_fs_conv_accessflags(int in)
{
	int flags = 0;

	if (in & TEE_FS_R_OK)
		flags |= R_OK;

	if (in & TEE_FS_W_OK)
		flags |= W_OK;

	if (in & TEE_FS_F_OK)
		flags |= F_OK;

	return flags;
}

static size_t tee_supp_fs_create_fname(char *file, char *out)
{
	strncpy(out, TEE_FS_PATH, sizeof(TEE_FS_PATH) + 1);
	strncat(out, file, PATH_MAX);
	return strlen(out);
}

static int tee_supp_fs_open(struct tee_fs_rpc *fsrpc)
{
	char fname[PATH_MAX];
	int flags;

	tee_supp_fs_create_fname((char *)(fsrpc + 1), fname);

	flags = tee_supp_fs_conv_oflags(fsrpc->flags);

	fsrpc->fd = open(fname, flags, S_IRUSR | S_IWUSR);

	return fsrpc->fd;
}

static int tee_supp_fs_close(struct tee_fs_rpc *fsrpc)
{
	return close(fsrpc->fd);
}

static int tee_supp_fs_read(struct tee_fs_rpc *fsrpc)
{
	void *data = (void *)(fsrpc + 1);

	return read(fsrpc->fd, data, fsrpc->len);
}

static int tee_supp_fs_write(struct tee_fs_rpc *fsrpc)
{
	void *data = (void *)(fsrpc + 1);

	return write(fsrpc->fd, data, fsrpc->len);
}

static int tee_supp_fs_seek(struct tee_fs_rpc *fsrpc)
{
	int wh = tee_supp_fs_conv_whence(fsrpc->flags);

	fsrpc->res = lseek(fsrpc->fd, fsrpc->arg, wh);

	return fsrpc->res;
}

static int tee_supp_fs_unlink(struct tee_fs_rpc *fsrpc)
{
	char fname[PATH_MAX];

	tee_supp_fs_create_fname((char *)(fsrpc + 1), fname);

	return unlink(fname);
}

static int tee_supp_fs_rename(struct tee_fs_rpc *fsrpc)
{
	char old_fn[PATH_MAX];
	char new_fn[PATH_MAX];
	size_t len = strlen((char *)(fsrpc + 1));

	tee_supp_fs_create_fname((char *)(fsrpc + 1), old_fn);
	tee_supp_fs_create_fname(((char *)(fsrpc + 1)) + len + 1, new_fn);

	return rename(old_fn, new_fn);
}

static int tee_supp_fs_truncate(struct tee_fs_rpc *fsrpc)
{
	return ftruncate(fsrpc->fd, fsrpc->arg);
}

static int tee_supp_fs_mkdir(struct tee_fs_rpc *fsrpc)
{
	char fname[PATH_MAX];
	mode_t mode;

	tee_supp_fs_create_fname((char *)(fsrpc + 1), fname);
	mode = tee_supp_fs_conv_mkdflags(fsrpc->flags);

	return mkdir(fname, mode);
}

static int tee_supp_fs_opendir(struct tee_fs_rpc *fsrpc)
{
	char fname[PATH_MAX];
	DIR *dir;
	int handle;

	tee_supp_fs_create_fname((char *)(fsrpc + 1), fname);

	dir = opendir(fname);
	if (!dir)
		return -1;

	handle = handle_get(&dir_handle_db, dir);
	if (handle < 0)
		closedir(dir);

	return handle;
}

static int tee_supp_fs_closedir(struct tee_fs_rpc *fsrpc)
{
	DIR *dir = handle_put(&dir_handle_db, fsrpc->arg);

	return closedir(dir);
}

static int tee_supp_fs_readdir(struct tee_fs_rpc *fsrpc)
{
	DIR *dir = handle_lookup(&dir_handle_db, fsrpc->arg);
	struct dirent *dirent;
	size_t len;

	do
		dirent = readdir(dir);
	while (dirent != NULL && dirent->d_name[0] == '.');

	if (dirent == NULL) {
		fsrpc->len = 0;
		return -1;
	}

	len = strlen(dirent->d_name);
	if (len > PATH_MAX)
		return -1;

	len++;
	memcpy((char *)(fsrpc + 1), dirent->d_name, len);
	fsrpc->len = len;

	return 0;
}

static int tee_supp_fs_rmdir(struct tee_fs_rpc *fsrpc)
{
	char fname[PATH_MAX];

	tee_supp_fs_create_fname((char *)(fsrpc + 1), fname);

	return rmdir(fname);
}

static int tee_supp_fs_access(struct tee_fs_rpc *fsrpc)
{
	char fname[PATH_MAX];
	int flags;

	int res;

	tee_supp_fs_create_fname((char *)(fsrpc + 1), fname);
	flags = tee_supp_fs_conv_accessflags(fsrpc->flags);

	res = access(fname, flags);

	return res;
}

int tee_supp_fs_init(void)
{
	struct stat st;

	mkdir(TEE_FS_SUBPATH, 0700);
	mkdir(TEE_FS_PATH, 0700);
	if (stat(TEE_FS_PATH, &st) != 0)
		return -1;
	return 0;
}

int tee_supp_fs_process(void *cmd, size_t cmd_size)
{
	struct tee_fs_rpc *fsrpc = cmd;
	int ret = -1;

	if (cmd_size < sizeof(struct tee_fs_rpc))
		return ret;

	if (cmd == NULL)
		return ret;

	switch (fsrpc->op) {
	case TEE_FS_OPEN:
		ret = tee_supp_fs_open(fsrpc);
		break;
	case TEE_FS_CLOSE:
		ret = tee_supp_fs_close(fsrpc);
		break;
	case TEE_FS_READ:
		ret = tee_supp_fs_read(fsrpc);
		break;
	case TEE_FS_WRITE:
		ret = tee_supp_fs_write(fsrpc);
		break;
	case TEE_FS_SEEK:
		ret = tee_supp_fs_seek(fsrpc);
		break;
	case TEE_FS_UNLINK:
		ret = tee_supp_fs_unlink(fsrpc);
		break;
	case TEE_FS_RENAME:
		ret = tee_supp_fs_rename(fsrpc);
		break;
	case TEE_FS_TRUNC:
		ret = tee_supp_fs_truncate(fsrpc);
		break;
	case TEE_FS_MKDIR:
		ret = tee_supp_fs_mkdir(fsrpc);
		break;
	case TEE_FS_OPENDIR:
		ret = tee_supp_fs_opendir(fsrpc);
		break;
	case TEE_FS_CLOSEDIR:
		ret = tee_supp_fs_closedir(fsrpc);
		break;
	case TEE_FS_READDIR:
		ret = tee_supp_fs_readdir(fsrpc);
		break;
	case TEE_FS_RMDIR:
		ret = tee_supp_fs_rmdir(fsrpc);
		break;
	case TEE_FS_ACCESS:
		ret = tee_supp_fs_access(fsrpc);
		break;
	default:
		break;
	}

	fsrpc->res = ret;

	return ret;
}
