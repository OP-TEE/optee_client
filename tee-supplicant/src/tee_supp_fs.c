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
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <handle.h>
#include <libgen.h>
#include <optee_msg_supplicant.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <teec_trace.h>
#include <tee_fs.h>
#include <tee_supp_fs.h>
#include <tee_supplicant.h>
#include <unistd.h>

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

/* Path to all secure storage files. */
#define TEE_FS_SUBPATH "/data"
#define TEE_FS_PATH "/data/tee/"

#ifndef PATH_MAX
#define PATH_MAX 255
#endif

#define TEE_FS_FILENAME_MAX_LENGTH 150

static pthread_mutex_t dir_handle_db_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct handle_db dir_handle_db =
		HANDLE_DB_INITIALIZER_WITH_MUTEX(&dir_handle_db_mutex);

static size_t tee_fs_get_absolute_filename(char *file, char *out,
					   size_t out_size)
{
	int s;

	if (!file || !out || (out_size <= sizeof(TEE_FS_PATH)))
		return 0;

	s = snprintf(out, out_size, "%s%s", TEE_FS_PATH, file);
	if (s < 0 || (size_t)s >= out_size)
		return 0;

	/* Safe to cast since we have checked that sizes are OK */
	return (size_t)s;
}

static int tee_fs_open(struct tee_fs_rpc *fsrpc)
{
	char abs_filename[PATH_MAX];
	char *filename = (char *)(fsrpc + 1);
	int flags;
	size_t filesize = tee_fs_get_absolute_filename(filename, abs_filename,
						       sizeof(abs_filename));
	if (!filesize)
		return -1; /* Corresponds to error using open */

	flags = tee_fs_conv_oflags(fsrpc->flags);
	fsrpc->fd = open(abs_filename, flags, S_IRUSR | S_IWUSR);
	return fsrpc->fd;
}

static int tee_fs_close(struct tee_fs_rpc *fsrpc)
{
	return close(fsrpc->fd);
}

static int tee_fs_read(struct tee_fs_rpc *fsrpc)
{
	void *data = (void *)(fsrpc + 1);

	return read(fsrpc->fd, data, fsrpc->len);
}

static int tee_fs_write(struct tee_fs_rpc *fsrpc)
{
	void *data = (void *)(fsrpc + 1);

	return write(fsrpc->fd, data, fsrpc->len);
}

static int tee_fs_seek(struct tee_fs_rpc *fsrpc)
{
	int wh = tee_fs_conv_whence(fsrpc->flags);

	fsrpc->res = lseek(fsrpc->fd, fsrpc->arg, wh);

	return fsrpc->res;
}

static int tee_fs_unlink(struct tee_fs_rpc *fsrpc)
{
	char abs_filename[PATH_MAX];
	char *filename = (char *)(fsrpc + 1);
	int ret = -1; /* Corresponds to error using unlink */
	size_t filesize = tee_fs_get_absolute_filename(filename, abs_filename,
						       sizeof(abs_filename));
	if (filesize)
		ret = unlink(abs_filename);

	return ret;
}

static int tee_fs_link(struct tee_fs_rpc *fsrpc)
{
	char old_fn[PATH_MAX];
	char new_fn[PATH_MAX];
	char *filenames = (char *)(fsrpc + 1);
	int ret = -1; /* Corresponds to error value for link */

	/*
	 * During a link operation secure world sends the two NULL terminated
	 * filenames as a single concatenated string, as for example:
	 *   "old.txt\0new.txt\0"
	 * Therefore we start by finding the offset to where the new filename
	 * begins.
	 */
	size_t offset_new_fn = strlen(filenames) + 1;
	size_t filesize = tee_fs_get_absolute_filename(filenames, old_fn,
						       sizeof(old_fn));
	if (!filesize)
		goto exit;

	filesize = tee_fs_get_absolute_filename(filenames + offset_new_fn,
						new_fn, sizeof(new_fn));
	if (filesize)
		ret = link(old_fn, new_fn);

exit:
	return ret;
}

static int tee_fs_rename(struct tee_fs_rpc *fsrpc)
{
	char old_fn[PATH_MAX];
	char new_fn[PATH_MAX];
	char *filenames = (char *)(fsrpc + 1);
	int ret = -1; /* Corresponds to error value for rename */

	/*
	 * During a rename operation secure world sends the two NULL terminated
	 * filenames as a single concatenated string, as for example:
	 *   "old.txt\0new.txt\0"
	 * Therefore we start by finding the offset to where the new filename
	 * begins.
	 */
	size_t offset_new_fn = strlen(filenames) + 1;
	size_t filesize = tee_fs_get_absolute_filename(filenames, old_fn,
						       sizeof(old_fn));
	if (!filesize)
		goto exit;

	filesize = tee_fs_get_absolute_filename(filenames + offset_new_fn,
						new_fn, sizeof(new_fn));
	if (filesize)
		ret = rename(old_fn, new_fn);

exit:
	return ret;
}

static int tee_fs_truncate(struct tee_fs_rpc *fsrpc)
{
	return ftruncate(fsrpc->fd, fsrpc->arg);
}

static int tee_fs_mkdir(struct tee_fs_rpc *fsrpc)
{
	char abs_dirname[PATH_MAX];
	char *dname = (char *)(fsrpc + 1);
	mode_t mode;
	int ret = -1; /* Same as mkir on error */
	size_t filesize = tee_fs_get_absolute_filename(dname, abs_dirname,
						       sizeof(abs_dirname));

	if (filesize) {
		mode = tee_fs_conv_mkdflags(fsrpc->flags);
		ret = mkdir(abs_dirname, mode);
	}

	return ret;
}

static int tee_fs_opendir(struct tee_fs_rpc *fsrpc)
{
	char abs_dirname[PATH_MAX];
	char *dname = (char *)(fsrpc + 1);
	DIR *dir;
	int handle = -1;
	size_t filesize = tee_fs_get_absolute_filename(dname, abs_dirname,
						       sizeof(abs_dirname));
	if (!filesize)
		goto exit;

	dir = opendir(abs_dirname);
	if (!dir)
		goto exit;

	handle = handle_get(&dir_handle_db, dir);
	if (handle < 0)
		closedir(dir);
exit:
	return handle;
}

static int tee_fs_closedir(struct tee_fs_rpc *fsrpc)
{
	DIR *dir = handle_put(&dir_handle_db, fsrpc->arg);

	return closedir(dir);
}

static int tee_fs_readdir(struct tee_fs_rpc *fsrpc)
{
	char *dname = (char *)(fsrpc + 1);
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
	memcpy(dname, dirent->d_name, len);
	fsrpc->len = len;

	return 0;
}

static int tee_fs_rmdir(struct tee_fs_rpc *fsrpc)
{
	char abs_dirname[PATH_MAX];
	char *dname = (char *)(fsrpc + 1);
	int ret = -1; /* Corresponds to the error value for rmdir */
	size_t filesize = tee_fs_get_absolute_filename(dname, abs_dirname,
						       sizeof(abs_dirname));

	if (filesize)
		ret = rmdir(abs_dirname);

	return ret;
}

static int tee_fs_access(struct tee_fs_rpc *fsrpc)
{
	char abs_filename[PATH_MAX];
	char *filename = (char *)(fsrpc + 1);
	int flags;
	int ret = -1; /* Corresponds to the error value for access */
	size_t filesize = tee_fs_get_absolute_filename(filename, abs_filename,
						       sizeof(abs_filename));
	if (filesize) {
		flags = tee_fs_conv_accessflags(fsrpc->flags);
		ret = access(abs_filename, flags);
	}

	return ret;
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

static TEEC_Result tee_supp_fs_process_primitive(void *cmd, size_t cmd_size)
{
	struct tee_fs_rpc *fsrpc = cmd;

	if (cmd_size < sizeof(struct tee_fs_rpc))
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!cmd)
		return TEEC_ERROR_BAD_PARAMETERS;

	switch (fsrpc->op) {
	case TEE_FS_OPEN:
		fsrpc->res = tee_fs_open(fsrpc);
		break;
	case TEE_FS_CLOSE:
		fsrpc->res = tee_fs_close(fsrpc);
		break;
	case TEE_FS_READ:
		fsrpc->res = tee_fs_read(fsrpc);
		break;
	case TEE_FS_WRITE:
		fsrpc->res = tee_fs_write(fsrpc);
		break;
	case TEE_FS_SEEK:
		fsrpc->res = tee_fs_seek(fsrpc);
		break;
	case TEE_FS_UNLINK:
		fsrpc->res = tee_fs_unlink(fsrpc);
		break;
	case TEE_FS_RENAME:
		fsrpc->res = tee_fs_rename(fsrpc);
		break;
	case TEE_FS_TRUNC:
		fsrpc->res = tee_fs_truncate(fsrpc);
		break;
	case TEE_FS_MKDIR:
		fsrpc->res = tee_fs_mkdir(fsrpc);
		break;
	case TEE_FS_OPENDIR:
		fsrpc->res = tee_fs_opendir(fsrpc);
		break;
	case TEE_FS_CLOSEDIR:
		fsrpc->res = tee_fs_closedir(fsrpc);
		break;
	case TEE_FS_READDIR:
		fsrpc->res = tee_fs_readdir(fsrpc);
		break;
	case TEE_FS_RMDIR:
		fsrpc->res = tee_fs_rmdir(fsrpc);
		break;
	case TEE_FS_ACCESS:
		fsrpc->res = tee_fs_access(fsrpc);
		break;
	case TEE_FS_LINK:
		fsrpc->res = tee_fs_link(fsrpc);
		break;
	default:
		EMSG("Unexpected REE FS operation: %d", fsrpc->op);
		return TEEC_ERROR_NOT_SUPPORTED;
	}

	return TEEC_SUCCESS;
}

static int open_wrapper(const char *fname, int flags)
{
	int fd;

	while (true) {
		fd = open(fname, flags);
		if (fd >= 0 || errno != EINTR)
			return fd;
	}
}

static TEEC_Result ree_fs_new_open(size_t num_params,
				   struct tee_ioctl_param *params)
{
	char abs_filename[PATH_MAX];
	char *fname;
	int fd;

	if (num_params != 3 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	fname = tee_supp_param_to_va(params + 1);
	if (!fname)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!tee_fs_get_absolute_filename(fname, abs_filename,
					  sizeof(abs_filename)))
		return TEEC_ERROR_BAD_PARAMETERS;

	fd = open_wrapper(abs_filename, O_RDWR);
	if (fd < 0)
		return TEEC_ERROR_ITEM_NOT_FOUND;

	params[2].u.value.a = fd;
	return TEEC_SUCCESS;
}

static TEEC_Result ree_fs_new_create(size_t num_params,
				     struct tee_ioctl_param *params)
{
	char abs_filename[PATH_MAX];
	char abs_dir[PATH_MAX];
	char *fname;
	char *d;
	int fd;
	const int flags = O_RDWR | O_CREAT | O_TRUNC;

	if (num_params != 3 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	fname = tee_supp_param_to_va(params + 1);
	if (!fname)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!tee_fs_get_absolute_filename(fname, abs_filename,
					  sizeof(abs_filename)))
		return TEEC_ERROR_BAD_PARAMETERS;

	fd = open_wrapper(abs_filename, flags);
	if (fd >= 0)
		goto out;
	if (errno != ENOENT)
		return TEEC_ERROR_GENERIC;

	/* Directory for file missing, try make to it */
	strncpy(abs_dir, abs_filename, sizeof(abs_dir));
	abs_dir[sizeof(abs_dir) - 1] = '\0';
	d = dirname(abs_dir);
	if (!mkdir(d, S_IRUSR | S_IWUSR | S_IXUSR)) {
		fd = open_wrapper(abs_filename, flags);
		if (fd >= 0)
			goto out;
		/*
		 * The directory was made but the file could still not be
		 * created.
		 */
		rmdir(d);
		return TEEC_ERROR_GENERIC;
	}
	if (errno != ENOENT)
		return TEEC_ERROR_GENERIC;

	/* Parent directory for file missing, try to make it */
	d = dirname(d);
	if (mkdir(d, S_IRUSR | S_IWUSR | S_IXUSR))
		return TEEC_ERROR_GENERIC;

	/* Try to make directory for file again */
	strncpy(abs_dir, abs_filename, sizeof(abs_dir));
	abs_dir[sizeof(abs_dir) - 1] = '\0';
	d = dirname(abs_dir);
	if (mkdir(d, S_IRUSR | S_IWUSR | S_IXUSR)) {
		d = dirname(d);
		rmdir(d);
		return TEEC_ERROR_GENERIC;
	}

	fd = open_wrapper(abs_filename, flags);
	if (fd < 0) {
		rmdir(d);
		d = dirname(d);
		rmdir(d);
		return TEEC_ERROR_GENERIC;
	}

out:
	params[2].u.value.a = fd;
	return TEEC_SUCCESS;
}

static TEEC_Result ree_fs_new_close(size_t num_params,
				    struct tee_ioctl_param *params)
{
	int fd;

	if (num_params != 1 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	fd = params[0].u.value.b;
	while (close(fd)) {
		if (errno != EINTR)
			return TEEC_ERROR_GENERIC;
	}
	return TEEC_SUCCESS;
}

static TEEC_Result ree_fs_new_read(size_t num_params,
				   struct tee_ioctl_param *params)
{
	uint8_t *buf;
	size_t len;
	off_t offs;
	int fd;
	ssize_t r;
	size_t s;

	if (num_params != 2 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	fd = params[0].u.value.b;
	offs = params[0].u.value.c;

	buf = tee_supp_param_to_va(params + 1);
	if (!buf)
		return TEEC_ERROR_BAD_PARAMETERS;
	len = params[1].u.memref.size;

	s = 0;
	r = -1;
	while (r && len) {
		r = pread(fd, buf, len, offs);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return TEEC_ERROR_GENERIC;
		}
		assert((size_t)r <= len);
		buf += r;
		len -= r;
		offs += r;
		s += r;
	}

	params[1].u.memref.size = s;
	return TEEC_SUCCESS;
}

static TEEC_Result ree_fs_new_write(size_t num_params,
				    struct tee_ioctl_param *params)
{
	uint8_t *buf;
	size_t len;
	off_t offs;
	int fd;
	ssize_t r;

	if (num_params != 2 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	fd = params[0].u.value.b;
	offs = params[0].u.value.c;

	buf = tee_supp_param_to_va(params + 1);
	if (!buf)
		return TEEC_ERROR_BAD_PARAMETERS;
	len = params[1].u.memref.size;

	while (len) {
		r = pwrite(fd, buf, len, offs);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return TEEC_ERROR_GENERIC;
		}
		assert((size_t)r <= len);
		buf += r;
		len -= r;
		offs += r;
	}

	return TEEC_SUCCESS;
}

static TEEC_Result ree_fs_new_truncate(size_t num_params,
				       struct tee_ioctl_param *params)
{
	size_t len;
	int fd;

	if (num_params != 1 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	fd = params[0].u.value.b;
	len = params[0].u.value.c;

	while (ftruncate(fd, len)) {
		if (errno != EINTR)
			return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static TEEC_Result ree_fs_new_remove(size_t num_params,
				     struct tee_ioctl_param *params)
{
	char abs_filename[PATH_MAX];
	char *fname;
	char *d;

	if (num_params != 2 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	fname = tee_supp_param_to_va(params + 1);
	if (!fname)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!tee_fs_get_absolute_filename(fname, abs_filename,
					  sizeof(abs_filename)))
		return TEEC_ERROR_BAD_PARAMETERS;

	if (unlink(abs_filename)) {
		if (errno == ENOENT)
			return TEEC_ERROR_ITEM_NOT_FOUND;
		return TEEC_ERROR_GENERIC;
	}

	/* If a file is removed, maybe the directory can be removed to? */
	d = dirname(abs_filename);
	if (!rmdir(d)) {
		/*
		 * If the directory was removed, maybe the parent directory
		 * can be removed too?
		 */
		d = dirname(d);
		rmdir(d);
	}

	return TEEC_SUCCESS;
}

static TEEC_Result ree_fs_new_rename(size_t num_params,
				     struct tee_ioctl_param *params)
{
	char old_abs_filename[PATH_MAX];
	char new_abs_filename[PATH_MAX];
	char *old_fname;
	char *new_fname;
	bool overwrite;

	if (num_params != 3 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	overwrite = !!params[0].u.value.b;

	old_fname = tee_supp_param_to_va(params + 1);
	if (!old_fname)
		return TEEC_ERROR_BAD_PARAMETERS;

	new_fname = tee_supp_param_to_va(params + 2);
	if (!new_fname)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!tee_fs_get_absolute_filename(old_fname, old_abs_filename,
					  sizeof(old_abs_filename)))
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!tee_fs_get_absolute_filename(new_fname, new_abs_filename,
					  sizeof(new_abs_filename)))
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!overwrite) {
		struct stat st;

		if (!stat(new_abs_filename, &st))
			return TEEC_ERROR_ACCESS_CONFLICT;
	}
	if (rename(old_abs_filename, new_abs_filename)) {
		if (errno == ENOENT)
			return TEEC_ERROR_ITEM_NOT_FOUND;
	}
	return TEEC_SUCCESS;
}

static TEEC_Result ree_fs_new_opendir(size_t num_params,
				      struct tee_ioctl_param *params)
{
	char abs_filename[PATH_MAX];
	char *fname;
	DIR *dir;
	int handle;

	if (num_params != 3 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	fname = tee_supp_param_to_va(params + 1);
	if (!fname)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!tee_fs_get_absolute_filename(fname, abs_filename,
					  sizeof(abs_filename)))
		return TEEC_ERROR_BAD_PARAMETERS;

	dir = opendir(abs_filename);
	if (!dir)
		return TEEC_ERROR_ITEM_NOT_FOUND;

	handle = handle_get(&dir_handle_db, dir);
	if (handle < 0) {
		closedir(dir);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	params[2].u.value.a = handle;
	return TEEC_SUCCESS;
}

static TEEC_Result ree_fs_new_closedir(size_t num_params,
				       struct tee_ioctl_param *params)
{
	DIR *dir;

	if (num_params != 1 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT)
		return TEEC_ERROR_BAD_PARAMETERS;

	dir = handle_put(&dir_handle_db, params[0].u.value.b);
	if (!dir)
		return TEEC_ERROR_BAD_PARAMETERS;

	closedir(dir);

	return TEEC_SUCCESS;
}

static TEEC_Result ree_fs_new_readdir(size_t num_params,
				      struct tee_ioctl_param *params)
{
	DIR *dir;
	struct dirent *dirent;
	char *buf;
	size_t len;
	size_t fname_len;

	if (num_params != 2 ||
	    (params[0].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) !=
			TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT)
		return TEEC_ERROR_BAD_PARAMETERS;


	buf = tee_supp_param_to_va(params + 1);
	if (!buf)
		return TEEC_ERROR_BAD_PARAMETERS;
	len = params[1].u.memref.size;

	dir = handle_lookup(&dir_handle_db, params[0].u.value.b);
	if (!dir)
		return TEEC_ERROR_BAD_PARAMETERS;

	while (true) {
		dirent = readdir(dir);
		if (!dirent)
			return TEEC_ERROR_ITEM_NOT_FOUND;
		if (dirent->d_name[0] != '.')
			break;
	}

	fname_len = strlen(dirent->d_name) + 1;
	params[1].u.memref.size = fname_len;
	if (fname_len > len)
		return TEEC_ERROR_SHORT_BUFFER;

	memcpy(buf, dirent->d_name, fname_len);

	return TEEC_SUCCESS;
}

TEEC_Result tee_supp_fs_process(struct tee_iocl_supp_recv_arg *recv)
{
	struct tee_ioctl_param *param = (void *)(recv + 1);

	if (recv->num_params == 1 && tee_supp_param_is_memref(param)) {
		void *va = tee_supp_param_to_va(param);

		if (!va)
			return TEEC_ERROR_BAD_PARAMETERS;
		return tee_supp_fs_process_primitive(va, param->u.memref.size);
	}

	if (!tee_supp_param_is_value(param))
		return TEEC_ERROR_BAD_PARAMETERS;

	switch (param->u.value.a) {
	case OPTEE_MRF_OPEN:
		return ree_fs_new_open(recv->num_params, param);
	case OPTEE_MRF_CREATE:
		return ree_fs_new_create(recv->num_params, param);
	case OPTEE_MRF_CLOSE:
		return ree_fs_new_close(recv->num_params, param);
	case OPTEE_MRF_READ:
		return ree_fs_new_read(recv->num_params, param);
	case OPTEE_MRF_WRITE:
		return ree_fs_new_write(recv->num_params, param);
	case OPTEE_MRF_TRUNCATE:
		return ree_fs_new_truncate(recv->num_params, param);
	case OPTEE_MRF_REMOVE:
		return ree_fs_new_remove(recv->num_params, param);
	case OPTEE_MRF_RENAME:
		return ree_fs_new_rename(recv->num_params, param);
	case OPTEE_MRF_OPENDIR:
		return ree_fs_new_opendir(recv->num_params, param);
	case OPTEE_MRF_CLOSEDIR:
		return ree_fs_new_closedir(recv->num_params, param);
	case OPTEE_MRF_READDIR:
		return ree_fs_new_readdir(recv->num_params, param);
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}
}
