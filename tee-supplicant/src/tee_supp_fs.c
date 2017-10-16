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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <teec_trace.h>
#include <tee_supp_fs.h>
#include <tee_supplicant.h>
#include <unistd.h>

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

#ifndef PATH_MAX
#define PATH_MAX 255
#endif

/* Path to all secure storage files. */
static char tee_fs_root[PATH_MAX];

#define TEE_FS_FILENAME_MAX_LENGTH 150

static pthread_mutex_t dir_handle_db_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct handle_db dir_handle_db =
		HANDLE_DB_INITIALIZER_WITH_MUTEX(&dir_handle_db_mutex);

static size_t tee_fs_get_absolute_filename(char *file, char *out,
					   size_t out_size)
{
	int s;

	if (!file || !out || (out_size <= strlen(tee_fs_root) + 1))
		return 0;

	s = snprintf(out, out_size, "%s%s", tee_fs_root, file);
	if (s < 0 || (size_t)s >= out_size)
		return 0;

	/* Safe to cast since we have checked that sizes are OK */
	return (size_t)s;
}

static int do_mkdir(const char *path, mode_t mode)
{
	struct stat st;

	if (mkdir(path, mode) != 0 && errno != EEXIST)
		return -1;

	if (stat(path, &st) != 0 && !S_ISDIR(st.st_mode))
		return -1;

	return 0;
}

static int mkpath(const char *path, mode_t mode)
{
	int status = 0;
	char *subpath = strdup(path);
	char *prev = subpath;
	char *curr;

	while (status == 0 && (curr = strchr(prev, '/')) != 0) {
		/*
		 * Check for root or double slash
		 */
		if (curr != prev) {
			*curr = '\0';
			status = do_mkdir(subpath, mode);
			*curr = '/';
		}
		prev = curr + 1;
	}
	if (status == 0)
		status = do_mkdir(path, mode);

	free(subpath);
	return status;
}

int tee_supp_fs_init(void)
{
	size_t n;
	mode_t mode = 0700;

	n = snprintf(tee_fs_root, sizeof(tee_fs_root), "%s/tee/", TEE_FS_PARENT_PATH);
	if (n >= sizeof(tee_fs_root))
		return -1;

	if (mkpath(tee_fs_root, mode) != 0)
		return -1;

	return 0;
}

static int open_wrapper(const char *fname, int flags)
{
	int fd;

	while (true) {
		fd = open(fname, flags | O_SYNC, 0600);
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
	if (fd < 0) {
		/*
		 * In case the problem is the filesystem is RO, retry with the
		 * open flags restricted to RO.
		 */
		fd = open_wrapper(abs_filename, O_RDONLY);
		if (fd < 0)
			return TEEC_ERROR_ITEM_NOT_FOUND;
	}

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
	if (!mkdir(d, 0700)) {
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
	if (mkdir(d, 0700))
		return TEEC_ERROR_GENERIC;

	/* Try to make directory for file again */
	strncpy(abs_dir, abs_filename, sizeof(abs_dir));
	abs_dir[sizeof(abs_dir) - 1] = '\0';
	d = dirname(abs_dir);
	if (mkdir(d, 0700)) {
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
	struct dirent *dent;
	bool empty = true;

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

	/*
	 * Ignore empty directories. Works around an issue when the
	 * data path is mounted over NFS. Due to the way OP-TEE implements
	 * TEE_CloseAndDeletePersistentObject1() currently, tee-supplicant
	 * still has a file descriptor open to the file when it's removed in
	 * ree_fs_new_remove(). In this case the NFS server may create a
	 * temporary reference called .nfs????, and the rmdir() call fails
	 * so that the TA directory is left over. Checking this special case
	 * here avoids that TEE_StartPersistentObjectEnumerator() returns
	 * TEE_SUCCESS when it should return TEEC_ERROR_ITEM_NOT_FOUND.
	 * Test case: "xtest 6009 6010".
	 */
	while ((dent = readdir(dir))) {
		if (dent->d_name[0] == '.')
			continue;
		empty = false;
		break;
	}
	if (empty) {
		closedir(dir);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}
	rewinddir(dir);

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

TEEC_Result tee_supp_fs_process(size_t num_params,
				struct tee_ioctl_param *params)
{
	if (!num_params || !tee_supp_param_is_value(params))
		return TEEC_ERROR_BAD_PARAMETERS;

	switch (params->u.value.a) {
	case OPTEE_MRF_OPEN:
		return ree_fs_new_open(num_params, params);
	case OPTEE_MRF_CREATE:
		return ree_fs_new_create(num_params, params);
	case OPTEE_MRF_CLOSE:
		return ree_fs_new_close(num_params, params);
	case OPTEE_MRF_READ:
		return ree_fs_new_read(num_params, params);
	case OPTEE_MRF_WRITE:
		return ree_fs_new_write(num_params, params);
	case OPTEE_MRF_TRUNCATE:
		return ree_fs_new_truncate(num_params, params);
	case OPTEE_MRF_REMOVE:
		return ree_fs_new_remove(num_params, params);
	case OPTEE_MRF_RENAME:
		return ree_fs_new_rename(num_params, params);
	case OPTEE_MRF_OPENDIR:
		return ree_fs_new_opendir(num_params, params);
	case OPTEE_MRF_CLOSEDIR:
		return ree_fs_new_closedir(num_params, params);
	case OPTEE_MRF_READDIR:
		return ree_fs_new_readdir(num_params, params);
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}
}
