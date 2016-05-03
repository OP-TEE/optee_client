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

#include <assert.h>
#include <errno.h>
#include <handle.h>
#include <sql_fs.h>
#include <sqlfs.h>
#include <sqlfs_internal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <tee_fs.h>

#include <teec_trace.h>

/*
 * File handles
 */
struct file_state {
	int fd;
	char *path;
	off_t pos;
	struct fuse_file_info fi;
};

static struct handle_db fd_db = HANDLE_DB_INITIALIZER;

/*
 * Directory handles
 */

TAILQ_HEAD(dir_head, dir_entry);

struct dir_state {
	int handle;
	struct dir_head dir_entries;
};

struct dir_entry {
	char *name;
	TAILQ_ENTRY(dir_entry) link;
};

static struct handle_db dir_db = HANDLE_DB_INITIALIZER;

static sqlfs_t *db;

static void put_file(struct file_state *fs)
{
	if (!fs)
		return;

	if (fs->fd >= 0)
		handle_put(&fd_db, fs->fd);

	free(fs->path);
	free(fs);
}

static struct file_state *new_file(const char *path)
{
	struct file_state *fs;
	int fd;

	fs = calloc(1, sizeof(*fs));
	if (!fs)
		return NULL;
	fs->fd = -1;

	fs->path = strdup(path);
	if (!fs->path)
		goto err;

	fd = handle_get(&fd_db, fs);
	if (fd < 0)
		goto err;

	fs->fd = fd;
	return fs;
err:
	put_file(fs);
	return NULL;
}

static void put_dir(struct dir_state *ds)
{
	struct dir_entry *entry;

	if (!ds)
		return;

	if (ds->handle >= 0)
		handle_put(&dir_db, ds->handle);

	TAILQ_FOREACH(entry, &ds->dir_entries, link)
		free(entry->name);
	free(ds);
}

static struct dir_state *new_dir(void)
{
	struct dir_state *ds;
	int handle;

	ds = calloc(1, sizeof(*ds));
	if (!ds)
		return NULL;
	ds->handle = -1;

	TAILQ_INIT(&ds->dir_entries);

	handle = handle_get(&dir_db, ds);
	if (handle < 0)
		goto err;

	ds->handle = handle;
	return ds;
err:
	put_dir(ds);
	return NULL;
}

static int sql_fs_open(struct tee_fs_rpc *fsrpc)
{
	char *path = (char *)(fsrpc + 1);
	struct file_state *fs;
	int rc;

	fs = new_file(path);
	if (!fs)
		return -ENOMEM;

	fs->fi.flags = tee_fs_conv_oflags(fsrpc->flags);
	rc = sqlfs_proc_open(db, path, &fs->fi);
	if (rc < 0) {
		put_file(fs);
		return rc;
	}

	return fs->fd;
}

static int sql_fs_close(struct tee_fs_rpc *fsrpc)
{
	struct file_state *fs = handle_lookup(&fd_db, fsrpc->fd);

	if (!fs)
		return -EBADF;

	put_file(fs);
	return 0;
}

static int sql_fs_read(struct tee_fs_rpc *fsrpc)
{
	struct file_state *fs = handle_lookup(&fd_db, fsrpc->fd);
	void *data = (void *)(fsrpc + 1);
	size_t len = fsrpc->len;
	int n;

	if (!fs)
		return -EBADF;

	n = sqlfs_proc_read(db, fs->path, data, len, fs->pos, &fs->fi);
	if (n > 0)
		fs->pos += n;

	return n;
}

static int sql_fs_write(struct tee_fs_rpc *fsrpc)
{
	struct file_state *fs = handle_lookup(&fd_db, fsrpc->fd);
	void *data = (void *)(fsrpc + 1);
	size_t len = fsrpc->len;
	int n;

	if (!fs)
		return -EBADF;

	n = sqlfs_proc_write(db, fs->path, data, len, fs->pos, &fs->fi);
	if (n > 0)
		fs->pos += n;

	return n;
}

static int sql_fs_seek(struct tee_fs_rpc *fsrpc)
{
	struct file_state *fs = handle_lookup(&fd_db, fsrpc->fd);
	int whence = tee_fs_conv_whence(fsrpc->flags);

	if (!fs)
		return -EBADF;

	switch (whence) {
	case SEEK_SET:
		fs->pos = fsrpc->arg;
		break;
	case SEEK_CUR:
		fs->pos += fsrpc->arg;
		break;
	case SEEK_END:
		{
		struct stat sb;
		int rc;

		rc = sqlfs_proc_getattr(db, fs->path, &sb);
		if (rc < 0)
			return rc;
		fs->pos = sb.st_size + fsrpc->arg;
		}
		break;
	default:
		return -EINVAL;
	}

	return fs->pos;
}

static int sql_fs_unlink(struct tee_fs_rpc *fsrpc)
{
	char *path = (char *)(fsrpc + 1);

	return sqlfs_proc_unlink(db, path);
}

static int sql_fs_rename(struct tee_fs_rpc *fsrpc)
{
	char *paths = (char *)(fsrpc + 1); /* "old.txt\0new.txt\0" */
	char *from = paths;
	char *to = paths + strlen(paths) + 1;

	return sqlfs_proc_rename(db, from, to);
}

static int sql_fs_truncate(struct tee_fs_rpc *fsrpc)
{
	struct file_state *fs = handle_lookup(&fd_db, fsrpc->fd);

	if (!fs)
		return -EBADF;

	return sqlfs_proc_truncate(db, fs->path, fs->pos);
}

static int sql_fs_mkdir(struct tee_fs_rpc *fsrpc)
{
	char *path = (char *)(fsrpc + 1);
	mode_t mode = tee_fs_conv_mkdflags(fsrpc->flags);

	return sqlfs_proc_mkdir(db, path, mode);
}

#define FILLER_SUCCESS	0
#define FILLER_ERROR	1

static int fill_dir(void *buf, const char *name, const struct stat *statp,
		    off_t off)
{
	struct dir_state *ds = (struct dir_state *)buf;
	struct dir_entry *de = NULL;
	char *dname;
	(void)statp;
	(void)off;

	if (!strcmp(name, ".") || !strcmp(name, ".."))
		return FILLER_SUCCESS;

	dname = strdup(name);
	if (!dname)
		goto err;

	de = calloc(1, sizeof(*de));
	if (!de)
		goto err;

	de->name = dname;
	TAILQ_INSERT_TAIL(&ds->dir_entries, de, link);
	return FILLER_SUCCESS;
err:
	free(dname);
	free(de);
	return FILLER_ERROR;
}

static int sql_fs_opendir(struct tee_fs_rpc *fsrpc)
{
	char *path = (char *)(fsrpc + 1);
	struct dir_state *ds;
	int rc;

	ds = new_dir();
	if (!ds)
		return -ENOMEM;

	rc = sqlfs_proc_readdir(db, path, ds, fill_dir, 0, NULL);
	if (rc < 0)
		goto err;

	return ds->handle;
err:
	put_dir(ds);
	return rc;
}

static int sql_fs_closedir(struct tee_fs_rpc *fsrpc)
{
	struct dir_state *ds = handle_lookup(&dir_db, fsrpc->arg);

	if (!ds)
		return -EBADF;

	put_dir(ds);

	return 0;
}

static int sql_fs_readdir(struct tee_fs_rpc *fsrpc)
{
	struct dir_state *ds = handle_lookup(&dir_db, fsrpc->arg);
	char *outname = (char *)(fsrpc + 1);
	size_t outlen = fsrpc->len;
	size_t len;
	char *name;
	struct dir_entry *de;

	if (!ds)
		return -EBADF;

	de = TAILQ_FIRST(&ds->dir_entries);
	if (!de)
		return -ENOENT;

	name = de->name;
	assert(name);
	len = strnlen(name, outlen);
	if (len == outlen)
		return -ENAMETOOLONG;

	TAILQ_REMOVE(&ds->dir_entries, de, link);
	memcpy(outname, name, len + 1);

	return 0;
}

static int sql_fs_rmdir(struct tee_fs_rpc *fsrpc)
{
	char *path = (char *)(fsrpc + 1);

	return sqlfs_proc_rmdir(db, path);
}

static int sql_fs_access(struct tee_fs_rpc *fsrpc)
{
	char *path = (char *)(fsrpc + 1);
	int flags = tee_fs_conv_accessflags(fsrpc->flags);

	return sqlfs_proc_access(db, path, flags);
}

static int sql_fs_begin(void)
{
	if (sqlfs_begin_transaction(db))
		return 0;
	return -1;
}

static int sql_fs_end(struct tee_fs_rpc *fsrpc)
{
	int rollback = fsrpc->arg;

	if (sqlfs_complete_transaction(db, !rollback))
		return 0;
	return -1;
}

#ifndef SQL_FS_DB_PATH
#define SQL_FS_DB_PATH "/data/tee/sstore.db"
#endif

static void mkdir_recursive(const char *path, int mode)
{
	char *dpath = strdup(path);
	char *cur;
	char *slash;

	if (!dpath)
		return;

	cur = dpath;
	for (;;) {
		slash = strchr(cur, '/');
		if (!slash)
			break;
		*slash = '\0';
		mkdir(dpath, mode);
		*slash = '/';
		cur = slash + 1;
	}

	free(dpath);
}

int sql_fs_init(void)
{
	const char *db_path = SQL_FS_DB_PATH;
	int rc;

	mkdir_recursive(db_path, 0700);
	rc = sqlfs_open(db_path, &db);
	if (!rc) {
		EMSG("Failed to open or create %s", db_path);
		return -1;
	}

	return 0;
}

/*
 * Returns < 0 when the requested operation could not be understood. Otherwise
 * returns 0. In this case, operation status is stored in the command.
 * A negative operation status means error; negative errno values are sometimes
 * used for convenience (debugging). The caller (OP-TEE) should not depend on
 * these exact values as they obviously depend on the Operating System.
 */
int sql_fs_process(void *cmd, size_t cmd_size)
{
	struct tee_fs_rpc *fsrpc = cmd;
	int st;

	if (cmd_size < sizeof(struct tee_fs_rpc))
		return -1;

	if (!cmd)
		return -1;

	switch (fsrpc->op) {
	case TEE_FS_OPEN:
		st = sql_fs_open(fsrpc);
		break;
	case TEE_FS_CLOSE:
		st = sql_fs_close(fsrpc);
		break;
	case TEE_FS_READ:
		st = sql_fs_read(fsrpc);
		break;
	case TEE_FS_WRITE:
		st = sql_fs_write(fsrpc);
		break;
	case TEE_FS_SEEK:
		st = sql_fs_seek(fsrpc);
		break;
	case TEE_FS_UNLINK:
		st = sql_fs_unlink(fsrpc);
		break;
	case TEE_FS_RENAME:
		st = sql_fs_rename(fsrpc);
		break;
	case TEE_FS_TRUNC:
		st = sql_fs_truncate(fsrpc);
		break;
	case TEE_FS_MKDIR:
		st = sql_fs_mkdir(fsrpc);
		break;
	case TEE_FS_OPENDIR:
		st = sql_fs_opendir(fsrpc);
		break;
	case TEE_FS_CLOSEDIR:
		st = sql_fs_closedir(fsrpc);
		break;
	case TEE_FS_READDIR:
		st = sql_fs_readdir(fsrpc);
		break;
	case TEE_FS_RMDIR:
		st = sql_fs_rmdir(fsrpc);
		break;
	case TEE_FS_ACCESS:
		st = sql_fs_access(fsrpc);
		break;
	case TEE_FS_LINK:
		st = -ENOTSUP;
		break;
	case TEE_FS_BEGIN:
		st = sql_fs_begin();
		break;
	case TEE_FS_END:
		st = sql_fs_end(fsrpc);
		break;
	default:
		EMSG("Unexpected SQL FS operation: %d", fsrpc->op);
		return -1;
	}

	fsrpc->res = st;
	return 0;
}
