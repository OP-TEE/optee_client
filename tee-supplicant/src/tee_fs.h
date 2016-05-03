/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
 * Structure for file related RPC calls
 *
 * @op     The operation like open, close, read, write etc
 * @flags  Flags to the operation shared with secure world
 * @arg    Argument to operation
 * @fd     Normal World file descriptor
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

/*
 * Operations shared with TEE.
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
#define TEE_FS_LINK      15
#define TEE_FS_BEGIN     16 /* SQL FS: begin transaction */
#define TEE_FS_END       17 /* SQL FS: end transaction */

/*
 * Open flags, defines shared with TEE.
 */
#define TEE_FS_O_RDONLY 0x1
#define TEE_FS_O_WRONLY 0x2
#define TEE_FS_O_RDWR   0x4
#define TEE_FS_O_CREAT  0x8
#define TEE_FS_O_EXCL   0x10
#define TEE_FS_O_APPEND 0x20
#define TEE_FS_O_TRUNC  0x40

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
#define TEE_FS_S_IXUSR 0x4

/*
 * Access flags, X_OK not supported, defines shared with TEE.
 */
#define TEE_FS_R_OK    0x1
#define TEE_FS_W_OK    0x2
#define TEE_FS_F_OK    0x4

/* Function to convert TEE open flags to UNIX IO */
static int tee_fs_conv_oflags(int in)
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

	if (in & TEE_FS_O_TRUNC)
		flags |= O_TRUNC;

	return flags;
}

/* Function to convert TEE seek flags to UNIX IO */
static int tee_fs_conv_whence(int in)
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
static mode_t tee_fs_conv_mkdflags(int in)
{
	int flags = 0;

	if (in & TEE_FS_S_IWUSR)
		flags |= S_IWUSR;

	if (in & TEE_FS_S_IRUSR)
		flags |= S_IRUSR;

	if (in & TEE_FS_S_IXUSR)
		flags |= S_IXUSR;

	return flags;
}

static int tee_fs_conv_accessflags(int in)
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

