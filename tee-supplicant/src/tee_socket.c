/*
 * Copyright (c) 2016-2017, Linaro Limited
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
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <optee_msg_supplicant.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <tee_client_api.h>
#include <teec_trace.h>
#include <tee_socket.h>
#include <tee_supplicant.h>
#include <unistd.h>

#include "handle.h"
#include "__tee_isocket_defines.h"
#include "__tee_ipsocket.h"
#include "__tee_tcpsocket_defines.h"
#include "__tee_tcpsocket_defines_extensions.h"
#include "__tee_udpsocket_defines.h"

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>


struct sock_instance {
	uint32_t id;
	struct handle_db db;
	TAILQ_ENTRY(sock_instance) link;
};

static pthread_mutex_t sock_mutex = PTHREAD_MUTEX_INITIALIZER;
TAILQ_HEAD(, sock_instance) sock_instances =
		TAILQ_HEAD_INITIALIZER(sock_instances);

static void sock_lock(void)
{
	pthread_mutex_lock(&sock_mutex);
}

static void sock_unlock(void)
{
	pthread_mutex_unlock(&sock_mutex);
}

static struct sock_instance *sock_instance_find(uint32_t instance_id)
{
	struct sock_instance *si;

	TAILQ_FOREACH(si, &sock_instances, link) {
		if (si->id == instance_id)
			return si;
	}
	return NULL;
}

static void *fd_to_handle_ptr(int fd)
{
	uintptr_t ptr;

	assert(fd >= 0);
	ptr = fd + 1;
	return (void *)ptr;
}

static int handle_ptr_to_fd(void *ptr)
{
	assert(ptr);
	return (uintptr_t)ptr - 1;
}

static int sock_handle_get(uint32_t instance_id, int fd)
{
	int handle = -1;
	struct sock_instance *si;

	sock_lock();

	si = sock_instance_find(instance_id);
	if (!si) {
		si = calloc(1, sizeof(*si));
		if (!si)
			goto out;
		si->id = instance_id;
		TAILQ_INSERT_TAIL(&sock_instances, si, link);
	}

	handle = handle_get(&si->db, fd_to_handle_ptr(fd));
out:
	sock_unlock();
	return handle;
}

static int sock_handle_to_fd(uint32_t instance_id, uint32_t handle)
{
	int fd = -1;
	struct sock_instance *si;

	sock_lock();
	si = sock_instance_find(instance_id);
	if (si)
		fd = handle_ptr_to_fd(handle_lookup(&si->db, handle));
	sock_unlock();
	return fd;
}

static void sock_handle_put(uint32_t instance_id, uint32_t handle)
{
	struct sock_instance *si;

	sock_lock();
	si = sock_instance_find(instance_id);
	if (si)
		handle_put(&si->db, handle);
	sock_unlock();
}

static bool chk_pt(struct tee_ioctl_param *param, uint32_t type)
{
	return (param->attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) == type;
}

static int fd_flags_add(int fd, int flags)
{
	int val;

	val = fcntl(fd, F_GETFD, 0);
	if (val == -1)
		return -1;

	val |= flags;

	return fcntl(fd, F_SETFL, val);
}

static TEEC_Result sock_connect(uint32_t ip_vers, unsigned int protocol,
				const char *server, uint16_t port, int *ret_fd)
{
	TEEC_Result r = TEEC_ERROR_GENERIC;
	struct addrinfo hints;
	struct addrinfo *res0;
	struct addrinfo *res;
	int fd = -1;
	char port_name[10];

	snprintf(port_name, sizeof(port_name), "%" PRIu16, port);

	memset(&hints, 0, sizeof(hints));

	switch (ip_vers) {
	case TEE_IP_VERSION_DC:
		hints.ai_family = AF_UNSPEC;
		break;
	case TEE_IP_VERSION_4:
		hints.ai_family = AF_INET;
		break;
	case TEE_IP_VERSION_6:
		hints.ai_family = AF_INET6;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (protocol == TEE_ISOCKET_PROTOCOLID_TCP)
		hints.ai_socktype = SOCK_STREAM;
	else if (protocol == TEE_ISOCKET_PROTOCOLID_UDP)
		hints.ai_socktype = SOCK_DGRAM;
	else
		return TEEC_ERROR_BAD_PARAMETERS;

	if (getaddrinfo(server, port_name, &hints, &res0))
		return TEE_ISOCKET_ERROR_HOSTNAME;

	for (res = res0; res; res = res->ai_next) {
		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd == -1) {
			if (errno == ENOMEM || errno == ENOBUFS)
				r = TEE_ISOCKET_ERROR_OUT_OF_RESOURCES;
			else
				r = TEEC_ERROR_GENERIC;
			continue;
		}

		if (connect(fd, res->ai_addr, res->ai_addrlen)) {
			if (errno == ETIMEDOUT)
				r = TEE_ISOCKET_ERROR_TIMEOUT;
			else
				r = TEEC_ERROR_COMMUNICATION;

			close(fd);
			fd = -1;
			continue;
		}

		if (fd_flags_add(fd, O_NONBLOCK)) {
			close(fd);
			fd = -1;
			r = TEEC_ERROR_GENERIC;
			break;
		}

		r = TEEC_SUCCESS;
		break;
	}

	freeaddrinfo(res0);
	*ret_fd = fd;
	return r;
}

static TEEC_Result tee_socket_open(size_t num_params,
				   struct tee_ioctl_param *params)
{
	TEEC_Result res;
	int handle;
	int fd;
	uint32_t instance_id;
	char *server;
	uint32_t ip_vers;
	uint16_t port;
	uint32_t protocol;

	if (num_params != 4 ||
	    !chk_pt(params + 0, TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT) ||
	    !chk_pt(params + 1, TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT) ||
	    !chk_pt(params + 2, TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT) ||
	    !chk_pt(params + 3, TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT))
		return TEEC_ERROR_BAD_PARAMETERS;

	instance_id = params[0].u.value.b;
	port = params[1].u.value.a;
	protocol = params[1].u.value.b;
	ip_vers = params[1].u.value.c;

	server = tee_supp_param_to_va(params + 2);
	if (!server || server[params[2].u.memref.size - 1] != '\0')
		return TEE_ISOCKET_ERROR_HOSTNAME;

	res = sock_connect(ip_vers, protocol, server, port, &fd);
	if (res != TEEC_SUCCESS)
		return res;

	handle = sock_handle_get(instance_id, fd);
	if (handle < 0) {
		close(fd);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	params[3].u.value.a = handle;
	return TEEC_SUCCESS;
}

static TEEC_Result tee_socket_close(size_t num_params,
				    struct tee_ioctl_param *params)
{
	int handle;
	uint32_t instance_id;
	int fd;

	if (num_params != 1 ||
	    !chk_pt(params + 0, TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT))
		return TEEC_ERROR_BAD_PARAMETERS;

	instance_id = params[0].u.value.b;
	handle = params[0].u.value.c;
	fd = sock_handle_to_fd(instance_id, handle);
	if (fd < 0)
		return TEEC_ERROR_BAD_PARAMETERS;
	sock_handle_put(instance_id, handle);
	if (close(fd)) {
		EMSG("tee_socket_close: close(%d): %s", fd, strerror(errno));
		return TEEC_ERROR_GENERIC;
	}
	return TEEC_SUCCESS;
}

static void sock_close_cb(int handle, void *ptr, void *arg)
{
	struct sock_instance *si = arg;
	int fd = handle_ptr_to_fd(ptr);

	if (close(fd))
		EMSG("sock_close_cb instance_id %d handle %d fd %d: %s",
		     si->id, handle, fd, strerror(errno));
}

static TEEC_Result tee_socket_close_all(size_t num_params,
					struct tee_ioctl_param *params)
{
	uint32_t instance_id;
	struct sock_instance *si;

	if (num_params != 1 ||
	    !chk_pt(params + 0, TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT))
		return TEEC_ERROR_BAD_PARAMETERS;

	instance_id = params[0].u.value.b;
	sock_lock();
	si = sock_instance_find(instance_id);
	if (si)
		handle_foreach_put(&si->db, sock_close_cb, si);
	sock_unlock();

	return TEEC_SUCCESS;
}

#define TS_NSEC_PER_SEC	1000000000

static void ts_add(const struct timespec *a, const struct timespec *b,
		   struct timespec *res)
{
	res->tv_sec = a->tv_sec + b->tv_sec;
	res->tv_nsec = a->tv_nsec + b->tv_nsec;
	if (res->tv_nsec >= TS_NSEC_PER_SEC) {
		res->tv_sec++;
		res->tv_nsec -= TS_NSEC_PER_SEC;
	}
}

static int ts_diff_to_polltimeout(const struct timespec *a,
				  const struct timespec *b)
{
	struct timespec diff;

	diff.tv_sec = a->tv_sec - b->tv_sec;
	diff.tv_nsec = a->tv_nsec - b->tv_nsec;
	if (a->tv_nsec < b->tv_nsec) {
		diff.tv_nsec += TS_NSEC_PER_SEC;
		diff.tv_sec--;
	}

	if ((diff.tv_sec - 1) > (INT_MAX / 1000))
		return INT_MAX;
	return diff.tv_sec * 1000 + diff.tv_nsec / (TS_NSEC_PER_SEC / 1000);
}

static void ts_delay_from_millis(uint32_t millis, struct timespec *res)
{
	res->tv_sec = millis / 1000;
	res->tv_nsec = (millis % 1000) * (TS_NSEC_PER_SEC / 1000);
}

static TEEC_Result poll_with_timeout(struct pollfd *pfd, nfds_t nfds,
				     uint32_t timeout)
{
	struct timespec now;
	struct timespec until = { 0, 0 }; /* gcc warning */
	int to = 0;
	int r;

	if (timeout == OPTEE_MRC_SOCKET_TIMEOUT_BLOCKING) {
		to = -1;
	} else {
		struct timespec delay;

		ts_delay_from_millis(timeout, &delay);

		if (clock_gettime(CLOCK_REALTIME, &now))
			return TEEC_ERROR_GENERIC;

		ts_add(&now, &delay, &until);
	}

	while (true) {
		if (to != -1)
			to = ts_diff_to_polltimeout(&until, &now);

		r = poll(pfd, nfds, to);
		if (!r)
			return TEE_ISOCKET_ERROR_TIMEOUT;
		if (r == -1) {
			/*
			 * If we're interrupted by a signal treat
			 * recalculate the timeout (if needed) and wait
			 * again.
			 */
			if (errno == EINTR) {
				if (to != -1 &&
				    clock_gettime(CLOCK_REALTIME, &now))
					return TEEC_ERROR_GENERIC;
				continue;
			}
			return TEEC_ERROR_BAD_PARAMETERS;
		}
		return TEEC_SUCCESS;
	}
}

static TEEC_Result write_with_timeout(int fd, const void *buf, size_t *blen,
				      uint32_t timeout)
{
	TEEC_Result res;
	struct pollfd pfd = { .fd = fd, .events = POLLOUT };
	ssize_t r;

	res = poll_with_timeout(&pfd, 1, timeout);
	if (res != TEEC_SUCCESS)
		return res;

	r = write(fd, buf, *blen);
	if (r == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return TEE_ISOCKET_ERROR_TIMEOUT;
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	*blen = r;
	return TEEC_SUCCESS;
}

static TEEC_Result tee_socket_send(size_t num_params,
				   struct tee_ioctl_param *params)
{
	TEEC_Result res;
	int handle;
	int fd;
	uint32_t instance_id;
	void *buf;
	size_t bytes;

	if (num_params != 3 ||
	    !chk_pt(params + 0, TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT) ||
	    !chk_pt(params + 1, TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT) ||
	    !chk_pt(params + 2, TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT))
		return TEEC_ERROR_BAD_PARAMETERS;

	instance_id = params[0].u.value.b;
	handle = params[0].u.value.c;
	fd = sock_handle_to_fd(instance_id, handle);
	if (fd < 0)
		return TEEC_ERROR_BAD_PARAMETERS;

	buf = tee_supp_param_to_va(params + 1);
	bytes = params[1].u.memref.size;
	res = write_with_timeout(fd, buf, &bytes, params[2].u.value.a);
	if (res == TEEC_SUCCESS)
		params[2].u.value.b = bytes;
	return res;
}

static TEEC_Result read_with_timeout(int fd, void *buf, size_t *blen,
				     uint32_t timeout)
{
	TEEC_Result res;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	ssize_t r;

	res = poll_with_timeout(&pfd, 1, timeout);
	if (res != TEEC_SUCCESS)
		return res;

	r = read(fd, buf, *blen);
	if (r == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return TEE_ISOCKET_ERROR_TIMEOUT;
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	*blen = r;
	return TEEC_SUCCESS;
}

static TEEC_Result tee_socket_recv(size_t num_params,
				   struct tee_ioctl_param *params)
{
	TEEC_Result res;
	int handle;
	int fd;
	uint32_t instance_id;
	void *buf;
	size_t bytes;

	if (num_params != 3 ||
	    !chk_pt(params + 0, TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT) ||
	    !chk_pt(params + 1, TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT) ||
	    !chk_pt(params + 2, TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT))
		return TEEC_ERROR_BAD_PARAMETERS;

	instance_id = params[0].u.value.b;
	handle = params[0].u.value.c;
	fd = sock_handle_to_fd(instance_id, handle);
	if (fd < 0)
		return TEEC_ERROR_BAD_PARAMETERS;

	buf = tee_supp_param_to_va(params + 1);

	bytes = params[1].u.memref.size;
	res = read_with_timeout(fd, buf, &bytes, params[2].u.value.a);
	if (res == TEEC_SUCCESS)
		params[1].u.memref.size = bytes;

	return res;
}

static TEEC_Result tee_socket_ioctl_tcp(int fd, uint32_t command,
					void *buf, size_t *blen)
{
	switch (command) {
	case TEE_TCP_SET_RECVBUF:
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, buf, *blen))
			return TEEC_ERROR_BAD_PARAMETERS;
		return TEEC_SUCCESS;
	case TEE_TCP_SET_SENDBUF:
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, buf, *blen))
			return TEEC_ERROR_BAD_PARAMETERS;
		return TEEC_SUCCESS;
	default:
		return TEEC_ERROR_NOT_SUPPORTED;
	}
}

static TEEC_Result sa_set_port(struct sockaddr *sa, socklen_t slen,
			       uint16_t port)
{
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sain = (void *)sa;

		if (slen < (socklen_t)sizeof(*sain))
			return TEEC_ERROR_BAD_PARAMETERS;
		sain->sin_port = htons(port);

		return TEEC_SUCCESS;
	}

	if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sain6 = (void *)sa;

		if (slen < (socklen_t)sizeof(*sain6))
			return TEEC_ERROR_BAD_PARAMETERS;
		sain6->sin6_port = htons(port);

		return TEEC_SUCCESS;
	}

	return TEEC_ERROR_BAD_PARAMETERS;
}

static TEEC_Result sa_get_port(struct sockaddr *sa, socklen_t slen,
			       uint16_t *port)
{
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sain = (void *)sa;

		if (slen < (socklen_t)sizeof(*sain))
			return TEEC_ERROR_BAD_PARAMETERS;
		*port = ntohs(sain->sin_port);

		return TEEC_SUCCESS;
	}

	if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sain6 = (void *)sa;

		if (slen < (socklen_t)sizeof(*sain6))
			return TEEC_ERROR_BAD_PARAMETERS;
		*port = ntohs(sain6->sin6_port);

		return TEEC_SUCCESS;
	}

	return TEEC_ERROR_BAD_PARAMETERS;
}

static TEEC_Result udp_changeaddr(int fd, int family, const char *server,
				  uint16_t port)
{
	TEEC_Result r = TEE_ISOCKET_ERROR_HOSTNAME;
	struct addrinfo hints;
	struct addrinfo *res0;
	struct addrinfo *res;
	char port_name[10];

	snprintf(port_name, sizeof(port_name), "%" PRIu16, port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(server, port_name, &hints, &res0))
		return TEE_ISOCKET_ERROR_HOSTNAME;
	for (res = res0; res; res = res->ai_next) {
		if (connect(fd, res->ai_addr, res->ai_addrlen)) {
			if (errno == ETIMEDOUT)
				r = TEE_ISOCKET_ERROR_TIMEOUT;
			else
				r = TEEC_ERROR_COMMUNICATION;
			continue;
		}
		r = TEEC_SUCCESS;
		break;
	}
	freeaddrinfo(res0);

	return r;
}

static TEEC_Result tee_socket_ioctl_udp(int fd, uint32_t command,
					void *buf, size_t *blen)
{
	TEEC_Result res;
	struct sockaddr_storage sass;
	struct sockaddr *sa = (struct sockaddr *)&sass;
	socklen_t len = sizeof(sass);
	uint16_t port;

	if (getpeername(fd, sa, &len))
		return TEEC_ERROR_BAD_PARAMETERS;

	switch (command) {
	case TEE_UDP_CHANGEADDR:
		res = sa_get_port(sa, len, &port);
		if (res != TEEC_SUCCESS)
			return res;

		if (!blen || *((char *)buf + *blen - 1) != '\0')
			return TEE_ISOCKET_ERROR_HOSTNAME;

		return udp_changeaddr(fd, sa->sa_family, buf, port);
	case TEE_UDP_CHANGEPORT:
		if (*blen != sizeof(port))
			return TEEC_ERROR_BAD_PARAMETERS;
		memcpy(&port, buf, sizeof(port));
		res = sa_set_port(sa, len, port);
		if (res != TEEC_SUCCESS)
			return res;
		if (connect(fd, sa, len))
			return TEEC_ERROR_GENERIC;
		return TEEC_SUCCESS;
	default:
		return TEEC_ERROR_NOT_SUPPORTED;
	}
}

static TEEC_Result tee_socket_ioctl(size_t num_params,
				    struct tee_ioctl_param *params)
{
	TEEC_Result res;
	int handle;
	int fd;
	uint32_t instance_id;
	uint32_t command;
	void *buf;
	int socktype;
	socklen_t l;
	size_t sz;

	if (num_params != 3 ||
	    !chk_pt(params + 0, TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT) ||
	    !chk_pt(params + 1, TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT) ||
	    !chk_pt(params + 2, TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT))
		return TEEC_ERROR_BAD_PARAMETERS;

	instance_id = params[0].u.value.b;
	handle = params[0].u.value.c;
	command = params[2].u.value.a;
	fd = sock_handle_to_fd(instance_id, handle);
	if (fd < 0)
		return TEEC_ERROR_BAD_PARAMETERS;

	l = sizeof(socktype);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socktype, &l))
		return TEEC_ERROR_BAD_PARAMETERS;

	buf = tee_supp_param_to_va(params + 1);

	switch (socktype) {
	case SOCK_STREAM:
		sz = params[1].u.memref.size;
		res = tee_socket_ioctl_tcp(fd, command, buf, &sz);
		params[1].u.memref.size = sz;
		return res;
	case SOCK_DGRAM:
		sz = params[1].u.memref.size;
		res = tee_socket_ioctl_udp(fd, command, buf, &sz);
		params[1].u.memref.size = sz;
		return res;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}
}

TEEC_Result tee_socket_process(size_t num_params,
			       struct tee_ioctl_param *params)
{
	if (!num_params || !tee_supp_param_is_value(params))
		return TEEC_ERROR_BAD_PARAMETERS;

	switch (params->u.value.a) {
	case OPTEE_MRC_SOCKET_OPEN:
		return tee_socket_open(num_params, params);
	case OPTEE_MRC_SOCKET_CLOSE:
		return tee_socket_close(num_params, params);
	case OPTEE_MRC_SOCKET_CLOSE_ALL:
		return tee_socket_close_all(num_params, params);
	case OPTEE_MRC_SOCKET_SEND:
		return tee_socket_send(num_params, params);
	case OPTEE_MRC_SOCKET_RECV:
		return tee_socket_recv(num_params, params);
	case OPTEE_MRC_SOCKET_IOCTL:
		return tee_socket_ioctl(num_params, params);
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}
}
