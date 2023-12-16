// SPDX-License-Identifier: BSD-3-Clause

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"
#include "server.h"

#include "utils.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

static int lib_prehooks(struct lib *lib)
{
	/* TODO: Implement lib_prehooks(). */
	return 0;
}

static int lib_load(struct lib *lib)
{
	/* TODO: Implement lib_load(). */
	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */
	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	/* TODO: Implement lib_posthooks(). */
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;

	ret = sscanf(buf, "%s %s %s", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	/* TODO: Implement server connection. */
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un server_addr;
	struct sockaddr_un client_addr;

	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, SOCKET_NAME);
	size_t server_addr_size = sizeof(server_addr);

	int bindret = bind(fd, (struct sockaddr *)&server_addr, server_addr_size);
	DIE(bindret < 0, "bind");
	int listenret = listen(fd, MAX_CLIENTS);
	DIE(listenret < 0, "listen");
	char buf[1024];
	int ret;
	struct lib lib;

	while (1) {
		/* TODO - get message from client */

		int clen = sizeof(client_addr);
		int client_socket = accept(fd, (struct sockaddr *) &client_addr, &clen);
		if (client_socket == -1)
			continue;
//		printf("%d\n", client_socket);
		int size = 0;
		while (size == 0) {
			size = recv(client_socket, buf, 1024, 0);
		}
		strcpy(buf, "ana are mere");

		write(client_socket, buf, 1024);
		/* TODO - parse message with parse_command and populate lib */
		/* TODO - handle request from client */
		ret = lib_run(&lib);
	}

	return 0;
}
