// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"

#include "utils.h"


int create_socket(void)
{
	/* TODO: Implement create_socket(). */
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	return fd;

}

int connect_socket(int fd)
{
/* TODO: Implement connect_socket(). */
	struct sockaddr_un server_addr;
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, SOCKET_NAME);
	size_t server_addr_size = sizeof(server_addr);

//	printf("try connect\n");
	int rc = connect(fd, (struct  sockaddr *)&server_addr, server_addr_size);
	return rc;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	/* TODO: Implement send_socket(). */
	int rc = send(fd, buf, len, 0);
	return rc;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	/* TODO: Implement recv_socket(). */
	int rc = recv(fd, buf, len, 0);
	return rc;
}

void close_socket(int fd)
{
	/* TODO: Implement close_socket(). */
	close(fd);
}
