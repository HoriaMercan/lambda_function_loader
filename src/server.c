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
#include <sys/wait.h>
#include <semaphore.h>
#include <sys/prctl.h>

#include <ctype.h>
#include <pthread.h>
#include "ipc.h"
#include "server.h"

#include "utils.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

#define FIFO_FILE "/tmp/myfifo"
#define MAX_FILE_NAME 1000

pthread_mutex_t mutex;
pthread_mutexattr_t attr;

sem_t sem;

static int lib_prehooks(struct lib *lib)
{
	/* TODO: Implement lib_prehooks(). */
	return 0;
}

char *rtrim(char *s)
{
	char* back = s + strlen(s);
	while(isspace(*--back));
	*(back+1) = '\0';
	return s;
}

// Returneaza 1 daca nu se loaduieste
static int lib_load(struct lib *lib)
{
	/* TODO: Implement lib_load(). */
	lib->handle = dlopen(lib->libname, RTLD_LAZY);

	if (lib->handle == NULL) {
		strcpy(lib->outputfile, OUTPUT_TEMPLATE);
		int fd = mkstemp(lib->outputfile);
//
		close(fd);

		FILE *file_err = fopen(lib->outputfile, "w");

		if (strlen(lib->filename))
			fprintf(file_err,
				"Error: %s %s %s could not be executed.\n",
				lib->libname, lib->funcname, lib->filename);
		else
			fprintf(file_err,
					"Error: %s %s could not be executed.\n",
					lib->libname, lib->funcname);

		fclose(file_err);

		return 1;
	}
	if (strlen(lib->filename) == 0) {
		lib->p_run = NULL;
		lib->run = dlsym(lib->handle, lib->funcname);

	} else {
		lib->run = NULL;
		lib->p_run = dlsym(lib->handle, lib->funcname);
	}

	if (lib->run == NULL && lib->p_run == NULL) {
		strcpy(lib->outputfile, OUTPUT_TEMPLATE);
		int fd = mkstemp(lib->outputfile);
//
		close(fd);

		FILE *file_err = fopen(lib->outputfile, "w");

		if (strlen(lib->filename))
			fprintf(file_err,
					"Error: %s %s %s could not be executed.\n",
					lib->libname, lib->funcname, lib->filename);
		else
			fprintf(file_err,
					"Error: %s %s could not be executed.\n",
					lib->libname, lib->funcname);

		fclose(file_err);

		return 1;
	}

	return 0;
}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */


	lib->outputfile = strdup(OUTPUT_TEMPLATE);

	int fd = mkstemp(lib->outputfile);
	int out = dup(1);
	int new_ = dup2(fd, 1);
	if (new_ != fd)
		close(fd);

	// aici faci FORK
	pid_t pid = fork();
	DIE(pid < 0, "fork esuat lamentabil");
	if (pid == 0) {
//		printf("Child: %d\n", pid);
//		printf("current fd: %d\n", fd);

//		printf("new_ = %d\n", new_);
		if (lib->run) {
			lib->run();
		} else {
			lib->p_run(lib->filename);
		}


		exit(0);
	}
	else {

//		printf("Parent: %d\n", pid);
		int status;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) {
			int exit_status = WEXITSTATUS(status);
			if (exit_status != 0) {
				char *error = strerror(exit_status);
				printf("%s\n", error);
			}
			if (exit_status == 0)
				return 0;
		}
//		if (WIFSIGNALED(status)) {
//			char *signal = strsignal(WEXITSTATUS(status));
//			printf("Error: %s could not be executed\n", lib->funcname);
//		}

	}
	dup2(out, new_);
	close(out);


	return 0;
}

static int lib_close(struct lib *lib)
{
	/* TODO: Implement lib_close(). */
	dlclose(lib->handle);
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

	switch (ret) {
		case 1:
			strcpy(func, "run");
		case 2:
			strcpy(params, "");
	}

	rtrim(params);
	rtrim(func);

	return ret;
}

int spawn_process(int client_socket, char *buf, struct lib lib) {
	pthread_mutex_lock(&mutex);
	int size = recv(client_socket, buf, 1024, 0);
	pthread_mutex_unlock(&mutex);
	buf[size] = 0;
	/* TODO - parse message with parse_command and populate lib */
	parse_command(buf, lib.libname, lib.funcname, lib.filename);
	/* TODO - handle request from client */

	lib_run(&lib);

	sprintf(buf, "%s\n", lib.outputfile);
	write(client_socket, buf, 1024);
	close(client_socket);
}

int main(void)
{

	sem_init(&sem, 1, 1);

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);

	pthread_mutex_init(&mutex, &attr);
	/* TODO: Implement server connection. */
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un server_addr;
	struct sockaddr_un client_addr;

	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, SOCKET_NAME);
	remove(SOCKET_NAME);
	size_t server_addr_size = sizeof(server_addr);

	int bindret = bind(fd, (struct sockaddr *)&server_addr, server_addr_size);
	DIE(bindret < 0, "bind");
	int listenret = listen(fd, MAX_CLIENTS);
	DIE(listenret < 0, "listen");
	char buf[1024];
	int ret;
	struct lib lib;

	lib.libname = malloc(MAX_FILE_NAME);
	lib.filename = malloc(MAX_FILE_NAME);
	lib.funcname = malloc(MAX_FILE_NAME);
	lib.outputfile = malloc(MAX_FILE_NAME);


	while (1) {
		/* TODO - get message from client */

		unsigned int clen = sizeof(client_addr);
		int client_socket = accept(fd, (struct sockaddr *) &client_addr, &clen);
		if (client_socket == -1)
			continue;

		pid_t pid = fork();
		if (pid == 0) {
			spawn_process(client_socket, buf, lib);
			exit(0);
		} else {
			int status;
//			waitpid(pid, &status, 0);
		}
	}

	return 0;
}
