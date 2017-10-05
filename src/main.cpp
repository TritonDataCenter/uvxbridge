/*
 * Copyright (C) 2017 Joyent Inc.
 * All rights reserved.
 *
 * Written by: Matthew Macy <matt.macy@joyent.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <unistd.h>

#include <iostream>
#include <map>
#include <string>

#include "uvxbridge.h"

static void
usage(void)
{
	printf("usage: [-p <port>] [-f <unix socket>]\n");
	exit(0);
}

#ifdef DEBUG
#define D printf
#else
#define D(...)
#endif


int
main(int argc, char *const argv[])
{
	int ch, s, bytes, cfd;
	long port = 0;
	const char *file = "default";
	struct sockaddr_un un;
	struct sockaddr_in in;
	struct sockaddr peer_addr;
	socklen_t pa_size;
	char buf[4096];
	vxstate_t state;

	while ((ch = getopt(argc, argv, "p:")) != -1) {
		switch (ch) {
			case 'p':
				port = strtol(optarg, NULL, 10);
				break;
			case 'f':
				file = optarg;
				break;
			case '?':
			default:
				usage();
		}
	}

	if (port == 0) {
		if ((s = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
			perror("socket failed");
			exit(1);
		}
		bzero(&un, sizeof(struct sockaddr_un));
		un.sun_family = AF_UNIX;
		strncpy(un.sun_path, file, sizeof(un.sun_path) - 1);
		if (bind(s, (struct sockaddr *)&un, sizeof(struct sockaddr_un)) < 0) {
			perror("bind failed");
			exit(1);
		}
	} else {
		int opt = 1;
		pa_size = sizeof(int);
		if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket failed");
			exit(1);
		}
		setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, pa_size);
		bzero(&in, sizeof(struct sockaddr_in));
		in.sin_len = sizeof(struct sockaddr_in);
		in.sin_family = AF_INET;
		in.sin_port = htons(port);
		in.sin_addr.s_addr = inet_addr("127.0.0.1");
		if (bind(s, (struct sockaddr *)&in, sizeof(struct sockaddr_in)) < 0) {
			perror("bind failed");
			exit(1);
		}
	}
	if (listen(s, 1) < 0) {
		perror("listen failed");
		exit(1);
	}
	bzero(buf, 4096);
	buf[4095] = '\0';
	while ((cfd = accept(s, (struct sockaddr *)&peer_addr, &pa_size)) >= 0) {
		int rc;
		D("accepted connection %d\n", cfd);
		while (1) {
			if ((bytes = read(cfd, buf, 4095)) < 0) {
				close(cfd);
				break;
			}
			D("dispatching cmd of %d bytes\n", bytes);
			rc = cmd_dispatch(cfd, buf, state);
			D("cmd_dispatch: %d\n", rc);
			bzero(buf, bytes);
		}
	}
	return 0;
}
