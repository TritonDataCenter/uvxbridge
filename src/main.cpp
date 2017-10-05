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


int
main(int argc, char *const argv[])
{
	int ch, s, bytes, cfd;
	long port = 31337;
	const char *file = "default";
	struct sockaddr_un addr, peer_addr;
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
	if ((s = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("socket failed");
		exit(1);
	}
	bzero(&addr, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, file, sizeof(addr.sun_path) - 1);
	if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
		perror("bind failed");
		exit(1);
	}
	if (listen(s, 1) < 0) {
		perror("listen failed");
		exit(1);
	
	}
	bzero(buf, 4096);
	buf[4095] = '\0';
	while ((cfd = accept(s, (struct sockaddr *)&peer_addr, &pa_size)) >= 0) {
		while (1) {
			if ((bytes = read(cfd, buf, 4095)) < 0) {
				close(cfd);
				break;
			}
			cmd_dispatch(cfd, buf, state);
			
			bzero(buf, bytes);
		}
	}
	return 0;
}
