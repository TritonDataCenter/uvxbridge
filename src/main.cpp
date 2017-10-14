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
#include <net/ethernet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "uvxbridge.h"
#include "uvxlan.h"

int debug;

static void
usage(char *name)
{
	printf("usage %s -i <ingress> -e <egress> -c <config> -m <config mac address> -p <provisioning agent mac address> [-d <level>]\n", name);
	exit(1);
}

static uint64_t
mac_parse(char *input)
{
	char *idx, *mac = strdup(input);
	const char *del = ":";
	uint64_t mac_num = 0;
	uint8_t *mac_nump = (uint8_t *)&mac_num;
	int i;

	for (i = 0; ((idx = strsep(&mac, del)) != NULL) && i < ETHER_ADDR_LEN; i++)
		mac_nump[i] = (uint8_t)strtol(idx, NULL, 16);
	free(mac);
	if (i < ETHER_ADDR_LEN)
		return 0;
	return	mac_num;
}

struct dp_thr_args {
	dp_args_t *port_args;
	vxstate_t *state;
};

void *
datapath_thr(void *args)
{
	struct dp_thr_args *dargs = (struct dp_thr_args *)args;

	run_datapath(dargs->port_args, dargs->state);
	return (NULL);
}

int
main(int argc, char *const argv[])
{
	int ch;
	char *ingress, *egress, *config, *log;
	uint64_t pmac, cmac;
	vxstate_t state, data_state;
	dp_args_t cmd_port_args, data_port_args;
	struct dp_thr_args dta;
	pthread_t dp_thread;

	ingress = egress = config = NULL;
	pmac = cmac = 0;
	while ((ch = getopt(argc, argv, "i:e:c:m:p:l:d:")) != -1) {
		switch (ch) {
			case 'i':
				ingress = optarg;
				break;
			case 'e':
				egress = optarg;
				break;
			case 'c':
				config = optarg;
				break;
			case 'p':
				pmac = mac_parse(optarg);
				break;
			case 'm':
				cmac = mac_parse(optarg);
				break;
			case 'l':
				log = optarg;
				break;
			case 'd':
				debug = strtol(optarg, NULL, 10);
				break;
			case '?':
			default:
				usage(argv[0]);
		}
	}
	if (pmac == 0) {
		printf("missing provisioning agent mac address\n");
		usage(argv[0]);
	}
	if (cmac == 0) {
		printf("missing bridge configuration mac address\n");
		usage(argv[0]);
	}
	if (config == NULL) {
		printf("missing config netmap interface\n");
		usage(argv[0]);
	}
	if (ingress == NULL && !debug) {
		printf("missing ingress netmap interface\n");
		usage(argv[0]);
	}
	if (egress == NULL && !debug) {
		printf("missing egress netmap interface\n");
		usage(argv[0]);
	}
	state.vs_prov_mac = pmac;
	state.vs_ctrl_mac = cmac;
	state.vs_seed = arc4random();
	state.vs_min_port = IPPORT_EPHEMERALFIRST;	/* 10000 */
	state.vs_max_port = IPPORT_EPHEMERALLAST;	/* 65535 */

	if (ingress != NULL && egress != NULL) {
		/* start datapath thread */
		bzero(&data_port_args, sizeof(dp_args_t));
		data_port_args.da_pa_name = ingress;
		data_port_args.da_pb_name = egress;
		data_port_args.da_pa = &state.vs_nm_ingress;
		data_port_args.da_pb = &state.vs_nm_egress;
		data_port_args.da_rx_dispatch = data_dispatch;
		data_port_args.da_poll_timeout = 1000;

		data_state = state;
		dta.state = &data_state;
		dta.port_args = &data_port_args;
		if (pthread_create(&dp_thread, NULL, datapath_thr, &dta)) {
			perror("failed to start datapath thread\n");
			exit(1);
		}
	}
	bzero(&cmd_port_args, sizeof(dp_args_t));
	cmd_port_args.da_pa_name = config;
	cmd_port_args.da_pb_name = NULL;
	cmd_port_args.da_pa = &state.vs_nm_config;
	cmd_port_args.da_rx_dispatch = cmd_dispatch;
	cmd_port_args.da_tx_dispatch = cmd_initiate;
	cmd_port_args.da_poll_timeout = 1000;
	run_datapath(&cmd_port_args, &state);
	return 0;
}
