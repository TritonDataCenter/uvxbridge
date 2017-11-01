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
#include "command.h"

#include <machine/atomic.h>

int debug;
int test;

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
	vxstate_dp_t *self_state;
	vxstate_t *config_state;
};

void *
datapath_thr(void *args)
{
	struct dp_thr_args *dargs = (struct dp_thr_args *)args;

	atomic_add_int(&dargs->config_state->vs_datapath_count, 1);
	nmdp_run(dargs->port_args, dargs->self_state);
	return (NULL);
}

void
start_datapath(char *ingress, char *egress, vxstate_t *state, int idx)
{
	pthread_t dp_thread;
	dp_args_t *data_port_args;
	struct dp_thr_args *dta;
	vxstate_dp_t *data_state;

	data_port_args = (dp_args_t *)malloc(sizeof(dp_args_t));
	dta = (struct dp_thr_args *)malloc(sizeof(*dta));
	bzero(data_port_args, sizeof(dp_args_t));
	data_state = new vxstate_dp_t(idx, state);
	state->vs_dp_states[idx] = data_state;
	dta->self_state = data_state;
	dta->config_state = state;
	dta->port_args = data_port_args;

	data_port_args->da_pa_name = ingress;
	data_port_args->da_pb_name = egress;
	data_port_args->da_pa = &state->vs_nm_ingress;
	data_port_args->da_pb = &state->vs_nm_egress;
	data_port_args->da_rx_dispatch = data_dispatch;
	data_port_args->da_poll_timeout = 1500;
	data_port_args->da_record = &data_state->vsd_record;
	if (debug)
		data_port_args->da_flags = DA_DEBUG;
	data_port_args->da_idx = idx;

	if (pthread_create(&dp_thread, NULL, datapath_thr, dta)) {
		perror("failed to start datapath thread\n");
		exit(1);
	}
}

/* ./uvxbridge -d 2 -p CA:FE:00:00:BA:BE -m CA:FE:00:00:BE:EF -c vale_a:1 */

int
main(int argc, char *const argv[])
{
	int ch;
	char *ingress, *egress, *config, *log;
	uint32_t icount, ecount;
	uint64_t pmac, cmac, hwmac;
	vxstate_t *state;
	dp_args_t cmd_port_args;

	ingress = egress = config = NULL;
	hwmac = test = ecount = icount = pmac = cmac = 0;
	while ((ch = getopt(argc, argv, "i:e:c:m:p:l:d:t:h:")) != -1) {
		switch (ch) {
			case 'i':
				ingress = optarg;
				icount++;
				break;
			case 'e':
				egress = optarg;
				ecount++;
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
			case 't':
				test = strtol(optarg, NULL, 10);
				break;
			case 'h':
				hwmac = mac_parse(optarg);
				break;
			case '?':
			default:
				usage(argv[0]);
		}
	}
	if (pmac == 0 && !test) {
		printf("missing provisioning agent mac address\n");
		usage(argv[0]);
	}
	if (cmac == 0 && !test) {
		printf("missing bridge configuration mac address\n");
		usage(argv[0]);
	}
	if (config == NULL && !test) {
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
	if (ingress && egress && !hwmac) {
		printf("missing egress hw address\n");
		usage(argv[0]);
	}
	if (ingress && egress && !strcmp(ingress, egress)) {
		printf("egress and ingress can't be the same");
		usage(argv[0]);
	}

	/* do any global datapath init first */
	nmdp_init();
	state = new vxstate_t(pmac, cmac, hwmac);
	ck_epoch_register(nmdp_epoch_get(), &state->vs_record, NULL);
	if (test == 1) {
		configure_beastie0(state);
	} else if (test == 2) {
		configure_beastie1(state);
	}
	for (uint32_t i = 0; i < icount; i++)
		start_datapath(ingress, egress, state, i);
	if (config == NULL) {
		while (1)
			sleep(1);
	}
	/* yield for 50ms intervals until all threads have started */
	while (state->vs_datapath_count != icount)
		usleep(50000);

	bzero(&cmd_port_args, sizeof(dp_args_t));
	cmd_port_args.da_pa_name = config;
	cmd_port_args.da_pb_name = NULL;
	cmd_port_args.da_pa = &state->vs_nm_config;
	cmd_port_args.da_rx_dispatch = cmd_dispatch_config;
	cmd_port_args.da_tx_dispatch = cmd_initiate;
	cmd_port_args.da_poll_timeout = 100;

	printf("ctrl_mac: %lx\n", state->vs_ctrl_mac);
	nmdp_run(&cmd_port_args, state);

	return 0;
}
