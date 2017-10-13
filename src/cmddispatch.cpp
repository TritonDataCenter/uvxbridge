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
#include <stdio.h>
#include <unistd.h>

#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include <iostream>
#include <map>
#include <string>

#include "uvxbridge.h"
#include "uvxlan.h"
#include "datapath.h"
extern int debug;

#ifdef old
static int
fte_get_all_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	result_map rmap;
	string tmp;
	auto &table = state.vs_ftable;

	for (auto it = table.begin(); it != table.end(); it++) {
		auto vit = state.vs_vni_table.mac2vni.find(it->first);
		if (vit == state.vs_vni_table.mac2vni.end())
			continue;
		rmap.insert("mac", be64toh(it->first));
		vnient_to_rmap(vit->second, rmap);
		vfe_to_rmap(it->second, rmap);
		tmp.append(rmap.to_str());
		tmp.append(" ");
		rmap.clear();
	}
	result = gen_result(seqno, ERR_SUCCESS, tmp);
	return 0;
}

static int
nd_get_all_handler(cmdmap_t &map, uint64_t seqno, l2tbl_t &tbl, string &result)
{
	result_map rmap;
	char buf[INET6_ADDRSTRLEN];
	struct in_addr in4;
	struct in6_addr in6;
	string tmp;

	for (auto it = tbl.l2t_v4.begin(); it != tbl.l2t_v4.end(); it++) {
		in4.s_addr = it->first;
		inet_ntop(AF_INET, &in4, buf,  INET6_ADDRSTRLEN);
		rmap.insert("mac", be64toh(it->second));
		rmap.insert("raddr", buf);
		tmp.append(rmap.to_str());
		tmp.append(" ");
		rmap.clear();
	}
	for (auto it = tbl.l2t_v6.begin(); it != tbl.l2t_v6.end(); it++) {
		inet_ntop(AF_INET6, &in6, buf,  INET6_ADDRSTRLEN);
		rmap.insert("mac", be64toh(it->second));
		rmap.insert("raddr", buf);
		tmp.append(rmap.to_str());
		tmp.append(" ");
		rmap.clear();
	}
	result = gen_result(seqno, ERR_SUCCESS, tmp);
	return 0;
}

static uint32_t
genmask(int prefixlen)
{
		uint64_t mask = (1UL << prefixlen)-1;
		mask <<= (32-prefixlen);
		return static_cast<uint32_t>(mask);
}

static int
route_update_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	char *raddr, *laddr, *def;
	uint64_t prefixlen;
	bool v6, lv6, is_default = false;
	int domain;
	rte_t ent;

	if (cmdmap_get_str(map, "raddr", &raddr))
		goto incomplete;
	if (cmdmap_get_str(map, "laddr", &laddr))
		goto incomplete;
	if (cmdmap_get_num(map, "prefixlen", prefixlen))
		goto incomplete;
	if (cmdmap_get_str(map, "default", &def))
		is_default = (strcmp(def, "true") == 0);

	bzero(&ent, sizeof(rte_t));
	v6 = (index(raddr, ':') != NULL);
	lv6 = (index(laddr, ':') != NULL);
	domain = v6 ? AF_INET6 : AF_INET;
	ent.ri_flags = RI_VALID;
	if ((lv6 != v6) || (v6 && prefixlen > 128) || (!v6 && prefixlen > 32))
		goto badparse;
	if (inet_pton(domain, raddr, &ent.ri_raddr))
		goto badparse;
	if (inet_pton(domain, laddr, &ent.ri_laddr))
		goto badparse;

	if (v6) {
		int incr, prefixlenrem = prefixlen;

		for (auto i = 0; i < 4 && prefixlenrem; i++) {
			incr = std::min(32, prefixlenrem);
			prefixlenrem -= incr;
			ent.ri_mask.in6.s6_addr32[i] = genmask(incr);
		}
		ent.ri_flags |= RI_IPV6;
	} else {
		ent.ri_mask.in4.s_addr = genmask(prefixlen);
	}

	/* XXX temporary for version 0 */
	if (!is_default || v6) {
		result = UNIMPLEMENTED(seqno);
		return 0;
	}
	if (is_default) {
		auto &dfltent = state.vs_dflt_rte;

		if (dfltent.ri_flags & RI_VALID)
			ent.ri_gen = dfltent.ri_gen + 1;
		memcpy(&dfltent, &ent, sizeof(rte_t));
	}
	
  badparse:
	result = dflt_result(seqno, ERR_PARSE);
	return EINVAL;
  incomplete:
	result = dflt_result(seqno, ERR_INCOMPLETE);
	return EINVAL;
}

#endif

int
cmd_dispatch(char *rxbuf, char *txbuf, path_state_t *ps, void *state)
{
	struct ether_header *eh;
	vxstate_t *vs = (vxstate_t *)state;
	uint64_t dmac;
	int etype;

	eh = (struct ether_header *)rxbuf;
	etype = ntohs(eh->ether_type);
	dmac = le64toh(*(uint64_t *)(rxbuf))& 0xffffffffffff;

	/* XXX check source mac too */
	if (dmac != vs->vs_ctrl_mac && debug < 2) {
		D("received control message to %lx expect %lx",
		  dmac, vs->vs_ctrl_mac);
		return 0;
	}
	if (debug >= 2)
		D("DISPATCHING");
	switch(etype) {
		case ETHERTYPE_ARP:
			return cmd_dispatch_arp(rxbuf, txbuf, ps, vs);
			break;
		case ETHERTYPE_IP:
			if (cmd_dispatch_ip(rxbuf, txbuf, ps, vs))
				return 1;
			break;
		default:
			/* we only support ipv4 - XXX */
			/* UNHANDLED */;
	}
	return 0;
}

int
cmd_initiate(char *rxbuf, char *txbuf, path_state_t *ps, void *arg)
{
	vxstate_t *state = (vxstate_t *)arg;
	rte_t *rte = &state->vs_dflt_rte;
	struct timeval tnow, delta;

	gettimeofday(&tnow, NULL);
	timersub(&tnow, &state->vs_tlast, &delta);
	if (delta.tv_sec < 1)
		return (0);
	state->vs_tlast.tv_sec = tnow.tv_sec;
	state->vs_tlast.tv_usec = tnow.tv_usec;

	if (rte->ri_flags & RI_VALID)
		cmd_send_heartbeat(rxbuf, txbuf, ps, state);
	else
		cmd_send_dhcp(rxbuf, txbuf, ps, state);

	return (1);
}
