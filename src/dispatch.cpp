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
extern int test;

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
cmd_initiate(char *rxbuf, char *txbuf, path_state_t *ps, void *arg)
{
	vxstate_t *oldstate, *newstate, *state = (vxstate_t *)arg;
	rte_t *rte = &state->vs_dflt_rte;
	struct timeval tnow, delta;
	int dp_count, count = 0;

	gettimeofday(&tnow, NULL);
	timersub(&tnow, &state->vs_tlast, &delta);
	if (delta.tv_sec < 1)
		return (0);
	state->vs_tlast.tv_sec = tnow.tv_sec;
	state->vs_tlast.tv_usec = tnow.tv_usec;

	if (__predict_true(test == 0)) {
		if (rte->ri_flags & RI_VALID)
			cmd_send_heartbeat(rxbuf, txbuf, ps, state);
		else
			cmd_send_dhcp(rxbuf, txbuf, ps, state);
		count = 1;
	}
	/* update all datapath threads with a copy of the latest state */
	dp_count = state->vs_datapath_count;
	if (dp_count) {
		newstate = new vxstate_t(*state);
		oldstate = state->vs_dp_states[0]->vsd_state;
		for (int i = 0; i < dp_count; i++)
			state->vs_dp_states[i]->vsd_state = newstate;
		/* XXX --- clunky LOLEBR --- sleep for 50ms before freeing */
		if (__predict_true(debug == 0)) {
			usleep(50000);
			if (__predict_false(oldstate != state))
				delete oldstate;
		}
	}
	return (count);
}
static int
udp_ingress(char *rxbuf, char *txbuf, path_state_t *ps, vxstate_dp_t *state)
{
	struct ether_header *eh = (struct ether_header *)rxbuf;
	struct ip *ip = (struct ip *)(uintptr_t)(eh + 1);
	struct udphdr *uh = (struct udphdr *)(ip + (ip->ip_hl << 2));
	uint16_t dport = ntohs(uh->uh_dport);

	switch (dport) {
		case DTLS_DPORT:
			/* XXX decrypt */
			break;
		case VXLAN_DPORT:
			return vxlan_decap_v4(rxbuf, txbuf, ps, state);
			break;
		default:
			/* XXX log */
			return (0);
			break;
	}
}

static int
ingress_dispatch(char *rxbuf, char *txbuf, path_state_t *ps, vxstate_dp_t *state)
{
	struct ether_vlan_header *evh;
	int etype;

	evh = (struct ether_vlan_header *)(rxbuf);
	if (evh->evl_encap_proto == htons(ETHERTYPE_VLAN))
		etype = ntohs(evh->evl_proto);
	else
		etype = ntohs(evh->evl_encap_proto);

	switch (etype) {
		case ETHERTYPE_ARP:
			return data_dispatch_arp_phys(rxbuf, txbuf, ps, state);
			break;
		case ETHERTYPE_IP:
			return udp_ingress(rxbuf, txbuf, ps, state);
			break;
		case ETHERTYPE_IPV6:
			/* not yet supported */
			break;
		default:
			printf("%s unrecognized packet type %x len: %d\n", __func__, etype, ps->ps_rx_len);
			break;
	}
	return (0);
}

static int
egress_dispatch(char *rxbuf, char *txbuf, path_state_t *ps, vxstate_dp_t *state)
{
	struct ether_vlan_header *evh;
	int etype;

	evh = (struct ether_vlan_header *)(rxbuf);
	if (evh->evl_encap_proto == htons(ETHERTYPE_VLAN))
		etype = ntohs(evh->evl_proto);
	else
		etype = ntohs(evh->evl_encap_proto);

	switch (etype) {
		case ETHERTYPE_ARP:
			data_dispatch_arp_vx(rxbuf, txbuf, ps, state);
			break;
		case ETHERTYPE_IP:
			return vxlan_encap_v4(rxbuf, txbuf, ps, state);
			break;
		case ETHERTYPE_IPV6:
			/* not yet supported */
			break;
		default:
			printf("%s unrecognized packet type %x len: %d\n", __func__, etype, ps->ps_rx_len);
			break;
	}
	return (0);
}

int
data_dispatch(char *rxbuf, char *txbuf, path_state_t *ps, void *arg)
{
	vxstate_dp_t *state = (vxstate_dp_t *)arg;

	if (ps->ps_dir == AtoB)
		return egress_dispatch(rxbuf, txbuf, ps, state);
	else
		return ingress_dispatch(rxbuf, txbuf, ps, state);
}
