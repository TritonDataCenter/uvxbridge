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
#include <stdio.h>

#include <net/ethernet.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>

#include "uvxbridge.h"
#include "uvxlan.h"
#include "proto.h"
#include "xxhash.h"

#define AE_REQUEST		0x0100040600080100UL
#define AE_REPLY		0x0200040600080100UL
#define AE_REVREQUEST		0x0300040600080100UL
#define AE_REVREPLY		0x0400040600080100UL

#define AE_REQUEST_ALL		0x0A00040600080100UL
#define AE_REVREQUEST_ALL	0x0B00040600080100UL
#define AE_VM_VXLANID_REQUEST	0x0C00040600080100UL
#define AE_VM_VXLANID_REQUEST_ALL	0x0D00040600080100UL
#define AE_VM_VXLANID_REPLY	0x0E00040600080100UL
#define AE_VM_VLANID_REQUEST	0x0F00040600080100UL
#define AE_VM_VLANID_REQUEST_ALL	0x1000040600080100UL
#define AE_VM_VLANID_REPLY	0x1100040600080100UL


#define A(val) printf("got %s\n", #val)
extern int debug;

int
cmd_dispatch_arp(char *rxbuf, char *txbuf, path_state_t *ps, vxstate_t *state)
{
	struct arphdr_ether *sah, *dah;
	struct ether_header *eh;
	int op;
	uint32_t hostip, targetpa = 0;
	uint16_t *rmacp, *lmacp;
	uint64_t len, targetha = 0, reply = 0;
	l2tbl_t &l2tbl = state->vs_l2_phys;
	ftable_t &ftable = state->vs_ftable;
	mac_vni_map_t &vnitbl = state->vs_vni_table.mac2vni;

	len = ps->ps_rx_len;
	if (len < ETHER_HDR_LEN + sizeof(struct arphdr_ether) && debug < 2)
		return 0;

	sah = (struct arphdr_ether *)(rxbuf + ETHER_HDR_LEN);
	dah = (struct arphdr_ether *)(txbuf + ETHER_HDR_LEN);
	op = ntohs(sah->ae_hdr.fields.ar_op);
	/* place holder */
	hostip = htobe32(0xDEADBEEF);

	switch (op) {
		case ARPOP_REQUEST: {
			A(ARPOP_REQUEST);
			auto it = l2tbl.l2t_v4.find(sah->ae_tpa);
			if (it != l2tbl.l2t_v4.end()) {
				reply = AE_REPLY;
				targetpa = sah->ae_tpa;
				targetha = it->second;
			}
			break;
		}
		case ARPOP_REPLY:
			A(ARPOP_REPLY);
			memcpy(&targetha, sah->ae_tha, ETHER_ADDR_LEN);
			if (targetha == 0)
				l2tbl.l2t_v4.erase(sah->ae_tpa);
			else
				l2tbl.l2t_v4.insert(pair<uint32_t, uint64_t>(sah->ae_tpa, targetha));
			break;
		case ARPOP_REVREQUEST: {
			/* ipv4 forwarding table lookup */
			A(ARPOP_REVREQUEST);
			memcpy(&targetha, sah->ae_tha, ETHER_ADDR_LEN);
			auto it = ftable.find(targetha);
			if (it != ftable.end() && it->second.vfe_v6 == 0) {
				reply = AE_REVREPLY;
				targetpa = it->second.vfe_raddr.in4.s_addr;
			}
			break;
		}
		case ARPOP_REVREPLY: {
			/* ipv4 forwarding table update */
			A(ARPOP_REVREPLY);
			memcpy(&targetha, sah->ae_tha, ETHER_ADDR_LEN);
			if (sah->ae_tpa == 0)
				ftable.erase(targetha);
			else {
				vfe_t vfe;
				vfe.vfe_raddr.in4.s_addr = sah->ae_tpa;
				ftable.insert(fwdent(targetha, vfe));
			}
			break;
		}
		case ARPOP_REQUEST_ALL:
			A(ARPOP_REQUEST_ALL);
			break;
		case ARPOP_REVREQUEST_ALL:
			A(ARPOP_REVREQUEST_ALL);
			break;
		case ARPOP_VM_VXLANID_REQUEST: {
			A(ARPOP_VM_VXLANID_REQUEST);
			memcpy(&targetha, sah->ae_tha, ETHER_ADDR_LEN);
			auto it = vnitbl.find(targetha);
			if (it != vnitbl.end()) {
				vnient_t ent;

				reply = AE_VM_VXLANID_REPLY;
				ent.data = it->second;
				targetpa = ent.fields.vxlanid;
			}
			break;
		}
		case ARPOP_VM_VXLANID_REQUEST_ALL:
			A(ARPOP_VM_VXLANID_REQUEST_ALL);
			break;
		case ARPOP_VM_VXLANID_REPLY:
			A(ARPOP_VM_VXLANID_REPLY);
			memcpy(&targetha, sah->ae_tha, ETHER_ADDR_LEN);
			if (sah->ae_tpa == 0)
				vnitbl.erase(targetha);
			else {
				vnient_t ent;
				auto it = vnitbl.find(targetha);

				if (it != vnitbl.end())
					ent.data = it->second;
				else
					ent.data = 0;
				ent.fields.vxlanid = sah->ae_tpa;
				vnitbl.insert(u64pair(targetha, ent.data));
			}
			break;
		case ARPOP_VM_VLANID_REQUEST: {
			A(ARPOP_VM_VLANID_REQUEST);
			memcpy(&targetha, sah->ae_tha, ETHER_ADDR_LEN);
			auto it = vnitbl.find(targetha);
			if (it != vnitbl.end()) {
				vnient_t ent;

				reply = AE_VM_VLANID_REPLY;
				ent.data = it->second;
				targetpa = ent.fields.vlanid;
			}
			break;
		}
		case ARPOP_VM_VLANID_REQUEST_ALL:
			A(ARPOP_VM_VLANID_REQUEST_ALL);
			break;
		case ARPOP_VM_VLANID_REPLY:
			A(ARPOP_VM_VLANID_REPLY);
			memcpy(&targetha, sah->ae_tha, ETHER_ADDR_LEN);
			if (sah->ae_tpa == 0)
				vnitbl.erase(targetha);
			else {
				vnient_t ent;
				auto it = vnitbl.find(targetha);

				if (it != vnitbl.end())
					ent.data = it->second;
				else
					ent.data = 0;
				ent.fields.vlanid = sah->ae_tpa;
				vnitbl.insert(u64pair(targetha, ent.data));
			}
			break;
		default:
			printf("unrecognized value data: 0x%016lX op: 0x%02X\n", sah->ae_hdr.data, op);
	}
	/* save potential cache stall to the end */
	if (reply) {
		eh = (struct ether_header *)txbuf;
		lmacp = (uint16_t *)(uintptr_t)&eh->ether_dhost;
		rmacp =  (uint16_t *)&state->vs_prov_mac;
		lmacp[0] = rmacp[0];
		lmacp[1] = rmacp[1];
		lmacp[2] = rmacp[2];
		rmacp =  (uint16_t *)&state->vs_ctrl_mac;
		lmacp[3] = rmacp[0];
		lmacp[4] = rmacp[1];
		lmacp[5] = rmacp[2];
		/* [6] */
		eh->ether_type = ETHERTYPE_ARP;
		/* [7-10] */
		dah->ae_hdr.data = reply;
		/* [11-13] - ar_sha */
		lmacp[11] = rmacp[0];
		lmacp[12] = rmacp[1];
		lmacp[13] = rmacp[2];
		/* [14-15] - ae_spa */
		dah->ae_spa = hostip;

		rmacp = (uint16_t *)&targetha;
		/* [16-18] - ae_tha */
		lmacp[16] = rmacp[0];
		lmacp[17] = rmacp[1];
		lmacp[18] = rmacp[2];
		/* actual value of interest */
		dah->ae_tpa = targetpa;
		*(ps->ps_tx_len) = 60;
		return (1);
	}
	return (0);
}

static __inline void
eh_fill(struct ether_header *eh, uint64_t smac, uint64_t dmac, uint16_t type)
{
	uint16_t *d, *s;

	d = (uint16_t *)(uintptr_t)eh; /* ether_dhost */
	s = (uint16_t *)&dmac;
	d[0] = s[0];
	d[1] = s[1];
	d[2] = s[2];
	s = (uint16_t *)&smac;
	d[3] = s[0];
	d[4] = s[1];
	d[5] = s[2];
	eh->ether_type = htons(type);
}

static void
ip_fill(struct ip *ip, uint32_t sip, uint32_t dip, uint16_t len, uint8_t proto)
{
	ip->ip_v = 4;
	ip->ip_hl = (sizeof(struct ip) >> 2);
	ip->ip_tos = 0;
	ip->ip_len = htons(len);
	ip->ip_id = 0;
	ip->ip_off = htons(IP_DF);
	ip->ip_ttl = 1;
	ip->ip_p = proto;
	ip->ip_sum = 0; /* XXX */
	/* these should always be kept in network byte order (BE) */
	ip->ip_src.s_addr = sip;
	ip->ip_dst.s_addr = dip;
}

static void
udp_fill(struct udphdr *uh, uint16_t sport, uint16_t dport, uint16_t len)
{
	uh->uh_sport = htons(sport);
	uh->uh_dport = htons(dport);
	uh->uh_ulen = htons(len + sizeof(*uh));
	uh->uh_sum = 0; /* XXX */
}

static void
dhcp_fill(struct dhcp *bp, vxstate_t *state)
{
	uint16_t *dstp, *srcp;
	bzero(bp, sizeof(*bp));
	bp->bp_op = BOOTREQUEST;
	bp->bp_htype = HTYPE_ETHERNET;
	bp->bp_hlen = ETHER_ADDR_LEN;
	bp->bp_hops = 0;
	bp->bp_xid = htonl(42); /* magic number :) */
	srcp = (uint16_t *)&state->vs_ctrl_mac;
	dstp = (uint16_t *)&bp->bp_chaddr;
	dstp[0] = srcp[0];
	dstp[1] = srcp[1];
	dstp[2] = srcp[2];
	bp->bp_vendid = htonl(BP_FIXED);
}

int
cmd_send_dhcp(char *rxbuf __unused, char *txbuf, path_state_t *ps, vxstate_t *state)
{
	struct ether_header *eh = (struct ether_header *)txbuf;
	struct ip *ip = (struct ip *)(uintptr_t)(eh + 1);
	struct udphdr *uh = (struct udphdr *)(ip + 1);
	struct dhcp *bp = (struct dhcp *)(uintptr_t)(uh + 1);

	eh_fill(eh, state->vs_ctrl_mac, state->vs_prov_mac, ETHERTYPE_IP);
	/* source IP unknown, dest broadcast IP */
	ip_fill(ip, 0, 0xffffffff, sizeof(*bp) + sizeof(*uh) + sizeof(*ip), IPPROTO_UDP);
	udp_fill(uh, IPPORT_BOOTPC, IPPORT_BOOTPS, sizeof(*bp));
	dhcp_fill(bp, state);
	*(ps->ps_tx_len) = BP_MSG_OVERHEAD + sizeof(*bp);
	return (1);
}

static void
uvxstat_fill(struct uvxstat *stat, vxstate_t *state)
{
	memcpy(stat, &state->vs_stats, sizeof(*stat));
}

int
cmd_send_heartbeat(char *rxbuf __unused, char *txbuf, path_state_t *ps,
				   vxstate_t *state)
{
	struct ether_header *eh = (struct ether_header *)txbuf;
	struct ip *ip = (struct ip *)(uintptr_t)(eh + 1);
	struct udphdr *uh = (struct udphdr *)(ip + 1);
	struct uvxstat *stat = (struct uvxstat *)(uintptr_t)(uh + 1);

	eh_fill(eh, state->vs_ctrl_mac, state->vs_prov_mac, ETHERTYPE_IP);
	/* source IP unknown, dest broadcast IP */
	ip_fill(ip, 0, 0xffffffff, sizeof(*stat) + sizeof(*uh) + sizeof(*ip), IPPROTO_UDP);
	udp_fill(uh, IPPORT_STATPC, IPPORT_STATPS, sizeof(*stat));
	uvxstat_fill(stat, state);
	*(ps->ps_tx_len) = BP_MSG_OVERHEAD + sizeof(*stat);
	return (1);
}

int
cmd_dispatch_bp(struct dhcp *bp, vxstate_t *state)
{
	rte_t *rte = &state->vs_dflt_rte;
	/* Validate BOOTP header */
	/* .... */
	/* we only care about our interface address and the gateway address */
	rte->ri_prefixlen = 24;
	rte->ri_mask.in4.s_addr = htobe32(0xffffff00);
	rte->ri_laddr.in4.s_addr = bp->bp_ciaddr.s_addr;
	rte->ri_raddr.in4.s_addr = bp->bp_giaddr.s_addr;
	rte->ri_flags = RI_VALID;
	DBG("route installed\n");
	return (1);
}

int
cmd_dispatch_ip(char *rxbuf, char *txbuf __unused, path_state_t *ps, vxstate_t *state)
{
	struct ip *ip = (struct ip *)(uintptr_t)(rxbuf + ETHER_HDR_LEN);
	struct udphdr *uh = (struct udphdr *)(uintptr_t)((caddr_t)ip + (ip->ip_hl << 2));
	struct dhcp *bp = (struct dhcp *)(uintptr_t)(uh + 1);
	/* validate ip header */

	/* validate the UDP header */


	/* we're only supporting a BOOTP response for the moment */
	if (ps->ps_rx_len < sizeof(*bp) + BP_MSG_OVERHEAD)
		return 0;

	return cmd_dispatch_bp(bp, state);
}

static uint64_t
mactou64(uint8_t *mac)
{
	uint64_t targetha = 0;
	uint16_t *src, *dst;

	src = (uint16_t *)(uintptr_t)mac;
	dst = (uint16_t *)targetha;
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	return (targetha);
}

static void
u64tomac(uint64_t smac, uint8_t *dmac)
{
	uint16_t *src, *dst;

	dst = (uint16_t *)(uintptr_t)dmac;
	src = (uint16_t *)&smac;
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
}

char *
get_ingress_txbuf(path_state_t *ps, vxstate_t *state)
{
	struct nm_desc *pa;
	struct netmap_ring *txring;
	struct netmap_slot *ts;

	pa = state->vs_nm_ingress;
	txring = NETMAP_TXRING(pa->nifp, pa->first_tx_ring);
	ts = &txring->slot[txring->cur];
	ps->ps_txring = txring;
	ps->ps_tx_len = &ts->len;
	return NETMAP_BUF(txring, ts->buf_idx);
}

void
txring_next(path_state_t *ps, uint16_t pktlen)
{
	struct netmap_ring *txring = ps->ps_txring;

	*ps->ps_tx_len = pktlen;
	txring->head = txring->cur = nm_ring_next(txring, txring->cur);
}

/*
 * Send a query to the provisioning agent
 */
void
data_send_arp(uint64_t targetha, uint32_t targetip, uint64_t op, vxstate_t *state)
{
	struct arphdr_ether ae;
	char *txbuf;
	path_state_t ps;

	/* get txbuf */
	if ((txbuf = get_ingress_txbuf(&ps, state)) == NULL)
		return;
	ae.ae_hdr.data = op;
	u64tomac(state->vs_ctrl_mac, ae.ae_sha);
	/* XXX - assume v4 */
	ae.ae_spa = state->vs_dflt_rte.ri_laddr.in4.s_addr;
	u64tomac(targetha, ae.ae_tha);
	ae.ae_tpa = targetip;
	eh_fill((struct ether_header *)txbuf, state->vs_ctrl_mac, state->vs_prov_mac,
			ETHERTYPE_ARP);
	memcpy(txbuf + ETHER_HDR_LEN, &ae, sizeof(struct arphdr_ether));
	txring_next(&ps, 60);
}

/*
 * Respond to queries for our encapsulating IP
 */
int
data_dispatch_arp_phys(char *rxbuf, char *txbuf __unused, path_state_t *ps,
				  vxstate_t *state)
{
	return (0);
}

/*
 * Proactively query the provisioning agent
 * - guest MAC -> vxlanid and vlanid when they ARP
 * - destination MAC -> remote IP when they ARP for the vxlan MAC
 * - remote IP -> remote MAC when the remote IP is first learned
 */
int
data_dispatch_arp_vx(char *rxbuf, char *txbuf __unused, path_state_t *ps,
				  vxstate_t *state)
{
	return (0);
}
/*
 * If valid, encapsulate rxbuf in to txbuf
 *
 */
int
vxlan_encap_v4(char *rxbuf, char *txbuf, path_state_t *ps __unused,
			   vxstate_t *state)
{
	struct ether_vlan_header *evh;
	int hdrlen, etype;
	mac_vni_map_t *vnitbl = &state->vs_vni_table.mac2vni;
	ftable_t *ftable = &state->vs_ftable;
	rte_t *rte = &state->vs_dflt_rte;
	arp_t *l2tbl = &state->vs_l2_phys.l2t_v4;
	struct vxlan_header *vh;
	vnient_t vnient;
	uint64_t *p, dstmac, targetha = 0;
	uint16_t sport, pktsize;
	uint32_t vxlanid, laddr, raddr, maskraddr, maskladdr, range;

	evh = (struct ether_vlan_header *)(rxbuf);
	laddr = rte->ri_laddr.in4.s_addr;

	if (evh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		hdrlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
		etype = ntohs(evh->evl_proto);
	} else {
		hdrlen = ETHER_HDR_LEN;
		etype = ntohs(evh->evl_encap_proto);
	}
	if (etype != ETHERTYPE_IP) {
		/* we shouldn't have gotten here -- log */
		return false;
	}
	/* first map evh->evl_shost -> vxlanid / vlanid  --- vs_vni_table */

	auto it_vni = vnitbl->find(targetha);
	if (it_vni != vnitbl->end()) {
		vnient.data = it_vni->second;
		vxlanid = vnient.fields.vxlanid;
	} else {
		data_send_arp(targetha, 0, AE_VM_VXLANID_REQUEST, state);
		/* send request for VXLANID */
		return (0);
	}
	/* next map evh->evl_dhost -> remote ip addr in the
	 * corresponding forwarding table - check vs_ftable
	 *
	 */
	targetha = mactou64(evh->evl_shost);
	auto it_fte = ftable->find(targetha);
	if (it_fte != ftable->end()) {
		raddr = it_fte->second.vfe_raddr.in4.s_addr;
	} else {
		/* send RARP for ftable entry */
		data_send_arp(targetha, 0, AE_REVREQUEST, state);
		return (0);
	}

	/* ..... */
	/* next check if remote ip is on our local subnet
	 * chech address & subnet mask
	 */
	maskraddr = raddr & rte->ri_mask.in4.s_addr;
	maskladdr = laddr & rte->ri_mask.in4.s_addr;
	/* .... */
	/* if yes - lookup MAC address for peer - vs_l2_phys */
	if (maskraddr == maskladdr) {
		auto it = l2tbl->find(raddr);
		if (it == l2tbl->end()) {
			/* call ARP for L2 addr */
			data_send_arp(0, raddr, AE_REQUEST, state);
			return (0);
		}
		dstmac = it->second;
	} else {
		/* .... */
		/* if no - lookup MAC address for corresponding router
		 * vs_dflt_rte -> vs_l2_phys
		 */
		auto it = l2tbl->find(rte->ri_raddr.in4.s_addr);
		if (it == l2tbl->end()) {
			/* call ARP for L2 addr */
			data_send_arp(0, raddr, AE_REQUEST, state);
			return (0);
		}
		dstmac = it->second;
	}

	/* calculate source port */
	range = state->vs_max_port - state->vs_min_port + 1;
	sport = XXH32(rxbuf, ETHER_HDR_LEN, state->vs_seed) % range;
	sport += state->vs_min_port;
	/* fill out final data -- XXX assume no VLAN */
	vh = (struct vxlan_header *)txbuf;
	eh_fill(&vh->vh_ehdr, state->vs_intf_mac, dstmac, ETHERTYPE_IP);
	pktsize = ps->ps_rx_len + sizeof(*vh) - sizeof(struct ether_header);
	ip_fill((struct ip *)(uintptr_t)&vh->vh_iphdr, laddr, raddr, pktsize, IPPROTO_UDP);
	pktsize -= sizeof(struct udphdr) - sizeof(struct ip);
	udp_fill((struct udphdr *)(uintptr_t)&vh->vh_udphdr, sport, VXLAN_DPORT, pktsize);
	p = (uint64_t *)(uintptr_t)&vh->vh_vxlanhdr;
	*p = 0;
	vh->vh_vxlanhdr.v_i = 1;
	vh->vh_vxlanhdr.v_vxlanid = vxlanid;
	nm_pkt_copy(rxbuf, txbuf + sizeof(*vh), ps->ps_rx_len);
    return (1);
}

int
vxlan_decap_v4(char *rxbuf, char *txbuf __unused, path_state_t *ps,
			   vxstate_t *state)
{
	return (0);
}
