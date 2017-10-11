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
	int op, len;
	uint32_t hostip, targetpa = 0;
	uint16_t *rmacp, *lmacp;
	uint64_t targetha = 0, reply = 0;
	l2tbl_t &l2tbl = state->vs_l2_phys;
	ftable_t &ftable = state->vs_ftable;

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
		case ARPOP_VM_VXLANID_REQUEST:
			A(ARPOP_VM_VXLANID_REQUEST);
			reply = AE_VM_VXLANID_REPLY;
			break;
		case ARPOP_VM_VXLANID_REQUEST_ALL:
			A(ARPOP_VM_VXLANID_REQUEST_ALL);
			break;
		case ARPOP_VM_VXLANID_REPLY:
			A(ARPOP_VM_VXLANID_REPLY);
			break;
		case ARPOP_VM_VLANID_REQUEST:
			A(ARPOP_VM_VLANID_REQUEST);
			reply = AE_VM_VLANID_REPLY;
			break;
		case ARPOP_VM_VLANID_REQUEST_ALL:
			A(ARPOP_VM_VLANID_REQUEST);
			break;
		case ARPOP_VM_VLANID_REPLY:
			A(ARPOP_VM_VLANID_REPLY);
			break;
		default:
			printf("unrecognized value data: 0x%016lX op: 0x%02X\n", sah->ae_hdr.data, op);
	}
	/* save potential cache stall to the end */
	if (reply) {
		eh = (struct ether_header *)txbuf;
		lmacp = (uint16_t *)&eh->ether_dhost;
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
		return (1);
	}
	return (0);
}

/*
 * If rxbuf contains a neighbor discovery request return true.
 * If it's an nd request we can handle, enqueue a response.
 *
 * dir = EGRESS => VX, dir = INGRESS => PHYS
 */
bool
nd_request(struct arphdr_ether *sae, arphdr_ether *dae, vxstate_t &state, l2tbl_t &tbl)
{
#if 0
//  XXX we assume prepopulated ARP table so ignore replies
//	if (ae->ae_req != arpopreq && ae->ae_req != arpopreply)
	if (sae->ae_req != arpopreq)
		return false;

	dae->ae_req = arpopreply;
#endif
	abort();
	return true;
}

/*
 * If valid, deencapsulate rxbuf in to txbuf
 *
 */
bool
vxlan_decap(char *rxbuf, char *txbuf, int len, vxstate_t &state __unused)
{

	nm_pkt_copy(rxbuf, txbuf, len);
	return true;
}

/*
 * If valid, encapsulate rxbuf in to txbuf
 *
 */
bool
vxlan_encap(char *rxbuf, char *txbuf, int len, vxstate_t &state __unused)
{
	struct ether_vlan_header *evh, *evhrsp;
	int hdrlen, etype;

	evh = (struct ether_vlan_header *)(rxbuf);
	if (evh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		hdrlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
		etype = ntohs(evh->evl_proto);
	} else {
		hdrlen = ETHER_HDR_LEN;
		etype = ntohs(evh->evl_encap_proto);
	}
	if (etype != ETHERTYPE_IP && etype != ETHERTYPE_IPV6)
		return false;
	/* first map evh->evl_shost -> vxlanid / vlanid */
	/* ..... */
	/* next map evh->evl_dhost -> remote ip addr in the corresponding forwarding table */
	/* ..... */
	/* next check if remote ip is on our local subnet */
	/* .... */
	/* if yes - lookup MAC address for peer */
	/* .... */
	/* if no - lookup MAC address for corresponding router */
	/* .... */
	/* use source IP for said subnet */
	/* calculate source port */
	/* .... */

	evhrsp = (struct ether_vlan_header *)(txbuf);
    nm_pkt_copy(rxbuf, txbuf, len);
    return true;
}
