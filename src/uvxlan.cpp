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

void
cmd_dispatch_arp(char *rxbuf, char *txbuf, vxstate_t *state,
				 struct netmap_ring *txring, u_int *pidx)
{
	struct arphdr_ether *sah, *dah;

	sah = (struct arphdr_ether *)(rxbuf + ETHER_HDR_LEN);
	dah = (struct arphdr_ether *)(txbuf + ETHER_HDR_LEN);
	switch (sah->ae_req) {
		case AE_REQUEST:
			A(AE_REQUEST);
			break;
		case AE_REPLY:
			A(AE_REPLY);
			break;
		case AE_REVREQUEST:
			A(AE_REVREQUEST);
			break;
		case AE_REVREPLY:
			A(AE_REVREPLY);
			break;
		case AE_REQUEST_ALL:
			A(AE_REQUEST_ALL);
			break;
		case AE_REVREQUEST_ALL:
			A(AE_REVREQUEST_ALL);
			break;
		case AE_VM_VXLANID_REQUEST:
			A(AE_VM_VXLANID_REQUEST);
			break;
		case AE_VM_VXLANID_REQUEST_ALL:
			A(AE_VM_VXLANID_REQUEST_ALL);
			break;
		case AE_VM_VXLANID_REPLY:
			A(AE_VM_VXLANID_REPLY);
			break;
		case AE_VM_VLANID_REQUEST:
			A(AE_VM_VLANID_REQUEST);
			break;
		case AE_VM_VLANID_REQUEST_ALL:
			A(AE_VM_VLANID_REQUEST);
			break;
		case AE_VM_VLANID_REPLY:
			A(AE_VM_VLANID_REPLY);
			break;
		default:
			printf("unrecognized value: 0x%016lX\n", sah->ae_req);
	}
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
