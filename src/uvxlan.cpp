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

#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>

#include "uvxbridge.h"
#include "uvxlan.h"
                                /*   hrd         pro      hln  pln     op   */
static uint8_t arpopreq_[8] =    {0x00, 0x01, 0x08, 0x00, 0x6, 0x4, 0x0, 0x1};
static uint64_t arpopreq = (uint64_t)arpopreq_;
static uint8_t arpopreply_[8] =  {0x00, 0x01, 0x08, 0x00, 0x6, 0x4, 0x0, 0x2};
static uint64_t arpopreply = (uint64_t)arpopreply_;

/*
 * If rxbuf contains a neighbor discovery request return true.
 * If it's an nd request we can handle, enqueue a response.
 *
 * dir = EGRESS => VX, dir = INGRESS => PHYS
 */
bool
nd_request(struct arphdr_ether *sae, arphdr_ether *dae, vxstate_t &state, l2tbl_t &tbl)
{

//  XXX we assume prepopulated ARP table so ignore replies
//	if (ae->ae_req != arpopreq && ae->ae_req != arpopreply)
	if (sae->ae_req != arpopreq)
		return false;

	dae->ae_req = arpopreply;
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
    nm_pkt_copy(rxbuf, txbuf, len);
    return true;
}
