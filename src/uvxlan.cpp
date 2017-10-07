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

/*
 * If rxbuf contains a neighbor discovery request, save a
 * response and return true
 * dir = EGRESS => VX, dir = INGRESS => PHYS
 */
bool
nd_request(char *rxbuf, uint16_t len, vxstate_t &state __unused, tundir_t dir)
{
	return false;
}

/*
 * If there are pending neighbor discovery responses copy one 
 * to txbuf and return true
 *
 * dir = EGRESS => PHYS, dir = INGRESS => VX
 */
bool
nd_response(char *txbuf, uint16_t *len, vxstate_t &state __unused, tundir_t dir)
{
	return false;
}

/*
 * If valid, deencapsulate rxbuf in to txbuf
 *
 */
static int
vxlan_decap(char *rxbuf, char *txbuf, int len, vxstate_t &state __unused)
{
	nm_pkt_copy(rxbuf, txbuf, len);
	return 0;
}

/*
 * If valid, encapsulate rxbuf in to txbuf
 *
 */
static int
vxlan_encap(char *rxbuf, char *txbuf, int len, vxstate_t &state __unused)
{
    nm_pkt_copy(rxbuf, txbuf, len);
    return 0;
}

int
vxlan_tun(char *rxbuf, char *txbuf, int len, vxstate_t &state, tundir_t dir)
{
	if (dir == INGRESS)
		return vxlan_decap(rxbuf, txbuf, len, state);
	else
		return vxlan_encap(rxbuf, txbuf, len, state);
}


