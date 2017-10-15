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

#ifndef UVXBRIDGE_H_
#define UVXBRIDGE_H_

#include <netinet/in.h>
#include <iostream>
#include <map>
#include <string>

using std::string;
using std::pair;
using std::map;
#define s6_addr32 __u6_addr.__u6_addr32

struct in6cmp {
	bool
	operator() (const in6_addr& lhs, const in6_addr& rhs) const
	{
		uint32_t tmp;

		if ((tmp = (rhs.s6_addr32[0] - lhs.s6_addr32[0])) != 0)
			return tmp > 0;
		if ((tmp = (rhs.s6_addr32[1] - lhs.s6_addr32[1])) != 0)
			return tmp > 0;
		if ((tmp = (rhs.s6_addr32[2] - lhs.s6_addr32[2])) != 0)
			return tmp > 0;
		if ((tmp = (rhs.s6_addr32[3] - lhs.s6_addr32[3])) != 0)
			return tmp > 0;
		return true;
	}
};

typedef map<uint32_t, uint64_t> arp_t;
typedef map<uint64_t, uint32_t> revarp_t;
typedef map<struct in6_addr, uint64_t, in6cmp> nd6_t;
typedef map<uint64_t,  struct in6_addr> revnd6_t;
typedef struct l2_table {
	arp_t l2t_v4;
	nd6_t l2t_v6;
} l2tbl_t;

typedef union vni_entry {
	uint64_t data;
	struct {
		uint64_t gen:28;
		uint64_t vlanid:12;
		uint64_t vxlanid:24;
	} fields;
} vnient_t;

typedef map<uint64_t, uint64_t> mac_vni_map_t;
typedef pair<uint64_t, uint64_t> u64pair;
typedef struct vm_vni_table {
	mac_vni_map_t mac2vni;
} vnitbl_t;

typedef union vxlan_in_addr {
	struct in_addr	in4;
	struct in6_addr	in6;
} vxin_t;

typedef struct vxlan_ftable_entry {
	union vxlan_in_addr vfe_raddr;
	uint64_t vfe_v6:1;
	uint64_t vfe_gen:15;
	uint64_t vfe_expire:48;
} vfe_t;


#define RI_VALID	(1 << 0)
#define RI_IPV6	(1 << 1)

typedef struct routeinfo {
	vxin_t		ri_mask;
	vxin_t		ri_raddr;
	vxin_t		ri_laddr;
	uint64_t	ri_flags;
	uint32_t	ri_gen;
	uint32_t	ri_prefixlen;
} rte_t;

typedef pair<uint64_t, vfe_t> fwdent;
typedef map<uint64_t, vfe_t> ftable_t;

struct uvxstat {
	uint64_t uvx_egress_rx_pkt;
	uint64_t uvx_egress_tx_pkt;
	uint64_t uvx_ingress_rx_pkt;
	uint64_t uvx_ingress_tx_pkt;
	uint64_t uvx_egress_rx_bytes;
	uint64_t uvx_egress_tx_bytes;
	uint64_t uvx_ingress_rx_bytes;
	uint64_t uvx_ingress_tx_bytes;
};

typedef struct vxlan_state {
	struct timeval vs_tlast;
	/* mac address for peer control interface */
	uint64_t vs_prov_mac;
	/* mac address for host control interface */
	uint64_t vs_ctrl_mac;
	/* mac address for physical interface */
	uint64_t vs_intf_mac;

	struct nm_desc *vs_nm_config;

	struct nm_desc *vs_nm_ingress;

	struct nm_desc *vs_nm_egress;
	
	/* forwarding table */
	ftable_t vs_ftable;

	/* phys nd table */
	l2tbl_t vs_l2_phys;

	/* vm vni table */
	vnitbl_t vs_vni_table;

	/* default route */
	rte_t vs_dflt_rte;

	/* statistics */
	struct uvxstat vs_stats;

	/* encap port allocation */
	uint16_t vs_min_port;
	uint16_t vs_max_port;
	uint32_t vs_seed;
} vxstate_t;

#define DBG(_fmt, ...)						\
do {									\
	   if (debug) {							\
		   fprintf(stderr, _fmt, ##__VA_ARGS__);	\
	   } \
} while (0)
#endif
