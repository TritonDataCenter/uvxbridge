/*
 * Copyright (C) 2017 Joyent Inc.
 * Copyright (C) 2017 Matthew Macy <matt.macy@joyent.com>
 * All rights reserved.
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
#include "proto.h"

#include <ipfw_exports.h>
#include "datapath.h"

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
		uint32_t gen:20;
		uint32_t vlanid:12;
		uint32_t vxlanid:24;
		uint32_t flags:8;
	} fields;
} vnient_t;

typedef struct intf_info {
	vnient_t ii_ent;
	struct ip_fw_chain *ii_chain;
	intf_info() {
		this->ii_ent.data = 0;
		this->ii_chain = ip_fw_chain_new();
	}
	~intf_info() {
		ip_fw_chain_delete(this->ii_chain);
		this->ii_chain = NULL;
	}
} intf_info_t;

typedef map<uint64_t, intf_info_t*> intf_info_map_t;
typedef pair<uint64_t, uint64_t> u64pair;

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
typedef map<uint32_t, ftable_t> ftablemap_t;

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

#define EC_VLAN 0x01
#define EC_IPV6 0x02
struct egress_cache {
	uint64_t ec_smac;
	uint64_t ec_dmac;
	uint64_t ec_flags;
	struct ip_fw_chain *ec_chain;
	union {
		struct vxlan_header vh;
		struct vxlan_vlan_header vvh;
	} ec_hdr;

};

/*
 * Need to have separate descriptors for each
 * txring/rxring pair to support multiple threads
 */
#define NM_PORT_MAX 1

typedef struct vxlan_state {
	/* vm vni/fw table */
	intf_info_map_t vs_intf_table;

	/* default route */
	rte_t vs_dflt_rte;

	/* forwarding table */
	ftablemap_t vs_ftables;

	/* phys nd table */
	l2tbl_t vs_l2_phys;

	/* encap port allocation */
	uint16_t vs_min_port;
	uint16_t vs_max_port;
	uint32_t vs_seed;

	/*
	 * Try to keep fields used only for configuration
	 * management below this line
	 */

	/* mac address for peer control interface */
	uint64_t vs_prov_mac;
	/* mac address for host control interface */
	uint64_t vs_ctrl_mac;
	/* mac address for physical interface */
	uint64_t vs_intf_mac;

	struct nm_desc *vs_nm_ingress;

	struct nm_desc *vs_nm_egress;

	/*
	 * Try to keep less frequently accessed
	 * structures below this line
	 */

	/* the last time *_initiate was executed */
	struct timeval vs_tlast;

	/* configuration netmap descriptor */
	struct nm_desc *vs_nm_config;

	volatile uint32_t vs_datapath_count;

	/* each data path's state */
	struct vxlan_state_dp *vs_dp_states[NM_PORT_MAX];

	vxlan_state(uint64_t pmac, uint64_t cmac) {
		this->vs_prov_mac = pmac;
		this->vs_ctrl_mac = cmac;
		this->vs_nm_ingress = this->vs_nm_egress = NULL;
		this->vs_tlast.tv_sec = this->vs_tlast.tv_usec = 0;
		/* XXX GET THE ACTUAL INTERFACE VALUE */
		this->vs_intf_mac = 0xCAFEBEEFBABE;
		this->vs_seed = arc4random();
		this->vs_min_port = IPPORT_HIFIRSTAUTO;	/* 49152 */
		this->vs_max_port = IPPORT_HILASTAUTO;	/* 65535 */
		this->vs_datapath_count = 0;
	}
} vxstate_t;

struct vxlan_state_dp;
struct ifnet;
struct netmap_port {
	struct vxlan_state_dp *np_state;
	datadir_t np_dir;
	struct ifnet *np_ifp;
};

typedef struct vxlan_state_dp {
	vxstate_t *vsd_state;

	/* egress cache if next == prev */
	struct egress_cache vsd_ecache;

	/* statistics */
	struct uvxstat vsd_stats;

	/* if data path - our identifier */
	uint32_t vsd_datapath_id;

	struct netmap_port vsd_ingress_port;

	struct netmap_port vsd_egress_port;

	vxlan_state_dp(uint32_t id, vxstate_t *state) {
		bzero(this, sizeof(*this));
		this->vsd_datapath_id = id;
		this->vsd_state = state;
		this->vsd_ingress_port.np_ifp = ifnet_alloc();
		this->vsd_egress_port.np_ifp = ifnet_alloc();
		this->vsd_ingress_port.np_state = this->vsd_egress_port.np_state = this;
		this->vsd_ingress_port.np_dir = BtoA;
		this->vsd_egress_port.np_dir = AtoB;
		/* XXX copy ingress / egress port names to ifnam */
	}
} vxstate_dp_t;

void configure_beastie0(vxstate_t *state);
void configure_beastie1(vxstate_t *state);

#define DBG(_fmt, ...)						\
do {									\
	   if (debug) {							\
		   fprintf(stderr, _fmt, ##__VA_ARGS__);	\
	   } \
} while (0)
#endif
