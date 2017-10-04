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
/*  
 * VERB command set
 * 
 *   Add forwarding table entry map destination host mac to remote ip
 * - UPDATE_FTE:<seqno> mac: big-endian 6 bytes
 *                raddr: <4-tuple| v6addr w/ no symbolic>
 *             expire: 8 bytes - useconds
 *         (result:seqno error:<errstr> (gen: 4 byte)?)
 *
 *  Get forwarding entry details
 * - GET_FTE:<seqno> big-endian 6 bytes
 *       (result:<seqno> error:<errstr> (raddr: <4-tuple| v6addr w/ no symbolic>
 *              expire: 8 bytes - useconds
 *                 gen: 4 byte)?)
 * 
 * - REMOVE_FTE:<seqno> vxmac: big-endian 6 bytes
 *       (result:<seqno> error:<errstr>)
 *
 * - GET_ALL_FTE:<seqno>
 *         (result: error:<errstr> (mac: big-endian 6 bytes
 *                 raddr: <4-tuple| v6addr w/ no symbolic>
 *                expire: 8 bytes - useconds
 *                   gen: 4 byte)*)  
 *
 *
 *   manage physical L2 table entries for remote IP
 * - SET_PHYS_ND:<seqno> mac: big-endian 6 bytes raddr: <4-tuple| v6addr w/ no symbolic>
 *   (result:<seqno> error:<errstr>)
 *
 * - DEL_PHYS_ND:<seqno> mac: big-endian 6 bytes | raddr: <4-tuple| v6addr w/ no symbolic>
 *   (result:<seqno> error:<errstr>)
 *
 * - GET_PHYS_ND:<seqno> raddr: <4-tuple| v6addr w/ no symbolic>
 *      (result:<seqno>  error:<errstr> (mac: big-endian 6 bytes)?)
 *
 * - GET_ALL_PHYS_ND:<seqno>
 *       (result:<seqno> error:<errstr> (mac: big-endian 6 bytes
 *               raddr: <4-tuple| v6addr w/ no symbolic>)*)
 *
 *
 *   manage vxlan L2 table entries for remote IP
 * - SET_VX_ND:<seqno> mac: big-endian 6 bytes raddr: <4-tuple| v6addr w/ no symbolic>
 *   (result:<seqno> error:<errstr>)
 *
 * - DEL_VX_ND:<seqno> mac: big-endian 6 bytes |
 *             raddr: <4-tuple| v6addr w/ no symbolic>
 *   (result:<seqno> error:<errstr>)
 *
 * - GET_VX_ND:<seqno> raddr: <4-tuple| v6addr w/ no symbolic>
 *      (result:<seqno> error:<errstr> (mac: big-endian 6 bytes)?)
 *
 * - GET_ALL_VX_ND:<seqno>
 *       (result:<seqno> error:<errstr> (mac: big-endian 6 bytes
 *               raddr: <4-tuple| v6addr w/ no symbolic>)*)
 *
 *
 *   map local VM mac to 5 byte vlanid|vxlanid
 * - UPDATE_VM_VNI:<seqno> vlanid: 2-bytes vxlanid: 3-bytes mac: 6-bytes
 *     (result:<seqno> error:<errstr> (gen: 4 byte))
 *
 * - GET_VM_VNI:<seqno> mac: 6-bytes
 *       (result:<seqno> error:<errstr> (vlanid: 2-bytes
 *              vxlanid: 3-bytes
 *                  gen: 4 byte))
 *
 * - REMOVE_VM_VNI:<seqno> mac: big-endian 6 bytes
 *       (result:<seqno> error:<errstr>)
 *
 * - GET_ALL_VM_VNI:<seqno>
 *       (result:<seqno>  error:<errstr> (mac: 6 bytes 
 *              vlanid: 2-bytes
 *              vxlanid: 3-bytes
 *                  gen: 4 byte)*)
 *
 *
 * - UPDATE_DEFAULT_ROUTE:<seqno> raddr: <4-tuple| v6addr w/ no symbolic>
 *       (result:<seqno> error:<errstr> (gen: 4 bytes)?)
 *
 * - REMOVE_DEFAULT_ROUTE:<seqno> raddr: <4-tuple| v6addr w/ no symbolic>
 *       (result:<seqno> error:<errstr>)
 *
 *
 *  Stop forwarding packets
 * - SUSPEND:<seqno>
 *       (result:<seqno> error:<errstr>)
 *
 *  Resume forwarding packets
 * - RESUME:<seqno>
 *       (result:<seqno> error:<errstr>)
 *
 *
 *  Signal that all seqno prior have completed, error value is the
 *  first error encountered since the last BARRIER issued, if any.
 * - BARRIER:<seqno>
 *       (result:<seqno> error:<errstr>)
 *
 *   Syntactic sugar for BARRIER+SUSPEND
 * - BEGIN_UPDATE:<seqno>
 *       (result:<seqno> error:<errstr>)
 *
 *   Syntactic sugar for BARRIER+RESUME
 * - COMMIT_UPDATE:<seqno>
 *       (result:<seqno> error:<errstr>)
 *
 *
 * Sample syntax:
 * client -> server: "VERB_UPDATE_DEFAULT_ROUTE:0x1 raddr:\"192.168.0.1\"\n"
 * server -> client: "(result:0x1 error:\"ERR_SUCCESS\" (gen:0x0))\n"
 * client -> server: "VERB_SET_PHYS_ND:0x2 raddr:\"192.168.0.1\" mac:0xbabecafebeef\n"
 * server -> client: "(result:0x2 error:\"ERR_SUCCESS\")"
 * client -> server: "VERB_GET_PHYS_ND_ALL:0x3\n"
 * server -> client: "(result:0x3 error:\"ERR_SUCCESS\" (raddr:\"192.168.0.1\" mac:0xbabecafebeef))\n"
 */

enum verb {
	VERB_BAD = 0x0,
	VERB_BARRIER = 0x1,

	VERB_SET_PHYS_ND = 0x10,
	VERB_GET_PHYS_ND = 0x11,
	VERB_DEL_PHYS_ND = 0x12,
	VERB_GET_ALL_PHYS_ND = 0x13,
	
	VERB_UPDATE_VM_VNI = 0x20,
	VERB_REMOVE_VM_VNI = 0x21,
	VERB_GET_VM_VNI = 0x22,
	VERB_GET_ALL_VM_VNI = 0x23,

	VERB_UPDATE_DEFAULT_ROUTE = 0x30,
	VERB_REMOVE_DEFAULT_ROUTE = 0x31,

	VERB_SET_VX_ND = 0x40,
	VERB_GET_VX_ND = 0x41,
	VERB_DEL_VX_ND = 0x42,
	VERB_GET_ALL_VX_ND = 0x43,

	VERB_SUSPEND = 0x50,
	VERB_RESUME = 0x51,
	VERB_BEGIN_UPDATE = 0x52,
	VERB_COMMIT_UPDATE = 0x53,

	VERB_UPDATE_FTE = 0x60,
	VERB_REMOVE_FTE = 0x61,
	VERB_GET_FTE = 0x62,
	VERB_GET_ALL_FTE = 0x63
};

enum verb_error {
	ERR_SUCCESS = 0,
	ERR_PARSE,
	ERR_INCOMPLETE,
	ERR_NOMEM,
	ERR_NOENTRY,
	ERR_NOTIMPL
};

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
		uint64_t pad:24;
		uint64_t vlanid:16;
		uint64_t vxlanid:24;
	} fields;
} vnient_t;

typedef map<uint64_t, uint64_t> mac_vni_map_t;
typedef struct vm_vni_table {
	mac_vni_map_t mac2vni;
} vnitbl_t;


union vxlan_in_addr {
	struct in_addr	in4;
	struct in6_addr	in6;
};
typedef struct vxlan_ftable_entry {
	union vxlan_in_addr vfe_raddr;
	uint64_t vfe_v6:1;
	uint64_t vfe_gen:15;
	uint64_t vfe_expire:48;
} vfe_t;

typedef pair<uint64_t, vfe_t> fwdent;
typedef map<uint64_t, vfe_t> ftable_t;

typedef struct vxlan_state {
	/* forwarding table */
	ftable_t vs_ftable;

	/* vx nd table */
	l2tbl_t vs_l2_vx;

	/* phys nd table */
	l2tbl_t vs_l2_phys;

	/* vm vni table */
	vnitbl_t vs_vni_table;

	/* default route */

} vxstate_t;



int parse_input(char *input, vxstate_t &state, string &result);

#endif
