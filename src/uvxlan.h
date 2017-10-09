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

#ifndef UVX_VXLAN_H_
#define UVX_VXLAN_H_
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

/*
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *
 *  Outer Ethernet Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             Outer Destination MAC Address                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Outer Destination MAC Address | Outer Source MAC Address      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                Outer Source MAC Address                       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |OptnlEthtype = C-Tag 802.1Q    | Outer.VLAN Tag Information    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Ethertype = 0x0800            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *  Outer IPv4 Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Version|  IHL  |Type of Service|          Total Length         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Identification        |Flags|      Fragment Offset    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Time to Live |Protocl=17(UDP)|   Header Checksum             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Outer Source IPv4 Address               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                   Outer Destination IPv4 Address              |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Outer UDP Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Source Port         |       Dest Port = VXLAN Port  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           UDP Length          |        UDP Checksum           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  VXLAN Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |R|R|R|R|I|R|R|R|            Reserved                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                VXLAN Network Identifier (VNI) |   Reserved    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Inner Ethernet Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             Inner Destination MAC Address                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Inner Destination MAC Address | Inner Source MAC Address      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                Inner Source MAC Address                       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |OptnlEthtype = C-Tag 802.1Q    | Inner.VLAN Tag Information    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Payload:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | Ethertype of Original Payload |                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 *  |                                  Original Ethernet Payload    |
 *  |                                                               |
 *  |(Note that the original Ethernet Frame’s FCS is not included)  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
 
struct vxlanhdr {
    uint32_t reserved0:4;
    uint32_t v_i:1;
    uint32_t reserved1:3;
    uint32_t reserved2:24;
    uint32_t v_vxlanid:24;
    uint32_t reserved3:8;
} __packed;

/*
 * IPv4 w/o VLAN
 */
struct vxlan_header {
    /* outer ether header */
    struct ether_header vh_ehdr;
    /* outer IP header */
    struct ip vh_iphdr;
	/* outer UDP header */
    struct udphdr vh_udphdr;
    /* outer vxlan id header */
    struct vxlanhdr vh_vxlanhdr;
} __packed;

/*
 * IPv4 w/ VLAN
 */
struct vxlan_vlan_header {
    /* outer ether header */
    struct ether_vlan_header vh_evhdr;
    /* outer IP header */
    struct ip vh_iphdr;
	/* outer UDP header */
    struct udphdr vh_udphdr;
    /* outer vxlan id header */
    struct vxlanhdr vh_vxlanhdr;
} __packed;

/*
 * IPv6 w/o VLAN
 */
struct vxlan_header6 {
    /* outer ether header */
    struct ether_header vh_ehdr;
    /* outer IP header */
    struct ip6_hdr vh_ip6hdr;
	/* outer UDP header */
    struct udphdr vh_udphdr;
    /* outer vxlan id header */
    struct vxlanhdr vh_vxlanhdr;
} __packed;

/*
 * IPv6 w/ VLAN
 */
struct vxlan_vlan_header6 {
    /* outer ether vlan header */
    struct ether_vlan_header vh_evhdr;
    /* outer IP header */
    struct ip6_hdr vh_ip6hdr;
    /* outer UDP header */
    struct udphdr vh_udphdr;
    /* outer vxlan id header */
    struct vxlanhdr vh_vxlanhdr;
} __packed;

bool vxlan_encap(char *rxbuf, char *txbuf, int len, vxstate_t &state);
bool vxlan_decap(char *rxbuf, char *txbuf, int len, vxstate_t &state);

/*
 * Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  ARP packets are variable
 * in size; the arphdr structure defines the fixed-length portion.
 * Protocol type values are the same as those for 10 Mb/s Ethernet.
 * It is followed by the variable-sized fields ar_sha, arp_spa,
 * arp_tha and arp_tpa in that order, according to the lengths
 * specified.  Field names used correspond to RFC 826.
 */
struct	arphdr {
	u_short	ar_hrd;		/* format of hardware address */
#define ARPHRD_ETHER 	1	/* ethernet hardware format */
#define ARPHRD_IEEE802	6	/* token-ring hardware format */
#define ARPHRD_ARCNET	7	/* arcnet hardware format */
#define ARPHRD_FRELAY 	15	/* frame relay hardware format */
#define ARPHRD_IEEE1394	24	/* firewire hardware format */
#define ARPHRD_INFINIBAND 32	/* infiniband hardware format */
	u_short	ar_pro;		/* format of protocol address */
	u_char	ar_hln;		/* length of hardware address */
	u_char	ar_pln;		/* length of protocol address */
	u_short	ar_op;		/* one of: */
#define	ARPOP_REQUEST	1	/* request to resolve address */
#define	ARPOP_REPLY	2	/* response to previous request */
#define	ARPOP_REVREQUEST 3	/* request protocol address given hardware */
#define	ARPOP_REVREPLY	4	/* response giving protocol address */
#define ARPOP_INVREQUEST 8 	/* request to identify peer */
#define ARPOP_INVREPLY	9	/* response identifying peer */

/* service private interface */
#define ARPOP_REQUEST_ALL		10	/* request for all ARP entries */
#define ARPOP_REVREQUEST_ALL		11	/* request for all forwarding table entries */

#define ARPOP_VM_VXLANID_REQUEST	12	/* get VM mac -> VXLAN mapping */
#define ARPOP_VM_VXLANID_REQUEST_ALL	13	/* get all VM mac -> VXLAN mappings */
#define ARPOP_VM_VXLANID_REPLY		14	/* set VM mac -> VXLAN mapping */
#define ARPOP_VM_VLANID_REQUEST	15	/* get VM mac -> VLAN mapping */
#define ARPOP_VM_VLANID_REQUEST_ALL	16	/* get all VM mac -> VLAN mappings */
#define ARPOP_VM_VLANID_REPLY		17	/* set VM mac -> VLAN mapping */

/* NB: delete an entry by issuing a gratuitous reply with 255.255.255.255 */

/*
 * The remaining fields are variable in size,
 * according to the sizes above.
 */
#ifdef COMMENT_ONLY
	u_char	ar_sha[];	/* sender hardware address */
	u_char	ar_spa[];	/* sender protocol address */
	u_char	ar_tha[];	/* target hardware address */
	u_char	ar_tpa[];	/* target protocol address */
#endif
};

#define ar_sha(ap)	(((caddr_t)((ap)+1)) +   0)
#define ar_spa(ap)	(((caddr_t)((ap)+1)) +   (ap)->ar_hln)
#define ar_tha(ap)	(((caddr_t)((ap)+1)) +   (ap)->ar_hln + (ap)->ar_pln)
#define ar_tpa(ap)	(((caddr_t)((ap)+1)) + 2*(ap)->ar_hln + (ap)->ar_pln)

struct arphdr_ether {
	uint64_t ae_req;
	uint8_t	 ae_sha[ETHER_ADDR_LEN];
	uint32_t ae_spa;
	uint8_t	 ae_dha[ETHER_ADDR_LEN];
	uint32_t ae_dpa;
} __packed;


bool nd_request(struct arphdr_ether *sae, struct arphdr_ether *dae,
				vxstate_t &state, l2tbl_t &tbl);
void cmd_dispatch_arp(char *rxbuf, char *txbuf, vxstate_t &state,
					  struct netmap_ring *txring, u_int *pidx);


#endif
