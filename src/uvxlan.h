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

typedef enum tundir {
	EGRESS,
	INGRESS
} tundir_t;

int vxlan_tun(char *rxbuf, char *txbuf, int len, vxstate_t &state, tundir_t dir);
bool nd_request(char *rxbuf, uint16_t len, vxstate_t &state, tundir_t dir);
bool nd_response(char *txbuf, uint16_t *len, vxstate_t &state, tundir_t dir);


#endif
