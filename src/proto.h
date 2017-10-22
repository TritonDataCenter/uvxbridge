#ifndef PROTO_H_
#define PROTO_H_
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#define BP_CHADDR_LEN	 16
#define BP_SNAME_LEN	 64
#define BP_FILE_LEN	128
#define BP_VEND_LEN	 64
#define BP_MINPKTSZ	300	/* to check sizeof(struct bootp) */
/* Overhead to fit a bootp message into an Ethernet packet. */
#define BP_MSG_OVERHEAD	(14 + 20 + 8)	/* Ethernet + IP + UDP headers */

struct dhcp {
	unsigned char	 bp_op;			/* packet opcode type */
	unsigned char	 bp_htype;			/* hardware addr type */
	unsigned char	 bp_hlen;			/* hardware addr length */
	unsigned char	 bp_hops;			/* gateway hops */
	uint32_t		 bp_xid;			/* transaction ID */
	unsigned short	 bp_secs;			/* seconds since boot began */
	unsigned short	 bp_flags;			/* RFC1532 broadcast, etc. */
	struct in_addr	 bp_ciaddr;			/* client IP address */
	struct in_addr	 bp_yiaddr;			/* 'your' IP address */
	struct in_addr	 bp_siaddr;			/* server IP address */
	struct in_addr	 bp_giaddr;			/* gateway IP address */
	/* 28 */
	unsigned char	 bp_chaddr[BP_CHADDR_LEN];	/* client hardware address */
	/* 44 */
	char		 bp_sname[BP_SNAME_LEN];	/* server host name */
	/* 108 */
	char		 bp_file[BP_FILE_LEN];	/* boot file name */
	/* 236 */
	uint32_t	 bp_vendid;
	unsigned char	 bp_vend[0];	/* vendor-specific area */
};

/*
 * UDP port numbers, server and client.
 */
#define IPPORT_BOOTPS           67
#define IPPORT_BOOTPC           68

#define BOOTREPLY               2
#define BOOTREQUEST             1

/*
 * Hardware types from Assigned Numbers RFC.
 */
#define HTYPE_ETHERNET            1
#define HTYPE_EXP_ETHERNET        2
#define HTYPE_AX25                3
#define HTYPE_PRONET              4
#define HTYPE_CHAOS               5
#define HTYPE_IEEE802             6
#define HTYPE_ARCNET              7

#define BP_FIXED				0x63825363

#define	IPPORT_STATPS			665 /* Sun DR */
#define	IPPORT_STATPC			666 /* DOOM */

#define IPPORT_IPFWPS			6666 /* unused */
#define IPPORT_IPFWPC			6667 /* unused */

#define VXLAN_DPORT	4789

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

#endif
