#ifndef PROTO_H_
#define PROTO_H_

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


#endif
