#ifndef PROTO_H_
#define PROTO_H_

#define BP_CHADDR_LEN	 16
#define BP_SNAME_LEN	 64
#define BP_FILE_LEN	128
#define BP_VEND_LEN	 64
#define BP_MINPKTSZ	300	/* to check sizeof(struct bootp) */
/* Overhead to fit a bootp message into an Ethernet packet. */
#define BP_MSG_OVERHEAD	(14 + 20 + 8)	/* Ethernet + IP + UDP headers */

struct bootp {
    unsigned char    bp_op;			/* packet opcode type */
    unsigned char    bp_htype;			/* hardware addr type */
    unsigned char    bp_hlen;			/* hardware addr length */
    unsigned char    bp_hops;			/* gateway hops */
    uint32_t	     bp_xid;			/* transaction ID */
    unsigned short   bp_secs;			/* seconds since boot began */
    unsigned short   bp_flags;			/* RFC1532 broadcast, etc. */
    struct in_addr   bp_ciaddr;			/* client IP address */
    struct in_addr   bp_yiaddr;			/* 'your' IP address */
    struct in_addr   bp_siaddr;			/* server IP address */
    struct in_addr   bp_giaddr;			/* gateway IP address */
    unsigned char    bp_chaddr[BP_CHADDR_LEN];	/* client hardware address */
    char	     bp_sname[BP_SNAME_LEN];	/* server host name */
    char	     bp_file[BP_FILE_LEN];	/* boot file name */
    unsigned char    bp_vend[BP_VEND_LEN];	/* vendor-specific area */
    /* note that bp_vend can be longer, extending to end of packet. */
};

#endif
