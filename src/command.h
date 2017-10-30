#ifndef _UVXCOMMAND_H_
#define _UVXCOMMAND_H_

#define	ETHERTYPE_UVXCONF		0xDECA	/* uxvxbridge config type  */
#define UVXMAGIC				0xABADCAFE
#define UVX_KEYSIZE 32

struct uvxcmd_header {
	uint16_t uh_seqno;
	uint16_t uh_op;
	uint16_t uh_rc;
	uint32_t uh_magic;
};

struct arp_request {
	uint32_t ar_pa;
};

struct arp_reply {
	uint32_t ar_pa;
	uint8_t ar_ha[ETHER_ADDR_LEN];
};

struct fte_request {
	uint32_t fr_vxlanid;
	uint8_t fr_ha[ETHER_ADDR_LEN];
};

struct fte_reply {
	uint32_t fr_pa;
	uint32_t fr_vxlanid;
	uint8_t fr_ha[ETHER_ADDR_LEN];
};

struct vm_intf_request {
	uint8_t vir_ha[ETHER_ADDR_LEN];
};

struct vm_intf_reply {
	uint16_t vir_vlanid;
	uint32_t vir_vxlanid;
	uint8_t	vir_ha[ETHER_ADDR_LEN];
	uint32_t vir_flags;
};

struct tun_configure_client {
	struct in_addr tcc_pa;
	uint8_t tcc_psk[UVX_KEYSIZE];
};

struct tun_configure_server {
	uint8_t tcs_psk[UVX_KEYSIZE];
};

struct tun_query {
	struct in_addr tq_pa;
	uint8_t tq_psk[UVX_KEYSIZE];
};

struct route_configure {
	uint32_t rc_lpa;
	uint32_t rc_rpa;
	uint16_t rc_prefixlen;
	uint16_t rc_flags;
};

#define CMD_OP_NONE			0x0
#define CMD_ARP_REQUEST		0x1
#define CMD_ARP_REPLY		0x2

#define CMD_FTE_REQUEST		0x3
#define CMD_FTE_REPLY		0x4

#define CMD_VM_INTF_REQUEST	0x5
#define CMD_VM_INTF_REPLY	0x6

#define CMD_TUN_SERVCONF	0x7
#define CMD_TUN_CLICONF	0x8
#define CMD_TUN_QUERY		0x9

#define CMD_ROUTE_CONFIGURE	0xA
#define CMD_ROUTE_QUERY		0xB

#define CMD_IPFW			0xC
#define CMD_HEARTBEAT		0xD

void uvxcmd_fill(char *txbuf, uint64_t smac, uint64_t dmac, uint32_t op);



#endif
