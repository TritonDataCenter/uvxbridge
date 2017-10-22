#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>


#include "uvxbridge.h"
#include "uvxlan.h"

static uint64_t
mac_parse(const char *input)
{
	char *idx, *mac = strdup(input);
	const char *del = ":";
	uint64_t mac_num = 0;
	uint8_t *mac_nump = (uint8_t *)&mac_num;
	int i;

	for (i = 0; ((idx = strsep(&mac, del)) != NULL) && i < ETHER_ADDR_LEN; i++)
		mac_nump[i] = (uint8_t)strtol(idx, NULL, 16);
	free(mac);
	if (i < ETHER_ADDR_LEN)
		return 0;
	return	mac_num;
}

/*
 * beastie0:
 *
 * config:	vale0:1
 * ingress:	vale0:2
 * egress:	vale2:0
 * cmac:	CA:FE:00:00:BE:EF
 * pmac:	CA:FE:00:00:BA:BE
 *
 * ifmac:	BA:DB:AB:EC:AF:E1
 * interface: 192.168.2.1 - gw: 192.168.2.254
 * vxlan:	00:a0:98:69:52:53 -> 150
 * ftable:	00:a0:98:11:1c:d8 -> 192.168.2.2
 * physarp:	192.168.2.2 -> BA:DB:AB:EC:AF:E2
 * 
 * beastie1:
 *
 * config:	vale1:1
 * ingress:	vale2:1
 * egress:	vale1:2
 * cmac:	CA:FE:00:01:BE:EF
 * pmac:	CA:FE:00:01:BA:BE
 *
 * ifmac:	BA:DB:AB:EC:AF:E2
 * interface: 192.168.2.2 - gw: 192.168.2.254
 * vxlan:	00:a0:98:11:1c:d8 -> 150
 * ftable:	00:a0:98:69:52:53 -> 192.168.2.1
 * physarp:	192.168.2.1 -> BA:DB:AB:EC:AF:E1
 */

void
configure_beastie0(vxstate_t *state)
{
	rte_t *rte = &state->vs_dflt_rte;
	mac_vni_map_t *vnitbl = &state->vs_vni_table.mac2vni;
	ftablemap_t *ftablemap = &state->vs_ftables;
	ftable_t ftable;
	arp_t *l2tbl = &state->vs_l2_phys.l2t_v4;
	uint64_t ptnet_mac0, ptnet_mac1, physarp;
	vfe_t vfe;
	vnient_t vnient;
	uint32_t vxlanid = ntohl(150);
	uint32_t peerip;

	state->vs_intf_mac = mac_parse("BA:DB:AB:EC:AF:E1");
	rte->ri_mask.in4.s_addr = ntohl(0xffffff00);
	rte->ri_laddr.in4.s_addr = inet_network("192.168.2.1");
	rte->ri_raddr.in4.s_addr = inet_network("192.168.2.254");
	ptnet_mac0 = mac_parse("00:a0:98:69:52:53");
	ptnet_mac1 = mac_parse("00:a0:98:11:1c:d8");

	vnient.data = 0;
	vnient.fields.vxlanid = vxlanid;
	vnitbl->insert(u64pair(ptnet_mac0, vnient.data));
	bzero(&vfe, sizeof(vfe_t));
	vfe.vfe_raddr.in4.s_addr = inet_network("192.168.2.2");
	ftable.insert(pair<uint64_t, vfe_t>(ptnet_mac1, vfe));
	ftablemap->insert(pair<uint32_t, ftable_t>(vxlanid, ftable));
	physarp = mac_parse("BA:DB:AB:EC:AF:E2");
	peerip = inet_network("192.168.2.2");
	l2tbl->insert(pair<uint32_t, uint64_t>(peerip, physarp));
}

void
configure_beastie1(vxstate_t *state)
{
	rte_t *rte = &state->vs_dflt_rte;
	mac_vni_map_t *vnitbl = &state->vs_vni_table.mac2vni;
	ftablemap_t *ftablemap = &state->vs_ftables;
	ftable_t ftable;
	arp_t *l2tbl = &state->vs_l2_phys.l2t_v4;
	uint64_t ptnet_mac0, ptnet_mac1, physarp;
	vfe_t vfe;
	vnient_t vnient;
	uint32_t vxlanid = ntohl(150);
	uint32_t peerip;

	state->vs_intf_mac = mac_parse("BA:DB:AB:EC:AF:E2");
	rte->ri_mask.in4.s_addr = ntohl(0xffffff00);
	rte->ri_laddr.in4.s_addr = inet_network("192.168.2.2");
	rte->ri_raddr.in4.s_addr = inet_network("192.168.2.254");
	ptnet_mac0 = mac_parse("00:a0:98:69:52:53");
	ptnet_mac1 = mac_parse("00:a0:98:11:1c:d8");

	vnient.data = 0;
	vnient.fields.vxlanid = vxlanid;
	vnitbl->insert(u64pair(ptnet_mac1, vnient.data));
	bzero(&vfe, sizeof(vfe_t));
	vfe.vfe_raddr.in4.s_addr = inet_network("192.168.2.1");
	ftable.insert(pair<uint64_t, vfe_t>(ptnet_mac1, vfe));
	ftablemap->insert(pair<uint32_t, ftable_t>(vxlanid, ftable));
	physarp = mac_parse("BA:DB:AB:EC:AF:E1");
	peerip = inet_network("192.168.2.1");
	l2tbl->insert(pair<uint32_t, uint64_t>(peerip, physarp));
}
