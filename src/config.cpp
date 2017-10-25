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
 * This assumes the guests are tap50,vale0:0 and tap51,vale1:0.
 * The datapth looks like:
 * guest0<->vale0:0<->vale0:1<->uvxbridge<->vale2:0<->vale2:1<->uvxbridge<->vale1:1<->vale1:0<->guest1
 *
 * With this configuration you'll need to manually add the peer's MAC address for the private
 * netwrk - see 'arp -s'
 *
 * beastie0 (vale0:0):
 *
 * ingress:	vale0:1
 * egress:	vale2:0
 *
 * config:	vale0:2 (provisioning agent can use vale0:3)
 * cmac:	CA:FE:00:00:BE:EF
 * pmac:	CA:FE:00:00:BA:BE
 *
 * ifmac:	BA:DB:AB:EC:AF:E1
 * interface: 192.168.2.1 - gw: 192.168.2.254
 * vxlan:	00:a0:98:69:52:53 -> 150
 * ftable:	00:a0:98:11:1c:d8 -> 192.168.2.2
 * physarp:	192.168.2.2 -> BA:DB:AB:EC:AF:E2
 *
 * ./uvxbridge -c vale0:1 -i vale0:2 -e vale2:0 -m CA:FE:00:00:BE:EF -p CA:FE:00:00:BA:BE -t 1
 *
 * beastie1 (vale1:0):
 *
 * ingress:	vale1:1
 * egress:	vale2:1
 *
 * config:	vale1:2 (provisioning agent can use vale1:3)
 * cmac:	CA:FE:00:01:BE:EF
 * pmac:	CA:FE:00:01:BA:BE
 *
 * ifmac:	BA:DB:AB:EC:AF:E2
 * interface: 192.168.2.2 - gw: 192.168.2.254
 * vxlan:	00:a0:98:11:1c:d8 -> 150
 * ftable:	00:a0:98:69:52:53 -> 192.168.2.1
 * physarp:	192.168.2.1 -> BA:DB:AB:EC:AF:E1
 *
 * ./uvxbridge -c vale1:1 -i vale1:2 -e vale2:1 -m CA:FE:00:01:BE:EF -p CA:FE:00:01:BA:BE -t 2
 *
 */

void
configure_beastie0(vxstate_t *state)
{
	rte_t *rte = &state->vs_dflt_rte;
	intf_info_map_t *intftbl = &state->vs_intf_table;
	ftablemap_t *ftablemap = &state->vs_ftables;
	ftable_t ftable;
	arp_t *l2tbl = &state->vs_l2_phys.l2t_v4;
	uint64_t ptnet_mac0, ptnet_mac1, physarp;
	vfe_t vfe;
	intf_info_t *intfent;
	uint32_t vxlanid = ntohl(150) >> 8;
	uint32_t peerip;

	state->vs_intf_mac = mac_parse("BA:DB:AB:EC:AF:E1");
	rte->ri_mask.in4.s_addr = 0xffffff00;
	rte->ri_laddr.in4.s_addr = inet_network("192.168.2.1");
	rte->ri_raddr.in4.s_addr = inet_network("192.168.2.254");
	rte->ri_prefixlen = 24;
	rte->ri_flags = RI_VALID;
	ptnet_mac0 = mac_parse("00:a0:98:69:52:53");
	ptnet_mac1 = mac_parse("00:a0:98:11:1c:d8");

	intfent = new intf_info();
	intfent->ii_ent.fields.vxlanid = vxlanid;
	intftbl->insert(pair<uint64_t, intf_info_t*>(ptnet_mac0, intfent));

	bzero(&vfe, sizeof(vfe_t));
	vfe.vfe_raddr.in4.s_addr = inet_network("192.168.2.2");
	/* map beastie1 mac to 'host' for beastie1 */
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
	intf_info_map_t *intftbl = &state->vs_intf_table;
	ftablemap_t *ftablemap = &state->vs_ftables;
	ftable_t ftable;
	arp_t *l2tbl = &state->vs_l2_phys.l2t_v4;
	uint64_t ptnet_mac0, ptnet_mac1, physarp;
	vfe_t vfe;
	intf_info_t *intfent;
	uint32_t vxlanid = ntohl(150) >> 8;
	uint32_t peerip;

	state->vs_intf_mac = mac_parse("BA:DB:AB:EC:AF:E2");
	rte->ri_mask.in4.s_addr = 0xffffff00;
	rte->ri_laddr.in4.s_addr = inet_network("192.168.2.2");
	rte->ri_raddr.in4.s_addr = inet_network("192.168.2.254");
	rte->ri_prefixlen = 24;
	rte->ri_flags = RI_VALID;
	ptnet_mac0 = mac_parse("00:a0:98:69:52:53");
	ptnet_mac1 = mac_parse("00:a0:98:11:1c:d8");

	intfent = new intf_info();
	intfent->ii_ent.fields.vxlanid = vxlanid;
	intftbl->insert(pair<uint64_t, intf_info_t*>(ptnet_mac1, intfent));

	bzero(&vfe, sizeof(vfe_t));
	vfe.vfe_raddr.in4.s_addr = inet_network("192.168.2.1");
	ftable.insert(pair<uint64_t, vfe_t>(ptnet_mac0, vfe));
	ftablemap->insert(pair<uint32_t, ftable_t>(vxlanid, ftable));
	physarp = mac_parse("BA:DB:AB:EC:AF:E1");
	peerip = inet_network("192.168.2.1");
	l2tbl->insert(pair<uint32_t, uint64_t>(peerip, physarp));
}
