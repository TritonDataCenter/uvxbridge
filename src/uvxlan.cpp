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

extern "C" {
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <stdio.h>

#include <net/ethernet.h>
struct rmlock { uint8_t pad; }; /* Needed by pfil.h */
#include <net/pfil.h> /* PFIL_IN */

int ipfw_check_frame(void *arg, struct mbuf **m0, struct ifnet *ifp,
					 int dir, struct inpcb *inp, struct ip_fw_chain *);

}
#include "uvxbridge.h"
#include "uvxlan.h"
#include "proto.h"
#include "command.h"
#include <nmutil.h>
#include "xxhash.h"
#include <glue.h>

#define A(val) printf("got %s\n", #val)
extern int debug;

#define AE_REQUEST             0x0100040600080100UL
#define AE_REPLY               0x0200040600080100UL
static int vxlan_encap(char *rxbuf, char *txbuf, path_state_t *ps,
						  vxstate_dp_t *dp_state);


/*
 * Send a query to the provisioning agent
 */
void
data_send_cmd(uint64_t targetha, uint32_t targetip, uint16_t op, vxstate_t *state)
{
	char *txbuf, *data;
	path_state_t ps;
	int len;

	if ((txbuf = get_txbuf(&ps, state->vs_nm_ingress)) == NULL)
		return;

	uvxcmd_fill(txbuf, state->vs_ctrl_mac, state->vs_prov_mac, op, 0, 0);
	len = sizeof(struct ether_header) + sizeof(struct uvxcmd_header);
	data = txbuf + len;
	switch (op) {
		case CMD_VM_INTF_REQUEST: {
			struct vm_intf_request *vir = (struct vm_intf_request *)data;
			u64tomac(targetha, vir->vir_ha);
			len += sizeof(*vir);
		}
			break;
		case CMD_FTE_REQUEST: {
			struct fte_request *fr = (struct fte_request *)data;
			fr->fr_vxlanid = targetip;
			u64tomac(targetha, fr->fr_ha);
			len += sizeof(*fr);
		}
			break;
		case CMD_ARP_REQUEST: {
			struct arp_request *ar = (struct arp_request *)data;
			ar->ar_pa = targetip;
			len += sizeof(*ar);
		}
			break;
		case CMD_VX_ARP_REQUEST: {
			struct vx_arp_request *var = (struct vx_arp_request *)data;
			var->var_pa = targetip;
			var->var_vxlanid = targetha;
			len += sizeof(*var);
		}
			break;
		default:
			/* error */
			return;
	}
	txring_next(&ps, len);
}

void
data_send_arp_phys(char *rxbuf, char *txbuf, path_state_t *ps, vxstate_t *state, int gratuitous)
{
	struct arphdr_ether *dae;
	struct ether_vlan_header *evh, *sevh;
	uint64_t dmac, broadcast = 0xFFFFFFFFFFFF;

	sevh = (struct ether_vlan_header *)(rxbuf);
	evh = (struct ether_vlan_header *)(txbuf);
	/* XXX hardcoding no VLAN */
	dae = (struct arphdr_ether *)(txbuf + ETHER_HDR_LEN);
	if (gratuitous)
		eh_fill((struct ether_header *)evh, state->vs_intf_mac, broadcast, ETHERTYPE_ARP);
	else {
		dmac = mactou64(sevh->evl_shost);
		eh_fill((struct ether_header *)evh, state->vs_intf_mac, dmac, ETHERTYPE_ARP);
	}
	dae->ae_hdr.data = AE_REPLY;
	dae->ae_spa = state->vs_dflt_rte.ri_laddr.in4.s_addr;
	u64tomac(state->vs_intf_mac, dae->ae_sha);
	dae->ae_tpa = state->vs_dflt_rte.ri_laddr.in4.s_addr;
	u64tomac(state->vs_intf_mac, dae->ae_tha);
	*(ps->ps_tx_len) = 60;
}

static void
uvxstat_fill(struct uvxstat *stat, vxstate_t *state)
{
	/* XXX -- only supports one datapath */
	if (state->vs_datapath_count)
		memcpy(stat, &state->vs_dp_states[0]->vsd_stats, sizeof(*stat));
}

/*
 * Respond to queries for our encapsulating IP
 */
static int
data_dispatch_arp_phys(char *rxbuf, char *txbuf, path_state_t *ps,
				  vxstate_dp_t *dp_state)
{
	vxstate_t *state = dp_state->vsd_state;
	struct arphdr_ether *sah;
	struct ether_vlan_header *evh;
	int etype, hdrlen;

	evh = (struct ether_vlan_header *)(rxbuf);
	if (evh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		etype = ntohs(evh->evl_proto);
		hdrlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
	} else {
		etype = ntohs(evh->evl_encap_proto);
		hdrlen = ETHER_HDR_LEN;
	}
	sah = (struct arphdr_ether *)(rxbuf + hdrlen);
	if (sah->ae_hdr.data != AE_REQUEST)
		return (0);
	if (sah->ae_tpa != state->vs_dflt_rte.ri_laddr.in4.s_addr)
		return (0);

	/* we've confirmed that it's bound for us - we need to respond */
	data_send_arp_phys(rxbuf, txbuf, ps, state, 0);
	return (1);
}

/*
 * Proactively query the provisioning agent
 * - guest MAC -> vxlanid and vlanid when they ARP
 * - destination MAC -> remote IP when they ARP for the vxlan MAC
 * - remote IP -> remote MAC when the remote IP is first learned
 */
static int
data_dispatch_arp_vx(char *rxbuf, char *txbuf, path_state_t *ps,
				  vxstate_dp_t *dp_state)
{
	struct ether_vlan_header *evh;
	struct arphdr_ether *sae;
	vxstate_t *state = dp_state->vsd_state;
	intf_info_map_t &intftbl = state->vs_intf_table;
	ftablemap_t *ftablemap = &state->vs_ftables;
	int etype, hdrlen;
	uint64_t mac;
	uint32_t vxlanid;

	evh = (struct ether_vlan_header *)rxbuf;
	if (evh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		hdrlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
		etype = ntohs(evh->evl_proto);
	} else {
		hdrlen = ETHER_HDR_LEN;
		etype = ntohs(evh->evl_encap_proto);
	}
	sae = (struct arphdr_ether *)(rxbuf + hdrlen);

	/* a host local VM MAC address -- need to have vxlanid */
	mac = mactou64(evh->evl_shost);
	if (mac == state->vs_intf_mac) {
		nm_pkt_copy(rxbuf, txbuf, ps->ps_rx_len);
		*ps->ps_tx_len = ps->ps_rx_len;
		return (1);
	}

	if (mac != state->vs_prov_mac) {
		auto it_ii = intftbl.find(mac);
		if (it_ii == intftbl.end()) {
			/* request vxlanid */
			data_send_cmd(mac, 0, CMD_VM_INTF_REQUEST, state);
			return (0);
		}
	}

	mac = mactou64(evh->evl_shost);
	/* the provisioning agent responded -- should be a remote IP */
	if (mac == state->vs_prov_mac &&
		sae->ae_hdr.fields.ar_op == ntohs(ARPOP_REPLY)) {
		/* check if we have an IP -> MAC mapping */
		mac = mactou64(evh->evl_dhost);
		auto it_ii = intftbl.find(mac);
		if (it_ii == intftbl.end()) {
			/* request vxlanid */
			data_send_cmd(mac, 0, CMD_VM_INTF_REQUEST, state);
			return (0);
		}
		vxlanid = it_ii->second->ii_ent.fields.vxlanid;
		auto it_ftable = ftablemap->find(vxlanid);
		if (it_ftable == ftablemap->end()) {
			/* send request for VXLANID */
			data_send_cmd(mac, 0, CMD_VM_INTF_REQUEST, state);
			return (0);
		}
		/* XXX -- implement a reverse lookup table for forwarding table entries */
		//data_send_cmd(vxlanid, sae->ae_tpa, AE_REVREQUEST, state);

	}
	return (0);
}

void
netmap_enqueue(struct mbuf *m, int proto __unused)
{
	struct netmap_port *peer = (struct netmap_port *)m->__m_peer;
	path_state_t ps;
	struct nm_desc *d;
	char *txbuf;

	if (peer == NULL) {
		D("error missing peer in %p", m);
		m_freem(m);
	}
	if (peer->np_dir == AtoB)
		d = peer->np_state->vsd_state->vs_nm_egress;
	else
		d = peer->np_state->vsd_state->vs_nm_ingress;
	bzero(&ps, sizeof(path_state_t));
	if ((txbuf = get_txbuf(&ps, d)) == NULL)
		return;
	if (peer->np_dir == AtoB) {
		ps.ps_rx_len = m->m_len;
		if (vxlan_encap((char *)m->m_data, txbuf, &ps, peer->np_state))
			txring_next(&ps, *(ps.ps_tx_len));
	} else {
		/* XXX --- fragmentation */
		nm_pkt_copy(m->m_data, txbuf, m->m_len);
		txring_next(&ps, m->m_len);
	}
	m_freem(m);
}

static int
ipfw_check(char *buf, uint16_t len, struct netmap_port *src, struct netmap_port *dst,
	struct ip_fw_chain *chain)
{
	struct mbuf m0, *mp;

	mp = &m0;
	m0.m_flags = M_STACK;
	m0.__m_extbuf = buf;
	m0.__m_extlen = len;
	m0.__m_peer = dst;
	m0.__m_callback = netmap_enqueue;
	m0.m_pkthdr.rcvif = src->np_ifp;
	m0.m_data = buf;
	m0.m_len = m0.m_pkthdr.len = len;
	ipfw_check_frame(NULL, &mp, NULL, PFIL_IN, NULL, chain);
	if (mp == NULL || m0.__m_peer != dst)
		return (0);
	return (1);
}


static void
tun_encrypt(char *txbuf, std::shared_ptr<Botan::BlockCipher> &cipher, vxstate_t *state)
{
	struct ip *ip;
	struct udphdr *uh;
	struct vxlanhdr *vh;
	uint8_t *data;
	uint32_t timestamp;

	timestamp = state->vs_timestamp;
	ip = (struct ip *)(txbuf + sizeof(struct ether_header));
	uh = (struct udphdr *)(ip + 1);
	data = (uint8_t *)(uh + 1);
	vh = (struct vxlanhdr *)data;
	vh->reserved0 = timestamp >> 21;
	vh->reserved1 = timestamp >> 8;
	vh->reserved2 = ip->ip_len;
	vh->reserved3 = timestamp;
	ip->ip_len = htons(state->vs_mtu);
	uh->uh_ulen = htons(state->vs_mtu - sizeof(*ip));
	uh->uh_dport = htons(443);
	cipher->encrypt_n((const uint8_t *)data, data, state->vs_mtu_blocks);
	cipher->clear();
}

/*
 * If valid, encapsulate rxbuf in to txbuf
 *
 */
static int
vxlan_encap(char *rxbuf, char *txbuf, path_state_t *ps,
			   vxstate_dp_t *dp_state)
{
	struct ether_vlan_header *evh;
	int hdrlen, etype;
	vfe_t *vfe;
	vxstate_t *state = dp_state->vsd_state;
	intf_info_map_t &intftbl = state->vs_intf_table;
	ftablemap_t *ftablemap = &state->vs_ftables;
	rte_t *rte = &state->vs_dflt_rte;
	arp_t *l2tbl = &state->vs_l2_phys.l2t_v4;
	struct egress_cache ec, *ecp;
	struct ip_fw_chain *chain;
	uint64_t srcmac, dstmac, targetha;
	uint16_t sport, pktsize;
	uint32_t vxlanid, laddr, raddr, maskraddr, maskladdr, range;

	evh = (struct ether_vlan_header *)(rxbuf);
	srcmac = mactou64(evh->evl_shost);
	dstmac = mactou64(evh->evl_dhost);
	/* ignore our own traffic */
	if (__predict_false(srcmac == state->vs_ctrl_mac))
		return (0);
	if (dp_state->vsd_ecache.ec_smac == srcmac &&
		dp_state->vsd_ecache.ec_dmac == dstmac) {
		ecp = &dp_state->vsd_ecache;
		chain = ecp->ec_chain;
		if (chain != NULL) {
			/* XXX do ipfw_check on packet */
			if (ipfw_check(rxbuf, ps->ps_rx_len, &dp_state->vsd_ingress_port,
						   &dp_state->vsd_egress_port, chain) == 0)
				return (0);
		}
		/* XXX VLAN only */
		memcpy(txbuf, &dp_state->vsd_ecache.ec_hdr.vh, sizeof(struct vxlan_header));
		nm_pkt_copy(rxbuf, txbuf + sizeof(struct vxlan_header), ps->ps_rx_len);
		if (ecp->ec_flags & EC_TUN) {
			tun_encrypt(txbuf, dp_state->vsd_ecache.ec_cipher, state);
			*(ps->ps_tx_len) = state->vs_mtu;
		} else 
			*(ps->ps_tx_len) = ps->ps_rx_len + sizeof(struct vxlan_header);
		return (1);
	}
	if (evh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		hdrlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
		etype = ntohs(evh->evl_proto);
	} else {
		hdrlen = ETHER_HDR_LEN;
		etype = ntohs(evh->evl_encap_proto);
	}
	ec.ec_flags = 0;
	ec.ec_smac = srcmac;
	ec.ec_dmac = dstmac;
	ec.ec_chain = NULL;
	pktsize = ps->ps_rx_len + sizeof(struct vxlan_header);
	/* fill out final data -- XXX assume no VLAN */
	*((uint64_t *)(uintptr_t)&ec.ec_hdr.vh.vh_vxlanhdr) = 0;
	ec.ec_hdr.vh.vh_vxlanhdr.v_i = 1;
	laddr = rte->ri_laddr.in4.s_addr;

	/* first map evh->evl_shost -> vxlanid / vlanid  --- vs_vni_table */
	targetha = srcmac;
	auto it_ii = intftbl.find(targetha);
	if (it_ii != intftbl.end()) {
		vxlanid = it_ii->second->ii_ent.fields.vxlanid;
	} else {
		data_send_cmd(targetha, 0, CMD_VM_INTF_REQUEST, state);
		/* send request for VXLANID */
		return (0);
	}
	if (it_ii->second->ii_ent.fields.flags & AE_IPFW_EGRESS) {
		ec.ec_chain = it_ii->second->ii_chain;
		/* XXX pass packet to ipfw_chk */
		if (ipfw_check(rxbuf, ps->ps_rx_len, &dp_state->vsd_ingress_port,
					   &dp_state->vsd_egress_port, ec.ec_chain) == 0)
			return (0);
	}
	ec.ec_hdr.vh.vh_vxlanhdr.v_vxlanid = vxlanid;
	/* calculate source port */
	range = state->vs_max_port - state->vs_min_port + 1;
	sport = XXH32(rxbuf, ETHER_HDR_LEN, state->vs_seed) % range;
	sport += state->vs_min_port;
	udp_fill(&ec.ec_hdr.vh.vh_udphdr, sport, VXLAN_DPORT,
			 pktsize - sizeof(struct ether_header) - sizeof(struct ip));

	/* next map evh->evl_dhost -> remote ip addr in the
	 * corresponding forwarding table - check vs_ftable
	 *
	 */
	auto it_ftable = ftablemap->find(vxlanid);
	if (it_ftable == ftablemap->end()) {
		data_send_cmd(targetha, 0, CMD_VM_INTF_REQUEST, state);
		/* send request for VXLANID */
		return (0);
	}
	targetha = mactou64(evh->evl_dhost);
	auto it_fte = it_ftable->second.find(targetha);
	if (it_fte != it_ftable->second.end()) {
		vfe = &it_fte->second;
		raddr = vfe->vfe_raddr.in4.s_addr;
	} else {
		/* send RARP for ftable entry */
		data_send_cmd(targetha, vxlanid, CMD_FTE_REQUEST, state);
		return (0);
	}
	ip_fill(&ec.ec_hdr.vh.vh_iphdr, laddr, raddr,
			pktsize - sizeof(struct ether_header), IPPROTO_UDP);

	/* ..... */
	/* next check if remote ip is on our local subnet
	 * chech address & subnet mask
	 */
	maskraddr = raddr & rte->ri_mask.in4.s_addr;
	maskladdr = laddr & rte->ri_mask.in4.s_addr;
	/* .... */
	/* if yes - lookup MAC address for peer - vs_l2_phys */
	if (maskraddr == maskladdr) {
		auto it = l2tbl->find(raddr);
		if (it == l2tbl->end()) {
			/* call ARP for L2 addr */
			data_send_cmd(0, raddr, CMD_ARP_REQUEST, state);
			return (0);
		}
		dstmac = it->second;
	} else {
		/* .... */
		/* if no - lookup MAC address for corresponding router
		 * vs_dflt_rte -> vs_l2_phys
		 */
		auto it = l2tbl->find(rte->ri_raddr.in4.s_addr);
		if (it == l2tbl->end()) {
			/* call ARP for L2 addr */
			data_send_cmd(0, raddr, CMD_ARP_REQUEST, state);
			return (0);
		}
		dstmac = it->second;
	}
	eh_fill(&ec.ec_hdr.vh.vh_ehdr, state->vs_intf_mac, dstmac, ETHERTYPE_IP);
	memcpy(&dp_state->vsd_ecache, &ec, sizeof(struct egress_cache));
	memcpy(txbuf, &ec.ec_hdr, sizeof(struct vxlan_header));
	nm_pkt_copy(rxbuf, txbuf + sizeof(struct vxlan_header), ps->ps_rx_len);

	if (!vfe->vfe_encrypt) {
		*(ps->ps_tx_len) = pktsize;
		return (1);
	}
	/* call encrypted channel */
	ec.ec_cipher = vfe->vfe_cipher;
	ec.ec_flags |= EC_TUN;
	tun_encrypt(txbuf, vfe->vfe_cipher, state);
	*(ps->ps_tx_len) = state->vs_mtu;
	return (1);
}

static int
vxlan_decap_v4(char *rxbuf, char *txbuf, path_state_t *ps,
			   vxstate_dp_t *dp_state)
{
	struct vxlan_header *vh = (struct vxlan_header *)rxbuf;
	struct ip *ip = &vh->vh_iphdr;
	uint32_t rxvxlanid = vh->vh_vxlanhdr.v_vxlanid;
	struct ether_header *eh = (struct ether_header *)(rxbuf + sizeof(*vh));
	uint64_t dmac = mactou64(eh->ether_dhost);
	vxstate_t *state = dp_state->vsd_state;
	intf_info_map_t &intftbl = state->vs_intf_table;
	uint16_t pktlen;
#if 0
	/* this check doesn't work */
	uint16_t iplen = ntohs(ip->ip_len);
	pktlen = min(ps->ps_rx_len, iplen + sizeof(*eh));
	if (iplen + sizeof(*eh) != ps->ps_rx_len) {
		printf("header len mismatch rx_len: %d iplen: %d\n",
			   ps->ps_rx_len, iplen + sizeof(*eh));
	}
#endif	
	pktlen = ps->ps_rx_len;

	if (__predict_false(pktlen <= sizeof(struct vxlan_header)))
		return (0);

	auto it = intftbl.find(dmac);
	/* we have no knowledge of this MAC address */
	if (it == intftbl.end())
		return (0);
	/* this MAC address isn't on the VXLAN that we were addressed with */
	if (it->second->ii_ent.fields.vxlanid != rxvxlanid)
		return (0);
	if (it->second->ii_ent.fields.flags & AE_IPFW_INGRESS) {
		/* XXX call ipfw_check */
		if (ipfw_check(rxbuf, ps->ps_rx_len, &dp_state->vsd_egress_port,
					   &dp_state->vsd_ingress_port,
					   it->second->ii_chain) == 0)
			return (0);

	}
	/* copy encapsulated packet */
	pktlen -= sizeof(struct vxlan_header);
	nm_pkt_copy(rxbuf + sizeof(*vh), txbuf, pktlen);
	*(ps->ps_tx_len) = pktlen;
	return (1);
}

static int
tun_decrypt_v4(char *rxbuf, char *txbuf, path_state_t *ps,
				vxstate_dp_t *dp_state)
{
	struct ip *ip = (struct ip *)(rxbuf + sizeof(struct ether_header));
	struct udphdr *uh = (struct udphdr *)(ip + 1);
	uint8_t *data = (uint8_t *)(uh + 1);
	struct vxlanhdr *vh = (struct vxlanhdr *)data;
	uint32_t timestamp, masked_timestamp;

	dp_state->vsd_cipher->decrypt(data);
	/* reassemble timestamp from reserved fields */
	timestamp = (vh->reserved0 << 21) | (vh->reserved1 << 8) | (vh->reserved3);
	masked_timestamp = dp_state->vsd_state->vs_timestamp & ((1<<25)-1);
	/* peer timestamp is more than 5 minutes different */
	if (abs((int)(masked_timestamp - timestamp)) > 3000)
		return (0);

	ip->ip_len = vh->reserved2;
	uh->uh_ulen = htons(ntohs(ip->ip_len) - sizeof(*ip));
	return vxlan_decap_v4(rxbuf, txbuf, ps, dp_state);
}

static int
udp_ingress(char *rxbuf, char *txbuf, path_state_t *ps, vxstate_dp_t *state)
{
	struct ether_header *eh = (struct ether_header *)rxbuf;
	struct ip *ip = (struct ip *)(uintptr_t)(eh + 1);
	struct udphdr *uh = (struct udphdr *)(ip + 1);
	uint16_t dport = ntohs(uh->uh_dport);

	switch (dport) {
		case DTLS_DPORT:
			/* XXX decrypt */
			return tun_decrypt_v4(rxbuf, txbuf, ps, state);
			break;
		case VXLAN_DPORT:
			return vxlan_decap_v4(rxbuf, txbuf, ps, state);
			break;
		default:
			/* XXX log */
			return (0);
			break;
	}
}

static int
ingress_dispatch(char *rxbuf, char *txbuf, path_state_t *ps, vxstate_dp_t *state)
{
	struct ether_vlan_header *evh;
	int etype;

	evh = (struct ether_vlan_header *)(rxbuf);
	if (evh->evl_encap_proto == htons(ETHERTYPE_VLAN))
		etype = ntohs(evh->evl_proto);
	else
		etype = ntohs(evh->evl_encap_proto);

	switch (etype) {
		case ETHERTYPE_ARP:
			return data_dispatch_arp_phys(rxbuf, txbuf, ps, state);
			break;
		case ETHERTYPE_IP:
			return udp_ingress(rxbuf, txbuf, ps, state);
			break;
		case ETHERTYPE_IPV6:
			/* V6 not currently supported on the underlay */
			break;
		default:
			printf("%s unrecognized packet type %x len: %d\n", __func__, etype, ps->ps_rx_len);
			break;
	}
	return (0);
}

static int
egress_dispatch(char *rxbuf, char *txbuf, path_state_t *ps, vxstate_dp_t *state)
{
	struct ether_vlan_header *evh;
	int etype;

	evh = (struct ether_vlan_header *)(rxbuf);
	if (evh->evl_encap_proto == htons(ETHERTYPE_VLAN))
		etype = ntohs(evh->evl_proto);
	else
		etype = ntohs(evh->evl_encap_proto);

	switch (etype) {
		case ETHERTYPE_ARP:
			data_dispatch_arp_vx(rxbuf, txbuf, ps, state);
			break;
		case ETHERTYPE_IP:
		case ETHERTYPE_IPV6:
			return vxlan_encap(rxbuf, txbuf, ps, state);
			break;
		default:
			printf("%s unrecognized packet type %x len: %d\n", __func__, etype, ps->ps_rx_len);
			break;
	}
	return (0);
}

int
data_dispatch(char *rxbuf, char *txbuf, path_state_t *ps, void *arg)
{
	vxstate_dp_t *state = (vxstate_dp_t *)arg;

	if (ps->ps_dir == AtoB)
		return egress_dispatch(rxbuf, txbuf, ps, state);
	else
		return ingress_dispatch(rxbuf, txbuf, ps, state);
}
