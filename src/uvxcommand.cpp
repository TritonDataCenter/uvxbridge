#include <sys/types.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <datapath.h>

#include <nmutil.h>
#include "command.h"
#include "uvxbridge.h"
#include "uvxlan.h"

void
uvxcmd_fill(char *txbuf, uint64_t smac, uint64_t dmac, uint16_t op, uint16_t rc, uint16_t seqno)
{
	struct ether_header *eh = (struct ether_header *)txbuf;
	struct uvxcmd_header *uh = (struct uvxcmd_header *)(eh + 1);

	eh_fill(eh, smac, dmac, ETHERTYPE_UVXCONF);
	uh->uh_magic = UVXMAGIC;
	uh->uh_op = op;
	uh->uh_rc = rc;
	uh->uh_seqno = seqno;
}

int
cmd_dispatch_config(char *rxbuf, char *txbuf, path_state_t *ps, void *arg)
{
	vxstate_t *state = (vxstate_t *)arg;
	struct uvxcmd_header *uh = (struct uvxcmd_header *)(rxbuf + sizeof(struct ether_header));
	caddr_t rxdata = (caddr_t)(uh + 1);
	caddr_t txdata = txbuf + sizeof(struct ether_header) + sizeof(struct uvxcmd_header);	
	uint16_t size, rc, op;

	size = rc = op = 0;
	
	if (uh->uh_magic != UVXMAGIC)
		return (0);

	switch (uh->uh_op) {
		case CMD_ARP_REQUEST: {
			struct arp_request *arq = (struct arp_request *)rxdata;
			struct arp_reply *are = (struct arp_reply *)txdata;
			l2tbl_t &l2tbl = state->vs_l2_phys;
			auto it = l2tbl.l2t_v4.find(arq->ar_pa);
			op = CMD_ARP_REPLY;
			
			if (it != l2tbl.l2t_v4.end()) {
				u64tomac(it->second, are->ar_ha);
				are->ar_pa = arq->ar_pa;
				size = sizeof(*are);
			} else {
				rc = ENOENT;
			}
		}
			break;
		case CMD_ARP_REPLY: {
			struct arp_reply *are = (struct arp_reply *)rxdata;
			uint64_t mac = mactou64(are->ar_ha);
			l2tbl_t &l2tbl = state->vs_l2_phys;
			if (mac)
				l2tbl.l2t_v4.insert(pair<uint32_t, uint64_t>(are->ar_pa, mac));
			else
				l2tbl.l2t_v4.erase(are->ar_pa);
		}
			break;
		case CMD_FTE_REQUEST:
			break;
		case CMD_FTE_REPLY:			
			break;
		case CMD_VM_INTF_REQUEST:
			break;
		case CMD_VM_INTF_REPLY:
			break;
		case CMD_DTLS_CONFIGURE:
			break;
		case CMD_DTLS_QUERY:
			break;
		case CMD_IPFW:
			break;
		default:
			rc = ENOSYS;
			op = 0;
			break;
	}
	uvxcmd_fill(txbuf, state->vs_ctrl_mac, state->vs_prov_mac, op, rc, uh->uh_seqno);
	return (1);
}
