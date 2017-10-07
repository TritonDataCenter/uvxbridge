#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>

#include "uvxbridge.h"
#include "uvxlan.h"

/*
 * If rxbuf contains a neighbor discovery request, save a
 * response and return true
 * dir = EGRESS => VX, dir = INGRESS => PHYS
 */
bool
nd_request(char *rxbuf, uint16_t len, vxstate_t &state __unused, tundir_t dir)
{
	return false;
}

/*
 * If there are pending neighbor discovery responses copy one 
 * to txbuf and return true
 *
 * dir = EGRESS => PHYS, dir = INGRESS => VX
 */
bool
nd_response(char *txbuf, uint16_t *len, vxstate_t &state __unused, tundir_t dir)
{
	return false;
}

/*
 * If valid, deencapsulate rxbuf in to txbuf
 *
 */
static int
vxlan_decap(char *rxbuf, char *txbuf, int len, vxstate_t &state __unused)
{
	nm_pkt_copy(rxbuf, txbuf, len);
	return 0;
}

/*
 * If valid, encapsulate rxbuf in to txbuf
 *
 */
static int
vxlan_encap(char *rxbuf, char *txbuf, int len, vxstate_t &state __unused)
{
    nm_pkt_copy(rxbuf, txbuf, len);
    return 0;
}

int
vxlan_tun(char *rxbuf, char *txbuf, int len, vxstate_t &state, tundir_t dir)
{
	if (dir == INGRESS)
		return vxlan_decap(rxbuf, txbuf, len, state);
	else
		return vxlan_encap(rxbuf, txbuf, len, state);
}


