/*
 * (C) 2011-2014 Luigi Rizzo, Matteo Landi
 *
 * BSD license
 *
 * A netmap client to bridge two network interfaces
 * (or one interface and the host stack).
 *
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS’’ AND
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

#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>

#include "uvxbridge.h"
#include "uvxlan.h"

static int verbose = 0;

static int do_abort = 0;
//static int zerocopy = 1; /* enable zerocopy if possible */

typedef enum tundir {
	EGRESS,
	INGRESS
} tundir_t;

static void
sigint_h(int sig)
{
	(void)sig;	/* UNUSED */
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}

/*
 * how many packets on this set of queues ?
 */
static int
pkt_queued(struct nm_desc *d, int tx)
{
	u_int i, tot = 0;
	
	if (tx) {
		for (i = d->first_tx_ring; i <= d->last_tx_ring; i++) {
			tot += nm_ring_space(NETMAP_TXRING(d->nifp, i));
		}
	} else {
		for (i = d->first_rx_ring; i <= d->last_rx_ring; i++) {
			tot += nm_ring_space(NETMAP_RXRING(d->nifp, i));
		}
	}
	return tot;
}

static struct netmap_ring *
vx_txring(vxstate_t &state, tundir_t dir)
{
	abort();
	return NULL;
}

static void
nd_dispatch(char *rxbuf, uint16_t len, vxstate_t &state, tundir_t dir)
{
	struct netmap_ring *txring;
	struct ether_vlan_header *evh, *evhrsp;
	struct arphdr_ether dae, *sae;
	int hdrlen, etype;
	bool hit;

	txring = vx_txring(state, dir);
	if (nm_ring_space(txring) == 0)
		return;

	evh = (struct ether_vlan_header *)(rxbuf);
	if (evh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		hdrlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
		etype = ntohs(evh->evl_proto);
	} else {
		hdrlen = ETHER_HDR_LEN;
		etype = ntohs(evh->evl_encap_proto);
	}
	/* bad packet size - XXX do we have 18 bytes of PAD? */
	if (len != hdrlen + sizeof(struct arphdr_ether))
		return;

	sae = (struct arphdr_ether *)(rxbuf + hdrlen);
	if (dir == EGRESS)
		hit = nd_request(sae, &dae, state, state.vs_l2_vx);
	else
		hit = nd_request(sae, &dae, state, state.vs_l2_phys);
	if (hit) {
		int k = txring->cur;
		struct netmap_slot *ts = &txring->slot[k];
		char *txbuf = NETMAP_BUF(txring, ts->buf_idx);

		/* advance ring */
		txring->head = txring->cur = nm_ring_next(txring, k);
		/* fill in response */
		evhrsp = (struct ether_vlan_header *)(txbuf);
		memcpy(&evhrsp->evl_dhost, &evh->evl_shost, ETHER_ADDR_LEN);
		memcpy(&evhrsp->evl_shost, &evh->evl_dhost, ETHER_ADDR_LEN);
		evhrsp->evl_encap_proto = etype;
		if (hdrlen != ETHER_HDR_LEN) {
			evhrsp->evl_tag = evh->evl_tag;
			evhrsp->evl_proto = evh->evl_proto;
		}
		memcpy(txbuf + hdrlen, &dae, sizeof(struct arphdr_ether));
	}
}

static bool
pkt_dispatch(char *rxbuf, char *txbuf, uint16_t len, vxstate_t &state, tundir_t dir)
{
	struct ether_vlan_header *evh;
	int etype;

	evh = (struct ether_vlan_header *)(rxbuf);
	if (evh->evl_encap_proto == htons(ETHERTYPE_VLAN))
		etype = ntohs(evh->evl_proto);
   else
		etype = ntohs(evh->evl_encap_proto);

	/* XXX we only handle ipv4 here for v0 */
	if (__predict_false(etype == ETHERTYPE_ARP)) {
		nd_dispatch(rxbuf, len, state, dir);
		return false;
	} else if (dir == INGRESS)
		return vxlan_decap(rxbuf, txbuf, len, state);
	else
		return vxlan_encap(rxbuf, txbuf, len, state);
}

/*
 * move up to _limit_ pkts from rxring to txring swapping buffers.
 */
static int
process_rings(struct netmap_ring *rxring, struct netmap_ring *txring,
			  u_int limit, const char *msg, vxstate_t &state, tundir_t dir)
{
	u_int j, k, m = 0;

	/* print a warning if any of the ring flags is set (e.g. NM_REINIT) */
	if (rxring->flags || txring->flags)
		D("%s rxflags %x txflags %x",
			msg, rxring->flags, txring->flags);
	j = rxring->cur; /* RX */
	k = txring->cur; /* TX */
	m = nm_ring_space(rxring);
	if (m < limit)
		limit = m;
	m = nm_ring_space(txring);
	if (m < limit)
		limit = m;
	m = limit;
	while (limit-- > 0) {
		struct netmap_slot *rs = &rxring->slot[j];
		struct netmap_slot *ts = &txring->slot[k];
		char *rxbuf, *txbuf;

		/* swap packets */
		if (ts->buf_idx < 2 || rs->buf_idx < 2) {
			D("wrong index rx[%d] = %d  -> tx[%d] = %d",
				j, rs->buf_idx, k, ts->buf_idx);
			sleep(2);
		}
		/* copy the packet length. */
		if (rs->len > 2048) {
			D("wrong len %d rx[%d] -> tx[%d]", rs->len, j, k);
			rs->len = 0;
		} else if (verbose > 1) {
			D("%s send len %d rx[%d] -> tx[%d]", msg, rs->len, j, k);
		}
		ts->len = rs->len;
#ifdef original
		if (zerocopy) {
			uint32_t pkt = ts->buf_idx;
			ts->buf_idx = rs->buf_idx;
			rs->buf_idx = pkt;
			/* report the buffer change. */
			ts->flags |= NS_BUF_CHANGED;
			rs->flags |= NS_BUF_CHANGED;
		} else {
			char *rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
			char *txbuf = NETMAP_BUF(txring, ts->buf_idx);
			nm_pkt_copy(rxbuf, txbuf, ts->len);
		}
#endif
		/*
		 * XXX we can’t do zero copy until we update VALE
		 * to provide the requisite headroom
		 */
		rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
		txbuf = NETMAP_BUF(txring, ts->buf_idx);
		j = nm_ring_next(rxring, j);
		/* we only need to advance the txring idx if txbuf is consumed */
		if (pkt_dispatch(rxbuf, txbuf, ts->len, state, dir))
			k = nm_ring_next(txring, k);
	}
	rxring->head = rxring->cur = j;
	txring->head = txring->cur = k;
	if (verbose && m > 0)
		D("%s sent %d packets to %p", msg, m, txring);

	return (m);
}

/* move packets from src to destination */
static int
move(struct nm_desc *src, struct nm_desc *dst, u_int limit, vxstate_t &state,
	 tundir_t dir)
{
	struct netmap_ring *txring, *rxring;
	u_int m = 0, si = src->first_rx_ring, di = dst->first_tx_ring;
	const char *msg = (src->req.nr_flags == NR_REG_SW) ?
		"host->net" : "net->host";

	while (si <= src->last_rx_ring && di <= dst->last_tx_ring) {
		rxring = NETMAP_RXRING(src->nifp, si);
		txring = NETMAP_TXRING(dst->nifp, di);
		ND("txring %p rxring %p", txring, rxring);
		if (nm_ring_empty(rxring)) {
			si++;
			continue;
		}
		if (nm_ring_empty(txring)) {
			di++;
			continue;
		}
		m += process_rings(rxring, txring, limit, msg, state, dir);
	}

	return (m);
}

int
run_datapath(vxstate_t &state)
{
	struct pollfd pollfd[2];
//	int ch;
	u_int burst = 1024, wait_link = 4;
	// pa = host; pb = egress 
	struct nm_desc *pa = NULL, *pb = NULL;
//	char *ifa = NULL, *ifb = NULL;

	sleep(wait_link);
	/* main loop */
	signal(SIGINT, sigint_h);
	while (!do_abort) {
		int n0, n1, ret;
		pollfd[0].events = pollfd[1].events = 0;
		pollfd[0].revents = pollfd[1].revents = 0;
		n0 = pkt_queued(pa, 0);
		n1 = pkt_queued(pb, 0);
#if defined(_WIN32) || defined(BUSYWAIT)
		if (n0) {
			ioctl(pollfd[1].fd, NIOCTXSYNC, NULL);
			pollfd[1].revents = POLLOUT;
		} else {
			ioctl(pollfd[0].fd, NIOCRXSYNC, NULL);
		}
		if (n1) {
			ioctl(pollfd[0].fd, NIOCTXSYNC, NULL);
			pollfd[0].revents = POLLOUT;
		} else {
			ioctl(pollfd[1].fd, NIOCRXSYNC, NULL);
		}
		ret = 1;
#else
		if (n0)
			pollfd[1].events |= POLLOUT;
		else
			pollfd[0].events |= POLLIN;
		if (n1)
			pollfd[0].events |= POLLOUT;
		else
			pollfd[1].events |= POLLIN;

		/* poll() also cause kernel to txsync/rxsync the NICs */
		ret = poll(pollfd, 2, 2500);
#endif /* defined(_WIN32) || defined(BUSYWAIT) */
		if (ret <= 0 || verbose)
		    D("poll %s [0] ev %x %x rx %d@%d tx %d,"
			     " [1] ev %x %x rx %d@%d tx %d",
				ret <= 0 ? "timeout" : "ok",
				pollfd[0].events,
				pollfd[0].revents,
				pkt_queued(pa, 0),
				NETMAP_RXRING(pa->nifp, pa->cur_rx_ring)->cur,
				pkt_queued(pa, 1),
				pollfd[1].events,
				pollfd[1].revents,
				pkt_queued(pb, 0),
				NETMAP_RXRING(pb->nifp, pb->cur_rx_ring)->cur,
				pkt_queued(pb, 1)
			);
		if (ret < 0)
			continue;
		if (pollfd[0].revents & POLLERR) {
			struct netmap_ring *rx = NETMAP_RXRING(pa->nifp, pa->cur_rx_ring);
			D("error on fd0, rx [%d,%d,%d)",
				rx->head, rx->cur, rx->tail);
		}
		if (pollfd[1].revents & POLLERR) {
			struct netmap_ring *rx = NETMAP_RXRING(pb->nifp, pb->cur_rx_ring);
			D("error on fd1, rx [%d,%d,%d)",
				rx->head, rx->cur, rx->tail);
		}
		if (pollfd[0].revents & POLLOUT)
			move(pb, pa, burst, state, INGRESS);

		if (pollfd[1].revents & POLLOUT)
			move(pa, pb, burst, state, EGRESS);

		/* We don’t need ioctl(NIOCTXSYNC) on the two file descriptors here,
		 * kernel will txsync on next poll(). */
	}	
	return 0;
}
