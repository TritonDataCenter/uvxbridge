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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS`` AND
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

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>

#include "datapath.h"

static int verbose = 0;

static int do_abort = 0;
//static int zerocopy = 1; /* enable zerocopy if possible */

static void
sigint_h(int sig)
{
    (void)sig;	/* UNUSED */
    do_abort = 1;
    signal(SIGINT, SIG_DFL);
}

static int
noop_dispatch(char *rxbuf __unused, char *txbuf __unused, path_state_t *ps __unused,
			  void *arg __unused)
{
	return (0);
}

/*
 * how many packets on this set of queues ?
 */
static u_int
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

/*
 * move up to _limit_ pkts from rxring to txring swapping buffers.
 */
static u_int
process_rings(struct netmap_ring *rxring, struct netmap_ring *txring,
			  u_int limit, const char *msg, pkt_dispatch_t rx_dispatch,
			  void *arg, datadir_t dir)
{
	u_int j, k, m = 0;
	path_state_t ps;

	ps.ps_tx_pidx = &k;
	ps.ps_rx_pidx = &j;
	ps.ps_dir = dir;
	ps.ps_rxring = rxring;
	ps.ps_txring = txring;
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
			D("wrong index rx[%d] = %d	-> tx[%d] = %d",
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
		ps.ps_rx_len = rs->len;
		ps.ps_tx_len = &ts->len;
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
		 * XXX we can't do zero copy until we update VALE
		 * to provide the requisite headroom
		 */
		rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
		txbuf = NETMAP_BUF(txring, ts->buf_idx);
		j = nm_ring_next(rxring, j);
		if (rx_dispatch(rxbuf, txbuf, &ps, arg))
			k = nm_ring_next(txring, k);
	}
	rxring->head = rxring->cur = j;
	txring->head = txring->cur = k;
	if (verbose && m > 0)
		D("%s sent %d packets to %p", msg, m, (void *)txring);

	return (m);
}

/* move packets from src to destination */
static u_int
move(struct nm_desc *src, struct nm_desc *dst, u_int limit,
     pkt_dispatch_t dispatch, void *arg, datadir_t dir)
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
		m += process_rings(rxring, txring, limit, msg, dispatch, arg, dir);
    }

    return (m);
}

static void
do_tx(struct nm_desc *pa, struct nm_desc *pb, pkt_dispatch_t tx_dispatch, void *arg)
{
	u_int k;
	path_state_t ps;
	char *txbuf;
	struct netmap_ring *txring;
	struct netmap_slot *ts;

	ps.ps_tx_pidx = &k;
	ps.ps_rx_pidx = NULL;
	ps.ps_rxring = NULL;
	ps.ps_rx_len = 0;

	/* transmit on port A */
	txring = NETMAP_TXRING(pa->nifp, pa->first_tx_ring);
	k = txring->cur;
	ts = &txring->slot[k];
	ps.ps_tx_len = &ts->len;
	txbuf = NETMAP_BUF(txring, ts->buf_idx);
	ps.ps_dir = AtoB;
	ps.ps_txring = txring;

	if (tx_dispatch(NULL, txbuf, &ps, arg))
		k = nm_ring_next(txring, k);
	txring->head = txring->cur = k;

	if (pa == pb)
		return;

	/* transmit on port B */
	txring = NETMAP_TXRING(pb->nifp, pb->first_tx_ring);
	k = txring->cur;
	ts = &txring->slot[k];
	txbuf = NETMAP_BUF(txring, ts->buf_idx);
	ps.ps_dir = BtoA;
	ps.ps_txring = txring;

	if (tx_dispatch(NULL, txbuf, &ps, arg))
		k = nm_ring_next(txring, k);
	txring->head = txring->cur = k;
}

// pa = host; pb = egress
static int
run_datapath_priv(struct nm_desc *pa, struct nm_desc *pb, pkt_dispatch_t rx_dispatch,
				  pkt_dispatch_t tx_dispatch, int timeout, void *arg)
{
    struct pollfd pollfd[2];
    u_int burst = 1024, wait_link = 2;

	/* setup poll(2) array */
	memset(pollfd, 0, sizeof(pollfd));
	pollfd[0].fd = pa->fd;
	pollfd[1].fd = pb->fd;

	if (pa != pb) {
		D("Wait %d secs for link to come up...", wait_link);
		sleep(wait_link);
	}
	D("Ready to go, %s 0x%x/%d <-> %s 0x%x/%d.",
		pa->req.nr_name, pa->first_rx_ring, pa->req.nr_rx_rings,
		pb->req.nr_name, pb->first_rx_ring, pb->req.nr_rx_rings);

    /* main loop */
    signal(SIGINT, sigint_h);
    while (!do_abort) {
		u_int n0, n1;
		int ret;

		if (tx_dispatch != NULL)
			do_tx(pa, pb, tx_dispatch, arg);
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
		ret = poll(pollfd, 2, timeout);
#endif /* defined(_WIN32) || defined(BUSYWAIT) */
		if (ret <= 0 || verbose) {
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
		}
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
			move(pb, pa, burst, rx_dispatch, arg, BtoA);

		if (pollfd[1].revents & POLLOUT)
			move(pa, pb, burst, rx_dispatch, arg, AtoB);

		/* We don't need ioctl(NIOCTXSYNC) on the two file descriptors here,
		 * kernel will txsync on next poll(). */
    }	
    return 0;
}

int
run_datapath(dp_args_t *port_args, void *arg)
{

    struct nm_desc *pa, *pb;
    char *pa_name, *pb_name;
	pkt_dispatch_t rx_dispatch = noop_dispatch;
	pkt_dispatch_t tx_dispatch = port_args->da_tx_dispatch;

	if (port_args->da_rx_dispatch != NULL)
		rx_dispatch = port_args->da_rx_dispatch;

    pa_name = port_args->da_pa_name;
    pb_name = port_args->da_pb_name;

    pa = nm_open(pa_name, NULL, 0, NULL);
    if (pa == NULL) {
		D("cannot open %s", pa_name);
		return (1);
    }
    if (port_args->da_pa != NULL)
		*(port_args->da_pa) = pa;
    if (pb_name != NULL) {
		pb = nm_open(pb_name, NULL, NM_OPEN_NO_MMAP, pa);
		if (pb == NULL) {
			D("cannot open %s", pb_name);
			return (1);
		}
		if (port_args->da_pb != NULL)
			*(port_args->da_pb) = pb;
    } else
		pb = pa;
    return run_datapath_priv(pa, pb, rx_dispatch, tx_dispatch,
							 port_args->da_poll_timeout, arg);
}
