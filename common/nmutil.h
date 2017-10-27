static uint64_t
mactou64(uint8_t *mac)
{
	uint64_t targetha = 0;
	uint16_t *src, *dst;

	src = (uint16_t *)(uintptr_t)mac;
	dst = (uint16_t *)&targetha;
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	return (targetha);
}

static void
u64tomac(uint64_t smac, uint8_t *dmac)
{
	uint16_t *src, *dst;

	dst = (uint16_t *)(uintptr_t)dmac;
	src = (uint16_t *)&smac;
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
}

char *
get_txbuf(path_state_t *ps, struct nm_desc *pa)
{
	struct netmap_ring *txring;
	struct netmap_slot *ts;

	if (__predict_false(pa == NULL))
		return (NULL);
	txring = NETMAP_TXRING(pa->nifp, pa->first_tx_ring);
	if (__predict_false(nm_ring_space(txring) == 0))
		return (NULL);
	ts = &txring->slot[txring->cur];
	ps->ps_txring = txring;
	ps->ps_tx_len = &ts->len;
	return NETMAP_BUF(txring, ts->buf_idx);
}

void
txring_next(path_state_t *ps, uint16_t pktlen)
{
	struct netmap_ring *txring = ps->ps_txring;

	*ps->ps_tx_len = pktlen;
	txring->head = txring->cur = nm_ring_next(txring, txring->cur);
}

static __inline void
eh_fill(struct ether_header *eh, uint64_t smac, uint64_t dmac, uint16_t type)
{
	uint16_t *d, *s;

	d = (uint16_t *)(uintptr_t)eh; /* ether_dhost */
	s = (uint16_t *)&dmac;
	d[0] = s[0];
	d[1] = s[1];
	d[2] = s[2];
	s = (uint16_t *)&smac;
	d[3] = s[0];
	d[4] = s[1];
	d[5] = s[2];
	eh->ether_type = htons(type);
}

static void
ip_fill(struct ip *ip, uint32_t sip, uint32_t dip, uint16_t len, uint8_t proto)
{
	ip->ip_v = 4;
	ip->ip_hl = (sizeof(struct ip) >> 2);
	ip->ip_tos = 0;
	ip->ip_len = htons(len);
	ip->ip_id = 0;
	ip->ip_off = htons(IP_DF);
	ip->ip_ttl = 1;
	ip->ip_p = proto;
	ip->ip_sum = 0; /* XXX */
	/* these should always be kept in network byte order (BE) */
	ip->ip_src.s_addr = sip;
	ip->ip_dst.s_addr = dip;
}

static void
udp_fill(struct udphdr *uh, uint16_t sport, uint16_t dport, uint16_t len)
{
	uh->uh_sport = htons(sport);
	uh->uh_dport = htons(dport);
	uh->uh_ulen = htons(len + sizeof(*uh));
	uh->uh_sum = 0; /* XXX */
}
