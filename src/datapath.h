#ifndef DATAPATH_H_
#define DATAPATH_H_

#ifdef __cplusplus
extern “C” {
#endif
typedef enum {
	AtoB,
	BtoA
} datadir_t;

typedef struct {
	uint16_t *ps_tx_len;
	uint16_t ps_rx_len;
	uint16_t ps_pad0;
	datadir_t ps_dir;

	/* only needed when consuming or sending more than one buffer */
	struct netmap_ring *ps_txring;
	struct netmap_ring *ps_rxring;
	u_int *ps_rx_pidx;
	u_int *ps_tx_pidx;
} path_state_t;

typedef struct {
	char *da_pa_name; /* name of the first netmap port */
	char *da_pb_name; /* optional name of the second netmap port */
	struct nm_desc **da_pa; /* pointer to where to store a’s nm_desc */
	struct nm_desc **da_pb; /* pointer to where to store b’s nm_desc */
} dp_args_t;

/*
 * PUBLIC - more general interface to netmap below:
 * 
 * 
 * pkt_dispatch_t: handles a packet
 * returns: 1 if txbuf was consumed else 0
 *   args:
 *     rxbuf: received packet
 *     txbuf: response packet
 *     ps: packet sizes and ring state
 *     arg: pointer to persistent state
 * 
 *
 * A trivial example used for bridging two interfaces or echoing:
 *
 * int
 * bridge_dispatch(char *rxbuf, char *txbuf, path_state_t *ps, void *arg __unused)
 * {
 *    nm_pkt_copy(rxbuf, txbuf, ps->ps_rx_len);
 *    *(ps->ps_tx_len) = ps->ps_rx_len;
 *    return (1);
 * }
 *
 *
 */
typedef int (*pkt_dispatch_t)(char *txbuf, char *rxbuf, path_state_t *ps, void *arg);

/*
 * run_datapath: executes event loop of packet handling
 *    returns: 1 on failure otherwise 0 if exits gracefully
 *    args:
 *      port_args: names of ports and resulting nm_descs 
 *      dispatch: the rx packet handler
 *      arg: the arg passed to dispatch
 *
 */
int run_datapath(dp_args_t *port_args, pkt_dispatch_t dispatch, void *arg);

#ifdef __cplusplus
}
#endif

#endif
