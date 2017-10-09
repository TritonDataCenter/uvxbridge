#ifndef DATAPATH_H_
#define DATAPATH_H_
typedef enum {
	AtoB,
	BtoA
} datadir_t;

typedef struct {
	struct netmap_ring *ps_txring;
	u_int *ps_pidx;
	datadir_t ps_dir;
} path_state_t;

typedef struct {
	char *da_pa_name; /* name of the first netmap port */
	char *da_pb_name; /* optional name of the second netmap port */
	struct nm_desc **da_pa; /* pointer to where to store a's nm_desc */
	struct nm_desc **da_pb; /* pointer to where to store b's nm_desc */
} dp_args_t;


int cmd_dispatch(char *rxbuf, char *txbuf, uint16_t len, void *state, path_state_t *);

/*
 * PUBLIC - more general interface to netmap below:
 * 
 * 
 * pkt_dispatch_t: handles a packet
 * returns: 1 if txbuf was consumed else 0
 *   args:
 *    txbuf: response packet
 *    rxbuf: received packet
 *    len: size of rxbuf
 *    arg: pointer to persistent state
 *    ps: only used by callers that need to send more than one packet in
 *        response
 *
 */
typedef int (*pkt_dispatch_t)(char *txbuf, char *rxbuf, uint16_t len, void *arg, path_state_t *);

/*
 * run_datapath: executes event loop of packet handling
 *    returns: 1 on failure otherwise 0 if exits gracefully
 *    args:
 *     port_args: names of ports and resulting nm_descs 
 *    dispatch: the rx packet handler
 *    arg: the arg passed to dispatch
 *
 */
int run_datapath(dp_args_t *port_args, pkt_dispatch_t dispatch, void *arg);



#endif
