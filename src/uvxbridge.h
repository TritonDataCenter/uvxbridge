#ifndef SIMPLEPARSER_H_
#define SIMPLEPARSER_H_

#include <netinet/in.h>
/*  
 * VERB command set
 * 
 *   Add forwarding table entry map destination host mac to remote ip
 * - UPDATE_FTE:<seqno> mac: big-endian 6 bytes
 *                raddr: <4-tuple| v6addr w/ no symbolic>
 *             expire: 8 bytes - useconds
 *         (result:seqno error:<errstr> (gen: 4 byte)?)
 *
 *  Get forwarding entry details
 * - GET_FTE:<seqno> big-endian 6 bytes
 *       (result:<seqno> error:<errstr> (raddr: <4-tuple| v6addr w/ no symbolic>
 *              expire: 8 bytes - useconds
 *                 gen: 4 byte)?)
 * 
 * - REMOVE_FTE:<seqno> vxmac: big-endian 6 bytes
 *       (result:<seqno> error:<errstr>)
 *
 * - GET_ALL_FTE:<seqno>
 *         (result: error:<errstr> (mac: big-endian 6 bytes
 *                 raddr: <4-tuple| v6addr w/ no symbolic>
 *                expire: 8 bytes - useconds
 *                   gen: 4 byte)*)  
 *
 *
 *   manage physical L2 table entries for remote IP
 * - SET_PHYS_ND:<seqno> mac: big-endian 6 bytes raddr: <4-tuple| v6addr w/ no symbolic>
 *   (result:<seqno> error:<errstr>)
 *
 * - DEL_PHYS_ND:<seqno> mac: big-endian 6 bytes | raddr: <4-tuple| v6addr w/ no symbolic>
 *   (result:<seqno> error:<errstr>)
 *
 * - GET_PHYS_ND:<seqno> raddr: <4-tuple| v6addr w/ no symbolic>
 *      (result:<seqno>  error:<errstr> (mac: big-endian 6 bytes)?)
 *
 * - GET_ALL_PHYS_ND:<seqno>
 *       (result:<seqno> error:<errstr> (mac: big-endian 6 bytes
 *               raddr: <4-tuple| v6addr w/ no symbolic>)*)
 *
 *
 *   manage vxlan L2 table entries for remote IP
 * - SET_VX_ND:<seqno> mac: big-endian 6 bytes raddr: <4-tuple| v6addr w/ no symbolic>
 *   (result:<seqno> error:<errstr>)
 *
 * - DEL_VX_ND:<seqno> mac: big-endian 6 bytes |
 *             raddr: <4-tuple| v6addr w/ no symbolic>
 *   (result:<seqno> error:<errstr>)
 *
 * - GET_VX_ND:<seqno> raddr: <4-tuple| v6addr w/ no symbolic>
 *      (result:<seqno> error:<errstr> (mac: big-endian 6 bytes)?)
 *
 * - GET_ALL_VX_ND:<seqno>
 *       (result:<seqno> error:<errstr> (mac: big-endian 6 bytes
 *               raddr: <4-tuple| v6addr w/ no symbolic>)*)
 *
 *
 *   map local VM mac to 5 byte vlanid|vxlanid
 * - UPDATE_VM_VNI:<seqno> vlanid: 2-bytes vxlanid: 3-bytes mac: 6-bytes
 *     (result:<seqno> error:<errstr> (gen: 4 byte))
 *
 * - GET_VM_VNI:<seqno> mac: 6-bytes
 *       (result:<seqno> error:<errstr> (vlanid: 2-bytes
 *              vxlanid: 3-bytes
 *                  gen: 4 byte))
 *
 * - REMOVE_VM_VNI:<seqno> mac: big-endian 6 bytes
 *       (result:<seqno> error:<errstr>)
 *
 * - GET_ALL_VM_VNI:<seqno>
 *       (result:<seqno>  error:<errstr> (mac: 6 bytes 
 *              vlanid: 2-bytes
 *              vxlanid: 3-bytes
 *                  gen: 4 byte)*)
 *
 *
 * - UPDATE_DEFAULT_ROUTE:<seqno> raddr: <4-tuple| v6addr w/ no symbolic>
 *       (result:<seqno> error:<errstr> (gen: 4 bytes)?)
 *
 * - REMOVE_DEFAULT_ROUTE:<seqno> raddr: <4-tuple| v6addr w/ no symbolic>
 *       (result:<seqno> error:<errstr>)
 *
 *
 *  Stop forwarding packets
 * - SUSPEND:<seqno>
 *       (result:<seqno> error:<errstr>)
 *
 *  Resume forwarding packets
 * - RESUME:<seqno>
 *       (result:<seqno> error:<errstr>)
 *
 *
 *  Signal that all seqno prior have completed, error value is the
 *  first error encountered since the last BARRIER issued, if any.
 * - BARRIER:<seqno>
 *       (result:<seqno> error:<errstr>)
 *
 *   Syntactic sugar for BARRIER+SUSPEND
 * - BEGIN_UPDATE:<seqno>
 *       (result:<seqno> error:<errstr>)
 *
 *   Syntactic sugar for BARRIER+RESUME
 * - COMMIT_UPDATE:<seqno>
 *       (result:<seqno> error:<errstr>)
 *
 */

enum verb {
	VERB_BAD = 0x0,
	VERB_BARRIER = 0x1,

	VERB_SET_PHYS_ND = 0x10,
	VERB_GET_PHYS_ND = 0x11,
	VERB_DEL_PHYS_ND = 0x12,
	VERB_GET_ALL_PHYS_ND = 0x13,
	
	VERB_UPDATE_VM_VNI = 0x20,
	VERB_REMOVE_VM_VNI = 0x21,
	VERB_GET_VM_VNI = 0x22,
	VERB_GET_ALL_VM_VNI = 0x23,

	VERB_UPDATE_DEFAULT_ROUTE = 0x30,
	VERB_REMOVE_DEFAULT_ROUTE = 0x31,

	VERB_SET_VX_ND = 0x40,
	VERB_GET_VX_ND = 0x41,
	VERB_DEL_VX_ND = 0x42,
	VERB_GET_ALL_VX_ND = 0x43,

	VERB_SUSPEND = 0x50,
	VERB_RESUME = 0x51,
	VERB_BEGIN_UPDATE = 0x52,
	VERB_COMMIT_UPDATE = 0x53,

	VERB_UPDATE_FTE = 0x60,
	VERB_REMOVE_FTE = 0x61,
	VERB_GET_FTE = 0x62,
	VERB_GET_ALL_FTE = 0x63
};

enum verb_error {
		ERR_SUCCESS = 0,
		ERR_PARSE,
		ERR_INCOMPLETE,
		ERR_NOMEM,
		ERR_NOENTRY
};

using std::string;
using std::pair;
using std::map;

typedef map<uint32_t, uint64_t> arp_t;
typedef map<uint64_t, uint32_t> revarp_t;
typedef map<struct in6_addr, uint64_t> nd6_t;
typedef map<uint64_t,  struct in6_addr> revnd6_t;
typedef struct l2_table {
		arp_t l2t_v4;
		revarp_t l2t_rev_v4;
		nd6_t l2t_v6;
		revnd6_t l2t_rev_v6;
} l2tbl_t;

typedef union vni_entry {
	uint64_t data;
	struct {
		uint64_t pad:24;
		uint64_t vlanid:16;
		uint64_t vxlanid:24;
	} fields;
} vnient_t;

typedef map<uint64_t, uint64_t> mac_vni_map_t;
typedef struct vm_vni_table {
	mac_vni_map_t mac2vni;
	mac_vni_map_t vni2mac;
} vnitbl_t;


union vxlan_sockaddr {
	struct in_addr	in4;
	struct in6_addr	in6;
};
typedef struct vxlan_ftable_entry {
		union vxlan_sockaddr vfe_raddr;
		uint64_t vfe_v6:1;
		uint64_t vfe_gen:15;
		uint64_t vfe_expire:48;
} vfe_t;

typedef pair<uint64_t, vfe_t> fwdent;
typedef map<uint64_t, vfe_t> ftable_t;

typedef struct vxlan_state {
		/* forwarding table */
		ftable_t vs_ftable;

		/* vx nd table */
		l2tbl_t vs_l2_vx;

		/* phys nd table */
		l2tbl_t vs_l2_phys;

		/* default route */

} vxstate_t;



int parse_input(char *input, vxstate_t &state, string &result);

#endif