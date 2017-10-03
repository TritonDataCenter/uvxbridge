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
 *   map 5-byte local VM mac to vlanid|vxlanid
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
 * - UPDATE_DEFAULT_ROUTE:<seqno> raddr: <4-tuple| v6addr w/ no symbolic>
 *       (result:<seqno> error:<errstr> (gen: 4 bytes)?)
 *
 * - REMOVE_DEFAULT_ROUTE:<seqno> raddr: <4-tuple| v6addr w/ no symbolic>
 *       (result:<seqno> error:<errstr>)
 *
 */

enum verb {
	VERB_BAD = 0x0,

	VERB_UPDATE_FTE = 0x2,
	VERB_REMOVE_FTE = 0x3,
	VERB_GET_FTE = 0x4,
	VERB_GET_ALL_FTE = 0x5,

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
	VERB_GET_ALL_VX_ND = 0x43
};

enum verb_error {
		ERR_SUCCESS = 0,
		ERR_PARSE,
		ERR_INCOMPLETE,
		ERR_NOENTRY
};


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

using std::string;
using std::pair;
using std::map;

typedef pair<uint64_t, vfe_t> fwdent;
typedef map<uint64_t, vfe_t> ftable_t;

typedef struct vxlan_state {
		/* forwarding table */
		ftable_t vs_ftable;

		/* vx nd table */

		/* phys nd table */

		/* default route */

} vxstate_t;



int parse_input(char *input, vxstate_t &state, string &result);

#endif
