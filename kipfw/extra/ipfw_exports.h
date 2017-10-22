#ifndef _EXTRAS_IPFW_EXPORTS_H_
#define _EXTRAS_IPFW_EXPORTS_H_

struct ipfw_wire_hdr {
	uint8_t mac[6];
	uint16_t pad;
	uint32_t optlen;	/* actual data len */
	uint32_t level;		/* or error */
	uint32_t optname;	/* or act len */
	uint32_t dir;		/* in or out */
};
#endif
