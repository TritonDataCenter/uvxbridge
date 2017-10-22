#ifndef _EXTRAS_IPFW_EXPORTS_H_
#define _EXTRAS_IPFW_EXPORTS_H_
#ifdef __cplusplus
extern "C" {
#endif

struct ipfw_wire_hdr {
	uint8_t mac[6];
	uint16_t pad;
	uint32_t optlen;	/* actual data len */
	uint32_t level;		/* or error */
	uint32_t optname;	/* or act len */
	uint32_t dir;		/* in or out */
};

struct ip_fw_chain;
struct sockopt;
struct ip_fw_chain *ip_fw_chain_new(void);
void ip_fw_chain_delete(struct ip_fw_chain *chain);
typedef int ip_fw_ctl_t(struct sockopt *, struct ip_fw_chain *);
extern ip_fw_ctl_t *ip_fw_ctl_ptr;

#ifdef __cplusplus
}
#endif

#endif
