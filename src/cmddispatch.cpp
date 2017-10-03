#include <sys/types.h>
#include <sys/endian.h>
#include <stdio.h>
#include <iostream>
#include <map>
#include <string>

#include <sys/socket.h>
#include <arpa/inet.h>
#include "uvxbridge.h"

static int
cmdmap_get_num(cmdmap_t &map, const char *key, uint64_t &val)
{
		auto it = map.find(string(key));

		if (it == map.end())
				return EINVAL;
		if (it->second.tag != TAG_NUMERIC)
				return EINVAL;
		val = it->second.value.numeric;

		return 0;
}

static int
cmdmap_get_str(cmdmap_t &map, const char *key, char **val)
{
		auto it = map.find(string(key));

		if (it == map.end())
				return EINVAL;
		if (it->second.tag != TAG_STRING)
				return EINVAL;
		*val = it->second.value.text;

		return 0;
}

static string
default_result(uint64_t seqno)
{
		char buf[32];
		snprintf(buf, 32, "(result:0x%lX)", seqno);
		return string(buf);
}
parse_value::parse_value(uint64_t numeric)
{
		this->tag = TAG_NUMERIC;
		this->value.numeric = numeric;
}

parse_value::parse_value(char *text)
{
		this->tag = TAG_STRING;
		this->value.text = strdup(text);
}

parse_value::~parse_value()
{
		switch(this->tag) {
		case TAG_STRING:
				free(this->value.text);
				break;
		case TAG_NUMERIC:
				break;
		}
}

typedef int (*cmdhandler_t)(cmdmap_t &map, uint64_t seqno, vxstate_t&, string&);

static int
fte_fill(vfe_t *fe, char *ip, uint64_t expire)
{
		int is_v6 = (index(ip, ':') != NULL);
		fe->vfe_gen++;
		fe->vfe_expire = expire;
		if (is_v6) {
				fe->vfe_v6 = 1;
				if (inet_pton(AF_INET6, ip, &fe->vfe_raddr.in6)) {
						return EINVAL;
				}
		} else {
				fe->vfe_v6 = 0;
				if (inet_aton(ip, &fe->vfe_raddr.in4)) {
						return EINVAL;
				}
		}
		return 0;
}

static int
fte_update_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
		uint64_t mac, expire;
		char *ip;
		int gen;

		if (cmdmap_get_num(map, "mac", mac))
				return EINVAL;
		if (cmdmap_get_num(map, "expire", expire))
				return EINVAL;
		if (cmdmap_get_str(map, "raddr", &ip))
				return EINVAL;
		auto it = state.vs_ftable.find(mac);
		if (it == state.vs_ftable.end()) {
				vfe_t fe;
				if (fte_fill(&fe, ip, expire))
						return EINVAL;
				state.vs_ftable.insert(fwdent(mac, fe));
		} else {
				auto fe = &it->second;
				return fte_fill(fe, ip, expire);
		}
		return 0;
}

static int
fte_remove_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{

		result = default_result(seqno);
		return 0;
}

static int
fte_get_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{

		return 0;
}

static int
fte_get_all_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{

		return 0;
}


static int
nd_phys_get_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		
		return 0;
}

static int
nd_phys_set_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		
		return 0;
}

static int
nd_phys_del_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		
		return 0;
}

static int
nd_phys_get_all_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		
		return 0;
}


static int
nd_vx_get_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		
		return 0;
}

static int
nd_vx_set_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		
		return 0;
}

static int
nd_vx_del_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		
		return 0;
}

static int
nd_vx_get_all_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		
		return 0;
}


static int
vm_vni_update_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		
		return 0;
}

static int
vm_vni_remove_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		
		return 0;
}

static int
vm_vni_get_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		return 0;
}

static int
vm_vni_get_all_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		return 0;
}

static int
route_update_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		return 0;
}

static int
route_remove_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
		return 0;
}

typedef struct _ent {
		const char *ent;
		cmdhandler_t handler;
		enum verb action;
		int pad0;
} ent_t;

#define KEYENT(action, handler) {#action, handler, action, 0} 


static ent_t ent_list[] = {
		KEYENT(VERB_UPDATE_FTE, fte_update_handler),
		KEYENT(VERB_REMOVE_FTE, fte_remove_handler),
		KEYENT(VERB_GET_FTE, fte_get_handler),
		KEYENT(VERB_GET_ALL_FTE, fte_get_all_handler),

		KEYENT(VERB_GET_PHYS_ND, nd_phys_get_handler),
		KEYENT(VERB_SET_PHYS_ND, nd_phys_set_handler),
		KEYENT(VERB_DEL_PHYS_ND, nd_phys_del_handler),
		KEYENT(VERB_GET_ALL_PHYS_ND, nd_phys_get_all_handler),

		KEYENT(VERB_UPDATE_VM_VNI, vm_vni_update_handler),
		KEYENT(VERB_REMOVE_VM_VNI, vm_vni_remove_handler),
		KEYENT(VERB_GET_VM_VNI, vm_vni_get_handler),
		KEYENT(VERB_GET_ALL_VM_VNI, vm_vni_get_all_handler),

		KEYENT(VERB_GET_VX_ND, nd_vx_get_handler),
		KEYENT(VERB_SET_VX_ND, nd_vx_set_handler),
		KEYENT(VERB_DEL_VX_ND, nd_vx_del_handler),
		KEYENT(VERB_GET_ALL_VX_ND, nd_vx_get_all_handler),

		
		KEYENT(VERB_UPDATE_DEFAULT_ROUTE, route_update_handler),
		KEYENT(VERB_REMOVE_DEFAULT_ROUTE, route_remove_handler),

		KEYENT(VERB_BAD, NULL) /* must be last */
};

static void
gather_args(cmdmap_t &map, char *input)
{
		char *indexp, *k, *tmp;
		const char *delim = " ";
		const char *kvdelim = ":";

		while (input != NULL) {
				indexp = strsep(&input, delim);
				k = strsep(&indexp, kvdelim);
				/* badly formed K:V pair */
				if (indexp == NULL)
						continue;
				/* STRING */
				if (indexp[0] == '"') {
						indexp++;
						if ((tmp = index(indexp, '"')) == NULL)
								continue;
						*tmp = '\0';
						map.insert(cmdent(string(k), parse_value(indexp)));
				}
				/* NUMBER */
				else if (indexp[0] == '0' && indexp[1] == 'x') {
						uint64_t v;
						indexp += 2;
						v = static_cast<uint64_t>(strtoll(indexp, NULL, 16));
						map.insert(cmdent(string(k), parse_value(v)));
						
				}
				/* UNKNOWN */
				else
						continue;
		}		
}

int
parse_input(char *input, struct vxlan_state &state, string &result)
{
		cmdmap_t map;
		const char *delim = " ";
		const char *kvdelim = ":";
		char *indexp, *verbstr;
		ent_t *verbent = ent_list;
		enum verb verb;
		uint64_t seqno;

		indexp = strsep(&input, delim);
		verbstr = strsep(&indexp, kvdelim);
		if (indexp == NULL || indexp[0] != '0' || indexp[1] != 'x')
				return EINVAL;
		indexp += 2;
		seqno = static_cast<uint64_t>(strtoll(indexp, NULL, 16));
		
		for (verbent = ent_list; verbent->action != VERB_BAD; verbent++) {
				if (!strcmp(verbent->ent, verbstr))
						break;
		}
		verb = verbent->action;
		if (verb == VERB_BAD)
				return EINVAL;
		gather_args(map, input);
		return verbent->handler(map, seqno, state, result);
}

