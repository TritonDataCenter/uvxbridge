#include <sys/types.h>
#include <sys/endian.h>
#include <stdio.h>
#include <iostream>
#include <map>
#include <string>

#include <sys/socket.h>
#include <arpa/inet.h>
#include "uvxbridge.h"

#define ERRENT(error) #error
static const char *err_list[] = {
		ERRENT(ERR_SUCCESS),
		ERRENT(ERR_PARSE),
		ERRENT(ERR_INCOMPLETE),
		ERRENT(ERR_NOENTRY)
};

enum value_type {
	TAG_NUMERIC = 0x1,
	TAG_STRING = 0x2
};
typedef struct parse_value {
		enum value_type tag;
		int pad0;
		union {
				uint64_t numeric;
				char* text;
		} value;

		parse_value(uint64_t numeric);
		parse_value(char *text);
		~parse_value();
} pv_t;

typedef pair<string, pv_t> cmdent;
typedef map<string,  pv_t> cmdmap_t;

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
dflt_result(uint64_t seqno, enum verb_error err)
{
		char buf[64];

		snprintf(buf, 64, "(result:0x%lX error:%s)", seqno, err_list[err]);
		return string(buf);
}

static string
gen_result(uint64_t seqno, enum verb_error err, string input)
{
		int len = input.size() + 64;
		char *buf;
		if ((buf = static_cast<char *>(malloc(len))) == NULL)
				return dflt_result(seqno, ERR_NOMEM);
		snprintf(buf, len, "(result:0x%lX error:%s %s)", seqno, err_list[err], input.c_str());
		auto s = string(buf);
		free(buf);
		return s;
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
#define s6_addr32 __u6_addr.__u6_addr32

static int
fte_fill(vfe_t *fe, char *ip, uint64_t expire)
{
		int is_v6 = (index(ip, ':') != NULL);
		fe->vfe_expire = expire;
		if (is_v6) {
				struct in6_addr	in6;
				uint32_t *pin6dst, *pin6src;

				fe->vfe_v6 = 1;
				if (inet_pton(AF_INET6, ip, &in6))
						return EINVAL;
				pin6dst = fe->vfe_raddr.in6.s6_addr32;
				pin6src = in6.s6_addr32;
				for (int i = 0; i < 4; i++)
						pin6dst[i] = htonl(pin6src[i]);
		} else {
				struct in_addr	in4;

				fe->vfe_v6 = 0;
				if (inet_aton(ip, &in4))
						return EINVAL;
				fe->vfe_raddr.in4.s_addr = htonl(in4.s_addr);
		}
		return 0;
}

static string
format_map(cmdmap_t &map)
{
		string result = string("( ");
		char buf[64];
		for (auto it = map.begin(); it != map.end(); it++) {
				if (it->second.tag == TAG_NUMERIC)
						snprintf(buf, 64, "%s:0x%lX ", it->first.c_str(),
								 it->second.value.numeric);
				else
						snprintf(buf, 64, "%s:\"%s\"", it->first.c_str(),
								 it->second.value.text);
				result.append(buf);
		}
		result.append(")");
		return result;
}

static int
fte_update_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
		uint64_t mac, expire;
		char *ip;
		int gen = 0;
		cmdmap_t result_map;
		enum verb_error err = ERR_INCOMPLETE;

		if (cmdmap_get_num(map, "mac", mac)) {
				result = dflt_result(seqno, err);
				return EINVAL;
		}
		auto it = state.vs_ftable.find(mac);
		if (cmdmap_get_num(map, "expire", expire))
				goto incomplete;
		if (cmdmap_get_str(map, "raddr", &ip))
				goto incomplete;
		if (it == state.vs_ftable.end()) {
				vfe_t fe;
				if (fte_fill(&fe, ip, expire))
						goto badparse;
				state.vs_ftable.insert(fwdent(mac, fe));
		} else {
				auto fe = &it->second;
				fe->vfe_gen++;
				gen = fe->vfe_gen;
				if (fte_fill(fe, ip, expire))
						goto badparse;
		}
		result_map.insert(cmdent(string("gen"), parse_value(gen)));
		result = gen_result(seqno, ERR_SUCCESS, format_map(result_map));
		return 0;
badparse:
		err = ERR_PARSE;
incomplete:
		result = dflt_result(seqno, err);
		return EINVAL;
}

static int
fte_remove_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{

		result = dflt_result(seqno, ERR_SUCCESS);
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

