/*
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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
	ERRENT(ERR_NOMEM),
	ERRENT(ERR_NOENTRY),
	ERRENT(ERR_NOTIMPL)
};

#define UNIMPLEMENTED(seqno) dflt_result(seqno, ERR_NOTIMPL)

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
	if (err != ERR_SUCCESS)
		return dflt_result(seqno, err);
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

struct result_map {
	cmdmap_t map;
	void insert(const char *key, uint64_t value);
	void insert(const char *key, char *value);
	string to_str();
};

string
result_map::to_str()
{
	cmdmap_t &map = this->map;
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

void
result_map::insert(const char *key, uint64_t value)
{
	this->map.insert(cmdent(string(key), parse_value(value)));
}

void
result_map::insert(const char *key, char *value)
{
	this->map.insert(cmdent(string(key), parse_value(value)));
}

static int
fte_update_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	uint64_t mac, expire;
	char *ip;
	int gen = 0;
	result_map rmap;
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
	rmap.insert("gen", gen);
	result = gen_result(seqno, ERR_SUCCESS, rmap.to_str());
	return 0;
 badparse:
	err = ERR_PARSE;
 incomplete:
	result = dflt_result(seqno, err);
	return EINVAL;
}

static int
fte_remove_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	uint64_t mac;

	if (cmdmap_get_num(map, "mac", mac)) {
		result = dflt_result(seqno, ERR_INCOMPLETE);
		return EINVAL;
	}
	state.vs_ftable.erase(mac);
	result = dflt_result(seqno, ERR_SUCCESS);
	return 0;
}

static string
vfe_to_str(vfe_t &fe)
{
	result_map rmap;
	char buf[INET6_ADDRSTRLEN];

	if (fe.vfe_v6)
		inet_ntop(AF_INET6, &fe.vfe_raddr.in6, buf,  INET6_ADDRSTRLEN);
	else
		inet_ntop(AF_INET, &fe.vfe_raddr.in4, buf,  INET6_ADDRSTRLEN);
	rmap.insert("raddr", buf);
	rmap.insert("gen", fe.vfe_gen);
	rmap.insert("expire", fe.vfe_expire);
	return rmap.to_str();
}

static int
fte_get_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	uint64_t mac;
	result_map rmap;

	if (cmdmap_get_num(map, "mac", mac)) {
		result = dflt_result(seqno, ERR_INCOMPLETE);
		return EINVAL;
	}
	auto it = state.vs_ftable.find(mac);
	if (it == state.vs_ftable.end()) {
		result = dflt_result(seqno, ERR_NOENTRY);
		return ENOENT;
	}
	result = gen_result(seqno, ERR_SUCCESS, vfe_to_str(it->second));
	return 0;
}

static int
fte_get_all_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	auto &table = state.vs_ftable;
	string tmp;
	for (auto it = table.begin(); it != table.end(); it++) {
		tmp.append(vfe_to_str(it->second));
		tmp.append(" ");
	}
	result = gen_result(seqno, ERR_SUCCESS, tmp);
	return 0;
}

static int
nd_get_handler(cmdmap_t &map, uint64_t seqno, l2tbl_t &tbl, string &result)
{
	result_map rmap;
	uint64_t mac;
	char buf[16];
	union vxlan_in_addr raddr;
	int rc;
	char *ip;
	bool v6;

	if (cmdmap_get_str(map, "raddr", &ip)) {
		result = dflt_result(seqno, ERR_INCOMPLETE);
		return EINVAL;
	}
	v6 = (index(ip, ':') != NULL);
	if (v6)
		rc = inet_pton(AF_INET6, ip, &raddr.in6);
	else
		rc = inet_pton(AF_INET, ip, &raddr.in4);
	if (rc) {
		result = dflt_result(seqno, ERR_PARSE);
		return EINVAL;
	}
	if (v6) {
		auto it = tbl.l2t_v6.find(raddr.in6);
		if (it == tbl.l2t_v6.end()) {
			goto noentry;
		}
		mac = it->second;
	} else {
		auto it = tbl.l2t_v4.find(raddr.in4.s_addr);
		if (it == tbl.l2t_v4.end()) {
			goto noentry;
		}
		mac = it->second;
	}
	snprintf(buf, 16, "0x%lX", be64toh(mac));
	rmap.insert("mac", buf);
	result = gen_result(seqno, ERR_SUCCESS, rmap.to_str());
	return 0;
  noentry:
	result = dflt_result(seqno, ERR_NOENTRY);
	return ENOENT;
}

static int
nd_set_handler(cmdmap_t &map, uint64_t seqno, l2tbl_t &tbl, string &result)
{
	uint64_t mac;
	union vxlan_in_addr raddr;
	int rc;
	char *ip;
	bool v6;

	if (cmdmap_get_str(map, "raddr", &ip))
		goto incomplete;
	if (cmdmap_get_num(map, "mac", mac))
		goto incomplete;
	v6 = (index(ip, ':') != NULL);
	if (v6)
		rc = inet_pton(AF_INET6, ip, &raddr.in6);
	else
		rc = inet_pton(AF_INET, ip, &raddr.in4);
	if (rc) {
		result = dflt_result(seqno, ERR_PARSE);
		return EINVAL;
	}
	mac = htobe64(mac);
	if (v6) {
		for (auto i = 0; i < 4; i++)
			raddr.in6.s6_addr32[i] = be32toh(raddr.in6.s6_addr32[i]);
		auto it = tbl.l2t_v6.find(raddr.in6);
		if (it != tbl.l2t_v6.end())
			it->second = mac;
		else
			tbl.l2t_v6.insert(pair<struct in6_addr, uint64_t>(raddr.in6, mac));
	} else {
		uint32_t addr4 = be32toh(raddr.in4.s_addr);

		auto it = tbl.l2t_v4.find(addr4);
		if (it != tbl.l2t_v4.end())
			it->second = mac;
		else
			tbl.l2t_v4.insert(pair<uint32_t, uint64_t>(addr4, mac));
	}
	result = dflt_result(seqno, ERR_SUCCESS);
	return 0;
  incomplete:
	result = dflt_result(seqno, ERR_INCOMPLETE);
	return EINVAL;
}

static int
nd_del_handler(cmdmap_t &map, uint64_t seqno, l2tbl_t &tbl, string &result)
{
	union vxlan_in_addr raddr;
	int rc;
	char *ip;
	bool v6;

	if (cmdmap_get_str(map, "raddr", &ip))
		goto incomplete;
	v6 = (index(ip, ':') != NULL);
	if (v6)
		rc = inet_pton(AF_INET6, ip, &raddr.in6);
	else
		rc = inet_pton(AF_INET, ip, &raddr.in4);
	if (rc) {
		result = dflt_result(seqno, ERR_PARSE);
		return EINVAL;
	}
	if (v6) {
		for (auto i = 0; i < 4; i++)
			raddr.in6.s6_addr32[i] = be32toh(raddr.in6.s6_addr32[i]);
		tbl.l2t_v6.erase(raddr.in6);
	} else {
		uint32_t addr4 = be32toh(raddr.in4.s_addr);

		tbl.l2t_v4.erase(addr4);
	}
	result = dflt_result(seqno, ERR_SUCCESS);
	return 0;
  incomplete:
	result = dflt_result(seqno, ERR_INCOMPLETE);
	return EINVAL;
}

static int
nd_get_all_handler(cmdmap_t &map, uint64_t seqno, l2tbl_t &tbl, string &result)
{
	result = UNIMPLEMENTED(seqno);
	return ENOTSUP;
}

static int
nd_phys_get_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	return nd_get_handler(map, seqno, state.vs_l2_phys, result);
}

static int
nd_phys_set_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	return nd_set_handler(map, seqno, state.vs_l2_phys, result);
}

static int
nd_phys_del_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	return nd_del_handler(map, seqno, state.vs_l2_phys, result);
}

static int
nd_phys_get_all_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	return nd_get_all_handler(map, seqno, state.vs_l2_phys, result);
}

static int
nd_vx_get_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	return nd_get_handler(map, seqno, state.vs_l2_vx, result);
}

static int
nd_vx_set_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	return nd_set_handler(map, seqno, state.vs_l2_vx, result);
}

static int
nd_vx_del_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	return nd_del_handler(map, seqno, state.vs_l2_vx, result);
}

static int
nd_vx_get_all_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	return nd_get_all_handler(map, seqno, state.vs_l2_vx, result);
}

static int
vm_vni_update_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	enum verb_error err = ERR_INCOMPLETE;
	uint64_t mac, vlanid, vxlanid;

	if (cmdmap_get_num(map, "mac", mac))
		goto incomplete;
	if (cmdmap_get_num(map, "vlanid", vlanid))
		goto incomplete;
	if (cmdmap_get_num(map, "vxlanid", vxlanid))
		goto incomplete;
	/* XXX */
	return 0;
 incomplete:
	result = dflt_result(seqno, err);
	return EINVAL;
}

static int
vm_vni_remove_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	enum verb_error err = ERR_INCOMPLETE;
	uint64_t mac;
	mac_vni_map_t &fwd = state.vs_vni_table.mac2vni;

	if (cmdmap_get_num(map, "mac", mac)) {
		result = dflt_result(seqno, err);
		return EINVAL;
	}
	result = dflt_result(seqno, ERR_SUCCESS);
	fwd.erase(mac);
	return 0;
}

static int
vm_vni_get_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	struct result_map rmap;
	uint64_t mac, vlanid, vxlanid, gen;
	vnient_t ent;

	if (cmdmap_get_num(map, "mac", mac )) {
		result = dflt_result(seqno, ERR_INCOMPLETE);
		return EINVAL;
	}
	auto it = state.vs_vni_table.mac2vni.find(mac);
	if (it == state.vs_vni_table.mac2vni.end()) {
		result = dflt_result(seqno, ERR_NOENTRY);
		return ENOENT;
	}
	ent.data = 	it->second;
	vxlanid = ent.fields.vxlanid;
	vlanid = ent.fields.vlanid;
	gen = ent.fields.gen;
	rmap.insert("vxlanid", vxlanid);
	rmap.insert("vlanid", vlanid);
	rmap.insert("gen", gen);
	result = gen_result(seqno, ERR_SUCCESS, rmap.to_str());
	return 0;
}

static int
vm_vni_get_all_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	result = UNIMPLEMENTED(seqno);
	return 0;
}

static int
route_update_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	result = UNIMPLEMENTED(seqno);
	return 0;
}

static int
route_remove_handler(cmdmap_t &map, uint64_t seqno, vxstate_t &state, string &result)
{
	result = UNIMPLEMENTED(seqno);
	return 0;
}

static int
suspend_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
	result = UNIMPLEMENTED(seqno);
	return 0;
}

static int
resume_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
	result = UNIMPLEMENTED(seqno);
	return 0;
}

static int
barrier_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
	result = UNIMPLEMENTED(seqno);
	return 0;
}

static int
begin_update_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
	result = UNIMPLEMENTED(seqno);
	return 0;
}

static int
commit_update_handler(cmdmap_t &map __unused, uint64_t seqno, vxstate_t &state, string &result)
{
	result = UNIMPLEMENTED(seqno);
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

	KEYENT(VERB_SUSPEND, suspend_handler),
	KEYENT(VERB_RESUME, resume_handler),
	KEYENT(VERB_BEGIN_UPDATE, begin_update_handler),
	KEYENT(VERB_COMMIT_UPDATE, commit_update_handler),

	KEYENT(VERB_BARRIER, barrier_handler),

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

