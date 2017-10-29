#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <fstream>
#include <memory>

#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <botan/x509cert.h>
#include <botan/pkcs8.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/credentials_manager.h>
#include <botan/x509self.h>
#include <botan/data_src.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include "dtls.h"

#include "uvxbridge.h"
#include "uvxlan.h"
#include <nmutil.h>

struct dtls_rx_args {
	int rc;
	int pad;
	char *txbuf;
	path_state_t *ps;
	struct vxlan_state_dp *dp_state;
};

static void
dtls_udp_fill(char *txbuf, void *payload, int len)
{
	struct ether_header *eh = (struct ether_header *)txbuf;
	struct ip *ip = (struct ip *)(uintptr_t)(eh + 1);
	struct udphdr *uh = (struct udphdr *)(ip + 1);
	void *data = (void *)(uintptr_t)(uh + 1);

	/* we can reuse the ether header and ip with the len adjusted */
	ip->ip_len = ntohs(sizeof(*ip) + sizeof(*uh) + len);
	udp_fill(uh, 443, 443, len);
	memcpy(data, payload, len);
}

class dtls_callbacks : public Botan::TLS::Callbacks
{
public:
	void
	tls_record_received(uint64_t rec_no __unused, const uint8_t buf[], size_t buf_len) override {
		struct dtls_rx_args *args = (struct dtls_rx_args *)this->dc_rx_cookie;
		/* pass up to vxlan_decap */
		args->ps->ps_rx_len = buf_len;
		args->rc = vxlan_decap_v4((char *)(uintptr_t)(buf), args->txbuf, args->ps, args->dp_state);
	}
	
	void
	tls_emit_data(const uint8_t buf[], size_t buf_len) override {
		dtls_udp_fill(*dc_tx_cookie, (char *)(uintptr_t)buf, buf_len);
	}

	bool
	tls_session_established(const Botan::TLS::Session& session __unused) override {
		return false;
	}

	void
	tls_alert(Botan::TLS::Alert alert __unused) override {
		/* close session or log */
	}

	dtls_callbacks(char **bufp) :
		dc_tx_cookie(bufp),
		dc_rx_cookie(bufp+1)
		{}
private:
	caddr_t *dc_tx_cookie;
	caddr_t *dc_rx_cookie;
};


class uvxbridge_credentials_manager : public Botan::Credentials_Manager
{
public:
	uvxbridge_credentials_manager(char key[UVX_KEYSIZE]) {
		this->key = string(key, UVX_KEYSIZE);
	}

	std::string psk_identity_hint(const std::string&, const std::string&) override {
		return "psk_hint";
	}
	std::string psk_identity(const std::string&, const std::string&, const std::string&) override {
		return "psk_id";
	}

	Botan::SymmetricKey psk(const std::string&, const std::string&, const std::string&) override {
		return Botan::SymmetricKey(key);
	}
private:
	string key;
};

class dtls_channel {
public:
	dtls_channel(Botan::TLS::Session_Manager& session_manager,
				 char key[UVX_KEYSIZE],
				 const Botan::TLS::Policy& policy,
				 Botan::RandomNumberGenerator& rng) {
		char **bufp = (char **)malloc(2*sizeof(char *));

		dc_tx_cookie = bufp;
		dc_rx_cookie = bufp+1;
		dtls_callbacks callbacks(bufp);
		uvxbridge_credentials_manager creds(key);

		/* XXX --- if this is a client we need to initiate a connection */
		this->dc_channel = new Botan::TLS::Server(callbacks, session_manager, creds, policy, rng, true);
	}
	dtls_channel(Botan::TLS::Session_Manager& session_manager,
				 char key[UVX_KEYSIZE],
				 const Botan::TLS::Policy& policy,
				 Botan::RandomNumberGenerator& rng,
				 char *addr,
				 uint16_t port) {
		char **bufp = (char **)malloc(2*sizeof(char *));

		dc_tx_cookie = bufp;
		dc_rx_cookie = bufp+1;
		dtls_callbacks callbacks(bufp);
		uvxbridge_credentials_manager creds(key);
		/* XXX --- if this is a client we need to initiate a connection */
		this->dc_channel = new Botan::TLS::Client(callbacks,
									  session_manager,
									  creds,
									  policy,
									  rng,
									  Botan::TLS::Server_Information(addr, port),
									  Botan::TLS::Protocol_Version::latest_dtls_version());

	}
	~dtls_channel() {
		delete dc_channel;
	}
	void transmit(char *buf, size_t buf_size, char *txbuf) {
		*dc_tx_cookie = txbuf;
		this->dc_channel->send((const uint8_t *)buf, buf_size);
		*dc_tx_cookie = NULL;
	}
	int receive(char *rxbuf, char *txbuf, path_state_t *ps,
				 struct vxlan_state_dp *dp_state) {
		struct dtls_rx_args args;

		args.txbuf = txbuf;
		args.ps = ps;
		args.dp_state = dp_state;
		args.rc = 0;
		*dc_rx_cookie = (caddr_t)&args;
		dc_channel->received_data((const uint8_t *)rxbuf, dp_state->vsd_state->vs_mtu);
		*dc_rx_cookie = NULL;
		return (args.rc);
	}
private:
	Botan::TLS::Channel *dc_channel;
	caddr_t *dc_tx_cookie;
	caddr_t *dc_rx_cookie;
};

void
dtls_channel_transmit(dtls_channel *channel, char *buf, size_t buf_size, char *txbuf)
{
	channel->transmit(buf, buf_size, txbuf);
}

int
dtls_channel_receive(dtls_channel *channel, char *rxbuf, char *txbuf, path_state_t *ps,
					 struct vxlan_state_dp *dp_state)
{
	return channel->receive(rxbuf, txbuf, ps, dp_state);
}

