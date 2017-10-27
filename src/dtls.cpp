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


class dtls_channel {
public:
	dtls_channel(Botan::TLS::Session_Manager& session_manager,
				 Botan::Credentials_Manager& creds,
				 const Botan::TLS::Policy& policy,
				 Botan::RandomNumberGenerator& rng) {
		char **bufp = (char **)malloc(2*sizeof(char *));

		dc_tx_cookie = bufp;
		dc_rx_cookie = bufp+1;
		dtls_callbacks callbacks(bufp);
		/* XXX --- if this is a client we need to initiate a connection */
		this->dc_channel = new Botan::TLS::Server(callbacks, session_manager, creds, policy, rng, true);
/*
		return new Botan::TLS::Client(callbacks,
									  session_mgr,
									  creds,
									  policy,
									  rng,
									  Botan::TLS::Server_Information("Joyent.net", 443),
									  Botan::TLS::Protocol_Version::latest_dtls_version());
*/
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

class uvxbridge_credentials_manager : public Botan::Credentials_Manager
{
public:
	uvxbridge_credentials_manager() {
		load_certstores();
	}
	
	uvxbridge_credentials_manager(Botan::RandomNumberGenerator& rng,
							  const std::string& server_crt,
							  const std::string& server_key) {
		Certificate_Info cert;

		cert.key.reset(Botan::PKCS8::load_key(server_key, rng));
		
		Botan::DataSource_Stream in(server_crt);
		while(!in.end_of_data()) {
			try {
				cert.certs.push_back(Botan::X509_Certificate(in));
			} catch(std::exception&) {

			}
		}

		// TODO: attempt to validate chain ourselves
		m_creds.push_back(cert);
	}

	void load_certstores() {
		try {
			// TODO: make path configurable
			const std::vector<std::string> paths = {
				"/etc/ssl/certs", "/usr/share/ca-certificates"
			};

			for(auto const& path : paths) {
				std::shared_ptr<Botan::Certificate_Store> cs(new Botan::Certificate_Store_In_Memory(path));
				m_certstores.push_back(cs);
			}
		} catch(std::exception&) { }
	}

	std::vector<Botan::Certificate_Store*>
	trusted_certificate_authorities(const std::string& type,
									const std::string& /*hostname*/) override
		{
			std::vector<Botan::Certificate_Store*> v;

			// don't ask for client certs
			if(type == "tls-server")
			{
				return v;
			}

			for(auto const& cs : m_certstores)
			{
				v.push_back(cs.get());
			}

			return v;
		}

	std::vector<Botan::X509_Certificate> cert_chain(
		const std::vector<std::string>& algos,
		const std::string& type,
		const std::string& hostname) override {
			BOTAN_UNUSED(type);

			for(auto const& i : m_creds) {
				if(std::find(algos.begin(), algos.end(), i.key->algo_name()) == algos.end())
					continue;

				if(hostname != "" && !i.certs[0].matches_dns_name(hostname))
					continue;

				return i.certs;
			}

			return std::vector<Botan::X509_Certificate>();
		}

	Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
										const std::string& /*type*/,
										const std::string& /*context*/) override {
		for(auto const& i : m_creds) {
			if(cert == i.certs[0])
				return i.key.get();
		}
		return nullptr;
	}

private:
	struct Certificate_Info	{
		std::vector<Botan::X509_Certificate> certs;
		std::shared_ptr<Botan::Private_Key> key;
	};

	std::vector<Certificate_Info> m_creds;
	std::vector<std::shared_ptr<Botan::Certificate_Store>> m_certstores;
};

