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




class dtls_uvxbridge_session : public Botan::TLS::Callbacks
{
	/*
	 * Peer IP
	 * nm_desc for egress
	 * any additional state
	 */
	
	void
	tls_record_received(uint64_t rec_no, const uint8_t buf[], size_t buf_len) override {
		/* pass up to vxlan_decap */
	}
	
	void
	tls_emit_data(const uint8_t buf[], size_t buf_len) override {
		/* copy data in the buffer to a UDP packet in the descriptors txring */
	}

	bool
	tls_session_established(const Botan::TLS::Session& session) override {
		return false;
	}
	
	void
	tls_alert(Botan::TLS::Alert alert) override {
		/* closs session or log */
	}
};

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

int
uvxbridge_server_setup(/* ... */) {
	dtls_uvxbridge_session callbacks;
	Botan::AutoSeeded_RNG rng;
	Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
	uvxbridge_credentials_manager creds;
	Botan::TLS::Strict_Policy policy;

	Botan::TLS::Server server(callbacks,
							  session_mgr,
							  creds,
							  policy,
							  rng,
							  true /* is_datagram */);
	return (0);
	
}

int
uvxbridge_client_setup(/* ... */) {
	dtls_uvxbridge_session callbacks;
	Botan::AutoSeeded_RNG rng;
	Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
	uvxbridge_credentials_manager creds;
	Botan::TLS::Strict_Policy policy;

	Botan::TLS::Client client(callbacks,
							  session_mgr,
							  creds,
							  policy,
							  rng,
							  Botan::TLS::Server_Information("Joyent.net", 443),
							  Botan::TLS::Protocol_Version::latest_dtls_version());
	return (0);
}
