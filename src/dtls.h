#ifndef _UVXBRIDGE_DTLS_
#define _UVXBRIDGE_DTLS_

#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <botan/credentials_manager.h>
#include <botan/data_src.h>
#include "datapath.h"

class dtls_channel;

dtls_channel *dtls_channel_alloc(Botan::TLS::Session_Manager& session_manager,
								 Botan::Credentials_Manager& creds __unused,
								 const Botan::TLS::Policy& policy,
								 Botan::RandomNumberGenerator& rng);


void dtls_channel_transmit(dtls_channel *channel, char *buf, size_t buf_size, char *txbuf);
int dtls_channel_receive(dtls_channel *channel, char *rxbuf, char *txbuf, path_state_t *ps,
						  struct vxlan_state_dp *);

#endif
