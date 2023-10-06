#pragma once

#include "base.hpp"

#include <map>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <shared_mutex>

namespace proxer::certificator {

class SelfSigner : public Base {
public:
	SelfSigner(EVP_PKEY* root_key, X509* root_certificate, EVP_PKEY* private_key);
	~SelfSigner();

	void set_params(PROXER_ASIO_NS::ssl::context& context, std::string_view domain) override;

private:
	EVP_PKEY* _root_key;
	X509* _root_certificate;
	EVP_PKEY* _private_key;
	PROXER_ASIO_NS::const_buffer _private_key_formatted;
	PROXER_ASIO_NS::const_buffer _root_certificate_formatted;
	std::shared_mutex _mutex;
	std::map<std::string, PROXER_ASIO_NS::const_buffer> _certificates;
};

} // namespace proxer::certificator
