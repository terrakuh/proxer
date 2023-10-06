#include "self_signer.hpp"

#include <cstddef>
#include <vector>

using namespace PROXER_ASIO_NS;

namespace {

bool add_extension(X509* cert, int nid, const char* value) noexcept
{
	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
	auto ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
	if (!ext) {
		return false;
	}
	int result = X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
	return result == 0;
}

const_buffer format_certificate(X509* certificate) noexcept
{
	auto bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, certificate);
	const char* ptr;
	auto size = BIO_get_mem_data(bio, &ptr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free(bio);
	return buffer(ptr, size);
}

const_buffer format_key(EVP_PKEY* key) noexcept
{
	auto bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
	const char* ptr;
	auto size = BIO_get_mem_data(bio, &ptr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free(bio);
	return buffer(ptr, size);
}

const_buffer generate_certificate(const std::string& domain, EVP_PKEY* root_key, X509* root_certificate,
                                  EVP_PKEY* private_key) noexcept
{
	auto certificate = X509_new();
	ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1);
	X509_set_version(certificate, 2); // which is version 3
	X509_gmtime_adj(X509_get_notBefore(certificate), 0);
	X509_gmtime_adj(X509_get_notAfter(certificate), 60 * 60 * 24 /* one day */);
	X509_set_pubkey(certificate, private_key);

	auto name = X509_get_subject_name(certificate);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("XX"), -1, -1,
	                           0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("The World"), -1,
	                           -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Proxer"), -1,
	                           -1, 0);
	X509_set_issuer_name(certificate, X509_get_subject_name(root_certificate));

	add_extension(certificate, NID_subject_alt_name, ("DNS:" + domain + ",DNS:*." + domain).c_str());
	add_extension(certificate, NID_basic_constraints, "critical,CA:FALSE");
	add_extension(certificate, NID_key_usage, "critical,digitalSignature,keyEncipherment");
	add_extension(certificate, NID_ext_key_usage, "serverAuth");

	X509_sign(certificate, root_key, EVP_sha512());

	auto buffer = format_certificate(certificate);
	X509_free(certificate);
	return buffer;
}

std::string base_domain(std::string_view domain) noexcept
{
	auto pos = domain.find_last_of(".");
	if (pos == std::string_view::npos ||
	    (pos = domain.substr(0, pos).find_last_of(".")) == std::string_view::npos) {
		return std::string{ domain };
	}
	return std::string{ domain.substr(pos + 1) };
}

} // namespace

namespace proxer::certificator {

SelfSigner::SelfSigner(EVP_PKEY* root_key, X509* root_certificate, EVP_PKEY* private_key)
{
	_root_key = root_key;
	_root_certificate = root_certificate;
	_private_key = private_key;
	_private_key_formatted = format_key(_private_key);
	_root_certificate_formatted = format_certificate(_root_certificate);
}

SelfSigner::~SelfSigner()
{
	for (const auto& [_, certificate] : _certificates) {
		std::free(const_cast<void*>(certificate.data()));
	}
	EVP_PKEY_free(_root_key);
	X509_free(_root_certificate);
	EVP_PKEY_free(_private_key);
	std::free(const_cast<void*>(_private_key_formatted.data()));
	std::free(const_cast<void*>(_root_certificate_formatted.data()));
}

void SelfSigner::set_params(PROXER_ASIO_NS::ssl::context& context, std::string_view domain)
{
	auto base_domain = ::base_domain(domain);

	const_buffer certificate{ nullptr, 0 };
	{
		std::shared_lock lock{ _mutex };
		if (const auto it = _certificates.find(base_domain); it != _certificates.end()) {
			certificate = it->second;
		} else {
			certificate = generate_certificate(base_domain, _root_key, _root_certificate, _private_key);
			lock.unlock();
			std::lock_guard _{ _mutex };
			_certificates.insert({ std::move(base_domain), certificate });
		}
	}

	context.use_private_key(_private_key_formatted, ssl::context::file_format::pem);
	std::vector<std::byte> chain;
	chain.resize(certificate.size() + _root_certificate_formatted.size());
	std::memcpy(chain.data(), certificate.data(), certificate.size());
	std::memcpy(chain.data() + certificate.size(), _root_certificate_formatted.data(),
	            _root_certificate_formatted.size());
	context.use_certificate_chain(buffer(chain));
}

} // namespace proxer::certificator
