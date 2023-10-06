#include "utility.hpp"

#include <cstdio>
#include <openssl/pem.h>

EVP_PKEY* proxer::certificator::load_key(const std::filesystem::path& path,
                                         const std::string& passphrase) noexcept
{
	const auto file = std::fopen(path.c_str(), "rb");
	auto key = EVP_PKEY_new();

	if (!PEM_read_PrivateKey(file, &key, nullptr,
	                         passphrase.empty() ? nullptr : const_cast<char*>(passphrase.data()))) {
		std::fclose(file);
		EVP_PKEY_free(key);
		return nullptr;
	}
	std::fclose(file);

	return key;
}

X509* proxer::certificator::load_certificate(const std::filesystem::path& path,
                                             const std::string& passphrase) noexcept
{
	const auto file = std::fopen(path.c_str(), "rb");
	auto certificate = X509_new();

	if (!PEM_read_X509(file, &certificate, nullptr,
	                   passphrase.empty() ? nullptr : const_cast<char*>(passphrase.data()))) {
		std::fclose(file);
		X509_free(certificate);
		return nullptr;
	}
	std::fclose(file);

	return certificate;
}

EVP_PKEY* proxer::certificator::generate_elliptic_curve_key(int nid) noexcept
{
	auto ec = EC_KEY_new_by_curve_name(NID_secp384r1);
	if (!EC_KEY_generate_key(ec)) {
		EC_KEY_free(ec);
		return nullptr;
	}

	auto key = EVP_PKEY_new();
	EVP_PKEY_assign_EC_KEY(key, ec);
	return key;
}
