#pragma once

#include <filesystem>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string>

namespace proxer::certificator {

[[nodiscard]] EVP_PKEY* load_key(const std::filesystem::path& path,
                                 const std::string& passphrase = "") noexcept;
[[nodiscard]] X509* load_certificate(const std::filesystem::path& path,
                                     const std::string& passphrase = "") noexcept;
[[nodiscard]] EVP_PKEY* generate_elliptic_curve_key(int nid = NID_secp384r1) noexcept;

} // namespace proxer::certificator
