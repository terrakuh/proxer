#pragma once

#include "../asio_include.hpp"

#include <string_view>

namespace proxer::certificator {

class Base {
public:
	virtual ~Base() = default;

	/**
	 * Sets at least the certificate and the private key in the context for the given hostname. The context is
	 * used for the client connecting to this proxy (so in server mode).
	 *
	 * @param context The context to modify.
	 * @param domain The domain for which the certificate will be used.
	 */
	virtual void set_params(PROXER_ASIO_NS::ssl::context& context, std::string_view domain) = 0;
};

} // namespace proxer::certificator
