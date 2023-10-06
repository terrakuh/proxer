#pragma once

#include "asio_include.hpp"
#include "certificator/base.hpp"
#include "detail/parser.hpp"

#include <boost/beast.hpp>
#include <memory>

namespace proxer {

class Connection : public std::enable_shared_from_this<Connection> {
public:
	static std::shared_ptr<Connection> launch(PROXER_ASIO_NS::ip::tcp::socket socket,
	                                          PROXER_ASIO_NS::ssl::context& ssl_context,
	                                          std::shared_ptr<certificator::Base> certificator);

private:
	std::shared_ptr<certificator::Base> _certificator;

	boost::beast::flat_buffer _socket_buffer;
	boost::beast::http::request<boost::beast::http::empty_body> _connect_request{};
	PROXER_ASIO_NS::ssl::context _socket_context;
	PROXER_ASIO_NS::ssl::stream<PROXER_ASIO_NS::ip::tcp::socket> _socket;
	
	boost::beast::flat_buffer _outbound_buffer;
	PROXER_ASIO_NS::ssl::context _outbound_context;
	PROXER_ASIO_NS::ssl::stream<PROXER_ASIO_NS::ip::tcp::socket> _outbound;
	
	detail::Parser<true> _socket_parser;
	detail::Parser<false> _outbound_parser;
	PROXER_ASIO_NS::ip::tcp::resolver _resolver;

	Connection(PROXER_ASIO_NS::ip::tcp::socket socket, PROXER_ASIO_NS::ssl::context& ssl_context,
	           std::shared_ptr<certificator::Base> certificator);
	void _handle_connect(asio_error_code ec, std::size_t bytes_transferred);
	void _handle_resolve(asio_error_code ec, PROXER_ASIO_NS::ip::tcp::resolver::results_type results);
	void _handle_tunnel_established(asio_error_code ec);
	void _do_socket_read();
	void _do_outbound_read();
	void _configure_socket_ssl(const std::string& domain) noexcept;
};

} // namespace proxer
