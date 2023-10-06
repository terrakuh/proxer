#include "connection.hpp"

#include "log.hpp"

using namespace PROXER_ASIO_NS;

namespace {

constexpr std::string_view connected_response = "HTTP/1.0 200 Connection established\r\n\r\n";

}

namespace proxer {

std::shared_ptr<Connection> Connection::launch(PROXER_ASIO_NS::ip::tcp::socket socket,
                                               PROXER_ASIO_NS::ssl::context& ssl_context,
                                               std::shared_ptr<certificator::Base> certificator)
{
	std::shared_ptr<Connection> connection{ new Connection{ std::move(socket), ssl_context,
		                                                      std::move(certificator) } };

	boost::beast::http::async_read(
	  connection->_socket.next_layer(), connection->_socket_buffer, connection->_connect_request,
	  std::bind(&Connection::_handle_connect, connection, std::placeholders::_1, std::placeholders::_2));

	return connection;
}

Connection::Connection(PROXER_ASIO_NS::ip::tcp::socket socket, PROXER_ASIO_NS::ssl::context& ssl_context,
                       std::shared_ptr<certificator::Base> certificator)
    : _certificator{ std::move(certificator) }, _socket_context{ ssl::context::tls_server },
      _socket{ std::move(socket), _socket_context }, _outbound_context{ ssl::context::tlsv12_client },
      _outbound{ _socket.get_executor(), _outbound_context }, _socket_parser{ _outbound },
      _outbound_parser{ _socket }, _resolver{ _socket.get_executor() }
{}

void Connection::_handle_connect(asio_error_code ec, std::size_t /* bytes_transferred */)
try {
	if (ec) {
		return;
	}

	if (_connect_request.method() != boost::beast::http::verb::connect) {
		return;
	}

	std::string host;
	std::string port;
	const auto target = _connect_request.target();
	PROXER_LOG_INFO("Requested to connect to " << target.to_string());
	if (const auto pos = target.find(":"); pos != boost::string_view::npos) {
		host = target.substr(0, pos).to_string();
		port = target.substr(pos + 1).to_string();
	}

	// _outbound.set_verify_mode(ssl::verify_peer);
	// _outbound.set_verify_callback(ssl::host_name_verification(host));
	_outbound.set_verify_callback([](bool /* preverified */, ssl::verify_context& /* ctx */) { return true; });

	ip::tcp::resolver::query query{ host };
	_resolver.async_resolve(host, port,
	                        std::bind(&Connection::_handle_resolve, shared_from_this(), std::placeholders::_1,
	                                  std::placeholders::_2));
} catch (const std::exception& e) {
	std::cout << e.what() << "\n";
}

void Connection::_handle_resolve(asio_error_code ec, PROXER_ASIO_NS::ip::tcp::resolver::results_type results)
{
	PROXER_LOG_DEBUG("Resolve finished: " << ec.what());
	if (ec) {
		return;
	}

	PROXER_LOG_DEBUG("Resolved host with " << results.size() << " results");
	if (results.empty()) {
		return;
	}

	_outbound.lowest_layer().async_connect(
	  *results, [self = shared_from_this(), hostname = results->host_name()](asio_error_code ec) mutable {
		  if (ec) {
			  return;
		  }

		  PROXER_LOG_DEBUG("Successfully connected to remote");
		  SSL_set_tlsext_host_name(self->_outbound.native_handle(), hostname.c_str());
		  self->_outbound.async_handshake(
		    ssl::stream_base::client, [self, hostname = std::move(hostname)](asio_error_code ec) mutable {
			    PROXER_LOG_DEBUG("Handshake done; ec=" << ec.message());
			    if (ec) {
				    return;
			    }

			    async_write(
			      self->_socket.next_layer(), buffer(connected_response),
			      [self, hostname = std::move(hostname)](asio_error_code ec, std::size_t /* bytes_transferred */) {
				      PROXER_LOG_DEBUG("Handshake with socket done; ec=" << ec.message());
				      if (ec) {
					      return;
				      }

				      self->_configure_socket_ssl(hostname);
				      self->_socket.async_handshake(
				        ssl::stream_base::server,
				        std::bind(&Connection::_handle_tunnel_established, self, std::placeholders::_1));
			      });
		    });
	  });
}

void Connection::_handle_tunnel_established(asio_error_code ec)
{
	if (ec) {
		return;
	}

	// Read the request from the socket and forward them to the server.
	_do_socket_read();
	_do_outbound_read();
}

void Connection::_do_socket_read()
{
	boost::beast::http::async_read(
	  _socket, _socket_buffer, _socket_parser,
	  [self = shared_from_this()](asio_error_code ec, std::size_t /* bytes_transferred */) {
		  if (ec) {
			  self->_outbound.next_layer().cancel();
			  return;
		  }
		  self->_do_socket_read();
	  });
}

void Connection::_do_outbound_read()
{
	boost::beast::http::async_read(
	  _outbound, _outbound_buffer, _outbound_parser,
	  [self = shared_from_this()](asio_error_code ec, std::size_t /* bytes_transferred */) {
		  if (ec) {
			  self->_socket.next_layer().cancel();
			  return;
		  }
		  self->_do_outbound_read();
	  });
}

void Connection::_configure_socket_ssl(const std::string& domain) noexcept
{
	auto socket = std::move(_socket.next_layer());

	_socket.~stream();
	_socket_context.~context();

	new (&_socket_context) ssl::context{ ssl::context::tls_server };
	_certificator->set_params(_socket_context, domain);

	new (&_socket) boost::asio::ssl::stream<boost::asio::ip::tcp::socket>{ std::move(socket), _socket_context };
}

} // namespace proxer
