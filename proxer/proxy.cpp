#include "proxy.hpp"

#include "log.hpp"

using namespace PROXER_ASIO_NS;

namespace proxer {

Proxy::Proxy(executor_type executor, const CURLIO_ASIO_NS::ip::tcp::endpoint& bind_address,
             std::shared_ptr<certificator::Base> certificator)
    : _acceptor{ executor, bind_address }, _ssl_context{ ssl::context::tls_client },
      _certificator{ std::move(certificator) }
{
	_ssl_context.set_default_verify_paths();
	_acceptor.async_accept(std::bind(&Proxy::_on_accept, this, std::placeholders::_1, std::placeholders::_2));
}

Proxy::executor_type Proxy::get_executor() noexcept { return _acceptor.get_executor(); }

void Proxy::_on_accept(curlio::detail::asio_error_code ec, CURLIO_ASIO_NS::ip::tcp::socket socket)
{
	if (!ec) {
		PROXER_LOG_INFO("New client connected: " << socket.remote_endpoint().address().to_string());
		Connection::launch(std::move(socket), _ssl_context, _certificator);

		_acceptor.async_accept(std::bind(&Proxy::_on_accept, this, std::placeholders::_1, std::placeholders::_2));
	}
}

} // namespace proxer
