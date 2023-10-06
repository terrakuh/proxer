#pragma once

#include "certificator/base.hpp"
#include "connection.hpp"
#include "queue.hpp"

#include <boost/beast.hpp>
#include <curlio/curlio.hpp>

namespace proxer {

using RequestQueue = Queue<boost::beast::http::request<boost::beast::http::empty_body>>;

class Proxy {
public:
	using executor_type = PROXER_ASIO_NS::any_io_executor;

	Proxy(executor_type executor, const CURLIO_ASIO_NS::ip::tcp::endpoint& bind_address,
	      std::shared_ptr<certificator::Base> certificator);
	Proxy(const Proxy& copy) = delete;

	void register_queue(RequestQueue& queue);

	executor_type get_executor() noexcept;
	Proxy& operator=(const Proxy& copy) = delete;

private:
	PROXER_ASIO_NS::ip::tcp::acceptor _acceptor;
	PROXER_ASIO_NS::ssl::context _ssl_context;
	std::shared_ptr<certificator::Base> _certificator;
	std::vector<RequestQueue*> _queues;

	void _on_accept(curlio::detail::asio_error_code ec, CURLIO_ASIO_NS::ip::tcp::socket socket);
};

} // namespace proxer
