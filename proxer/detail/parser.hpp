#pragma once

#include "../asio_include.hpp"

#include <boost/beast.hpp>

namespace proxer::detail {

template<bool IsRequest>
class Parser : public boost::beast::http::basic_parser<IsRequest> {
public:
	Parser(PROXER_ASIO_NS::ssl::stream<PROXER_ASIO_NS::ip::tcp::socket>& output);

protected:
	void on_request_impl(boost::beast::http::verb method, boost::beast::string_view method_str,
	                     boost::beast::string_view target, int version, boost::beast::error_code& ec) override;
	void on_response_impl(int code, boost::beast::string_view reason, int version,
	                      boost::beast::error_code& ec) override;
	void on_field_impl(boost::beast::http::field name, boost::beast::string_view name_string,
	                   boost::beast::string_view value, boost::beast::error_code& ec) override;
	void on_header_impl(boost::beast::error_code& ec) override;
	void on_body_init_impl(const boost::optional<std::uint64_t>& content_length,
	                       boost::beast::error_code& ec) override;
	std::size_t on_body_impl(boost::beast::string_view body, boost::beast::error_code& ec) override;
	void on_chunk_header_impl(std::uint64_t size, boost::beast::string_view extensions,
	                          boost::beast::error_code& ec) override;
	std::size_t on_chunk_body_impl(std::uint64_t remain, boost::beast::string_view body,
	                               boost::beast::error_code& ec) override;
	void on_finish_impl(boost::beast::error_code& ec) override;

private:
	PROXER_ASIO_NS::ssl::stream<PROXER_ASIO_NS::ip::tcp::socket>& _output;
};

} // namespace proxer::detail
