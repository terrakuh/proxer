#include "parser.hpp"

#include <sstream>

namespace proxer::detail {

template<bool IsRequest>
inline Parser<IsRequest>::Parser(PROXER_ASIO_NS::ssl::stream<PROXER_ASIO_NS::ip::tcp::socket>& output)
    : _output{ output }
{}

template<bool IsRequest>
inline void Parser<IsRequest>::on_request_impl(boost::beast::http::verb method,
                                               boost::beast::string_view method_str,
                                               boost::beast::string_view target, int version,
                                               boost::beast::error_code& ec)
{
	std::stringstream stream{};
	stream << method_str << " " << target << "HTTP/1.1\r\n";
	PROXER_ASIO_NS::write(_output, PROXER_ASIO_NS::buffer(std::move(stream).str()), ec);
}

template<bool IsRequest>
inline void Parser<IsRequest>::on_response_impl(int code, boost::beast::string_view reason, int version,
                                                boost::beast::error_code& ec)
{
	std::stringstream stream{};
	stream << "HTTP/1.1 " << code << " " << reason << "\r\n";
	PROXER_ASIO_NS::write(_output, PROXER_ASIO_NS::buffer(std::move(stream).str()), ec);
}

template<bool IsRequest>
inline void Parser<IsRequest>::on_field_impl(boost::beast::http::field name,
                                             boost::beast::string_view name_string,
                                             boost::beast::string_view value, boost::beast::error_code& ec)
{
	if (name == boost::beast::http::field::host) {
	}

	// Forward the header.
	PROXER_ASIO_NS::write(_output, PROXER_ASIO_NS::buffer(name_string.data(), name_string.size()), ec);
	!ec&& PROXER_ASIO_NS::write(_output, PROXER_ASIO_NS::buffer(": ", 2), ec);
	!ec&& PROXER_ASIO_NS::write(_output, PROXER_ASIO_NS::buffer(value.data(), value.size()), ec);
	!ec&& PROXER_ASIO_NS::write(_output, PROXER_ASIO_NS::buffer("\r\n", 2), ec);
}

template<bool IsRequest>
inline void Parser<IsRequest>::on_header_impl(boost::beast::error_code& ec)
{
	PROXER_ASIO_NS::write(_output, PROXER_ASIO_NS::buffer("\r\n", 2), ec);
}

template<bool IsRequest>
inline void Parser<IsRequest>::on_body_init_impl(const boost::optional<std::uint64_t>& /* content_length */,
                                                 boost::beast::error_code& /* ec */)
{}

template<bool IsRequest>
inline std::size_t Parser<IsRequest>::on_body_impl(boost::beast::string_view body,
                                                   boost::beast::error_code& ec)
{
	return _output.write_some(PROXER_ASIO_NS::buffer(body.data(), body.size()), ec);
}

template<bool IsRequest>
inline void Parser<IsRequest>::on_chunk_header_impl(std::uint64_t size, boost::beast::string_view extensions,
                                                    boost::beast::error_code& ec)
{
	PROXER_ASIO_NS::write(_output, PROXER_ASIO_NS::buffer(std::to_string(size)), ec);
	!ec&& PROXER_ASIO_NS::write(_output, PROXER_ASIO_NS::buffer(extensions.data(), extensions.size()), ec);
	!ec&& PROXER_ASIO_NS::write(_output, PROXER_ASIO_NS::buffer("\r\n", 2), ec);
}

template<bool IsRequest>
inline std::size_t Parser<IsRequest>::on_chunk_body_impl(std::uint64_t remain, boost::beast::string_view body,
                                                         boost::beast::error_code& ec)
{
	const auto written = _output.write_some(PROXER_ASIO_NS::buffer(body.data(), body.size()), ec);
	if (!ec && written == body.size() && remain == 0) {
		PROXER_ASIO_NS::write(_output, PROXER_ASIO_NS::buffer("\r\n", 2), ec);
	}
	return written;
}

template<bool IsRequest>
inline void Parser<IsRequest>::on_finish_impl(boost::beast::error_code& /* ec */)
{}

template class Parser<false>;
template class Parser<true>;

} // namespace proxer::detail
