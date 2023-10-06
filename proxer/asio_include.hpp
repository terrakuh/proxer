#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#define PROXER_ASIO_NS boost::asio

namespace proxer {

using asio_error_code = boost::system::error_code;

}
