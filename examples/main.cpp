#include <proxer/proxer.hpp>

using namespace PROXER_ASIO_NS;

int main()
{
	io_service service{};

	auto certificator = std::make_shared<proxer::certificator::SelfSigner>(
	  proxer::certificator::load_key("/home/yunus/Projects/proxer/ca.key"),
	  proxer::certificator::load_certificate("/home/yunus/Projects/proxer/ca.crt"),
	  proxer::certificator::generate_elliptic_curve_key());

	proxer::Proxy proxy{ service.get_executor(),
		                   ip::tcp::endpoint{ ip::address::from_string("127.0.0.1"), 8080 }, certificator };

	service.run();
}
