#pragma once

#include <curlio/curlio.hpp>
#include <queue>
#include <utility>
#include <vector>

namespace proxer {

template<typename Type>
class Queue {
public:
	using executor_type = CURLIO_ASIO_NS::any_io_executor;

	Queue(executor_type executor) : _strand{ std::move(executor) } {}

	template<typename Value, typename Token>
	auto async_push(Value&& value, Token&& token)
	{
		return CURLIO_ASIO_NS::async_initiate<Token, void(curlio::detail::asio_error_code)>(
		  [this](auto handler, auto&& value) {
			  CURLIO_ASIO_NS::dispatch(_strand, [this, handler = std::move(handler),
			                                     value = std::forward<decltype(value)>(value)]() mutable {
				  if (_poppers.empty()) {
					  _queue.push(std::move(value));
				  } else {
					  _poppers.front().second({}, std::move(value));
					  _poppers.pop_front();
				  }

				  auto executor = CURLIO_ASIO_NS::get_associated_executor(handler, get_executor());
				  CURLIO_ASIO_NS::post(std::move(executor),
				                       std::bind(std::move(handler), curlio::detail::asio_error_code{}));
			  });
		  },
		  std::forward<Token>(token), std::forward<Value>(value));
	}
	template<typename Token>
	auto async_pop(Token&& token)
	{
		return CURLIO_ASIO_NS::async_initiate<Token, void(curlio::detail::asio_error_code, Type)>(
		  [this](auto handler) {
			  CURLIO_ASIO_NS::dispatch(_strand, [this, handler = std::move(handler)]() mutable {
				  if (_queue.empty()) {
					  auto slot = CURLIO_ASIO_NS::get_associated_cancellation_slot(handler);

					  if (slot.is_connected()) {
						  slot.emplace([this, id = _poppers_registered](CURLIO_ASIO_NS::cancellation_type_t /* type */) {
							  CURLIO_ASIO_NS::dispatch(_strand, [this, id] {
								  for (auto it = _poppers.begin(); it != _poppers.end(); ++it) {
									  // Only call if not cancelled already.
									  if (id == it->first) {
										  it->second(CURLIO_ASIO_NS::error::operation_aborted, Type{});
										  _poppers.erase(it);
										  break;
									  }
								  }
							  });
						  });
					  }

					  _poppers.push_back({
					    _poppers_registered++,
					    [handler = std::move(handler)](curlio::detail::asio_error_code ec, Type value) mutable {
						    auto executor = CURLIO_ASIO_NS::get_associated_executor(handler, get_executor());
						    CURLIO_ASIO_NS::post(std::move(executor),
						                         std::bind(std::move(handler), ec, std::move(value)));
					    },
					  });
				  } else {
					  auto executor = CURLIO_ASIO_NS::get_associated_executor(handler, get_executor());
					  CURLIO_ASIO_NS::post(
					    std::move(executor),
					    std::bind(std::move(handler), curlio::detail::asio_error_code{}, std::move(_queue.front())));
					  _queue.pop();
				  }
			  });
		  },
		  std::forward<Token>(token));
	}

	executor_type get_executor() const noexcept { return _strand.get_inner_executor(); }

private:
	CURLIO_ASIO_NS::strand<executor_type> _strand;
	std::queue<Type> _queue;
	std::vector<std::pair<std::size_t, curlio::detail::Function<void(curlio::detail::asio_error_code, Type)>>>
	  _poppers;
	/// This keeps track of how many popper have been added into the queue. This helps with the cancellation
	/// support.
	std::size_t _poppers_registered = 0;
};

} // namespace proxer
