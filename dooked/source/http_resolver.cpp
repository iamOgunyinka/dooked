#include "http_resolver.hpp"

namespace dooked {

void http_resolver_t::send_next_request() {
  try {
    name_ = names_.next_item();
    perform_http_request();
  } catch (empty_container_exception_t const &) {
  }
}

void http_resolver_t::perform_http_request() {
  http_request_handler_.emplace();
  auto &https_request =
      http_request_handler_->request_.emplace<https_request_handler_t>(
          io_context_, ssl_context_, name_);
  https_request.start([this](response_type_e const rt, int const content_length,
                             std::string const &response) {
    tcp_request_result(rt, content_length, response);
  });
}

void http_resolver_t::tcp_request_result(response_type_e const rt,
                                         int const content_length,
                                         std::string const &response_string) {
  switch (rt) {
  case response_type_e::bad_request: {
    result_map_.insert(name_, content_length, 400);
    return send_next_request();
  }
  case response_type_e::forbidden: {
    result_map_.insert(name_, content_length, 403);
    return send_next_request();
  }
  case response_type_e::cannot_connect:
  case response_type_e::cannot_resolve_name:
  case response_type_e::cannot_send: {
    result_map_.insert(name_, 0, static_cast<int>(rt));
    return send_next_request();
  }
  case response_type_e::http_redirected: {
    ++http_redirects_count_;
    if (http_redirects_count_ >= 10) { // too many redirects
      result_map_.insert(name_, 0, 309);
      return send_next_request();
    }
    auto &http_request =
        http_request_handler_->request_.emplace<http_request_handler_t>(
            io_context_, uri{response_string}.host());
    return http_request.start(
        [this](auto const rt, auto const len, auto const &rstr) {
          tcp_request_result(rt, len, rstr);
        });
  }
  case response_type_e::https_redirected: {
    ++http_redirects_count_;
    if (http_redirects_count_ >= 10) { // too many redirects
      result_map_.insert(name_, 0, 309);
      return send_next_request();
    }
    auto &https_request =
        http_request_handler_->request_.emplace<https_request_handler_t>(
            io_context_, ssl_context_, uri{response_string}.host());
    return https_request.start(
        [this](auto const rt, auto const len, auto const &rstr) {
          tcp_request_result(rt, len, rstr);
        });
  }
  case response_type_e::not_found: { // HTTP(S) 404
    result_map_.insert(name_, content_length, 404);
    return send_next_request();
  }
  case response_type_e::ok: {
    result_map_.insert(name_, content_length, 200);
    return send_next_request();
  }
  case response_type_e::recv_timed_out: { // retry, wait timeout
    ++http_retries_count_;
    if (http_retries_count_ > 5) {
      result_map_.insert(name_, 0, static_cast<int>(rt));
      return send_next_request();
    }
    auto http_socket_type =
        std::get_if<http_request_handler_t>(&(http_request_handler_->request_));
    if (http_socket_type) {
      auto &req =
          http_request_handler_->request_.emplace<http_request_handler_t>(
              io_context_, uri{response_string}.host());
      req.start([this](auto const rt, auto const len, auto const &rstr) {
        tcp_request_result(rt, len, rstr);
      });
    } else {
      auto &req =
          http_request_handler_->request_.emplace<https_request_handler_t>(
              io_context_, ssl_context_, response_string);
      req.start([this](auto const rt, auto const len, auto const &rstr) {
        tcp_request_result(rt, len, rstr);
      });
    }
    return;
  }
  case response_type_e::ssl_change_context:
  case response_type_e::ssl_handshake_failed: {
    // to-do
    return send_next_request();
  }
  case response_type_e::ssl_change_to_http: {
    auto &req = http_request_handler_->request_.emplace<http_request_handler_t>(
        io_context_, name_);
    req.start([this](auto const rt, auto const len, auto const &rstr) {
      tcp_request_result(rt, len, rstr);
    });
    return;
  }
  case response_type_e::server_error: {
    result_map_.insert(name_, content_length, 503);
    return send_next_request();
  }
  default: {
    result_map_.insert(name_, 0, 0);
    return send_next_request();
  }
  } // end switch

  send_next_request();
}

http_resolver_t::http_resolver_t(net::io_context &ioc, ssl::context &sslc,
                                 domain_list_t &names,
                                 map_container_t<dns_record_t> &result_map)
    : io_context_{ioc}, ssl_context_{sslc}, names_{names}, result_map_{
                                                               result_map} {}
} // namespace dooked
