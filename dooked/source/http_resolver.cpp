#include "http_resolver.hpp"

namespace dooked {

http_resolver_t::http_resolver_t(net::io_context &ioc, ssl::context *sslc,
                                 domain_list_t &names,
                                 map_container_t<dns_record_t> &result_map)
    : io_context_(ioc), default_tls_context_(sslc), names_(names),
      result_map_(result_map) {}

void http_resolver_t::send_next_request() {
  try {
    http_retries_count_ = http_retries_count_ = 0;
    if (!(bool)is_default_tls_) {
      default_tls_context_ = tls13_holder_->original_ssl_context_;
    }
    name_ = names_.next_item();
    perform_http_request();
  } catch (empty_container_exception_t const &) {
  }
}

void http_resolver_t::perform_http_request() {
  http_request_handler_.emplace();
  send_http_request(name_);
}

void http_resolver_t::send_http_request(std::string const &address) {
  auto &http_request =
      http_request_handler_->request_.emplace<http_request_handler_t>(
          io_context_, uri{address}.host());
  http_request.start([this](response_type_e const rt, int const content_length,
                            std::string const &response) {
    tcp_request_result(rt, content_length, response);
  });
}

void http_resolver_t::send_https_request(std::string const &address) {
  auto &https_request =
      http_request_handler_->request_.emplace<https_request_handler_t>(
          io_context_, *default_tls_context_, uri{address}.host());
  return https_request.start(
      [this](auto const rt, auto const len, auto const &rstr) {
        tcp_request_result(rt, len, rstr);
      });
}

void http_resolver_t::on_resolve_error() {
  auto https_socket_type =
      std::get_if<https_request_handler_t>(&(http_request_handler_->request_));
  if (!https_socket_type) {
    return send_https_request(name_);
  }
  // if we are here, we must have tried https too and it fails.
  result_map_.insert(name_, 0,
                     static_cast<int>(response_type_e::cannot_resolve_name));
  return send_next_request();
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
  case response_type_e::cannot_resolve_name:
    return on_resolve_error();
  case response_type_e::cannot_connect:
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
    return send_http_request(response_string);
  }
  case response_type_e::https_redirected: {
    ++http_redirects_count_;
    if (http_redirects_count_ >= 10) { // too many redirects
      result_map_.insert(name_, 0, 309);
      return send_next_request();
    }
    return send_https_request(response_string);
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
      return send_http_request(response_string);
    } else {
      return send_https_request(response_string);
    }
  }
  case response_type_e::ssl_change_context:
  case response_type_e::ssl_handshake_failed: {
    return switch_ssl_method(response_string);
  }
  case response_type_e::ssl_change_to_http:
    return send_http_request(name_);
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

void http_resolver_t::switch_ssl_method(std::string const &name) {
  if (!tls13_holder_ || is_default_tls_) {
    if (!tls13_holder_) { // first time switching SSL context, tls_v12
      auto &tls_v13_context = get_tlsv13_context();
      auto &ssl_holder =
          tls13_holder_.emplace(tls_v13_context, default_tls_context_);
    }
    default_tls_context_ = &(tls13_holder_->tls_v13_context_);
    is_default_tls_ = 0;
    auto &req =
        http_request_handler_->request_.emplace<https_request_handler_t>(
            io_context_, *default_tls_context_, name);
    return req.start([this](auto const rt, auto const len, auto const &rstr) {
      tcp_request_result(rt, len, rstr);
    });
  } else {
    // switch back to tls v 1.2
    default_tls_context_ = tls13_holder_->original_ssl_context_;
    is_default_tls_ = 1;
    send_next_request();
  }
}

} // namespace dooked
