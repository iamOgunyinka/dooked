#include "requests.hpp"
#include "utils.hpp"
#include <boost/asio/strand.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/write.hpp>

#include <random>

namespace dooked {
bool starts_with(std::string const &str, std::string const &prefix) {
  return std::equal(str.cbegin(), str.cbegin() + prefix.size(), prefix.cbegin(),
                    [](char const a, char const b) {
                      return (std::toupper(a) == std::toupper(b));
                    });
}

std::array<char const *, 14> const request_handler::user_agents = {
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/41.0.2228.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
    "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
    "Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0",
    "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 "
    "Firefox/68.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:67.0) Gecko/20100101 Firefox/67.0",
    "Mozilla/5.0 (X11; Linux i686; rv:67.0) Gecko/20100101 Firefox/67.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:67.0) Gecko/20100101 Firefox/67.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/74.0.3729.28 Safari/537.36 OPR/61.0.3298.6 (Edition developer)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like "
    "Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134"};

std::string get_random_agent() {
  static std::random_device rd{};
  static std::mt19937 gen{rd()};
  static std::uniform_int_distribution<> uid(0, 13);
  return request_handler::user_agents[uid(gen)];
}

// ========================= HTTP =============================

http_socket_t::http_socket_t(net::io_context &io_context,
                             std::string domain_name,
                             std::vector<std::string> resolved_addresses)
    : io_{io_context}, domain_{std::move(domain_name)} {
  if (!resolved_addresses.empty()) {
    resolved_ip_addresses_.reserve(resolved_addresses.size());
    for (auto const &address : resolved_addresses) {
      resolved_ip_addresses_.push_back({net::ip::make_address(address), 80});
    }
  }
}

http_socket_t::http_socket_t(
    net::io_context &io_context, std::string domain_name,
    std::vector<net::ip::tcp::endpoint> resolved_addresses)
    : io_{io_context}, domain_{std::move(domain_name)},
      resolved_ip_addresses_{std::move(resolved_addresses)} {}

void http_socket_t::start(completion_cb_t cb) {
  callback_ = std::move(cb);
  prepare_request();
  establish_connection();
}

void http_socket_t::prepare_request() {
  request_.emplace();
  request_->method(http::verb::get);
  request_->version(11);
  request_->target("/");
  request_->keep_alive(true);
  request_->set(http::field::host, domain_);
  request_->set(http::field::cache_control, "no-cache");
  request_->set(http::field::user_agent, get_random_agent());
  request_->set(http::field::accept, "*/*");
}

void http_socket_t::establish_connection() {
  if (resolved_ip_addresses_.empty()) {
    return resolve_name();
  }
  socket_.emplace(io_);
  socket_->expires_after(std::chrono::seconds(5));
  socket_->async_connect(
      resolved_ip_addresses_.cbegin(), resolved_ip_addresses_.cend(),
      [=](auto const &ec, auto const &) { on_connected(ec); });
}

void http_socket_t::resolve_name() {
  if (resolver_) {
    if (callback_) {
      callback_(response_type_e::cannot_resolve_name, 0, "");
    }
    return;
  }
  resolver_.emplace(io_);
  resolver_->async_resolve(
      domain_, "http", [this](auto const &error, auto const &results) {
        if (error) {
          if (callback_) {
            callback_(response_type_e::cannot_resolve_name, 0, error.message());
            return;
          }
        }
        resolved_ip_addresses_.clear();
        resolved_ip_addresses_.reserve(results.size());
        for (auto const &r : results) {
          resolved_ip_addresses_.push_back(r.endpoint());
        }
        return establish_connection();
      });
}

void http_socket_t::on_connected(beast::error_code const ec) {
  if (ec) {
    return reconnect();
  }
  send_http_data();
}

void http_socket_t::reconnect() {
  if (++connect_retries_ >= 3) {
    if (callback_) {
      return callback_(response_type_e::cannot_connect, 0, {});
    }
  } else {
    establish_connection();
  }
}

void http_socket_t::send_http_data() {
  socket_->expires_after(std::chrono::seconds(5));
  http::async_write(*socket_, *request_,
                    [this](auto const ec, std::size_t const sz) {
                      if (ec) {
                        return resend_data();
                      }
                      receive_data();
                    });
}

void http_socket_t::resend_data() {
  if (++send_retries_ >= 3) {
    if (callback_) {
      return callback_(response_type_e::cannot_send, 0, {});
    }
  } else {
    send_http_data();
  }
}

void http_socket_t::receive_data() {
  socket_->expires_after(std::chrono::seconds(5));
  response_.emplace();
  buffer_ = {};

  http::async_read(*socket_, buffer_, *response_,
                   [this](beast::error_code const ec, std::size_t const sz) {
                     on_data_received(ec, sz);
                   });
}

void http_socket_t::on_data_received(beast::error_code const ec,
                                     std::size_t const bytes_received) {

  response_type_e response_int = response_type_e::unknown_response;
  if (ec) {
#ifdef _DEBUG
    spdlog::error(ec.message());
#endif // _DEBUG

    if (callback_) {
      callback_(response_type_e::recv_timed_out, 0, {});
    }
    return;
  }
  int const status_code = response_->result_int();
  int const status_code_simple = status_code / 100;
  std::string response_string{};

  if (status_code_simple == 2) {
    response_int = response_type_e::ok;
  } else if (status_code_simple == 3) { // redirected
    response_string = (*response_)[http::field::location].to_string();
    if (response_string.empty()) {
      response_int = response_type_e::unknown_response;
    } else {
      if (starts_with(response_string, "https")) {
        response_int = response_type_e::https_redirected;
      } else {
        response_int = response_type_e::http_redirected;
      }
    }
  } else if (status_code_simple == 4) {
    if (status_code == 404) {
      response_int = response_type_e::not_found;
    } else if (status_code == 400) {
      response_int = response_type_e::bad_request;
    }
  } else if (status_code_simple == 5) {
    response_int = response_type_e::server_error;
  } else {
    response_int = response_type_e::unknown_response;
  }
  if (callback_) {
    callback_(response_int, (int)bytes_received, response_string);
  }
}

// ================== HTTPS ================================

void https_socket_t::perform_ssl_ritual() {
  if (!SSL_set_tlsext_host_name(ssl_stream_->native_handle(),
                                domain_name_.c_str())) {
    beast::error_code ec{static_cast<int>(::ERR_get_error()),
                         net::error::get_ssl_category()};
    // spdlog::error("Unable to set TLS because: {}", ec.message());
  }
}

void https_socket_t::perform_ssl_handshake() {
  beast::get_lowest_layer(*ssl_stream_).expires_after(std::chrono::seconds(15));
  ssl_stream_->async_handshake(
      net::ssl::stream_base::client,
      [=](beast::error_code ec) { return on_ssl_handshake(ec); });
}

void https_socket_t::on_ssl_handshake(beast::error_code ec) {
  if (ec.category() == net::error::get_ssl_category() &&
      ec.value() == ERR_PACK(ERR_LIB_SSL, 0, SSL_R_SHORT_READ)) {
    return send_https_data();
  }
  if (ec) {
    // spdlog::error("SSL handshake: {}", ec.message());
    return;
  }
  send_https_data();
}

void https_socket_t::send_https_data() {
  beast::get_lowest_layer(*ssl_stream_).expires_after(std::chrono::seconds(10));
  http::async_write(
      *ssl_stream_, *get_request_,
      beast::bind_front_handler(&https_socket_t::on_data_sent, this));
}

void https_socket_t::on_data_sent(beast::error_code ec, std::size_t) {
  if (ec) {
    return;
  }
  receive_data();
}

void https_socket_t::prepare_request_data() {
  get_request_.emplace();
  get_request_->method(http::verb::get);
  get_request_->version(11);
  get_request_->target("/");
  get_request_->keep_alive(true);
  get_request_->set(http::field::host, domain_name_);
  get_request_->set(http::field::cache_control, "no-cache");
  get_request_->set(http::field::user_agent, get_random_agent());
  get_request_->set(http::field::accept, "*/*");
}

void https_socket_t::receive_data() {
  response_.emplace();
  recv_buffer_.emplace();
  beast::get_lowest_layer(*ssl_stream_).expires_after(std::chrono::seconds(10));
  http::async_read(*ssl_stream_, *recv_buffer_, *response_,
                   [this](beast::error_code ec, std::size_t const sz) {
                     on_data_received(ec, sz);
                   });
}

void https_socket_t::connect() {
  if (resolved_ip_addresses_.empty()) {
    return resolve_name();
  }
  ssl_stream_.emplace(net::make_strand(io_), ssl_context_);
  beast::get_lowest_layer(*ssl_stream_).expires_after(std::chrono::seconds(10));
  beast::get_lowest_layer(*ssl_stream_)
      .async_connect(resolved_ip_addresses_.cbegin(),
                     resolved_ip_addresses_.cend(),
                     [=](auto const &ec, auto const &) { on_connect(ec); });
}

void https_socket_t::reconnect() {}

void https_socket_t::start(completion_cb_t callback) {
  callback_ = std::move(callback);
  prepare_request_data();
  connect();
}

void https_socket_t::on_connect(beast::error_code const ec) {
  if (ec) {
    return reconnect();
  }
  perform_ssl_handshake();
}
https_socket_t::https_socket_t(net::io_context &io_context,
                               net::ssl::context &ssl_context)
    : io_{io_context}, ssl_context_{ssl_context} {}

void https_socket_t::resolve_name() {
  if (resolver_) {
    if (callback_) {
      callback_(response_type_e::cannot_resolve_name, 0, "");
    }
    return;
  }

  resolver_.emplace(net::make_strand(io_));
  resolver_->async_resolve(
      domain_name_, "https", [this](auto const &error, auto const &results) {
        if (error) {
          if (callback_) {
            callback_(response_type_e::cannot_resolve_name, 0, error.message());
            return;
          }
        }
        resolved_ip_addresses_.clear();
        resolved_ip_addresses_.reserve(results.size());
        for (auto const &r : results) {
          resolved_ip_addresses_.push_back(r.endpoint());
        }
        return connect();
      });
}

void https_socket_t::on_data_received(beast::error_code const ec,
                                      std::size_t const bytes_received) {
  response_type_e response_int = response_type_e::unknown_response;
  if (ec) {
#ifdef _DEBUG
    spdlog::error(ec.message());
#endif // _DEBUG

    if (callback_) {
      callback_(response_type_e::recv_timed_out, 0, {});
    }
    return;
  }
  int const status_code = response_->result_int();
  int const status_code_simple = status_code / 100;
  std::string response_string{};

  if (status_code_simple == 2) {
    response_int = response_type_e::ok;
  } else if (status_code_simple == 3) { // redirected
    response_string = (*response_)[http::field::location].to_string();
    if (response_string.empty()) {
      response_int = response_type_e::unknown_response;
    } else {
      if (starts_with(response_string, "https")) {
        response_int = response_type_e::https_redirected;
      } else {
        response_int = response_type_e::http_redirected;
      }
    }
  } else if (status_code_simple == 4) {
    if (status_code == 404) {
      response_int = response_type_e::not_found;
    } else if (status_code == 400) {
      response_int = response_type_e::bad_request;
    }
  } else if (status_code_simple == 5) {
    response_int = response_type_e::server_error;
  } else {
    response_int = response_type_e::unknown_response;
  }
  if (callback_) {
    callback_(response_int, (int)bytes_received, response_string);
  }
}
} // namespace dooked
