#pragma once
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/string_body.hpp>

#include <optional>
#include <variant>

namespace dooked {
namespace net = boost::asio;
namespace ssl = net::ssl;
namespace beast = boost::beast;
namespace http = beast::http;

enum class response_type_e : std::uint8_t {
  ok = 0,
  cannot_resolve_name = 1,
  cannot_connect = 11,
  cannot_send = 12,
  unknown_response = 2,
  http_redirected = 31,
  https_redirected = 32,
  not_found = 44,
  bad_request = 40,
  forbidden = 43,
  server_error = 5,
  recv_timed_out = 6,
  ssl_change_context = 70,
  ssl_change_to_http = 71,
  ssl_handshake_failed = 72
};

using completion_cb_t = std::function<void(response_type_e, int, std::string)>;

class http_request_handler_t {
  net::io_context &io_;
  std::string domain_;
  std::vector<net::ip::tcp::endpoint> resolved_ip_addresses_;
  std::optional<beast::tcp_stream> socket_;
  std::optional<net::ip::tcp::resolver> resolver_;
  std::optional<http::response<http::string_body>> response_;
  std::optional<http::request<http::empty_body>> request_;
  beast::flat_buffer buffer_{};
  int connect_retries_ = 0;
  int send_retries_ = 0;
  completion_cb_t callback_ = nullptr;

private:
  void establish_connection();
  void resolve_name();
  void on_connected(beast::error_code);
  void prepare_request();
  void send_http_data();
  void receive_data();
  void reconnect();
  void resend_data();
  void on_data_received(beast::error_code, std::size_t);

public:
  http_request_handler_t(net::io_context &, std::string);
  void start(completion_cb_t = nullptr);
};

class https_request_handler_t {
  net::io_context &io_;
  net::ssl::context &ssl_context_;
  std::string domain_name_;
  std::optional<ssl::stream<beast::tcp_stream>> ssl_stream_;
  std::optional<http::request<http::empty_body>> get_request_;
  std::optional<http::response<http::string_body>> response_;
  std::optional<net::ip::tcp::resolver> resolver_;
  std::optional<beast::flat_buffer> recv_buffer_{};
  std::vector<net::ip::tcp::endpoint> resolved_ip_addresses_;
  completion_cb_t callback_ = nullptr;
  int reconnect_count_ = 0;

private:
  void perform_ssl_ritual();
  void connect();
  void receive_data();
  void reconnect();
  void send_https_data();
  void on_data_sent(beast::error_code, std::size_t const);
  void prepare_request_data();
  void on_connect(beast::error_code);
  void on_data_received(beast::error_code, std::size_t const);
  void perform_ssl_handshake();
  void on_ssl_handshake(boost::system::error_code);
  void resolve_name();

public:
  https_request_handler_t(net::io_context &, net::ssl::context &, std::string);
  void start(completion_cb_t = nullptr);
};

// needed to
struct dummy_struct_t {};

struct request_t {
  std::variant<dummy_struct_t, http_request_handler_t, https_request_handler_t>
      request_;
};

struct request_handler_t {
  static std::array<char const *, 14> const user_agents;
};
} // namespace dooked
