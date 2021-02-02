#pragma once

#include "dns.hpp"
#include "http_requests_handler.hpp"
#include "utils.hpp"
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <optional>

// max dns wait time in seconds
#define DOOKED_MAX_DNS_WAIT_TIME 5

namespace dooked {
namespace net = boost::asio;

using udp_stream_t = net::ip::udp::socket;
using error_code = boost::system::error_code;

struct dns_supported_record_type_t {
  static std::array<dns_record_type_e, 8> const supported_types;
};

class custom_resolver_socket_t {
  net::io_context &io_;
  domain_list_t &names_;
  resolver_address_list_t &resolvers_;
  map_container_t<dns_record_t> &result_map_;

  net::ssl::context *ssl_context_;
  std::optional<udp_stream_t> udp_stream_;
  std::optional<net::ip::udp::endpoint> default_ep_;
  std::optional<net::steady_timer> timer_;

  // if we defer HTTP, there's no need to construct this.
  std::optional<request_t> http_request_handler_;
  // this is only used iff (1) we didn't defer HTTP requests
  // (2) there was a request to switch from TLS 1.2 to 1.3
  std::optional<temporary_ssl_holder_t> tls_v13_holder_;

  resolver_address_t current_resolver_{};
  bool deferring_http_request_ = false;
  bool is_default_tls_ = true;

private:
  domain_list_t::value_type name_{};
  dns_record_type_e current_rec_type_ = dns_record_type_e::DNS_REC_UNDEFINED;
  int last_processed_dns_index_ = -1;
  int http_retries_count_ = 0;
  int http_redirects_count_ = 0;
  int const supported_dns_record_size_;
  static constexpr std::size_t const sizeof_packet_header = 12;
  ucstring_t send_buffer_{};
  ucstring_t recv_buffer_{};

  // dns related member functions
private:
  dns_record_type_e dns_next_record_type();
  void dns_send_network_request();
  void dns_receive_network_data();
  void dns_establish_udp_connection();
  void dns_on_data_sent();
  void dns_on_data_received(error_code, std::size_t);
  void dns_send_next_request();
  void dns_serialize_packet(dns_packet_t const &);
  void dns_continue_probe();

  // http related "handlers"
private:
  void perform_http_request();
  void http_result_obtained(response_type_e, int, std::string const &);
  void on_http_resolve_error();
  void send_https_request(std::string const &address);
  void send_http_request(std::string const &address);
  void http_switch_tls_requested(std::string const &);

public:
  custom_resolver_socket_t(net::io_context &, net::ssl::context *,
                           domain_list_t &, resolver_address_list_t &,
                           map_container_t<dns_record_t> &);
  void defer_http_request(bool const defer);
  void start();
};

void parse_dns_response(dns_packet_t &, ucstring_t &);
void dns_create_query(std::string const &name, std::uint16_t const type,
                  std::uint16_t const id, ucstring_t &bufp);

std::string rcode_to_string(dns_rcode_e);
} // namespace dooked
