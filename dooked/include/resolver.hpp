#pragma once

#include "dns.hpp"
#include "requests.hpp"
#include "utils.hpp"
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <optional>

namespace dooked {
namespace net = boost::asio;

using udp_stream_t = net::ip::udp::socket;
using error_code = boost::system::error_code;

struct dns_supported_record_type_t {
  static std::array<dns_record_type_e, 10> const supported_types;
};

class custom_resolver_socket_t {
  net::io_context &io_;
  net::ssl::context &ssl_context_;
  std::optional<udp_stream_t> udp_stream_;
  std::optional<net::ip::udp::endpoint> default_ep_;
  std::optional<net::steady_timer> timer_;
  std::optional<request_t> http_request_handler_;

  domain_list_t &names_;
  resolver_address_list_t &resolvers_;
  map_container_t<dns_record_t> &result_map_;
  resolver_address_t current_resolver_{};
  bool deferring_http_request_ = false;

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

private:
  dns_record_type_e next_record_type();
  void send_network_request();
  void receive_network_data();
  void establish_udp_connection();
  void on_data_sent();
  void on_data_received(error_code, std::size_t);
  void send_next_request();
  void serialize_packet(dns_packet_t const &);
  void perform_http_request();
  void continue_dns_probe();
  void tcp_request_result(response_type_e, int, std::string const &);

public:
  custom_resolver_socket_t(net::io_context &, net::ssl::context &,
                           domain_list_t &, resolver_address_list_t &,
                           map_container_t<dns_record_t> &);
  void defer_http_request(bool const defer);
  void start();
};

void parse_dns_response(dns_packet_t &, ucstring_t &);
void create_query(std::string const &name, std::uint16_t type, std::uint16_t id,
                  ucstring_t &bufp);

std::string rcode_to_string(dns_rcode_e);
} // namespace dooked
