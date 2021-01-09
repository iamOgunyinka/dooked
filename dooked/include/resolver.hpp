#pragma once

#include "dns.hpp"
#include "utils.hpp"
#include <boost/beast/core/tcp_stream.hpp>
#include <optional>

namespace dooked {
namespace net = boost::asio;
using udp_stream_t = net::ip::udp::socket;

struct rr_data_t {
  dns_record_type_e type{};
  std::uint16_t len{};
  ucstring::const_pointer msg{};
};

struct dns_supported_record_type_t {
  static std::array<dns_record_type_e, 13> const supported_types;
};

class custom_resolver_socket_t {
  net::io_context &io_;
  std::optional<udp_stream_t> udp_stream_;
  std::optional<net::ip::udp::endpoint> default_ep_;
  // std::optional<net::steady_timer> timer_;
  domain_list_t &names_;
  resolver_address_list_t &resolvers_;
  resolver_address_t current_resolver_{};

private:
  domain_list_t::value_type name_{};
  dns_record_type_e current_rec_type_ = dns_record_type_e::DNS_REC_UNDEFINED;
  int last_processed_dns_index_ = -1;
  int retries_ = 0;
  int const supported_dns_record_size_;
  static constexpr std::size_t const sizeof_packet_header = 12;
  std::uint16_t query_id_{};
  ucstring send_buffer_{};
  ucstring recv_buffer_{};

private:
  void create_connection();
  dns_record_type_e next_record_type();
  void send_network_request();
  void receive_network_data();
  void establish_udp_connection();
  void on_data_sent();
  void on_data_received(boost::system::error_code, std::size_t);
  void send_next_request();

public:
  custom_resolver_socket_t(net::io_context &, domain_list_t &,
                           resolver_address_list_t &);
  void start();
};

void create_query(std::string const &name, std::uint16_t type, std::uint16_t id,
                  ucstring &bufp);

void parse_dns_response(dns_packet_t &, ucstring &, int );
void serialize_packet(dns_packet_t const &);
std::string rcode_to_string(dns_rcode);
} // namespace dooked
