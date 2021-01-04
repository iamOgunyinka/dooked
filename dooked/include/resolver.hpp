#pragma once
#include "domainname.hpp"
#include "utils.hpp"
#include <boost/asio/ip/udp.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <optional>
#include <string>

namespace dooked {
namespace net = boost::asio;
using udp_stream_t = net::ip::udp::socket;

template <typename Value>
constexpr void set_16bit_value(unsigned char *p, Value const value) {
  p[0] = (value >> 8) & 0xFF;
  p[1] = (value & 0xFF);
}

template <typename Value>
constexpr void set_qid(unsigned char *p, Value const value) {
  set_16bit_value(p, value);
}

template <typename T, typename V>
constexpr void set_opcode(T &target, V const &value) {
  target[2] |= static_cast<unsigned char>((value & 0xF) << 3);
}

template <typename T, typename V>
constexpr void set_opcode_rd(T &target, V const &value) {
  target[2] |= static_cast<unsigned char>(value & 0x1);
}

template <typename T, typename V>
constexpr void set_rcode(T &target, V const &value) {
  target[3] |= (value & 0xF);
}

template <typename V>
constexpr void set_qd_count(unsigned char *t, V const &v) {
  set_16bit_value(t + 4, v);
}

template <typename V>
constexpr void set_an_count(unsigned char *t, V const &v) {
  set_16bit_value(t + 6, v);
}

template <typename V>
constexpr void set_ns_count(unsigned char *t, V const &v) {
  set_16bit_value(t + 8, v);
}

template <typename V>
constexpr void set_question_type(unsigned char *t, V const &v) {
  set_16bit_value(t, v);
}

template <typename V>
constexpr void set_question_class(unsigned char *t, V const &v) {
  set_16bit_value(t + 2, v);
}

template <typename T, typename U> auto minimum(T const &t, U const &u) {
  return t < u ? t : u;
}

template <typename T, typename U> auto maximum(T const &t, U const &u) {
  return t < u ? u : t;
}

enum class dns_record_type_e : std::uint16_t {
  DNS_REC_INVALID = 0xFFFF, // Error code
  DNS_REC_UNDEFINED = 0,
  DNS_REC_A = 1,
  DNS_REC_AAAA = 28,
  DNS_REC_AFSDB = 18,
  DNS_REC_ANY = 255,
  DNS_REC_APL = 42,
  DNS_REC_CAA = 257,
  DNS_REC_CDNSKEY = 60,
  DNS_REC_CDS = 59,
  DNS_REC_CERT = 37,
  DNS_REC_CNAME = 5,
  DNS_REC_DHCID = 49,
  DNS_REC_DLV = 32769,
  DNS_REC_DNAME = 39,
  DNS_REC_DNSKEY = 48,
  DNS_REC_DS = 43,
  DNS_REC_HIP = 55,
  DNS_REC_IPSECKEY = 45,
  DNS_REC_KEY = 25,
  DNS_REC_KX = 36,
  DNS_REC_LOC = 29,
  DNS_REC_MX = 15,
  DNS_REC_NAPTR = 35,
  DNS_REC_NS = 2,
  DNS_REC_NSEC = 47,
  DNS_REC_NSEC3 = 50,
  DNS_REC_NSEC3PARAM = 51,
  DNS_REC_OPENPGPKEY = 61,
  DNS_REC_PTR = 12,
  DNS_REC_RP = 17,
  DNS_REC_RRSIG = 46,
  DNS_REC_SIG = 24,
  DNS_REC_SOA = 6,
  DNS_REC_SRV = 33,
  DNS_REC_SSHFP = 44,
  DNS_REC_TA = 32768,
  DNS_REC_TKEY = 249,
  DNS_REC_TLSA = 52,
  DNS_REC_TSIG = 250,
  DNS_REC_TXT = 16,
  DNS_REC_URI = 256
};

enum class dns_section {
  DNS_SECTION_QUESTION = 0,
  DNS_SECTION_ANSWER = 1,
  DNS_SECTION_AUTHORITY = 2,
  DNS_SECTION_ADDITIONAL = 3
};

enum class dns_rcode {
  DNS_RCODE_OK = 0,
  DNS_RCODE_FORMERR = 1,
  DNS_RCODE_SERVFAIL = 2,
  DNS_RCODE_NXDOMAIN = 3,
  DNS_RCODE_NOTIMP = 4,
  DNS_RCODE_REFUSED = 5,
  DNS_RCODE_YXDOMAIN = 6,
  DNS_RCODE_YXRRSET = 7,
  DNS_RCODE_NOTAUTH = 9,
  DNS_RCODE_NOTZONE = 10,
  DNS_RCODE_BADVERS = 16,
  DNS_RCODE_BADKEY = 17,
  DNS_RCODE_BADTIME = 18,
  DNS_RCODE_BADMODE = 19,
  DNS_RCODE_BADNAME = 20,
  DNS_RCODE_BADALG = 21,
  DNS_RCODE_BADTRUNC = 22,
  DNS_RCODE_BADCOOKIE = 23
};

enum class dns_class {
  DNS_CLS_IN = 0x0001,          // DNS Class Internet
  DNS_CLS_CH = 0x0003,          // DNS Class Chaos
  DNS_CLS_HS = 0x0004,          // DNS Class Hesiod
  DNS_CLS_QCLASS_NONE = 0x00FE, // DNS Class QCLASS None
  DNS_CLS_QCLASS_ANY = 0x00FF   // DNS Class QCLASS Any
};

struct dns_header_t {
  bool rd{};
  bool tc{};
  bool aa{};
  bool qr{};
  bool ad{};
  bool z{};
  bool cd{};
  bool ra{};

  uint8_t rcode{};
  uint8_t opcode{};
  uint16_t id{};
  uint16_t q_count{};    // query count
  uint16_t ans_count{};  // answer count
  uint16_t auth_count{}; // authority count
  uint16_t add_count{};  // additional information count
};

struct dns_alternate_question_t {
  domainname dns_name;
  dns_record_type_e type;
  unsigned int dns_class_;
};

struct dns_question_t {
  ucstring dns_name;
  dns_record_type_e type;
  unsigned int dns_class_;
};

struct dns_head_t {
  dns_header_t header;
  dns_question_t question;
};

struct dns_record_t {
  std::string rr_name{};  // Resource Record(RR) name
  dns_record_type_e type; // RR TYPE (2 octets)
  uint16_t dns_class_{};  // RR CLASS codes(2 octets)
  uint16_t length{};      // length in octets of the RDATA field.
  uint32_t ttl{};         // time to live(4 octets)
  std::variant<net::ip::address, ucstring> rdata{};
};

struct dns_alternate_record_t {
  domainname name{};
  dns_record_type_e type; // RR TYPE (2 octets)
  uint16_t dns_class_{};  // RR CLASS codes(2 octets)
  uint16_t rd_length{};   // length in octets of the RDATA field.
  uint32_t ttl{};         // time to live(4 octets)
  ucstring_ptr rdata{};
};

struct dns_body_t {
  std::vector<dns_alternate_record_t> answers{};
  //  std::vector<dns_record_t> authorities{};
  //  std::vector<dns_record_t> additional_info{};
};

struct dns_packet_t {
  dns_head_t head;
  dns_body_t body;
};

enum class rr_flags_e {
  R_NONE = 0,
  R_ASP = 1,
  R_COMPRESS = 2,
  R_ASPCOMPRESS = 3
};

struct rr_type_t {
  char name[9]{};
  std::uint16_t type{};
  char properties[9]{};
  rr_flags_e flags = rr_flags_e::R_NONE;
  dns_record_type_e rr_type_name;
};

struct dns_supported_record_type_t {
  static std::array<rr_type_t, 13> const supported_types;
};

struct resolver_address_t {
  net::ip::udp::endpoint ep{};
};

using resolver_address_list_t = circular_queue_t<resolver_address_t>;

class custom_resolver_socket_t {
  net::io_context &io_;
  std::optional<udp_stream_t> udp_stream_;
  net::steady_timer timer_;
  domain_list_t &names_;
  resolver_address_list_t &resolvers_;
  resolver_address_t current_resolver_{};
  boost::system::error_code read_ec_{};

private:
  domain_t name_{};
  dns_record_type_e current_rec_type_ = dns_record_type_e::DNS_REC_UNDEFINED;
  int last_processed_dns_index_ = -1;
  int const supported_dns_record_size_;
  static constexpr int const max_ops_waiting_ = 2;
  static constexpr std::size_t const sizeof_packet_header = 12;
  int ops_waiting_{};
  std::uint16_t query_id_{};
  std::size_t bytes_read_{};
  ucstring generic_buffer_{};

private:
  dns_record_type_e next_record_type();
  void send_network_request();
  void receive_network_data();
  void establish_udp_connection();
  void on_data_sent(boost::system::error_code);
  void on_data_received();
  void send_next_request();
  void parse_dns_response(dns_packet_t &);
  void parse_dns_header(dns_packet_t &);
  ucstring::const_pointer parse_dns_question(dns_packet_t &);
  ucstring::const_pointer parse_dns_qname(dns_packet_t &, ucstring::size_type);
  void parse_dns_body(dns_packet_t &, ucstring::const_pointer);
  dns_body_t parse_dns_body_impl(ucstring::const_pointer);

public:
  custom_resolver_socket_t(net::io_context &, domain_list_t &,
                           resolver_address_list_t &);
  void start();
};
void create_query(std::string const &name, std::uint16_t type, std::uint16_t id,
                  ucstring &bufp);

void alternate_parse_dns(dns_packet_t &, ucstring &);
void read_section(std::vector<dns_alternate_record_t> &, int, ucstring &,
                  int &);
std::uint32_t uint32_value(unsigned char const *buff);
dns_alternate_record_t read_raw_record(ucstring &buf, int &pos);
void raw_record_read(dns_record_type_e, ucstring_ptr &, std::uint16_t &,
                     ucstring &, int, int);
void serialize_packet(dns_packet_t const &);
} // namespace dooked
