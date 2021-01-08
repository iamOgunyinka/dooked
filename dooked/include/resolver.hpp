#pragma once
#include "domainname.hpp"
#include "utils.hpp"
#include <boost/beast/core/tcp_stream.hpp>
#include <optional>
#include <string>

namespace dooked {
namespace net = boost::asio;
using udp_stream_t = net::ip::udp::socket;

template <typename Value>
constexpr void set_16bit_value(unsigned char *p, Value const value) {
  p[0] = static_cast<unsigned char>((value >> 8) & 0xFF);
  p[1] = static_cast<unsigned char>(value & 0xFF);
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

// http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
enum class dns_rcode {
  DNS_RCODE_NO_ERROR = 0,
  DNS_RCODE_FORMAT_ERR = 1,
  DNS_RCODE_SERVER_FAILED = 2,
  DNS_RCODE_NXDOMAIN = 3, // non-existing domain
  DNS_RCODE_NOT_IMPLEMENTED = 4,
  DNS_RCODE_REFUSED = 5,
  DNS_RCODE_YXDOMAIN = 6, // name exists when it should not
  DNS_RCODE_YXRRSET = 7,  // resource record set exist when it should not
  DNS_RCODE_NXRRSET = 8,  // rr set that should exist does not
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

struct dns_alternate_head_t {
  dns_header_t header;
  std::vector<dns_alternate_question_t> questions{};
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
  dns_alternate_head_t head;
  dns_body_t body;
};

enum class rr_flags_e {
  R_NONE = 0,
  R_ASP = 1,
  R_COMPRESS = 2,
  R_ASPCOMPRESS = 3
};

struct rr_data_t {
  dns_record_type_e type{};
  std::uint16_t len{};
  ucstring_cptr msg{};
};

struct dns_supported_record_type_t {
  static std::array<rr_type_t, 13> const supported_types;
};

struct dns_extractor_t {
  query_result_t extract(dns_packet_t const &);
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
  bool result_ready_ = false;

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

void alternate_parse_dns(dns_packet_t &, ucstring &);
void read_section(std::vector<dns_alternate_record_t> &, int, ucstring &,
                  int &);
std::uint32_t uint32_value(unsigned char const *buff);
dns_alternate_record_t read_raw_record(ucstring &buf, int &pos);
void raw_record_read(dns_record_type_e, ucstring_ptr &, std::uint16_t &,
                     ucstring &, int, int);
void serialize_packet(dns_packet_t const &);
a_record_list_t get_a_record(dns_packet_t const &);
aaaa_record_list_t get_aaaa_record(dns_packet_t const &);
mx_record_list_t get_mx_record(dns_packet_t const &);
ns_record_list_t get_ns_record(dns_packet_t const &);
ptr_record_list_t get_ptr_record(dns_packet_t const &);
std::vector<rr_data_t>
get_records(dns_packet_t const &packet, bool fail_if_none = false,
            bool follow_cname = true,
            std::vector<domainname> *followed_cnames = nullptr);
std::string rcode_to_string(dns_rcode);
std::vector<rr_data_t>
i_get_records(dns_packet_t const &packet, bool fail_if_none, bool follow_cname,
              int recursive_level, domainname const &dname,
              dns_record_type_e qt, std::vector<domainname> *followed_cnames);
} // namespace dooked
