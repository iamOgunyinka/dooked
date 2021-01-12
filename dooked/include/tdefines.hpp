#pragma once
#include <cstdint>

namespace dooked {

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
enum class dns_rcode_e {
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

  std::uint8_t rcode{};
  std::uint8_t opcode{};
  std::uint16_t id{};
  std::uint16_t q_count{};    // query count
  std::uint16_t ans_count{};  // answer count
  std::uint16_t auth_count{}; // authority count
};

} // namespace dooked
