#pragma once

#ifdef _MSC_VER
#include <ws2tcpip.h>
#pragma warning(disable : 4996)
#endif

#include "tdefines.hpp"
#include "ucstring.hpp"

#include <inttypes.h>
#include <string>
#include <vector>

namespace dooked {
struct dns_question_t {
  ucstring_view_t dns_name;
  dns_record_type_e type;
  unsigned int dns_class_;
};

struct dns_head_t {
  dns_header_t header;
  std::vector<dns_question_t> questions{};
};

struct static_string_t {
  unsigned char name[0xFF]{};
  std::uint8_t name_length{};
};

struct dns_alternate_record_t {
  static_string_t name{};
  dns_record_type_e type; // RR TYPE (2 octets)
  uint16_t dns_class_{};  // RR CLASS codes(2 octets)
  uint16_t rd_length{};   // length in octets of the RDATA field.
  uint32_t ttl{};         // time to live(4 octets)
  union rd_data_u {
    std::uint8_t *raw;
    static_string_t name;
    in_addr in_addr_;
    in6_addr in6_addr_;
    rd_data_u() : raw{nullptr} {}
  } data; // RData
};

struct dns_record_t {
  std::string name{};
  std::string rdata{};
  dns_record_type_e type; // RR TYPE (2 octets)
  uint16_t dns_class_{};  // RR CLASS codes(2 octets)
  uint16_t rd_length{};   // length in octets of the RDATA field.
  uint32_t ttl{};         // time to live(4 octets)
};

struct dns_body_t {
  std::vector<dns_record_t> answers{};
};

struct dns_packet_t {
  dns_head_t head;
  dns_body_t body;
};

bool parse_name(std::uint8_t const *begin, std::uint8_t const *buf,
                std::uint8_t const *end, unsigned char *name, std::uint8_t *len,
                std::uint8_t **next);

std::string dns_record_type2str(dns_record_type_e type);

bool dns_parse_record_raw(std::uint8_t *begin, std::uint8_t *buf,
                          std::uint8_t const *end, std::uint8_t **next,
                          dns_alternate_record_t *record);
bool dns_parse_record(std::uint8_t *begin, std::uint8_t *buf,
                      std::uint8_t const *end, std::uint8_t **next,
                      dns_alternate_record_t *record);
bool dns_print_readable(char **buf, size_t buflen, unsigned char const *source,
                        size_t len);
std::string dns_name2str(static_string_t const &name);
std::string dns_raw_record_data2str(dns_alternate_record_t *record,
                                    std::uint8_t *begin, std::uint8_t *end);
dns_section_e dns_get_section(std::uint16_t index, dns_head_t *header);
void dns_extract_query_result(dns_packet_t &packet, std::uint8_t *begin,
                              std::size_t len, std::uint8_t *next);
} // namespace dooked
