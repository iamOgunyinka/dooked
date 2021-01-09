#define ASIO_STANDALONE
#define ASIO_HEADER_ONLY

#include "dns.hpp"
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

int inet_pton(int af, const char *src, void *dst) {
  sockaddr_storage ss;
  int size = sizeof(ss);
  char src_copy[INET6_ADDRSTRLEN + 1];

  ZeroMemory(&ss, sizeof(ss));
  /* stupid non-const API */
  strncpy(src_copy, src, INET6_ADDRSTRLEN + 1);
  src_copy[INET6_ADDRSTRLEN] = 0;

  if (WSAStringToAddressA(src_copy, af, NULL, (sockaddr *)&ss, &size) == 0) {
    switch (af) {
    case AF_INET:
      *(in_addr *)dst = ((sockaddr_in *)&ss)->sin_addr;
      return 1;
    case AF_INET6:
      *(in6_addr *)dst = ((sockaddr_in6 *)&ss)->sin6_addr;
      return 1;
    }
  }
  return 0;
}

const char *inet_ntop(int af, const void *src, char *dst, socklen_t size) {
  sockaddr_storage ss;
  unsigned long s = size;

  ZeroMemory(&ss, sizeof(ss));
  ss.ss_family = af;

  switch (af) {
  case AF_INET:
    ((sockaddr_in *)&ss)->sin_addr = *(in_addr *)src;
    break;
  case AF_INET6:
    ((sockaddr_in6 *)&ss)->sin6_addr = *(in6_addr *)src;
    break;
  default:
    return NULL;
  }
  /* cannot direclty use &size because of strict aliasing rules */
  return (WSAAddressToStringA((sockaddr *)&ss, sizeof(ss), NULL, dst, &s) == 0)
             ? dst
             : NULL;
}
#endif // _WIN32

namespace dooked {
std::string dns_record_type2str(dns_record_type_e type) {
  switch (type) {
  case dns_record_type_e::DNS_REC_A:
    return "A";
  case dns_record_type_e::DNS_REC_AAAA:
    return "AAAA";
  case dns_record_type_e::DNS_REC_AFSDB:
    return "AFSDB";
  case dns_record_type_e::DNS_REC_ANY:
    return "ANY";
  case dns_record_type_e::DNS_REC_APL:
    return "APL";
  case dns_record_type_e::DNS_REC_CAA:
    return "CAA";
  case dns_record_type_e::DNS_REC_CDNSKEY:
    return "CDNSKEY";
  case dns_record_type_e::DNS_REC_CDS:
    return "CDS";
  case dns_record_type_e::DNS_REC_CERT:
    return "CERT";
  case dns_record_type_e::DNS_REC_CNAME:
    return "CNAME";
  case dns_record_type_e::DNS_REC_DHCID:
    return "DHCID";
  case dns_record_type_e::DNS_REC_DLV:
    return "DLV";
  case dns_record_type_e::DNS_REC_DNAME:
    return "DNAME";
  case dns_record_type_e::DNS_REC_DNSKEY:
    return "DNSKEY";
  case dns_record_type_e::DNS_REC_DS:
    return "DS";
  case dns_record_type_e::DNS_REC_HIP:
    return "HIP";
  case dns_record_type_e::DNS_REC_IPSECKEY:
    return "IPSECKEY";
  case dns_record_type_e::DNS_REC_KEY:
    return "KEY";
  case dns_record_type_e::DNS_REC_KX:
    return "KX";
  case dns_record_type_e::DNS_REC_LOC:
    return "LOC";
  case dns_record_type_e::DNS_REC_MX:
    return "MX";
  case dns_record_type_e::DNS_REC_NAPTR:
    return "NAPTR";
  case dns_record_type_e::DNS_REC_NS:
    return "NS";
  case dns_record_type_e::DNS_REC_NSEC:
    return "NSEC";
  case dns_record_type_e::DNS_REC_NSEC3:
    return "NSEC3";
  case dns_record_type_e::DNS_REC_NSEC3PARAM:
    return "NSEC3PARAM";
  case dns_record_type_e::DNS_REC_OPENPGPKEY:
    return "OPENPGPKEY";
  case dns_record_type_e::DNS_REC_PTR:
    return "PTR";
  case dns_record_type_e::DNS_REC_RRSIG:
    return "RRSIG";
  case dns_record_type_e::DNS_REC_RP:
    return "RP";
  case dns_record_type_e::DNS_REC_SIG:
    return "SIG";
  case dns_record_type_e::DNS_REC_SOA:
    return "SOA";
  case dns_record_type_e::DNS_REC_SRV:
    return "SRV";
  case dns_record_type_e::DNS_REC_SSHFP:
    return "SSHFP";
  case dns_record_type_e::DNS_REC_TA:
    return "TA";
  case dns_record_type_e::DNS_REC_TKEY:
    return "TKEY";
  case dns_record_type_e::DNS_REC_TLSA:
    return "TLSA";
  case dns_record_type_e::DNS_REC_TSIG:
    return "TSIG";
  case dns_record_type_e::DNS_REC_TXT:
    return "TXT";
  case dns_record_type_e::DNS_REC_URI:
    return "URI";
  default: {
    std::string numbuf(16, '\0');
    snprintf(numbuf.data(), 16, "%" PRIu16, (uint16_t)type);
    return numbuf;
  }
  }
}
bool parse_name(std::uint8_t const *begin, std::uint8_t const *buf,
                std::uint8_t const *end, unsigned char *name, std::uint8_t *len,
                std::uint8_t **next) {
  std::uint8_t first{};
  int label_type{};
  int label_len{};
  int name_len{};
  std::uint8_t *pointer{nullptr};

  while (true) {
    if (buf >= end) {
      return false;
    }
    first = *buf;
    label_type = (first & 0xC0);
    if (label_type == 0xC0) // Compressed
    {
      if (next && !pointer) {
        *next = (std::uint8_t *)buf + 2;
      }
      pointer = (std::uint8_t *)(begin + (htons(*((uint16_t *)buf)) & 0x3FFF));
      if (pointer >= buf) {
        return false;
      }
      buf = pointer;
    } else if (label_type == 0x00) // Uncompressed
    {
      label_len = (first & 0x3F);
      name_len += label_len + 1;
      if (name_len >= 0xFF) {
        return false;
      }
      if (label_len == 0) {
        if (name_len == 1) {
          *(name++) = '.';
        }
        *name = 0;
        if (next && !pointer) {
          *next = (std::uint8_t *)(buf + label_len + 1);
        }
        if (name_len <= 1) {
          *len = (std::uint8_t)name_len;
        } else {
          *len = (std::uint8_t)(name_len - 1);
        }
        return true;
      } else {
        if (buf + label_len + 1 > end) {
          return false;
        }
        memcpy(name, buf + 1, (size_t)label_len);
        *(name + label_len) = '.';
        name += label_len + 1;
        buf += label_len + 1;
      }
    } else {
      return false;
    }
  }
}

bool dns_parse_record_raw(std::uint8_t *begin, std::uint8_t *buf,
                          std::uint8_t const *end, std::uint8_t **next,
                          dns_alternate_record_t *record) {
  if (!parse_name(begin, buf, end, record->name.name, &record->name.name_length,
                  next)) {
    return false;
  }
  if (*next + 10 > end) {
    return false;
  }

  record->type = (dns_record_type_e)ntohs((*(uint16_t *)(*next)));
  record->dns_class_ = ntohs((*(uint16_t *)(*next + 2)));
  record->ttl = ntohl((*(uint32_t *)(*next + 4)));
  record->rd_length = ntohs((*(uint16_t *)(*next + 8)));
  *next = *next + 10;
  record->data.raw = *next;

  *next = *next + record->rd_length;
  if (*next > end) {
    return false;
  }
  return true;
}

bool dns_parse_record(std::uint8_t *begin, std::uint8_t *buf,
                      std::uint8_t const *end, std::uint8_t **next,
                      dns_alternate_record_t *record) {
  if (!dns_parse_record_raw(begin, buf, end, next, record)) {
    return false;
  }

  if (record->type == dns_record_type_e::DNS_REC_A) {
    if (record->rd_length != 4) {
      return false;
    }
  } else if (record->type == dns_record_type_e::DNS_REC_AAAA) {
    if (record->rd_length != 16) {
      return false;
    }
  } else if (record->type == dns_record_type_e::DNS_REC_NS) {
    if (record->rd_length > 0xFF) {
      return false;
    }
    static_string_t name{};
    if (!parse_name(begin, record->data.raw, end, record->data.name.name,
                    &record->data.name.name_length, nullptr)) {
      return false;
    }
  }

  return true;
}

bool dns_print_readable(char **buf, std::size_t buflen,
                        unsigned char const *source, std::size_t len) {
  char *endbuf = *buf + buflen;
  for (size_t i = 0; i < len; i++) {
    if (source[i] >= ' ' && source[i] <= '~' && source[i] != '\\') {
      if (*buf >= endbuf - 1) {
        **buf = 0;
        return false;
      }
      *((*buf)++) = source[i];
    } else {
      if (*buf >= endbuf - 4) {
        **buf = 0;
        return false;
      }
      *((*buf)++) = '\\';
      *((*buf)++) = 'x';
      char hex1 = (char)((source[i] >> 8) & 0xF);
      char hex2 = (char)(source[i] & 0xF);
      *((*buf)++) = (char)(hex1 + (hex1 < 10 ? '0' : ('a' - 10)));
      *((*buf)++) = (char)(hex2 + (hex2 < 10 ? '0' : ('a' - 10)));
    }
  }
  **buf = 0;
  return true;
}

std::string dns_name2str(static_string_t const &name) {
  std::string buf(0xFF * 4, '\0');
  char *ptr = buf.data();
  dns_print_readable(&ptr, sizeof(buf), name.name, name.name_length);
  return buf;
}

std::string dns_raw_record_data2str(dns_alternate_record_t *record,
                                    std::uint8_t *begin, std::uint8_t *end) {
  static constexpr int const raw_buf_size = 0xFFFF0;
  std::string raw_buf(raw_buf_size, '\0');
  auto buf = raw_buf.data();
  static_string_t name;

  char *ptr = buf;

  switch (record->type) {
  case dns_record_type_e::DNS_REC_NS:
  case dns_record_type_e::DNS_REC_CNAME:
  case dns_record_type_e::DNS_REC_DNAME:
  case dns_record_type_e::DNS_REC_PTR:
    parse_name(begin, record->data.raw, end, name.name, &name.name_length,
               nullptr);
    dns_print_readable(&ptr, raw_buf_size, name.name, name.name_length);
    break;
  case dns_record_type_e::DNS_REC_MX: {
    if (record->rd_length < 3) {
      goto raw;
    }
    parse_name(begin, record->data.raw + 2, end, name.name, &name.name_length,
               nullptr);
    int no =
        sprintf(buf, "%" PRIu16 " ", ntohs(*((uint16_t *)record->data.raw)));
    ptr += no;
    dns_print_readable(&ptr, raw_buf_size, name.name, name.name_length);
  } break;
  case dns_record_type_e::DNS_REC_TXT: {
    auto record_end = record->data.raw + record->rd_length;
    auto data_ptr = record->data.raw;
    while (data_ptr < record_end) {
      auto length = *(data_ptr++);
      if (data_ptr + length <= record_end) {
        *(ptr++) = '"';
        dns_print_readable(&ptr, raw_buf_size, data_ptr, length);
        data_ptr += length;
        *(ptr++) = '"';
        *(ptr++) = ' ';
      } else {
        break;
      }
    }
    *ptr = 0;
    break;
  }
  case dns_record_type_e::DNS_REC_SOA: {
    std::uint8_t *next;
    // We have 5 32-bit values plus two names.
    if (record->rd_length < 22) {
      goto raw;
    }

    parse_name(begin, record->data.raw, end, name.name, &name.name_length,
               &next);
    dns_print_readable(&ptr, raw_buf_size, name.name, name.name_length);
    *(ptr++) = ' ';

    if (next + 20 >= record->data.raw + record->rd_length) {
      goto raw;
    }
    parse_name(begin, next, end, name.name, &name.name_length, &next);
    dns_print_readable(&ptr, raw_buf_size, name.name, name.name_length);
    *(ptr++) = ' ';
    if (next + 20 > record->data.raw + record->rd_length) {
      goto raw;
    }

    sprintf(ptr, "%" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32,
            ntohl(*((uint32_t *)next)), ntohl(*(((uint32_t *)next) + 1)),
            ntohl(*(((uint32_t *)next) + 2)), ntohl(*(((uint32_t *)next) + 3)),
            ntohl(*(((uint32_t *)next) + 4)));
    break;
  }
  case dns_record_type_e::DNS_REC_A: {
    if (record->rd_length != 4) {
      goto raw;
    }
    inet_ntop(AF_INET, record->data.raw, buf, raw_buf_size);
  } break;
  case dns_record_type_e::DNS_REC_AAAA: {
    if (record->rd_length != 16) {
      goto raw;
    }
    inet_ntop(AF_INET6, record->data.raw, buf, raw_buf_size);
  } break;
  case dns_record_type_e::DNS_REC_CAA: {
    if (record->rd_length < 2 || record->data.raw[1] < 1 ||
        record->data.raw[1] > 15 ||
        record->data.raw[1] + 2 > record->rd_length) {
      goto raw;
    }
    int written =
        sprintf(ptr, "%" PRIu8 " ", (std::uint8_t)(record->data.raw[0] >> 7));
    if (written < 0) {
      return raw_buf;
    }
    ptr += written;
    dns_print_readable(&ptr, raw_buf_size, record->data.raw + 2,
                       record->data.raw[1]);
    *(ptr++) = ' ';
    *(ptr++) = '"';
    dns_print_readable(&ptr, raw_buf_size,
                       record->data.raw + 2 + record->data.raw[1],
                       (size_t)(record->rd_length - record->data.raw[1] - 2));
    *(ptr++) = '"';
    *ptr = 0;
  } break;
  raw:
  default:
    dns_print_readable(&ptr, raw_buf_size, record->data.raw, record->rd_length);
    *ptr = 0;
  }
  return raw_buf;
}

dns_section dns_get_section(std::uint16_t index, dns_alternate_head_t *head) {
  if (index < head->header.ans_count) {
    return dns_section::DNS_SECTION_ANSWER;
  } else if (index < head->header.ans_count + head->header.auth_count) {
    return dns_section::DNS_SECTION_AUTHORITY;
  } else {
    return dns_section::DNS_SECTION_ADDITIONAL;
  }
}

void dns_extract_query_result(dns_packet_t &packet, std::uint8_t *begin,
                              std::size_t len, std::uint8_t *next) {
  uint16_t i = 0;

  for (int i = 0; i < packet.head.header.ans_count; ++i) {
    dns_alternate_record_t rec{};
    if (dns_parse_record_raw(begin, next, begin + len, &next, &rec)) {
      auto section = dns_get_section(i++, &packet.head);
      if (section == dns_section::DNS_SECTION_ANSWER) {
        dns_record_t record{};
        record.name = dns_name2str(rec.name);
        record.type = rec.type;
        record.dns_class_ = rec.dns_class_;
        record.rd_length = rec.rd_length;
        record.ttl = rec.ttl;
        record.rdata = dns_raw_record_data2str(&rec, begin, begin + len);
        packet.body.answers.push_back(std::move(record));
      }
    }
  }
}

} // namespace dooked
