#include "resolver.hpp"

namespace dooked {

std::array<rr_type_t, 13> const dns_supported_record_type_t::supported_types{
    rr_type_t{"A", 1, "i", rr_flags_e::R_NONE, dns_record_type_e::DNS_REC_A},
    rr_type_t{"NS", 2, "d", rr_flags_e::R_ASPCOMPRESS,
              dns_record_type_e::DNS_REC_NS},
    rr_type_t{"CNAME", 5, "d", rr_flags_e::R_COMPRESS,
              dns_record_type_e::DNS_REC_CNAME},
    rr_type_t{"SOA", 6, "dmltttt", rr_flags_e::R_COMPRESS,
              dns_record_type_e::DNS_REC_SOA},
    rr_type_t{"PTR", 12, "d", rr_flags_e::R_COMPRESS,
              dns_record_type_e::DNS_REC_PTR},
    rr_type_t{"MX", 15, "sd", rr_flags_e::R_ASPCOMPRESS,
              dns_record_type_e::DNS_REC_MX},
    rr_type_t{"TXT", 16, "h", rr_flags_e::R_NONE,
              dns_record_type_e::DNS_REC_TXT},
    rr_type_t{"AFSDB", 18, "sd", rr_flags_e::R_ASP,
              dns_record_type_e::DNS_REC_AFSDB},
    rr_type_t{"AAAA", 28, "6", rr_flags_e::R_NONE,
              dns_record_type_e::DNS_REC_AAAA},
    rr_type_t{"LOC", 29, "o", rr_flags_e::R_NONE,
              dns_record_type_e::DNS_REC_LOC},
    rr_type_t{"SRV", 33, "sssd", rr_flags_e::R_ASP,
              dns_record_type_e::DNS_REC_SRV},
    rr_type_t{"NAPTR", 35, "sscccd", rr_flags_e::R_NONE,
              dns_record_type_e::DNS_REC_NAPTR},
    rr_type_t{"DNAME", 39, "d", rr_flags_e::R_ASP,
              dns_record_type_e::DNS_REC_DNAME}};

void set_dns_header_value(ucstring::value_type *q, std::uint16_t id) {
  set_qid(q, id);
  set_opcode(q, 0);    // set opcode to 'Query' type
  set_opcode_rd(q, 1); // set the RD flag to 1.
  set_qd_count(q, 1);
}

void create_query(std::string const &name, std::uint16_t record_type,
                  std::uint16_t request_id, ucstring &buffer) {

  constexpr static auto const max_cd_name = 255;
  constexpr static auto const max_header_size = 12;
  constexpr static auto const max_question_size = 4;
  constexpr static auto const max_label = 63;
  constexpr static auto const max_size =
      max_cd_name + max_header_size + max_question_size;

  // (query_id=2bytes, header=12bytes, question "body" = 4) == 18
  size_t len = name.size() + 18;
  buffer.resize(len);

  /* Set up the header. */
  set_dns_header_value(&buffer[0], request_id);

  auto domain_name = name.c_str();
  /* A name of "." is a screw case for the loop below, so adjust it. */
  if (strcmp(domain_name, ".") == 0) {
    domain_name++;
  }

  unsigned char *question = &buffer[0] + max_header_size;
  /* Start writing out the name after the header. */
  const char *p = nullptr;

  while (*domain_name) {
    if (*domain_name == '.') {
      throw bad_name_exception_t{domain_name};
    }

    /* Count the number of bytes in this label. */
    len = 0;
    for (p = domain_name; *p && *p != '.'; p++) {
      if (*p == '\\' && *(p + 1) != 0) {
        p++;
      }
      len++;
    }
    if (len > max_label) {
      throw bad_name_exception_t{domain_name};
    }

    /* Encode the length and copy the data. */
    *question++ = (unsigned char)len;
    for (p = domain_name; *p && *p != '.'; p++) {
      if (*p == '\\' && *(p + 1) != 0) {
        p++;
      }
      *question++ = *p;
    }

    /* Go to the next label and repeat, unless we hit the end. */
    if (!*p) {
      break;
    }
    domain_name = p + 1;
  }

  /* Add the zero-length label at the end. */
  *question++ = 0;

  /* Finish off the question with the type and class. */
  set_question_type(question, record_type);
  set_question_class(question, 1); // class IN

  question += max_question_size;
  std::size_t const buflen = (question - (&buffer[0]));

  /* Reject names that are longer than the maximum of 255 bytes that's
   * specified in RFC 1035 ("To simplify implementations, the total length of
   * a domain name (i.e., label octets and label length octets) is restricted
   * to 255 octets or less."). */
  if (buflen > max_size) {
    throw bad_name_exception_t{domain_name};
  }

  /* we know this fits in an int at this point */
  buffer.resize(buflen);
}

custom_resolver_socket_t::custom_resolver_socket_t(
    net::io_context &io_context, domain_list_t &domain_list,
    resolver_address_list_t &resolvers)
    : io_{io_context}, timer_{io_}, names_{domain_list}, resolvers_{resolvers},
      supported_dns_record_size_{
          dns_supported_record_type_t::supported_types.size()} {}

void custom_resolver_socket_t::start() { send_next_request(); }

void custom_resolver_socket_t::send_next_request() {
  try {
    current_rec_type_ = next_record_type();
    if (current_rec_type_ == dns_record_type_e::DNS_REC_UNDEFINED) {
      name_ = names_.next_item();
      current_rec_type_ = next_record_type();
    }
    query_id_ = get_random_integer();
    auto const query_type = static_cast<std::uint16_t>(current_rec_type_);
    generic_buffer_.clear();
    create_query(name_.domain_name, query_type, query_id_, generic_buffer_);
    send_network_request();
  } catch (empty_container_exception_t const &) {
  } catch (bad_name_exception_t const &) {
  }
}

void custom_resolver_socket_t::send_network_request() {
  if (!udp_stream_) {
    return establish_udp_connection();
  }

  udp_stream_->async_send_to(
      net::const_buffer(generic_buffer_.data(), generic_buffer_.size()),
      current_resolver_.ep,
      [this](auto const &error_code, auto const) { on_data_sent(error_code); });
}

void custom_resolver_socket_t::on_data_sent(
    boost::system::error_code const ec) {
  if (!ec) {
    establish_udp_connection(); // get a new resolver and retry
  }
  receive_network_data();
}

void custom_resolver_socket_t::receive_network_data() {
  generic_buffer_.clear();
  static constexpr auto const receive_buf_size = 512;
  generic_buffer_.resize(receive_buf_size);
  ops_waiting_ = max_ops_waiting_;
  read_ec_ = {};
  bytes_read_ = 0;

  udp_stream_->async_receive_from(
      net::mutable_buffer(generic_buffer_.data(), receive_buf_size),
      current_resolver_.ep,
      [=](auto const err_code, std::size_t const bytes_received) {
        bytes_read_ = bytes_received;
        if (--ops_waiting_ == max_ops_waiting_ - 1) {
          timer_.cancel();
          read_ec_ = err_code;
        } else if (ops_waiting_ == 0) {
          return on_data_received();
        }
      });
  timer_.expires_after(std::chrono::seconds(30));
  timer_.async_wait([=](boost::system::error_code const error_code) {
    if (--ops_waiting_ == max_ops_waiting_ - 1) {
      udp_stream_->cancel();
      if (error_code) {
        read_ec_ = net::error::timed_out;
      } else {
        read_ec_ = error_code;
      }
    } else if (ops_waiting_ == 0) {
      on_data_received();
    }
  });
}

void custom_resolver_socket_t::on_data_received() {
  if (bytes_read_ == 0 || read_ec_ == net::error::timed_out) {
    udp_stream_.reset();
    return send_network_request();
  }
  if (bytes_read_ < sizeof_packet_header) {
    return send_next_request();
  }
  generic_buffer_.resize(bytes_read_);
  bytes_read_ = 0;
  dns_packet_t packet{};
  // parse_dns_response(packet);
  alternate_parse_dns(packet, generic_buffer_);
  serialize_packet(packet);
}

void custom_resolver_socket_t::establish_udp_connection() {
  current_resolver_ = resolvers_.next_item();
  udp_stream_.emplace(io_);
  udp_stream_->open(net::ip::udp::v4());
  udp_stream_->set_option(net::ip::udp::socket::reuse_address(true));
  return send_network_request();
}

dns_record_type_e custom_resolver_socket_t::next_record_type() {
  auto &supported_types = dns_supported_record_type_t::supported_types;
  if (supported_dns_record_size_ == -1) {
    return supported_types[++last_processed_dns_index_].rr_type_name;
  }
  // special case: done with current name, retrieve next one.
  if (last_processed_dns_index_ >= supported_dns_record_size_) {
    last_processed_dns_index_ = -1;
    return dns_record_type_e::DNS_REC_UNDEFINED;
  }
  return supported_types[++last_processed_dns_index_].rr_type_name;
}

void custom_resolver_socket_t::parse_dns_response(dns_packet_t &packet) {
  parse_dns_header(packet);
  parse_dns_question(packet);
  auto &header = packet.head.header;

  if (header.id != query_id_ || header.rcode != 0 || header.rd != 1 ||
      !header.ans_count) {
    return send_next_request();
  }
}

void custom_resolver_socket_t::parse_dns_body(
    dns_packet_t &packet, ucstring::const_pointer body_begin) {
  packet.body = parse_dns_body_impl(body_begin);
}

dns_body_t custom_resolver_socket_t::parse_dns_body_impl(
    ucstring::const_pointer body_begin) {
  return dns_body_t{};
}

void custom_resolver_socket_t::parse_dns_header(dns_packet_t &packet) {
  static constexpr std::size_t const dns_packet_min_size = 17;
  bool name_parsed{};
  uint8_t *qname_end{};
  auto &response_buffer = generic_buffer_;

  if (response_buffer.size() < dns_packet_min_size) {
    throw invalid_dns_response_t();
  }

  auto const buf = response_buffer.c_str();
  auto &head = packet.head;
  head.header.id = ntohs((*(uint16_t *)buf));
  head.header.qr = (bool)(buf[2] & 0x80);
  head.header.opcode = (uint8_t)((buf[2] & (0x78)) >> 3);
  head.header.aa = (bool)(buf[2] & 0x04);
  head.header.tc = (bool)(buf[2] & 0x02);
  head.header.rd = (bool)(buf[2] & 0x01);
  head.header.ra = (bool)(buf[3] & 0x80);
  head.header.z = (bool)(buf[4] & 0x40);
  head.header.ad = (bool)(buf[3] & 0x20);
  head.header.cd = (bool)(buf[3] & 0x10);
  head.header.rcode = (uint8_t)(buf[3] & 0x0F);
  head.header.ans_count = ntohs((*(uint16_t *)(buf + 6)));
  head.header.auth_count = ntohs((*(uint16_t *)(buf + 8)));
  head.header.add_count = ntohs((*(uint16_t *)(buf + 10)));
  head.header.q_count = ntohs((*(uint16_t *)(buf + 4)));

  if (head.header.q_count != 1) {
    throw invalid_dns_response_t{"question count more than one"};
  }
}

ucstring::const_pointer
custom_resolver_socket_t::parse_dns_question(dns_packet_t &packet) {
  auto &question = packet.head.question;
  auto &response_buffer = generic_buffer_;
  auto body_begin = parse_dns_qname(packet, 12);
  auto const response_buffer_end =
      response_buffer.data() + response_buffer.size();
  if (body_begin == response_buffer_end ||
      body_begin + 2 > response_buffer_end) {
    throw invalid_dns_response_t{"abrupt end of response"};
  }

  auto &head = packet.head;
  head.question.type = (dns_record_type_e)ntohs((*(uint16_t *)body_begin));
  head.question.dns_class_ = ntohs((*(uint16_t *)(body_begin + 2)));
  if (body_begin) {
    body_begin = body_begin + 4;
  }
  return body_begin;
}

ucstring::const_pointer custom_resolver_socket_t::parse_dns_qname(
    dns_packet_t &packet, ucstring::size_type const question_start_index) {
  auto &qname = packet.head.question.dns_name;
  qname.resize(0xFF);
  uint8_t const *pointer{nullptr};
  auto &response_buffer = generic_buffer_;
  ucstring::pointer name = qname.data();
  ucstring::const_pointer *next = nullptr;
  ucstring::const_pointer begin = response_buffer.data();
  ucstring::const_pointer buf = response_buffer.data() + question_start_index;
  ucstring::const_pointer end = response_buffer.data() + response_buffer.size();

  ucstring::value_type first{};
  int label_len{};
  int name_len{};

  while (true) {
    if (buf >= end) {
      return end;
    }
    first = *buf;
    int const label_type = (first & 0xC0);
    if (label_type == 0xC0) // Compressed
    {
      if (next && !pointer) {
        *next = buf + 2;
      }
      pointer = begin + (htons(*((uint16_t *)buf)) & 0x3FFF);
      if (pointer >= buf) {
        return end;
      }
      buf = pointer;
    } else if (label_type == 0x00) // Uncompressed
    {
      label_len = (first & 0x3F);
      name_len += label_len + 1;
      if (name_len >= 0xFF) {
        return end;
      }
      if (label_len == 0) {
        if (name_len == 1) {
          *(name++) = '.';
        }
        *name = 0;
        if (next && !pointer) {
          *next = buf + label_len + 1;
        }
        if (name_len <= 1) {
          qname.resize(name_len);
        } else {
          qname.resize(name_len - 1);
        }
        return *next;
      } else {
        if (buf + label_len + 1 > end) {
          return end;
        }
        memcpy(name, buf + 1, (std::size_t)label_len);
        *(name + label_len) = '.';
        name += label_len + 1;
        buf += label_len + 1;
      }
    } else {
      return end;
    }
  }
  return end;
}

std::uint16_t uint16_value(unsigned char const *buff) {
  return buff[0] * 256 + buff[1];
}

std::uint32_t uint32_value(unsigned char const *buff) {
  return uint16_value(buff) * 65'536 + uint16_value(buff + 2);
}

void alternate_parse_dns(dns_packet_t &packet, ucstring &buff) {
  int const buffer_len = buff.size();
  if (buffer_len < 12) {
    throw invalid_dns_response_t("Corrupted DNS packet: too small for header");
  }

  auto &header = packet.head.header;
  auto const *data = buff.data();

  header.id = uint16_value(data);
  header.qr = data[2] & 128;
  header.opcode = (data[2] & 120) >> 3;
  header.aa = data[2] & 4;
  header.tc = data[2] & 2;
  header.rd = data[2] & 1;
  header.ra = data[3] & 128;
  header.z = (data[3] & 112) >> 3;
  header.rcode = data[3] & 15;

  int const qdc = uint16_value(data + 4);
  int const adc = uint16_value(data + 6);
  int const nsc = uint16_value(data + 8);
  int const arc = uint16_value(data + 10);
  int pos = 12;
  /* read question section */
  std::vector<dns_alternate_question_t> questions{};
  std::vector<dns_alternate_record_t> answers{};

  for (int t = 0; t < qdc; t++) {
    if (pos >= buffer_len) {
      throw invalid_dns_response_t("Message too small for question item!");
    }
    int const x = dom_comprlen(buff, pos);
    if (pos + x + 4 > buffer_len) {
      throw invalid_dns_response_t("Message too small for question item !");
    }
    auto const dns_type =
        static_cast<dns_record_type_e>(uint16_value(data + pos + x));
    auto const dns_class = uint16_value(data + pos + x + 2);
    questions.push_back({domainname(buff, pos), dns_type, dns_class});

    pos += x;
    pos += 4;
  }

  /* read other sections */
  read_section(answers, adc, buff, pos);
  packet.body.answers = std::move(answers);
}

void read_section(std::vector<dns_alternate_record_t> &answers, int count,
                  ucstring &buf, int &buf_start_position) {
  while (--count >= 0) {
    answers.push_back(read_raw_record(buf, buf_start_position));
  }
}

dns_alternate_record_t read_raw_record(ucstring &buffer, int &pos) {
  domainname dom{};

  dns_alternate_record_t rr{};
  int const buffer_size = buffer.size();
  if (pos >= buffer_size) {
    throw general_exception_t("Message too small for RR");
  }
  auto x = dom_comprlen(buffer, pos);
  if (pos + x + 10 > buffer_size) {
    throw general_exception_t("Message too small for RR");
  }
  auto const msg = buffer.data();
  rr.name = domainname(buffer, pos);
  rr.type = static_cast<dns_record_type_e>(uint16_value(msg + pos + x));
  rr.dns_class_ = uint16_value(msg + pos + x + 2);
  rr.ttl = uint32_value(msg + pos + x + 4);

  pos += x + 10;
  x = uint16_value(msg + pos - 2);
  if (x != 0) {
    raw_record_read(rr.type, rr.rdata, rr.rd_length, buffer, pos, x);
  }
  pos += x;

  return rr;
}

std::optional<rr_type_t> get_rrtype_info(dns_record_type_e type) {
  auto &stypes = dns_supported_record_type_t::supported_types;
  auto iter = std::find_if(
      stypes.cbegin(), stypes.cend(),
      [type](rr_type_t const &rtype) { return rtype.rr_type_name == type; });
  if (iter == stypes.cend()) {
    return std::nullopt;
  }
  return *iter;
}

int rr_len(char const prop, ucstring &buffer, int ix, int len) {
  auto const msg_rbuffer = buffer.data();

  switch (prop) {
  case 'd': /* a domain name */
  case 'm': /* email address */
    return dom_comprlen(buffer, ix);
  case 'i': /* ipv4 number */
  case 'l': /* 32-bit number */
  case 't':
    return 4;
  case 's': /* 16-bit number */
    return 2;
  case 'c': /* character string */
    return msg_rbuffer[ix] + 1;
  case 'h': // character strings */
  {
    auto ptr = msg_rbuffer + ix;
    while (ptr - msg_rbuffer - ix < len) {
      ptr += *ptr + 1;
    }
    if (ptr != msg_rbuffer + ix + len) {
      throw general_exception_t("Character strings too long for RR");
    }
    return len;
  }
  case 'n': /* NULL rdata */
    return len;
  case 'w': /* well-known services */
    if (len < 5) {
      throw general_exception_t("WKS RR too long for RR");
    }
    return len;
  case '6': /* ipv6 address */
    return 16;
  case '7': // ipv6 address + prefix
  {
    int x = ((135 - msg_rbuffer[ix]) / 8); /* prefix length in bytes */
    if (ix + x + 1 >= len) {
      throw general_exception_t("A6 too long for RR");
    }
    if (msg_rbuffer[ix] != 0)
      /* domain name nessecary */
      x += dom_comprlen(buffer, ix + x + 1);
    return x + 1;
  }
  case 'o': /* DNS LOC */
    if (msg_rbuffer[ix] != 0) {
      throw general_exception_t("Unsupported LOC version");
    }
    return 16;
  }
  throw general_exception_t("Unknown RR item type " + std::string(1, prop));
}

void raw_record_read(dns_record_type_e const rtype, ucstring_ptr &rdata,
                     std::uint16_t &rd_length, ucstring &buffer, int ix,
                     int len) {
  auto const info = get_rrtype_info(rtype);
  char const *ptr = nullptr;
  std::string res;
  int x{};
  ucstring_ptr dom{};
  auto const message_rbuffer = buffer.data();

  if (ix + len > buffer.size()) {
    throw general_exception_t("RR doesn't fit in DNS message");
  }
  if (info) {
    /* we support the RR type */
    try {
      ptr = info->properties;
      while (*ptr) {
        x = rr_len(*ptr, buffer, ix, len);
        if (x > len) {
          throw general_exception_t("RR item too long!");
        }
        if (*ptr == 'd' || *ptr == 'm') {
          /* domain name: needs to be decompressed */
          dom = dom_uncompress(buffer, ix);
          res.append((char *)dom, domlen(dom));
          free(dom);
        } else {
          res.append((char *)message_rbuffer + ix, x);
        }

        ix += x;
        len -= x;

        ptr++;
      }
      if (len != 0) {
        throw general_exception_t("extra data in RR");
      }
    } catch (general_exception_t const &p) {
      throw general_exception_t(std::string("Parsing RR failed: ") + p.what());
    }
    if (len != 0) {
      throw general_exception_t("RR length too long");
    }
  } else {
    /* we do not support the RR type: just copy it altogether */
    res.append((char *)message_rbuffer + ix, len);
  }
  rd_length = res.length();
  rdata = (unsigned char *)memdup((void *)res.c_str(), res.length());
}

void serialize_packet(dns_packet_t const &packet) {}
} // namespace dooked
