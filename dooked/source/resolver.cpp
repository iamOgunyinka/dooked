#include "resolver.hpp"
#include "ucstring.hpp"

namespace dooked {

std::array<dns_record_type_e, 26> const
    dns_supported_record_type_t::supported_types{
        dns_record_type_e::DNS_REC_A,        dns_record_type_e::DNS_REC_NS,
        dns_record_type_e::DNS_REC_CNAME,    dns_record_type_e::DNS_REC_SOA,
        dns_record_type_e::DNS_REC_PTR,      dns_record_type_e::DNS_REC_MX,
        dns_record_type_e::DNS_REC_TXT,      dns_record_type_e::DNS_REC_AFSDB,
        dns_record_type_e::DNS_REC_AAAA,     dns_record_type_e::DNS_REC_LOC,
        dns_record_type_e::DNS_REC_SRV,      dns_record_type_e::DNS_REC_NAPTR,
        dns_record_type_e::DNS_REC_DNAME,    dns_record_type_e::DNS_REC_APL,
        dns_record_type_e::DNS_REC_IPSECKEY, dns_record_type_e::DNS_REC_CERT,
        dns_record_type_e::DNS_REC_KEY,      dns_record_type_e::DNS_REC_DNAME,
        dns_record_type_e::DNS_REC_SIG,      dns_record_type_e::DNS_REC_DNSKEY,
        dns_record_type_e::DNS_REC_TKEY,     dns_record_type_e::DNS_REC_TLSA,
        dns_record_type_e::DNS_REC_CAA,      dns_record_type_e::DNS_REC_URI,
        dns_record_type_e::DNS_REC_CDNSKEY,  dns_record_type_e::DNS_REC_CDS};

void set_dns_header_value(ucstring_t::pointer q, std::uint16_t id) {
  set_qid(q, id);
  set_opcode(q, 0);    // set opcode to 'Query' type
  set_opcode_rd(q, 1); // set the RD flag to 1.
  set_qd_count(q, 1);
}

void create_query(std::string const &name, std::uint16_t record_type,
                  std::uint16_t request_id, ucstring_t &buffer) {

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
    resolver_address_list_t &resolvers,
    map_container_t<dns_record_t> &result_map)
    : io_{io_context}, names_{domain_list}, resolvers_{resolvers},
      result_map_{result_map},
      supported_dns_record_size_{
          dns_supported_record_type_t::supported_types.size()} {}

void custom_resolver_socket_t::start() { send_next_request(); }

void custom_resolver_socket_t::send_next_request() {
  try {
    if (name_.empty()) {
      name_ = names_.next_item();
    }
    current_rec_type_ = next_record_type();
    if (current_rec_type_ == dns_record_type_e::DNS_REC_UNDEFINED) {
      name_ = names_.next_item();
      current_rec_type_ = next_record_type();
    }

    query_id_ = get_random_integer();
    auto const query_type = static_cast<std::uint16_t>(current_rec_type_);
    send_buffer_.clear();
    create_query(name_, query_type, query_id_, send_buffer_);
    send_network_request();
  } catch (empty_container_exception_t const &) {
  } catch (bad_name_exception_t const &except) {
    spdlog::error(except.what());
  }
}

void custom_resolver_socket_t::send_network_request() {
  if (!udp_stream_) {
    return establish_udp_connection();
  }
  udp_stream_->async_send_to(
      net::buffer(send_buffer_.data(), send_buffer_.size()),
      current_resolver_.ep, 0,
      [this](auto const, auto const s) { on_data_sent(); });
}

void custom_resolver_socket_t::on_data_sent() { return receive_network_data(); }

void custom_resolver_socket_t::receive_network_data() {
  recv_buffer_.clear();
  static constexpr auto const receive_buf_size = 512;
  recv_buffer_.resize(receive_buf_size);
  if (!default_ep_) {
    default_ep_.emplace();
  }

  udp_stream_->async_receive_from(
      net::buffer(&recv_buffer_[0], receive_buf_size), *default_ep_,
      [this](net::error_code const err_code, std::size_t const bytes_received) {
#ifdef _DEBUG
  // spdlog::info("Data received. Bytes received: {}", bytes_received);
#endif // _DEBUG
        if (bytes_received == 0 || err_code == net::error::operation_aborted) {
          udp_stream_.reset();
          return send_network_request();
        } else if (!err_code && bytes_received != 0) {
          on_data_received(err_code, bytes_received);
        }
      });

  timer_.emplace(io_, std::chrono::seconds(5));
  timer_->async_wait([=](auto const error_code) {
    // if the response took more than 5seconds, cancel and resend
    if (!error_code) {
      return udp_stream_->cancel();
    }
  });
}

void custom_resolver_socket_t::on_data_received(net::error_code const ec,
                                                std::size_t const bytes_read) {
  if (bytes_read < sizeof_packet_header) {
    return send_next_request();
  }
  recv_buffer_.resize(bytes_read);
  dns_packet_t packet{};
  try {
    parse_dns_response(packet, recv_buffer_, query_id_);
    serialize_packet(packet);
  } catch (std::exception const &e) {
    spdlog::error(e.what());
  }
  send_next_request();
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
    return supported_types[++last_processed_dns_index_];
  }
  // special case: done with current name, retrieve next one.
  if (last_processed_dns_index_ >= (supported_dns_record_size_ - 1)) {
    last_processed_dns_index_ = -1;
    return dns_record_type_e::DNS_REC_UNDEFINED;
  }
  return supported_types[++last_processed_dns_index_];
}

void custom_resolver_socket_t::serialize_packet(dns_packet_t const &packet) {
  if (packet.body.answers.empty()) {
#ifdef _DEBUG
    if (auto &questions = packet.head.questions; !questions.empty()) {
      auto const type = dns_record_type2str(packet.head.questions[0].type);
      spdlog::info("No answer for: {}", type);
    }
#endif
    return;
  }
  auto &answers = packet.body.answers;
  for (auto const &answer : answers) {
    result_map_.append(name_, answer);
  }
}

std::uint16_t uint16_value(unsigned char const *buff) {
  return buff[0] * 256 + buff[1];
}

void parse_dns_response(dns_packet_t &packet, ucstring_t &buff,
                        int const query_id) {
  int const buffer_len = buff.size();
  if (buffer_len < 12) {
    throw invalid_dns_response_t("Corrupted DNS packet: too small for header");
  }

  auto &header = packet.head.header;
  auto const *data = buff.cdata();

  header.id = uint16_value(data);
  header.qr = data[2] & 128;
  header.opcode = (data[2] & 120) >> 3;
  header.aa = data[2] & 4;
  header.tc = data[2] & 2;
  header.rd = data[2] & 1;
  header.ra = data[3] & 128;
  header.z = (data[3] & 112) >> 3;
  header.rcode = data[3] & 15;
  header.q_count = uint16_value(data + 4);
  header.ans_count = uint16_value(data + 6);
  header.auth_count = uint16_value(data + 8);

  if (query_id != header.id) {
    return spdlog::error(
        "The response sent by the server isn't what we asked for: {} => {}",
        header.id, query_id);
  }
  auto const rcode = static_cast<dns_rcode_e>(header.rcode);
  if (rcode != dns_rcode_e::DNS_RCODE_NO_ERROR) {
    return spdlog::error("Server response code: {}", rcode_to_string(rcode));
  }
  /* read question section */
  auto &questions = packet.head.questions;
  int pos = 12;
  for (int t = 0; t < header.q_count; t++) {
    if (pos >= buffer_len) {
      throw invalid_dns_response_t("Message too small for question item!");
    }
    int const x = dom_comprlen(buff, pos);
    if (pos + x + 4 > buffer_len) {
      throw invalid_dns_response_t("Message too small for question item!");
    }
    auto const dns_type =
        static_cast<dns_record_type_e>(uint16_value(data + pos + x));
    auto const dns_class = uint16_value(data + pos + x + 2);

    questions.push_back({ucstring_view_t(buff, pos), dns_type, dns_class});
    pos += x + 4;
  }

  /* read other sections */
  packet.body.answers.reserve(header.ans_count);
  auto rdata = buff.data();
  dns_extract_query_result(packet, rdata, buffer_len, rdata + pos);
}

std::string rcode_to_string(dns_rcode_e const rcode) {
  switch (rcode) {
  case dns_rcode_e::DNS_RCODE_BADALG:
    return "Algorithm not supported";
  case dns_rcode_e::DNS_RCODE_BADCOOKIE:
    return "Bad/missing Server Cookie";
  case dns_rcode_e::DNS_RCODE_BADKEY:
    return "Key not recognized";
  case dns_rcode_e::DNS_RCODE_BADMODE:
    return "Bad TKEY Mode";
  case dns_rcode_e::DNS_RCODE_BADNAME:
    return "Duplicate key name";
  case dns_rcode_e::DNS_RCODE_BADTIME:
    return "Signature out of time window";
  case dns_rcode_e::DNS_RCODE_BADTRUNC:
    return "Bad Truncation";
  case dns_rcode_e::DNS_RCODE_BADVERS:
    return "Bad OPT Version";
  case dns_rcode_e::DNS_RCODE_FORMAT_ERR:
    return "format error";
  case dns_rcode_e::DNS_RCODE_NOTAUTH:
    return "Server Not Authoritative for zone";
  case dns_rcode_e::DNS_RCODE_NOTZONE:
    return "Name not contained in zone";
  case dns_rcode_e::DNS_RCODE_NOT_IMPLEMENTED:
    return "not implemented";
  case dns_rcode_e::DNS_RCODE_NO_ERROR:
    return "OK";
  case dns_rcode_e::DNS_RCODE_NXDOMAIN:
    return "non-existing domain";
  case dns_rcode_e::DNS_RCODE_NXRRSET:
    return "non-existing resource record";
  case dns_rcode_e::DNS_RCODE_REFUSED:
    return "request refused";
  case dns_rcode_e::DNS_RCODE_SERVER_FAILED:
    return "internal server error";
  case dns_rcode_e::DNS_RCODE_YXDOMAIN:
    return "Name Exists when it should not";
  case dns_rcode_e::DNS_RCODE_YXRRSET:
    return "RR Set Exists when it should not";
  }
  throw general_exception_t{"unknown error"};
}
} // namespace dooked
