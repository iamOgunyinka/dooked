#include "dns_resolver.hpp"
#include "ucstring.hpp"

namespace dooked {

std::array<dns_record_type_e, 8> const
    dns_supported_record_type_t::supported_types{
        dns_record_type_e::DNS_REC_A,     dns_record_type_e::DNS_REC_AAAA,
        dns_record_type_e::DNS_REC_CNAME, dns_record_type_e::DNS_REC_MX,
        dns_record_type_e::DNS_REC_TXT,   dns_record_type_e::DNS_REC_NS,
        dns_record_type_e::DNS_REC_PTR,   dns_record_type_e::DNS_REC_DNAME};

void set_dns_header_value(ucstring_t::pointer q, std::uint16_t id) {
  set_qid(q, id);
  set_opcode(q, 0);    // set opcode to 'Query' type
  set_opcode_rd(q, 1); // set the RD flag to 1.
  set_qd_count(q, 1);
}

void dns_create_query(std::string const &name, std::uint16_t record_type,
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
    net::io_context &io_context, net::ssl::context *ssl_context,
    domain_list_t &domain_list, resolver_address_list_t &resolvers,
    map_container_t<dns_record_t> &result_map)
    : io_{io_context}, names_{domain_list}, resolvers_{resolvers},
      result_map_{result_map}, ssl_context_{ssl_context},
      supported_dns_record_size_(
          dns_supported_record_type_t::supported_types.size()) {}

void custom_resolver_socket_t::defer_http_request(bool const defer) {
  deferring_http_request_ = defer;
}

void custom_resolver_socket_t::start() { dns_send_next_request(); }

void custom_resolver_socket_t::dns_send_next_request() {
  try {
    if (name_.empty()) {
      name_ = names_.next_item();
    }
    current_rec_type_ = dns_next_record_type();
    if (current_rec_type_ == dns_record_type_e::DNS_REC_UNDEFINED) {
      if (!deferring_http_request_) {
        return perform_http_request();
      }
      names_.next_item();
      current_rec_type_ = dns_next_record_type();
    }

    auto const query_id = get_random_integer();
    auto const query_type = static_cast<std::uint16_t>(current_rec_type_);
    send_buffer_.clear();
    dns_create_query(name_, query_type, query_id, send_buffer_);
    dns_send_network_request();
  } catch (empty_container_exception_t const &) {
  } catch (bad_name_exception_t const &except) {
    spdlog::error(except.what());
  }
}

void custom_resolver_socket_t::dns_continue_probe() {
  name_.clear();
  http_redirects_count_ = http_retries_count_ = 0;
  if (!is_default_tls_) {
    // switch back to tls v1.2
    ssl_context_ = tls_v13_holder_->original_ssl_context_;
  }
  dns_send_next_request();
}

void custom_resolver_socket_t::dns_send_network_request() {
  if (!udp_stream_) {
    return dns_establish_udp_connection();
  }
  udp_stream_->async_send_to(
      net::buffer(send_buffer_.data(), send_buffer_.size()),
      current_resolver_.ep, 0,
      [this](auto const, auto const s) { dns_on_data_sent(); });
}

void custom_resolver_socket_t::dns_on_data_sent() {
  return dns_receive_network_data();
}

void custom_resolver_socket_t::dns_receive_network_data() {
  recv_buffer_.clear();
  static constexpr auto const receive_buf_size = 512;
  recv_buffer_.resize(receive_buf_size);
  if (!default_ep_) {
    default_ep_.emplace();
  }

  udp_stream_->async_receive_from(
      net::buffer(&recv_buffer_[0], receive_buf_size), current_resolver_.ep,
      [this](auto const err_code, std::size_t const bytes_received) {
        if (bytes_received == 0 || err_code == net::error::operation_aborted) {
          // if there was a timeout, we "close" the UDP connection, pick a new
          // resolver and try
          udp_stream_.reset();
          return dns_send_network_request();
        } else if (!err_code && bytes_received != 0) {
          dns_on_data_received(err_code, bytes_received);
        }
      });

  timer_.emplace(io_, std::chrono::seconds(DOOKED_MAX_DNS_WAIT_TIME));
  timer_->async_wait([=](auto const error_code) {
    // if the response took more than 5seconds, cancel and resend
    if (!error_code) {
      return udp_stream_->cancel();
    }
  });
}

void custom_resolver_socket_t::dns_on_data_received(
    error_code const ec, std::size_t const bytes_read) {
  if (bytes_read < sizeof_packet_header) {
    return dns_send_next_request();
  }
  recv_buffer_.resize(bytes_read);
  dns_packet_t packet{};
  try {
    parse_dns_response(packet, recv_buffer_);
    dns_serialize_packet(packet);
  } catch (std::exception const &e) {
    spdlog::error(e.what());
  }
  dns_send_next_request();
}

void custom_resolver_socket_t::dns_establish_udp_connection() {
  current_resolver_ = resolvers_.next_item();
  udp_stream_.emplace(io_);
  udp_stream_->open(net::ip::udp::v4());
  udp_stream_->set_option(net::ip::udp::socket::reuse_address(true));

  return dns_send_network_request();
}

dns_record_type_e custom_resolver_socket_t::dns_next_record_type() {
  auto &supported_types = dns_supported_record_type_t::supported_types;
  if (last_processed_dns_index_ == -1) {
    return supported_types[++last_processed_dns_index_];
  }
  // special case: done with current name, retrieve next one.
  if (last_processed_dns_index_ >= (supported_dns_record_size_ - 1)) {
    last_processed_dns_index_ = -1;
    return dns_record_type_e::DNS_REC_UNDEFINED;
  }
  return supported_types[++last_processed_dns_index_];
}

void custom_resolver_socket_t::dns_serialize_packet(
    dns_packet_t const &packet) {
  if (packet.body.answers.empty() || packet.head.questions.empty()) {
    return;
  }
  auto &temp_name = packet.head.questions[0].dns_name;
  auto const len = (temp_name.name[temp_name.name_length - 1] == '.')
                       ? temp_name.name_length - 1
                       : temp_name.name_length;
  std::string const name((char const *)temp_name.name, len);
  for (auto const &answer : packet.body.answers) {
    result_map_.append(name, answer);
  }
}

void custom_resolver_socket_t::http_switch_tls_requested(
    std::string const &name) {
  if (!tls_v13_holder_ || is_default_tls_) {
    if (!tls_v13_holder_) { // first time switching SSL context, tls_v12
      auto &tls_v13_context = get_tlsv13_context();
      auto &ssl_holder = tls_v13_holder_.emplace(tls_v13_context, ssl_context_);
    }
    ssl_context_ = &(tls_v13_holder_->tls_v13_context_);
    is_default_tls_ = 0;
    return send_https_request(name);
  }
  // switch back to tls v 1.2
  ssl_context_ = tls_v13_holder_->original_ssl_context_;
  is_default_tls_ = 1;
  dns_send_next_request();
}

void custom_resolver_socket_t::send_http_request(std::string const &address) {
  auto &http_request =
      http_request_handler_->request_.emplace<http_request_handler_t>(
          io_, uri{address}.host());
  http_request.start([this](response_type_e const rt, int const content_length,
                            std::string const &response) {
    http_result_obtained(rt, content_length, response);
  });
}

void custom_resolver_socket_t::send_https_request(std::string const &address) {
  auto &https_request =
      http_request_handler_->request_.emplace<https_request_handler_t>(
          io_, *ssl_context_, uri{address}.host());
  return https_request.start(
      [this](auto const rt, auto const len, auto const &rstr) {
        http_result_obtained(rt, len, rstr);
      });
}

void custom_resolver_socket_t::on_http_resolve_error() {
  // by default we do http resolve first, that may fail if the
  // address is strictly HTTPS, so let's resolve to HTTPS
  auto https_socket_type =
      std::get_if<https_request_handler_t>(&(http_request_handler_->request_));
  if (!https_socket_type) {
    return send_https_request(name_);
  }
  // if we are here, we must have tried https too and it fails.
  result_map_.insert(name_, 0,
                     static_cast<int>(response_type_e::cannot_resolve_name));
  return dns_continue_probe();
}

void custom_resolver_socket_t::http_result_obtained(
    response_type_e const rt, int const content_length,
    std::string const &response_string) {

  switch (rt) {
  case response_type_e::bad_request: {
    result_map_.insert(name_, content_length, 400);
    return dns_continue_probe();
  }
  case response_type_e::forbidden: {
    result_map_.insert(name_, content_length, 403);
    return dns_continue_probe();
  }
  case response_type_e::cannot_resolve_name: {
    return on_http_resolve_error();
  }
  case response_type_e::cannot_connect:
  case response_type_e::cannot_send: {
    result_map_.insert(name_, 0, static_cast<int>(rt));
    return dns_continue_probe();
  }
  case response_type_e::http_redirected: {
    ++http_redirects_count_;
    if (http_redirects_count_ >= 10) { // too many redirects
      result_map_.insert(name_, 0, 309);
      return dns_continue_probe();
    }
    return send_http_request(response_string);
  }
  case response_type_e::https_redirected: {
    ++http_redirects_count_;
    if (http_redirects_count_ >= 10) { // too many redirects
      result_map_.insert(name_, 0, 309);
      return dns_continue_probe();
    }
    return send_https_request(response_string);
  }
  case response_type_e::not_found: { // HTTP(S) 404
    result_map_.insert(name_, content_length, 404);
    return dns_continue_probe();
  }
  case response_type_e::ok: {
    result_map_.insert(name_, content_length, 200);
    return dns_continue_probe();
  }
  case response_type_e::recv_timed_out: { // retry, wait timeout
    ++http_retries_count_;
    if (http_retries_count_ > 5) {
      result_map_.insert(name_, 0, static_cast<int>(rt));
      return dns_continue_probe();
    }
    auto http_socket_type =
        std::get_if<http_request_handler_t>(&(http_request_handler_->request_));
    if (http_socket_type) {
      return send_http_request(response_string);
    } else {
      return send_https_request(response_string);
    }
  }
  case response_type_e::ssl_change_context:
  case response_type_e::ssl_handshake_failed: {
    return http_switch_tls_requested(response_string);
  }
  case response_type_e::ssl_change_to_http: {
    return send_http_request(name_);
  }
  case response_type_e::server_error: {
    result_map_.insert(name_, content_length, 503);
    return dns_continue_probe();
  }
  default: {
    result_map_.insert(name_, 0, 0);
    return dns_continue_probe();
  }
  } // end switch
}

void custom_resolver_socket_t::perform_http_request() {
  auto const &result = result_map_.cresult();
  auto const iter = result.find(name_);
  http_request_handler_.emplace();
  send_http_request(name_);
}

// ============ helper functions ===============

std::uint16_t uint16_value(unsigned char const *buff) {
  return buff[0] * 256 + buff[1];
}

void parse_dns_response(dns_packet_t &packet, ucstring_t &buff) {
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

  int const question_count = uint16_value(data + 4);
  int const answer_count = uint16_value(data + 6);
  auto const rcode = static_cast<dns_rcode_e>(header.rcode);

  if (rcode != dns_rcode_e::DNS_RCODE_NO_ERROR) {
    return
#ifdef _DEBUG
        spdlog::error("Response code: {}", rcode_to_string(rcode))
#endif // _DEBUG
            ;
  }

  /* read question section -- which would almost always be 1.*/
  auto &questions = packet.head.questions;
  auto rdata = buff.data() + 12;
  for (int t = 0; t < question_count; t++) {
    static_string_t name{};
    unsigned char *new_end{};
    bool const successful = parse_name(data, rdata, data + buffer_len,
                                       name.name, &name.name_length, &new_end);
    if ((new_end + 2) > (data + buffer_len) || !successful) {
      spdlog::error("There was an error parsing the question");
      return;
    }
    auto const type = static_cast<dns_record_type_e>(uint16_value(new_end));
    auto const class_ = uint16_value(new_end + 2);
    questions.push_back(dns_question_t{name, type, class_});
    rdata = new_end + 4;
  }

  /* read answers sections */
  packet.body.answers.reserve(answer_count);
  dns_extract_query_result(answer_count, packet, buff.data(), buffer_len,
                           rdata);
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
