#pragma once

#include "dns.hpp"
#include "requests.hpp"
#include "utils.hpp"

namespace dooked {
class http_resolver_t {
  net::io_context &io_context_;
  ssl::context &ssl_context_;
  domain_list_t &names_;
  map_container_t<dns_record_t> &result_map_;
  std::optional<request_t> http_request_handler_;
  std::string name_{};
  int http_redirects_count_ = 0;
  int http_retries_count_ = 0;

private:
  void perform_http_request();
  void send_next_request();
  void tcp_request_result(response_type_e, int, std::string const &);

public:
  http_resolver_t(net::io_context &, ssl::context &, domain_list_t &,
                  map_container_t<dns_record_t> &);
  void start() { send_next_request(); }
};
} // namespace dooked
