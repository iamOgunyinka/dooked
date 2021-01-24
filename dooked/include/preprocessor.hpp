#pragma once

#include "resolver.hpp"

namespace dooked {

struct json_data_t {
  std::string domain_name{};
  std::string rdata{};
  int ttl{};
  int http_code{};
  int content_length{};

  dns_record_type_e type;

  static json_data_t serialize(std::string const &d, int const len,
                               int const http_code,
                               json::object_t &json_object) {
    json_data_t data{};
    data.domain_name = d;
    data.type =
        dns_str_to_record_type(json_object["type"].get<json::string_t>());
    data.rdata = json_object["info"].get<json::string_t>();
    data.ttl = json_object["ttl"].get<json::number_integer_t>();
    data.content_length = len;
    data.http_code = http_code;
    return data;
  }
};

struct jd_domain_comparator_t {
  bool operator()(json_data_t const &a, json_data_t const &b) const {
    return a.domain_name < b.domain_name;
  }
};

struct runtime_args_t {
  std::optional<resolver_address_list_t> resolvers;
  opt_domain_list_t names;
  std::optional<std::vector<json_data_t>> previous_data;
  std::unique_ptr<std::ofstream> output_file{};
  std::string output_filename{};
  http_process_e http_request_time_;
};

void to_json(json &j, dns_record_t const &record);
void compare_results(std::vector<json_data_t> const &previous_result,
                     map_container_t<dns_record_t> const &current_result);
void write_json_result(map_container_t<dns_record_t> const &result_map,
                       runtime_args_t const &rt_args);
void start_name_checking(runtime_args_t &&rt_args);
void run_program(cli_args_t const &cli_args);
} // namespace dooked
