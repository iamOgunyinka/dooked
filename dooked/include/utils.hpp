#pragma once

#include <boost/asio/ip/udp.hpp>
#include <exception>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace dooked {
template <typename T> using opt_list_t = std::optional<std::vector<T>>;

enum file_type_e { stdin_type, txt_type, json_type, unknown_type };

struct cli_args_t {
  std::string resolver{}; // defaults to 8.8.8.8
  std::string resolver_filename{};
  std::string output_filename{};
  std::string input_filename{};

  int file_type = file_type_e::stdin_type;
  bool include_date = false;
};

struct resolver_address_t {
  boost::asio::ip::udp::endpoint ep{};
};

template <typename T> class circular_queue_t {
  std::vector<T> const container_;
  mutable std::mutex mutex_;
  mutable typename std::vector<T>::size_type index_ = 0;

public:
  circular_queue_t(std::vector<T> &&container)
      : container_{std::move(container)} {}
  T const &next_item() const {
    std::lock_guard<std::mutex> lock_g{mutex_};
    if (index_ >= container_.size()) {
      index_ = 0;
    }
    return container_[index_++];
  }
};

using resolver_address_list_t = circular_queue_t<resolver_address_t>;

struct empty_container_exception_t : std::exception {
  empty_container_exception_t() : std::exception{} {}
};

struct invalid_dns_response_t : std::exception {
  invalid_dns_response_t() : std::exception{} {}
  invalid_dns_response_t(char const *w) : std::exception{w} {}
};

struct general_exception_t : std::exception {
  general_exception_t(char const *w) : std::exception{w} {}
  general_exception_t(std::string const &w) : std::exception{w.c_str()} {}
};

struct bad_name_exception_t : std::runtime_error {
  bad_name_exception_t(std::string const &domain_name)
      : std::runtime_error{domain_name} {}
  bad_name_exception_t(char const *name) : std::runtime_error{name} {}
};

// only one thread does push_backs, which happens way before reading
// however, multiple threads will read from it later.
template <typename T, typename Container = std::deque<T>> class synced_queue_t {
  std::queue<T, Container> container{};
  std::mutex mutex{};

public:
  synced_queue_t() = default;
  synced_queue_t(synced_queue_t const &) = delete;
  synced_queue_t(synced_queue_t &&queue)
      : container{std::move(queue.container)} {}
  void push_back(T const &item) { container.push(item); }
  void push_back(T &&item) { container.push(std::move(item)); }
  T next_item() {
    std::lock_guard<std::mutex> lockg{mutex};
    if (container.empty()) {
      throw empty_container_exception_t{};
    }
    T data = container.front();
    container.pop();
    return data;
  }
  typename std::queue<T, Container>::size_type size() {
    return container.size();
  }
  using value_type = T;
};

struct ipv4_address_t {
  std::string address{};
};

struct ipv6_address_t {
  std::string address{};
};

class domainname; // forward declaration

struct mx_record_result_t {
  std::uint16_t pref{}; // preference
  std::unique_ptr<domainname> server{};
};

struct ns_record_result_t {
  std::unique_ptr<domainname> domain{};
};

struct ptr_record_result_t {
  std::unique_ptr<domainname> domain{};
};

struct other_raw_result_t {
  std::unique_ptr<char[]> result{};
};

// name aliases
using ucstring = std::basic_string<unsigned char>;
using ucstring_cptr = ucstring::const_pointer;
using ucstring_ptr = ucstring::pointer;
using ucstring_view = std::basic_string_view<unsigned char>;
using a_record_list_t = std::vector<ipv4_address_t>;
using aaaa_record_list_t = std::vector<ipv6_address_t>;
using mx_record_list_t = std::vector<mx_record_result_t>;
using ns_record_list_t = std::vector<ns_record_result_t>;
using ptr_record_list_t = std::vector<ptr_record_result_t>;
using other_record_list_t = std::vector<other_raw_result_t>;
using domain_list_t = synced_queue_t<std::string>;
using opt_domain_list_t = std::optional<domain_list_t>;
using query_result_t =
    std::variant<a_record_list_t, aaaa_record_list_t, mx_record_list_t,
                 ns_record_list_t, ptr_record_list_t, other_record_list_t>;
// free utility functions
bool is_text_file(std::string const &file_extension);
bool is_json_file(std::string const &file_extension);
std::vector<std::string> split_string(std::string const &str,
                                      char const *delim);
opt_list_t<std::string> get_names(std::string const &filename);
std::string get_file_extension(std::filesystem::path const &file_path);
std::uint16_t get_random_integer();
bool timet_to_string(std::string &output, std::size_t t, char const *format);
std::uint16_t uint16_value(unsigned char const *buff);
int dom_comprlen(ucstring_view const &, int);
ucstring_ptr dom_uncompress(ucstring const &, int);
ucstring_ptr domdup(ucstring_cptr);
void *memdup(void const *src, int len);

} // namespace dooked
