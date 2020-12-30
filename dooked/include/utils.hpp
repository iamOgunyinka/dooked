#pragma once
#include <boost/asio/ip/address.hpp>
#include <exception>
#include <filesystem>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <variant>
#include <vector>

namespace dooked {
enum file_type_e { stdin_type, txt_type, json_type, unknown_type };

struct cli_args_t {
  std::string resolver_filename{}; // defaults to 8.8.8.8
  std::string output_filename{};
  std::string input_filename{};

  int file_type = file_type_e::stdin_type;
};

struct empty_container_exception_t : std::exception {
  empty_container_exception_t() : std::exception{} {}
};

struct invalid_dns_response_t : std::exception {
  invalid_dns_response_t() : std::exception{} {}
  invalid_dns_response_t(char const *w) : std::exception{w} {}
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
      : container{std::move(queue.container)}, mutex{std::move(queue.mutext)} {}
  void push_back(T const &item) { container.push_back(item); }
  void push_back(T &&item) { container.push(std::move(item)); }
  T next_item() {
    std::lock_guard<std::mutex> lockg{mutex};
    if (container.empty()) {
      throw empty_container{};
    }
    return container.pop();
  }
};

template <typename T> class circular_queue_t {
  std::vector<T> const container_;
  mutable std::vector<T>::size_type index_ = 0;

public:
  circular_queue_t(std::vector<T> &&container)
      : container_{std::move(container)} {}
  T const &next_item() const {
    if (index_ >= container_.size()) {
      index = 0;
    }
    return container_[index++];
  }
};

struct ip_address_t {
  std::vector<boost::asio::ip::address> ip_addresses;
};

struct mx_record_t {};

struct domain_t {
  std::string domain_name{};
};

// name aliases
using a_record_t = ip_address_t;
using aaaa_record_t = ip_address_t;
using domain_list_t = synced_queue_t<domain_t>;
using opt_domain_list_t = std::optional<domain_list_t>;
using query_result_t = std::variant<a_record_t, aaaa_record_t, mx_record_t>;
// free utility functions
bool is_text_file(std::string const &file_extension);
bool is_json_file(std::string const &file_extension);
opt_domain_list_t get_domain_names(std::string const &filename);
std::string get_file_extension(std::filesystem::path const &file_path);
std::uint16_t get_random_integer();
} // namespace dooked
