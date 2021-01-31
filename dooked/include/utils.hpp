#pragma once

#include "spdlog/spdlog.h"
#include "ucstring.hpp"
#include <boost/asio/ip/udp.hpp>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <json.hpp>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace dooked {
using namespace fmt::v7;
namespace net = boost::asio;
using json = nlohmann::json;

template <typename T> using opt_list_t = std::optional<std::vector<T>>;

enum class file_type_e { txt_type, json_type, unknown_type };
enum class http_process_e { in_place, deferred };

struct cli_args_t {
  std::string resolver{}; // defaults to 8.8.8.8
  std::string resolver_filename{};
  std::string output_filename{};
  std::string input_filename{};

  int file_type = static_cast<int>(file_type_e::txt_type);
  int post_http_request = static_cast<int>(http_process_e::in_place);
  int thread_count = 0;
  int content_length = -1;
  bool include_date = false;
};

struct resolver_address_t {
  net::ip::udp::endpoint ep{};
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

// contains result for all searches.
template <typename ValueType> class map_container_t {
  struct response_t {
    int content_length_{};
    int http_status_ = 0;
    std::vector<ValueType> dns_result_list_;
  };
  std::map<std::string, response_t> map_;
  std::optional<std::mutex> opt_mutex_;

  void append_impl(std::string const &key, ValueType const &value) {
    auto &container = map_[key].dns_result_list_;
    auto iter = std::find(container.cbegin(), container.cend(), value);
    if (iter == container.cend()) {
      container.push_back(value);
    }
  }

public:
  map_container_t(bool use_lock = false) : map_{}, opt_mutex_{} {
    if (use_lock) {
      opt_mutex_.emplace();
    }
  }
  // needed by different threads
  void append(std::string const &key, ValueType const &value) {
    if (!opt_mutex_) {
      return append_impl(key, value);
    }
    // lock before doing any insertion
    std::lock_guard<std::mutex> lock_g{*opt_mutex_};
    append_impl(key, value);
  }

  void insert(std::string const &name, int const len, int const http_status) {
    if (!opt_mutex_) {
      map_[name].content_length_ = len;
      map_[name].http_status_ = http_status;
      return;
    }
    std::lock_guard<std::mutex> lock_g{*opt_mutex_};
    map_[name].content_length_ = len;
    map_[name].http_status_ = http_status;
  }
  // only used by main thread, after all "computations" has been
  // done. There's no need for locks here.
  auto &cresult() const { return map_; }
  auto &result() { return map_; }
  bool empty() const { return map_.empty(); }
};

using resolver_address_list_t = circular_queue_t<resolver_address_t>;

struct empty_container_exception_t : std::runtime_error {
  empty_container_exception_t() : std::runtime_error{"empty container"} {}
};

struct invalid_dns_response_t : std::runtime_error {
  invalid_dns_response_t() : std::runtime_error{"invalid dns response"} {}
  invalid_dns_response_t(char const *w) : std::runtime_error{w} {}
};

struct general_exception_t : std::runtime_error {
  general_exception_t(char const *w) : std::runtime_error{w} {}
  general_exception_t(std::string const &w) : std::runtime_error{w.c_str()} {}
};

struct bad_name_exception_t : std::runtime_error {
  bad_name_exception_t(std::string const &domain_name)
      : std::runtime_error{domain_name} {}
  bad_name_exception_t(char const *name) : std::runtime_error{name} {}
};

struct uri {
  uri(std::string const &url_s);
  std::string path() const;
  std::string host() const;
  std::string target() const;
  std::string protocol() const;

private:
  void parse(std::string const &);
  std::string host_;
  std::string protocol_;
  std::string query_;
  std::string path_;
};

// only one thread does push_backs, which happens way before reading
// however, multiple threads will read from it later.
template <typename T, typename Container = std::deque<T>> class synced_queue_t {
  std::queue<T, Container> container_{};
  std::mutex mutex_{};

public:
  synced_queue_t() = default;
  synced_queue_t(synced_queue_t const &) = delete;
  synced_queue_t(std::queue<T, Container> &&container)
      : container_{std::move(container)} {}
  synced_queue_t(synced_queue_t &&queue)
      : container_{std::move(queue.container_)} {}
  void push_back(T const &item) { container_.push(item); }
  void push_back(T &&item) { container_.push(std::move(item)); }
  T next_item() {
    std::lock_guard<std::mutex> lockg{mutex_};
    if (container_.empty()) {
      throw empty_container_exception_t{};
    }
    T data = container_.front();
    container_.pop();
    return data;
  }
  typename std::queue<T, Container>::size_type size() {
    return container_.size();
  }
  std::queue<T, Container> clone() const { return container_; }
  using value_type = T;
};

using domain_list_t = synced_queue_t<std::string>;
using opt_domain_list_t = std::optional<domain_list_t>;

// free utility functions
bool is_text_file(std::string const &file_extension);
bool is_json_file(std::string const &file_extension);
void trim(std::string &s);
std::string trim_copy(std::string s);
std::string get_file_type(std::filesystem::path const &file_path);
std::uint16_t get_random_integer();
bool timet_to_string(std::string &output, std::size_t t, char const *format);
std::uint16_t uint16_value(unsigned char const *buff);
int dom_comprlen(ucstring_view_t const &, int);
void trim_string(std::string &);
std::string get_filepath(std::string const &filename);
void split_string(std::string const &str, std::vector<std::string> &cont,
                  char delim);

namespace detail {

template <typename T>
opt_list_t<T> read_text_file(std::filesystem::path const &file_path) {
  std::ifstream input_file(file_path);
  if (!input_file) {
    return std::nullopt;
  }
  std::vector<T> domain_names{};
  std::string line{};
  while (std::getline(input_file, line)) {
    trim(line);
    if (line.empty()) {
      continue;
    }
    domain_names.push_back({line});
  }
  return domain_names;
}

template <typename T, typename Iterator>
opt_list_t<T> read_json_string(Iterator const begin, Iterator const end) {
  std::vector<T> result{};

  try {

    json json_content = json::parse(begin, end);
    auto object_root = json_content.get<json::object_t>();
    auto const result_list = object_root["result"].get<json::array_t>();

    for (auto const &result_item : result_list) {
      auto json_object = result_item.get<json::object_t>();

      for (auto const json_item : json_object) {
        std::string const domain_name = json_item.first;
        auto internal_object = json_item.second.get<json::object_t>();
        auto const domain_detail_list =
            internal_object["dns_probe"].get<json::array_t>();
        auto const content_length =
            internal_object["content_length"].get<json::number_integer_t>();
        auto const http_code =
            internal_object["http_code"].get<json::number_integer_t>();

        for (auto const &domain_detail : domain_detail_list) {
          auto domain_object = domain_detail.get<json::object_t>();
          result.push_back(T::serialize(domain_name, content_length, http_code,
                                        domain_object));
        }
      }
    }
  } catch (std::runtime_error const &e) {
    spdlog::error(e.what());
    return std::nullopt;
  }
  return result;
}

template <typename T>
opt_list_t<T> read_json_file(std::filesystem::path const &file_path) {
  std::ifstream input_file(file_path);
  if (!input_file) {
    return std::nullopt;
  }
  auto const file_size = std::filesystem::file_size(file_path);
  std::vector<char> file_buffer(file_size);
  input_file.read(&file_buffer[0], file_size);
  return read_json_string<T>(file_buffer.cbegin(), file_buffer.cend());
}

} // namespace detail

template <typename T>
opt_list_t<T> get_names(std::string const &filename,
                        file_type_e const file_type = file_type_e::txt_type) {
  bool const using_stdin = filename.empty();

  // read line by line and send the result back as-is.
  if (using_stdin && file_type == file_type_e::txt_type) { // use stdin
    std::string domain_name{};
    std::vector<T> domain_names;
    while (std::getline(std::cin, domain_name)) {
      domain_names.push_back({domain_name});
    }
    return domain_names;

    // read line by line but parse the JSON result
  } else if (using_stdin && file_type == file_type_e::json_type) {
    std::ostringstream ss{};
    std::string line{};
    while (std::getline(std::cin, line)) {
      ss << line;
    }
    auto const buffer{ss.str()};
    if constexpr (!std::is_same_v<T, std::string>) {
      return detail::read_json_string<T>(buffer.cbegin(), buffer.cend());
    }
    return std::nullopt;
  } else if (using_stdin) {
    return std::nullopt;
  }

  std::filesystem::path const file{filename};
  if (!std::filesystem::exists(file)) {
    return std::nullopt;
  }
  switch (file_type) {
  case file_type_e::txt_type:
    return detail::read_text_file<T>(file);
  case file_type_e::json_type:
    if constexpr (!std::is_same_v<T, std::string>) {
      return detail::read_json_file<T>(file);
    }
  }
  // if we are here, we were unable to determine the type
  auto const file_extension{get_file_type(file)};
  if (is_text_file(file_extension)) {
    return detail::read_text_file<T>(file);
  } else if (is_json_file(file_extension)) {
    if constexpr (!std::is_same_v<T, std::string>) {
      return detail::read_json_file<T>(file);
    }
  }
  // if file extension/type cannot be determined, read as TXT file
  return detail::read_text_file<T>(file);
}

} // namespace dooked
