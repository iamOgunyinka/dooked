#include "utils.hpp"
#include <boost/process.hpp>
#include <fstream>
#include <iostream>
#include <random>

namespace dooked {
namespace bp = boost::process;

bool is_text_file(std::string const &file_extension) {
  return file_extension.find(".txt") != std::string::npos ||
         file_extension.find("text/plain") != std::string::npos;
}

bool is_json_file(std::string const &file_extension) {
  return file_extension.find(".json") != std::string::npos ||
         file_extension.find("application/json") != std::string::npos;
}

std::string get_file_extension(std::filesystem::path const &file_path) {
  if (file_path.has_extension()) {
    return file_path.extension().string();
  }

#ifdef _WIN32
  return {};
#else // _WIN32

  auto const command = "file -ib " + file_path.string();
  bp::ipstream out{};
  try {
    bp::system(command, bp::std_out > out);
  } catch (std::exception const &e) {
    std::cerr << "Command: " << command;
    std::cerr << "Exception: " << e.what() << std::endl;
    return {};
  }
  std::string console_output{};
  std::getline(out, console_output);
  return console_output;
#endif
}

std::size_t newline_count(std::filesystem::path const &filename) {
  auto const command = "wc -l " + filename.string();
  bp::ipstream out{};
  try {
    bp::system(command, bp::std_out > out);
  } catch (std::exception const &e) {
    std::cerr << "Command: " << command;
    std::cerr << "Exception: " << e.what() << std::endl;
    return {};
  }
  std::size_t total_lines{};
  out >> total_lines;
  return total_lines;
}

opt_domain_list_t read_text_file(std::filesystem::path const &file_path) {
  std::ifstream input_file(file_path);
  if (!input_file) {
    return std::nullopt;
  }
  domain_list_t domain_names{};
  std::string line{};
  while (std::getline(input_file, line)) {
    line = boost::trim_copy(line);
    if (line.empty()) {
      continue;
    }
    domain_names.push_back({line});
  }
  return domain_names;
}

opt_domain_list_t read_json_file(std::filesystem::path const &file_path) {
  return domain_list_t{};
}

opt_domain_list_t get_domain_names(std::string const &filename) {
  if (filename.empty()) { // use stdin
    std::string domain_name{};
    domain_list_t domain_names;
    while (std::getline(std::cin, domain_name)) {
      domain_names.push_back({domain_name});
    }
    return domain_names;
  }
  std::filesystem::path const file{filename};
  if (!std::filesystem::exists(file)) {
    return std::nullopt;
  }
  auto const file_extension{get_file_extension(file)};
  if (is_text_file(file_extension)) {
    return read_text_file(file);
  } else if (is_json_file(file_extension)) {
    return read_json_file(file);
  }
  // if file extension/type cannot be determined, read as TXT file
  return read_text_file(file);
}

std::uint16_t get_random_integer() {
  static std::random_device rd{};
  static std::mt19937 gen{rd()};
  static std::uniform_int_distribution<> uid(
      1, std::numeric_limits<std::uint16_t>::max());
  return uid(gen);
}

} // namespace dooked