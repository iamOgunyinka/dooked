#include "utils.hpp"
#include <boost/process.hpp>
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
    spdlog::error("Command: {}.\nException: {}", command, e.what());
    return {};
  }
  std::string console_output{};
  std::getline(out, console_output);
  return console_output;
#endif
}

opt_list_t<std::string> read_text_file(std::filesystem::path const &file_path) {
  std::ifstream input_file(file_path);
  if (!input_file) {
    return std::nullopt;
  }
  std::vector<std::string> domain_names{};
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

opt_list_t<std::string> read_json_file(std::filesystem::path const &file_path) {
  return {};
}

opt_list_t<std::string> get_names(std::string const &filename) {
  if (filename.empty()) { // use stdin
    std::string domain_name{};
    std::vector<std::string> domain_names;
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

std::vector<std::string> split_string(std::string const &str,
                                      char const *delim) {
  std::size_t const delim_length = std::strlen(delim);
  std::size_t from_pos{};
  std::size_t index{str.find(delim, from_pos)};
  if (index == std::string::npos) {
    return {str};
  }
  std::vector<std::string> result{};
  while (index != std::string::npos) {
    result.emplace_back(str.data() + from_pos, index - from_pos);
    from_pos = index + delim_length;
    index = str.find(delim, from_pos);
  }
  if (from_pos < str.length()) {
    result.emplace_back(str.data() + from_pos, str.size() - from_pos);
  }
  return result;
}

int dom_comprlen(ucstring_view const &buff, int ix) {
  int len = 0;
  auto ptr = buff.data() + ix;
  auto end = buff.data() + buff.length();

  while (true) {
    if (ptr >= end) {
      throw invalid_dns_response_t("Domain name exceeds message borders");
    }

    if (*ptr == 0) {
      /* we're at the end! */
      return len + 1;
    }
    if ((*ptr & 192) == 192) {
      if (ptr + 1 >= end) {
        throw invalid_dns_response_t(
            "Compression offset exceeds message borders");
      }
      return len + 2;
    }
    unsigned char x = *ptr & 192;
    if (x != 0) {
      throw invalid_dns_response_t("Unknown domain label type");
    }
    len += *ptr + 1;
    ptr += *ptr + 1;
    if (len >= 255) {
      throw invalid_dns_response_t("Domain name too long");
    }
  }
}

std::string arecord_to_string(ipv4_address_t const &a) {
  auto &add = a.address;
  return "{}.{}.{}.{}"_format(
      static_cast<int>(add[0]), static_cast<int>(add[1]),
      static_cast<int>(add[2]), static_cast<int>(add[3]));
}

ucstring::pointer dom_uncompress(ucstring const &buff, int ix) {
  static constexpr int const dom_reclevel = 10;
  int reclevel = 0, len = 0;
  auto message_start = buff.cdata();
  auto ptr = message_start + ix;
  auto end = message_start + buff.size();
  unsigned char dbuff[255]{};

  while (true) {
    if (ptr >= end) {
      throw invalid_dns_response_t("Domain name exceeds message borders");
    }
    if (*ptr == 0) {
      /* we're at the end! */
      dbuff[len] = '\0';
      return domdup(dbuff);
    }

    if ((*ptr & 192) == 192) {
      if (++reclevel >= dom_reclevel) {
        throw invalid_dns_response_t("Max dom recursion level reached");
      }
      if (ptr + 1 >= end) {
        throw invalid_dns_response_t(
            "Compression offset exceeds message borders");
      }
      int const val = (ptr[0] & 63) * 256 + ptr[1];
      if (val >= (ptr - message_start)) {
        throw invalid_dns_response_t("Bad compression offset");
      }
      ptr = message_start + val;
      continue;
    }

    if ((*ptr & 192) != 0) {
      throw invalid_dns_response_t("Unknown domain label type");
    }
    if (len + *ptr + 1 >= 255) {
      throw invalid_dns_response_t("Domain name too long");
    }
    if (ptr + *ptr + 1 >= end) {
      throw invalid_dns_response_t("Domain name exceeds message borders");
    }
    memcpy(dbuff + len, ptr, *ptr + 1);
    len += *ptr + 1;
    ptr += *ptr + 1;
  }

  //  return domdup(dbuff);
}

bool timet_to_string(std::string &output, std::size_t t, char const *format) {
  std::time_t current_time = t;
#if _MSC_VER && !__INTEL_COMPILER
#pragma warning(disable : 4996)
#endif
  auto const tm_t = std::localtime(&current_time);

  if (!tm_t) {
    return false;
  }
  output.clear();
  output.resize(32);
  auto const trimmed_size =
      std::strftime(output.data(), output.size(), format, tm_t);
  if (trimmed_size > 0) {
    output.resize(trimmed_size);
    return true;
  }
  output.clear();
  return false;
}
} // namespace dooked
