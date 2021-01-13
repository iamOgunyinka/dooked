#include "utils.hpp"
#include <cctype>
#include <functional>
#include <locale>
#include <random>

namespace dooked {

// ============= the following code is copied directly from stackoverflow
// https://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring

// trim from start (in place)
void ltrim(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
            return !std::isspace(ch);
          }));
}

// trim from end (in place)
void rtrim(std::string &s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       [](unsigned char ch) { return !std::isspace(ch); })
              .base(),
          s.end());
}

// trim from both ends (in place)
void trim(std::string &s) {
  ltrim(s);
  rtrim(s);
}

// trim from start (copying)
std::string ltrim_copy(std::string s) {
  ltrim(s);
  return s;
}

// trim from end (copying)
std::string rtrim_copy(std::string s) {
  rtrim(s);
  return s;
}

// trim from both ends (copying)
std::string trim_copy(std::string s) {
  trim(s);
  return s;
}
//===============================================================
void split_string(std::string const &str, std::vector<std::string> &cont,
                  char const delim) {
  std::stringstream ss{str};
  std::string token{};
  while (std::getline(ss, token, delim)) {
    trim(token);
    if (!token.empty()) {
      cont.push_back(token);
    }
  }
}

bool is_text_file(std::string const &file_extension) {
  return file_extension.find(".txt") != std::string::npos ||
         file_extension.find("text/plain") != std::string::npos;
}

bool is_json_file(std::string const &file_extension) {
  return file_extension.find(".json") != std::string::npos ||
         file_extension.find("application/json") != std::string::npos;
}

std::string get_file_type(std::filesystem::path const &file_path) {
  if (file_path.has_extension()) {
    return file_path.extension().string();
  }

#ifdef _WIN32
  return {};
#else // _WIN32

  auto const command = "file -ib " + file_path.string();
  boost::process::ipstream out{};
  try {
    boost::process::system(command, boost::process::std_out > out);
  } catch (std::exception const &e) {
    spdlog::error("Command: {}.\nException: {}", command, e.what());
    return {};
  }
  std::string console_output{};
  std::getline(out, console_output);
  return console_output;
#endif
}

void trim_string(std::string &str) { trim(str); }

std::string get_filepath(std::string const &filename) {
  if (filename.empty()) {
    return {};
  }
  return std::filesystem::path(filename).replace_extension().string();
}

std::uint16_t get_random_integer() {
  static std::random_device rd{};
  static std::mt19937 gen{rd()};
  static std::uniform_int_distribution<> uid(
      1, std::numeric_limits<std::uint16_t>::max());
  return uid(gen);
}

int dom_comprlen(ucstring_view_t const &buff, int ix) {
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
