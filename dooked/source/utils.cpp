#include "utils.hpp"
#include <cctype>
#include <functional>
#include <locale>
#include <random>

#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#endif // _WIN32

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

uri::uri(std::string const &url_s) { parse(url_s); }

std::string uri::target() const { return path_ + "?" + query_; }

std::string uri::protocol() const { return protocol_; }

std::string uri::path() const { return path_; }

std::string uri::host() const { return host_; }

void uri::parse(std::string const &url_s) {
  std::string const prot_end{"://"};
  std::string::const_iterator prot_i =
      std::search(url_s.begin(), url_s.end(), prot_end.begin(), prot_end.end());
  protocol_.reserve(
      static_cast<std::size_t>(std::distance(url_s.cbegin(), prot_i)));
  std::transform(url_s.begin(), prot_i, std::back_inserter(protocol_),
                 [](int c) { return std::tolower(c); });
  if (prot_i == url_s.end()) {
    prot_i = url_s.begin();
  } else {
    std::advance(prot_i, prot_end.length());
  }
  std::string::const_iterator path_i = std::find(prot_i, url_s.end(), '/');
  host_.reserve(static_cast<std::size_t>(std::distance(prot_i, path_i)));
  std::transform(prot_i, path_i, std::back_inserter(host_),
                 [](int c) { return std::tolower(c); });
  std::string::const_iterator query_i = std::find(path_i, url_s.end(), '?');
  path_.assign(path_i, query_i);
  if (query_i != url_s.end())
    ++query_i;
  query_.assign(query_i, url_s.end());
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

  std::string result{};
#ifdef _WIN32
  // haven't figured what to do on Windows
#else
  std::string const command = "file -ib " + file_path.string();
  auto file = popen(command.c_str(), "r");
  if (!file) {
    return {};
  }
  char buffer[128]{};
  while (!feof(file)) {
    if (fgets(buffer, sizeof(buffer), file) == nullptr) {
      break;
    }
    result += buffer;
  }
  pclose(file);
#endif
  return result;
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
