#define CATCH_CONFIG_MAIN
#include "../dooked/include/utils.hpp"
#include <catch.hpp>

TEST_CASE("Testing the readability of files", "[utils.hpp]") {
#ifdef _WIN32
  auto const filename_with_extension =
      R"(D:\Visual Studio Projects\dooked\dooked\tests\misc\file.json)";
  auto const filename_wo_extension =
      R"(D:\Visual Studio Projects\dooked\dooked\tests\misc\foo)";
#else
  auto const filename_with_extension = "./file.json";
  auto const filename_wo_extension = "./foo"; // just a plain text
#endif // _WIN32

  using dooked::get_file_extension;
  using dooked::is_json_file;
  using dooked::is_text_file;

  SECTION("Testing filenames without extension") {
    auto const extension = get_file_extension(filename_wo_extension);
    REQUIRE(!is_json_file(extension));
#ifdef _WIN32
    // on Windows, file type is unknown
    REQUIRE(!is_text_file(extension));
#else
    // but we can determine the file type on Linux systems
    REQUIRE(is_text_file(extension));
#endif // _WIN32
  }

  SECTION("Testing filenames with extension") {
    auto const extension = get_file_extension(filename_with_extension);
    REQUIRE(is_json_file(extension));
    REQUIRE(!is_text_file(extension));
  }

  SECTION("Testing file content extraction") {}
}

namespace dooked {
void *memdup(const void *src, int len) {
  if (len == 0) {
    return nullptr;
  }
  void *ret = malloc(len);
  memcpy(ret, src, len);
  return ret;
}

using ucstring_ptr = unsigned char *;
using ucstring_cptr = unsigned char const *;

int domlen(ucstring_cptr dom) {
  int len = 1;
  while (*dom) {
    if (*dom > 63) {
      throw std::runtime_error("Unknown domain nibble");
    }
    len += *dom + 1;
    dom += *dom + 1;
    if (len > 255) {
      throw std::runtime_error("Length too long");
    }
  }
  return len;
}

ucstring_ptr domdup(ucstring_cptr dom) {
  return static_cast<ucstring_ptr>(memdup(dom, domlen(dom)));
}
} // namespace dooked
