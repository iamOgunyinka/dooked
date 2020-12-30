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
