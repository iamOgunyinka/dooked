#define CATCH_CONFIG_MAIN
#include "../dooked/include/requests.hpp"
#include "../dooked/include/utils.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <catch.hpp>

namespace dooked {

namespace net = boost::asio;
struct cresponse_t {
  response_type_e rt;
  int length_;
  std::string message{};
};

cresponse_t try_https_function() {
  net::io_context io_context{};
  net::ssl::context ssl_context(net::ssl::context::tlsv12_client);
  ssl_context.set_default_verify_paths();
  ssl_context.set_verify_mode(net::ssl::verify_none);

  cresponse_t response{};
  http_request_handler_t handler{io_context, /*ssl_context, */ "facebook.com",
                                 std::vector<std::string>{}};
  handler.start([&response](response_type_e const rt, int const length,
                            std::string const &response_string) {
    response.length_ = length;
    response.message = response_string;
    response.rt = rt;
  });
  io_context.run();
  return response;
}
} // namespace dooked

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

  using dooked::get_file_type;
  using dooked::is_json_file;
  using dooked::is_text_file;

  SECTION("Testing filenames without extension") {
    auto const extension = get_file_type(filename_wo_extension);
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
    auto const extension = get_file_type(filename_with_extension);
    REQUIRE(is_json_file(extension));
    REQUIRE(!is_text_file(extension));
  }

  SECTION("Testing HTTPS websites") {
    auto const resp = dooked::try_https_function();
    spdlog::info(resp.message);
    //REQUIRE(resp.length_ != 0);
    REQUIRE((int)resp.rt == (int)dooked::response_type_e::ok);
    REQUIRE(!resp.message.empty());
  }
}
