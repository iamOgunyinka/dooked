// dooked.cpp : This file contains the 'main' function. Program execution begins
// and ends there.
//

#include "resolver.hpp"
#include "utils.hpp"
#include <CLI11.hpp>
#include <algorithm>
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <json.hpp>
#include <thread>

namespace dooked {

struct runtime_args_t {
  std::optional<resolver_address_list_t> resolvers;
  opt_domain_list_t names;
  std::unique_ptr<std::ofstream> output_file{};
};

void thread_functor(boost::asio::io_context &io_context,
                    runtime_args_t &rt_args, int const socket_count) {
  std::vector<std::unique_ptr<custom_resolver_socket_t>> sockets{};
  sockets.reserve(socket_count);
  for (int i = 0; i < socket_count; ++i) {
    sockets.push_back(std::make_unique<custom_resolver_socket_t>(
        io_context, *rt_args.names, *rt_args.resolvers));
    sockets.back()->start();
  }
  io_context.run();
}

void start_name_checking(runtime_args_t &&rt_args) {
  auto const native_thread_count = (std::min)(
      rt_args.names->size(), (std::size_t)std::thread::hardware_concurrency());
  boost::asio::io_context io_context(native_thread_count);
  std::size_t const max_open_sockets = 100;
  std::size_t const sockets_per_thread = max_open_sockets / native_thread_count;
  boost::asio::thread_pool thread_pool(native_thread_count);
  for (std::size_t index = 0; index < native_thread_count; ++index) {
    boost::asio::post(thread_pool, [&] {
      thread_functor(io_context, rt_args, sockets_per_thread);
    });
  }
  thread_pool.join();
}

void run_program(cli_args_t const &cli_args) {
  runtime_args_t rt_args{};
  // settle resolvers.
  std::vector<std::string> resolver_strings{};
  if (cli_args.resolver_filename.empty()) {
    if (cli_args.resolver.empty()) {
      resolver_strings.push_back("8.8.8.8 53");
    } else {
      resolver_strings = split_string(cli_args.resolver, ",");
    }
  } else {
    if (auto resolvers = get_names(cli_args.resolver_filename);
        resolvers && !resolvers->empty()) {
      resolver_strings = std::move(*resolvers);
    } else {
      std::cerr << "Unable to read file content\n";
      return;
    }
  }
  // read input file
  if (auto domain_names = get_names(cli_args.input_filename); domain_names) {
    rt_args.names.emplace();
    for (auto const &domain_name : *domain_names) {
      rt_args.names->push_back({domain_name});
    }
  } else {
    std::cerr << "There was an error trying to get input file\n";
    return;
  }
  // try opening an output file
  {
    std::string filename{};
    bool const output_specified = !cli_args.output_filename.empty();
    if (!output_specified || cli_args.include_date) {
      std::string appended_time{};
      bool const time_obtained =
          timet_to_string(appended_time, std::time(nullptr), "%d%m%Y_%H%M%S");
      if (output_specified && time_obtained) {
        filename = cli_args.output_filename + "-" + appended_time + ".json";
      } else if (!output_specified && !time_obtained) {
        std::cerr << "Unable to generate time for output name,"
                     "will use output filename only\n";
        return;
      } else if (!time_obtained && output_specified) {
        std::clog << "Unable to generate name for output file\n";
        filename = cli_args.output_filename + ".json";
      }
    } else {
      filename = cli_args.output_filename + ".json";
    }
    std::ofstream file{filename, std::ios::trunc};
    if (!file) {
      std::cerr << "unable to open `" + filename + "` for out\n";
      return;
    }
    rt_args.output_file = std::make_unique<std::ofstream>(std::move(file));
  }

  // convert strings to UDP endpoints( IP address
  std::vector<resolver_address_t> resolver_eps{};
  resolver_eps.reserve(resolver_strings.size());
  auto the_transformer = [](auto &&resolver) -> resolver_address_t {
    auto const split = split_string(resolver, " ");
    if (split.size() != 2) {
      throw general_exception_t{"invalid ip:port => " + resolver};
    }
    std::uint16_t const port = std::stoi(split[1]);
    return {boost::asio::ip::udp::endpoint{
        boost::asio::ip::make_address(split[0]), port}};
  };

  std::transform(resolver_strings.begin(), resolver_strings.end(),
                 std::back_inserter(resolver_eps), the_transformer);
  rt_args.resolvers.emplace(std::move(resolver_eps));
  return start_name_checking(std::move(rt_args));
}

} // namespace dooked

int main(int argc, char **argv) {
  CLI::App app{"dooked -- a CLI tool to enumerate DNS info"};
  dooked::cli_args_t cli_args{};
  app.add_option("-o,--output", cli_args.output_filename,
                 "write result to output file");
  app.add_option(
      "-ft,--file-type", cli_args.file_type,
      "the file type used as input file: stdin=0(default), txt=1, json=2");
  app.add_option(
      "-i,--input-file", cli_args.input_filename,
      "if not using stdin, this is the input file to use, type is deduceable "
      "by file extension or file type returned by linux's `file`");
  app.add_option("-rl,--resolver-list", cli_args.resolver_filename,
                 "a filename consisting of IP addresses to resolve names");
  app.add_option("-r,--resolver", cli_args.resolver,
                 "a (possible) list of resolvers separated by comma. If -rl "
                 "and -r isn't specified, -r is defaulted to 8.8.8.8");
  app.add_flag("-dt", cli_args.include_date,
               "append present datetime(-ddMMyyyy_hhmmss) in output name");

  CLI11_PARSE(app, argc, argv);
  dooked::run_program(cli_args);
  return 0;
}
