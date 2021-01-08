// dooked.cpp : This file contains the 'main' function. Program execution begins
// and ends there.
//

#include "resolver.hpp"
#include <CLI11.hpp>
#include <boost/algorithm/string.hpp>
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
  sockets.resize(socket_count);
  for (int i = 0; i < socket_count; ++i) {
#ifdef _DEBUG
    auto const thread_id =
        std::hash<std::thread::id>{}(std::this_thread::get_id());
    spdlog::info("Opening sockets: {} in thread {}", i + 1, thread_id);
#endif // _DEBUG
    sockets[i] = std::make_unique<custom_resolver_socket_t>(
        io_context, *rt_args.names, *rt_args.resolvers);
    sockets[i]->start();
  }
  io_context.run();
}

void start_name_checking(runtime_args_t &&rt_args) {
  auto const native_thread_count = (std::min)(
      rt_args.names->size(), (std::size_t)std::thread::hardware_concurrency());
  boost::asio::io_context io_context(native_thread_count);
  auto const max_open_sockets =
      (std::min)(rt_args.names->size(), (std::size_t)100);
  std::size_t const sockets_per_thread = max_open_sockets / native_thread_count;
#ifdef _DEBUG
  spdlog::info("Native thread count: {}", native_thread_count);
  spdlog::info("sockets per thread: {}", sockets_per_thread);
#endif // _DEBUG

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
#ifdef _DEBUG
      spdlog::info("No resolver specified, using default");
#endif // _DEBUG
      resolver_strings.push_back("8.8.8.8 53");
    } else {
      boost::split(resolver_strings, cli_args.resolver, boost::is_any_of(","));
    }
  } else {
    if (auto resolvers = get_names(cli_args.resolver_filename);
        resolvers && !resolvers->empty()) {
      resolver_strings = std::move(*resolvers);
    } else {
      return spdlog::error("Unable to read file content");
    }
  }
#ifdef _DEBUG
  spdlog::info("Total resolvers: {}", resolver_strings.size());
  for (auto const &res : resolver_strings) {
    spdlog::info("res => {}", res);
  }
#endif // _DEBUG

  // read input file
  if (auto domain_names = get_names(cli_args.input_filename); domain_names) {
    rt_args.names.emplace();

    for (auto const &domain_name : *domain_names) {
#ifdef _DEBUG
      spdlog::info("Domain name: {}", domain_name);
#endif // _DEBUG
      rt_args.names->push_back({domain_name});
    }
  } else {
    return spdlog::error("There was an error trying to get input file");
  }
  // try opening an output file
  {
    std::string filename{};
    bool const output_specified = !cli_args.output_filename.empty();
    if (!output_specified || cli_args.include_date) {
      std::string appended_time{};
      bool const time_obtained =
          timet_to_string(appended_time, std::time(nullptr), "%d_%m_%Y__%H_%M_%S");
      if (output_specified && time_obtained) {
        filename = "{}-{}.json"_format(cli_args.output_filename, appended_time);
      } else if (!output_specified && !time_obtained) {
        return spdlog::error("Unable to generate time for output name,"
                             "will use output filename only");
      } else if (!time_obtained && output_specified) {
        spdlog::warn("Unable to generate name for output file");
        filename = cli_args.output_filename + ".json";
      } else if (!output_specified && time_obtained) {
        filename = "dooked-{}.json"_format(appended_time);
      }
    } else {
      filename = "{}.json"_format(cli_args.output_filename);
    }
    std::ofstream file{filename, std::ios::trunc};
    if (!file) {
      return spdlog::error("unable to open `{}` for out", filename);
    }
#ifdef _DEBUG
    spdlog::info("Output filename: {}", filename);
#endif // _DEBUG
    rt_args.output_file = std::make_unique<std::ofstream>(std::move(file));
  }

  // convert strings to UDP endpoints( IP address
#ifdef _DEBUG
  spdlog::info("Converting UDP endpoints");
#endif // _DEBUG
  std::vector<resolver_address_t> resolver_eps{};
  resolver_eps.reserve(resolver_strings.size());
  auto the_transformer = [](auto &&resolver) -> resolver_address_t {
    std::vector<std::string> split{};
    boost::split(split, resolver, boost::is_any_of(" \t"));
    unsigned int port = 53;

    if (auto const split_size = split.size();
        (split_size < 1 || split_size > 2)) {
#ifdef _DEBUG
      spdlog::info("Split: {} => {}", split.size(), split[0]);
#endif // _DEBUG
      throw general_exception_t{"invalid ip:port => " + resolver};
    }
    if (split.size() == 2) {
      port = std::stoul(split[1]);
    }
    boost::trim(split[0]);
    boost::system::error_code ec{};
    auto const ip_address = boost::asio::ip::make_address(split[0], ec);
    if (ec) {
      throw general_exception_t{ec.message()};
    }
    boost::asio::ip::udp::endpoint const ep{ip_address, (std::uint16_t)port};
    return {ep};
  };
  try {
    for (auto const &resolver_string : resolver_strings) {
      resolver_eps.push_back(the_transformer(resolver_string));
    }
  } catch (std::exception const &e) {
    return spdlog::error(e.what());
  }
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
      "-t,--file-type", cli_args.file_type,
      "the file type used as input file: stdin=0(default), txt=1, json=2");
  app.add_option(
      "-i,--input-file", cli_args.input_filename,
      "if not using stdin, this is the input file to use, type is deduceable "
      "by file extension or file type returned by linux's `file`");
  app.add_option("-l,--resolver-list", cli_args.resolver_filename,
                 "a filename consisting of IP addresses to resolve names");
  app.add_option("-r,--resolver", cli_args.resolver,
                 "a (possible) list of resolvers separated by comma. If -rl "
                 "and -r isn't specified, -r is defaulted to 8.8.8.8");
  app.add_flag("-d", cli_args.include_date,
               "append present datetime(-ddMMyyyy_hhmmss) in output name");

#ifdef _DEBUG
  spdlog::info("parsing file: {}", argc);
#endif // _DEBUG

#ifdef _DEBUG
  cli_args.input_filename = "D:\\Visual Studio Projects\\dooked\\x64"
                            "\\Debug\\names.txt";
  cli_args.resolver_filename = "D:\\Visual Studio Projects\\dooked"
                               "\\x64\\Debug\\resolvers.txt";
#else
  CLI11_PARSE(app, argc, argv);
#endif // _DEBUG
  dooked::run_program(cli_args);
  return 0;
}
