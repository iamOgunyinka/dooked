#include "preprocessor.hpp"
#include <asio/io_context.hpp>
#include <asio/thread_pool.hpp>
#include <set>
#include <thread>

namespace dooked {
void to_json(json &j, dns_record_t const &record) {
  j = json{{"ttl", record.ttl},
           {"type", dns_record_type2str(record.type)},
           {"info", record.rdata}};
}

void compare_results(std::vector<json_data_t> const &previous_result,
                     map_container_t<dns_record_t> const &current_result) {
#ifdef _DEBUG
  spdlog::info("Trying to compare old with new result");
#endif // _DEBUG
}

void write_json_result(map_container_t<dns_record_t> const &result_map,
                       runtime_args_t const &rt_args) {
  if (result_map.empty()) {
    std::error_code ec{};
    if (!std::filesystem::remove(rt_args.output_filename, ec)) {
      spdlog::error("unable to remove {}", rt_args.output_filename);
    }
    return;
  }

  json::array_t list;
  for (auto const &result_pair : result_map.result()) {
    json::object_t object;
    object[result_pair.first] = result_pair.second;
    list.push_back(std::move(object));
  }
  json::object_t res_object;

  res_object["program"] = "dooked";
  res_object["result"] = std::move(list);
  (*rt_args.output_file) << json(res_object).dump(2) << "\n";
  rt_args.output_file->close();
}

void thread_functor(asio::io_context &io_context, runtime_args_t &rt_args,
                    map_container_t<dns_record_t> &result_map,
                    int const socket_count) {
  std::vector<std::unique_ptr<custom_resolver_socket_t>> sockets{};
  sockets.resize(socket_count);
  for (int i = 0; i < socket_count; ++i) {
    sockets[i] = std::make_unique<custom_resolver_socket_t>(
        io_context, *rt_args.names, *rt_args.resolvers, result_map);
    sockets[i]->start();
  }
  io_context.run();
}

void start_name_checking(runtime_args_t &&rt_args) {
  auto const native_thread_count = (std::min)(
      rt_args.names->size(), (std::size_t)std::thread::hardware_concurrency());
  asio::io_context io_context(native_thread_count);

  auto const max_open_sockets =
      (std::min)(rt_args.names->size(), (std::size_t)100);
  // minimum of 1 socket per thread
  std::size_t const sockets_per_thread = (std::max)(
      (std::size_t)1, std::size_t(max_open_sockets / native_thread_count));
#ifdef _DEBUG
  spdlog::info("Native thread count: {}", native_thread_count);
  spdlog::info("sockets per thread: {}", sockets_per_thread);
  spdlog::info("total input: {}", rt_args.names->size());
#endif // _DEBUG

  bool const using_lock = (native_thread_count > 1);
  map_container_t<dns_record_t> result_map(using_lock);

  asio::thread_pool thread_pool(native_thread_count);
  for (std::size_t index = 0; index < native_thread_count; ++index) {
    asio::post(thread_pool, [&] {
      thread_functor(io_context, rt_args, result_map, sockets_per_thread);
    });
  }
  thread_pool.join();
  write_json_result(result_map, rt_args);

  // compare old with new result
  if (rt_args.previous_data) {
    return compare_results(*rt_args.previous_data, result_map);
  }
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
      split_string(cli_args.resolver, resolver_strings, ',');
    }
  } else {
    if (auto resolvers = get_names<std::string>(cli_args.resolver_filename);
        resolvers && !resolvers->empty()) {
      resolver_strings = std::move(*resolvers);
    } else {
      return spdlog::error("Unable to read file content");
    }
  }
#ifdef _DEBUG
  spdlog::info("Total resolvers: {}", resolver_strings.size());
#endif // _DEBUG

  // read input file
  if (is_text_file(cli_args.input_filename) ||
      cli_args.input_filename.empty()) {
    auto domain_names = get_names<std::string>(cli_args.input_filename);
    if (domain_names && !domain_names->empty()) {
      rt_args.names.emplace();
      for (auto const &domain_name : *domain_names) {
        rt_args.names->push_back({domain_name});
      }
    } else {
      return spdlog::error("There was an error trying to get input file");
    }
  } else if (is_json_file(cli_args.input_filename)) {
    rt_args.previous_data = get_names<json_data_t>(cli_args.input_filename);
    auto &previous_records = rt_args.previous_data;
    if (previous_records && !previous_records->empty()) {
      std::set<std::string> unique_names{};
      for (auto const &domain_name : *previous_records) {
        unique_names.insert(domain_name.domain_name);
      }
      rt_args.names.emplace();
      for (auto const &name : unique_names) {
        rt_args.names->push_back(name);
      }
    } else {
      return spdlog::error("There was an error trying to get input file");
    }
  }
  // try opening an output file
  {
    std::string filename{};
    auto const out_file_path{get_filepath(cli_args.output_filename)};
    bool const output_specified = !out_file_path.empty();
    if (!output_specified || cli_args.include_date) {
      std::string appended_time{};
      bool const time_obtained = timet_to_string(
          appended_time, std::time(nullptr), "%d_%m_%Y__%H_%M_%S");
      if (output_specified && time_obtained) {
        filename = "{}-{}.json"_format(out_file_path, appended_time);
      } else if (!output_specified && !time_obtained) {
        return spdlog::error("Unable to generate time for output name,"
                             "will use output filename only");
      } else if (!time_obtained && output_specified) {
        spdlog::warn("Unable to generate name for output file");
        filename = "{}.json"_format(out_file_path);
      } else if (!output_specified && time_obtained) {
        filename = "dooked-{}.json"_format(appended_time);
      }
    } else {
      filename = "{}.json"_format(out_file_path);
    }
    std::ofstream file{filename, std::ios::trunc};
    if (!file) {
      return spdlog::error("unable to open `{}` for out", filename);
    }
#ifdef _DEBUG
    spdlog::info("Output filename: {}", filename);
#endif // _DEBUG
    rt_args.output_file = std::make_unique<std::ofstream>(std::move(file));
    rt_args.output_filename = std::move(filename);
  }

  // convert strings to UDP endpoints( IP address
#ifdef _DEBUG
  spdlog::info("Converting UDP endpoints");
#endif // _DEBUG
  std::vector<resolver_address_t> resolver_eps{};
  resolver_eps.reserve(resolver_strings.size());
  auto the_transformer = [](auto &&resolver) -> resolver_address_t {
    std::vector<std::string> split{};
    split_string(resolver, split, ' ');
    unsigned int port = 53;

    if (auto const split_size = split.size();
        (split_size < 1 || split_size > 2)) {
      throw general_exception_t{"invalid ip:port => " + resolver};
    }
    if (split.size() == 2) {
      port = std::stoul(split[1]);
    }
    trim(split[0]);
    asio::error_code ec{};
    auto const ip_address = asio::ip::make_address(split[0], ec);
    if (ec) {
      throw general_exception_t{ec.message()};
    }
    asio::ip::udp::endpoint const ep{ip_address, (std::uint16_t)port};
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
