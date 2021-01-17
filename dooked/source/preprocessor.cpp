#include "preprocessor.hpp"
#include <asio/io_context.hpp>
#include <asio/thread_pool.hpp>
#include <random>
#include <set>
#include <thread>

namespace dooked {
char get_random_char() {
  static std::random_device rd{};
  static std::mt19937 gen{rd()};
  static std::uniform_int_distribution<> uid(0, 52);
  static char const *all_alphas =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
  return all_alphas[uid(gen)];
}

std::string get_random_string(std::uint16_t const length) {
  std::string result{};
  result.reserve(length);
  for (std::size_t i = 0; i != length; ++i) {
    result.push_back(get_random_char());
  }
  return result;
}

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
  // previous data is already sorted.
  // current data is a pre-sorted data.
  auto const &current_data_map = current_result.cresult();
  auto const end_iter = previous_result.cend();
  auto const domain_comparator = jd_domain_comparator_t{};

  for (auto iter = previous_result.cbegin(); iter < end_iter;) {
    auto const current_find_iter = current_data_map.find(iter->domain_name);
    if (current_find_iter == current_data_map.end()) {
      continue;
    }
    auto const &current_domain_info_list = current_find_iter->second;
    auto const last_elem_iter =
        std::upper_bound(iter, end_iter, *iter, domain_comparator);
    auto const previous_total_elem = std::distance(iter, last_elem_iter);
    auto const current_total_elem = current_domain_info_list.size();

    // something is missing
    if (current_total_elem < previous_total_elem) {
      for (auto start_iter = iter; start_iter != last_elem_iter; ++start_iter) {
        bool const found = std::binary_search(
            current_domain_info_list.cbegin(), current_domain_info_list.cend(),
            *start_iter, [](auto const &a, auto const &b) {
              return a.type == b.type && a.rdata == b.rdata;
            });
        if (!found) {
          spdlog::info("[{}][{}] missing.", iter->domain_name,
                       dns_record_type2str(start_iter->type));
        }
      }
      // information may have been changed
    } else if (current_total_elem == previous_total_elem) {
      std::vector<dns_record_t> newly_detected{};
      for (auto start_iter = iter; start_iter != last_elem_iter; ++start_iter) {
        auto const eq_range = std::equal_range(
            current_domain_info_list.begin(), current_domain_info_list.end(),
            *start_iter,
            [](auto const &a, auto const &b) { return a.type < b.type; });
        auto const find_iter =
            std::find_if(eq_range.first, eq_range.second,
                         [&val = *start_iter](dns_record_t const &record) {
                           return val.rdata == record.rdata;
                         });
        // one of the previous record wasn't found
        if (find_iter == eq_range.second) {
          if (std::distance(eq_range.first, eq_range.second) == 1) {
            spdlog::info("[{}][{}] changed from `{}` to `{}`",
                         iter->domain_name,
                         dns_record_type2str(start_iter->type),
                         start_iter->rdata, eq_range.first->rdata);
          } else {
            spdlog::info(
                "[{}][{}] seems `{}` has been removed", iter->domain_name,
                dns_record_type2str(start_iter->type), start_iter->rdata);
          }
        }
      }
    } else {
      // or new information added
      for (auto const &current_elem : current_domain_info_list) {
        bool const found =
            std::binary_search(iter, last_elem_iter, current_elem,
                               [](auto const &a, auto const &b) {
                                 return a.type == b.type && a.rdata == b.rdata;
                               });
        if (!found) {
          spdlog::info("[{}][{}] added.", iter->domain_name,
                       dns_record_type2str(current_elem.type));
        }
      }
    }
    iter = last_elem_iter;
  }
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
  for (auto const &result_pair : result_map.cresult()) {
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
                    std::size_t const socket_count) {
  std::vector<std::unique_ptr<custom_resolver_socket_t>> sockets{};
  sockets.resize(socket_count);
  for (std::size_t i = 0; i < socket_count; ++i) {
    sockets[i] = std::make_unique<custom_resolver_socket_t>(
        io_context, *rt_args.names, *rt_args.resolvers, result_map);
    sockets[i]->start();
  }
  io_context.run();
}

bool process_text_file(std::string const &input_filename,
                       runtime_args_t &rt_args) {
  auto domain_names = get_names<std::string>(input_filename);
  if (domain_names && !domain_names->empty()) {
    rt_args.names.emplace();
    for (auto const &domain_name : *domain_names) {
      rt_args.names->push_back({domain_name});
    }
  } else {
    spdlog::error("There was an error trying to get input file");
    return false;
  }
  return true;
}

bool process_json_file(std::string const &input_filename,
                       runtime_args_t &rt_args) {
  rt_args.previous_data =
      get_names<json_data_t>(input_filename, file_type_e::json_type);
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
    spdlog::error("There was an error trying to get input file");
    return false;
  }
  return true;
}

// most likely from stdin
bool determine_unknown_file(cli_args_t const &cli_args,
                            runtime_args_t &rt_args) {
  bool const using_stdin = cli_args.input_filename.empty();
  if (!using_stdin) {
    return false;
  }
  auto const filename = std::filesystem::temp_directory_path() /
                        get_random_string(get_random_integer());
  std::ofstream temp_file{filename};
  if (!temp_file) {
    spdlog::error("unable to open temporary file");
    return false;
  }
  std::string line{};
  while (std::getline(std::cin, line)) {
    temp_file << line;
  }
  auto const file_type = get_file_type(filename);
  std::error_code ec{};
  // read the file and remove the temporary file thereafter
  if (is_text_file(file_type)) {
    return (process_text_file(filename.string(), rt_args) &&
            std::filesystem::remove(filename, ec));
  } else if (is_json_file(file_type)) {
    return process_json_file(filename.string(), rt_args) &&
           std::filesystem::remove(filename, ec);
  }
  return false;
}

bool read_input_file(cli_args_t const &cli_args, runtime_args_t &rt_args) {
  bool const using_stdin = cli_args.input_filename.empty();
  if (using_stdin) {
    auto const file_type = static_cast<file_type_e>(cli_args.file_type);
    if (file_type == file_type_e::txt_type) {
      return process_text_file(cli_args.input_filename, rt_args);
    } else if (file_type == file_type_e::json_type) {
      return process_json_file(cli_args.input_filename, rt_args);
    }
    return determine_unknown_file(cli_args, rt_args);
  }

  auto const file_type = get_file_type(cli_args.input_filename);
  if (is_text_file(file_type)) {
    return process_text_file(cli_args.input_filename, rt_args);
  } else if (is_json_file(file_type)) {
    return process_json_file(cli_args.input_filename, rt_args);
  }
  return false;
}

void start_name_checking(runtime_args_t &&rt_args) {
  auto const native_thread_count = (std::min)(
      rt_args.names->size(), (std::size_t)std::thread::hardware_concurrency());
  asio::io_context io_context((int)native_thread_count);

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
    auto &previous_data = *rt_args.previous_data;

    // sort the (domain)names in alphabetical order first
    std::sort(previous_data.begin(), previous_data.end(),
              [](json_data_t const &a, json_data_t const &b) {
                return std::tie(a.domain_name, a.type) <
                       std::tie(b.domain_name, b.type);
              });
    /*
    // then sort each (domain) names based on the record type(A, AAAA...)
    auto iter_start = previous_data.begin();
    auto const iter_end = previous_data.end();
    while (iter_start < iter_end) {
      auto new_iter = std::upper_bound(
          iter_start, iter_end, *iter_start,
          [](json_data_t const &first, json_data_t const &second) {
            return first.domain_name < second.domain_name;
          });
      std::sort(iter_start, new_iter,
                [](json_data_t const &a, json_data_t const &b) {
                  return a.query_type < b.query_type;
                });
      iter_start = new_iter;
    }
    */

    auto &result = result_map.result();
    for (auto &res : result) {
      std::sort(res.second.begin(), res.second.end(),
                [](dns_record_t const &a, dns_record_t const &b) {
                  return std::tie(a.type, a.rdata) < std::tie(b.type, b.rdata);
                });
    }
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

  // read input file
  if (!read_input_file(cli_args, rt_args)) {
    return;
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

  // convert strings to UDP endpoints
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
