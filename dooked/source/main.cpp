#include "cli_preprocessor.hpp"
#include <CLI/CLI.hpp>

// we've tried as much as possible to stay away from global variables but
// in this case, we need to pass this variable down a long long stack of
// calls and parameterizing a simple bool just isn't worth it and since
// it is always set and never changes, guess we can swing this.

bool no_bytes_count = false;

int main(int argc, char **argv) {
  CLI::App app{"dooked -- a CLI tool to enumerate DNS info"};
  dooked::cli_args_t cli_args{};

  app.add_option("-o,--output", cli_args.output_filename,
                 "write result to output file");
  app.add_option(
      "-f,--file-type", cli_args.file_type,
      "the file type used as input file: (default)txt=0, txt=1, unknown=2");
  app.add_option(
      "-i,--input-file", cli_args.input_filename,
      "if not using stdin, this is the input file to use, type is deduceable "
      "by file extension or file type returned by linux's `file`");
  app.add_option("-l,--resolver-list", cli_args.resolver_filename,
                 "a filename consisting of IP addresses to resolve names");
  app.add_option("-r,--resolver", cli_args.resolver,
                 "a (possible) list of resolvers separated by comma. If -l "
                 "and -r isn't specified, -r is defaulted to 8.8.8.8");
  app.add_option("-t,--threads", cli_args.thread_count,
                 "total threads to use(default: " +
                     std::to_string(DOOKED_SUPPORTED_THREADS) + ")");
  app.add_option(
      "-c,--content-length", cli_args.content_length,
      "show content lengths that changed more than --content-length");
  app.add_flag("-d,--include-date", cli_args.include_date,
               "append present datetime(-ddMMyyyy_hhmmss) in output name");
  app.add_flag(
      "--defer", cli_args.post_http_request,
      "defers http request until after all DNS requests have been completed");
  app.add_flag("--nbc", no_bytes_count,
               "in case `content-length` is missing in an HTTP header field,"
               "program returns 0 as the content-length as opposed the total"
               "bytes returned from the call to I/O socket read");

  CLI11_PARSE(app, argc, argv);
  dooked::run_program(cli_args);
  return 0;
}
