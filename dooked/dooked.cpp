// dooked.cpp : This file contains the 'main' function.
// let's keep as simple a file as it can get

#include "preprocessor.hpp"
#include <CLI11.hpp>

int main(int argc, char **argv) {
  CLI::App app{"dooked -- a CLI tool to enumerate DNS info"};
  dooked::cli_args_t cli_args{};

  app.add_option("-o,--output", cli_args.output_filename,
                 "write result to output file");
  app.add_option(
      "-t,--file-type", cli_args.file_type,
      "the file type used as input file: (default)txt=0, txt=1, unknown=2");
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

  CLI11_PARSE(app, argc, argv);

  dooked::run_program(cli_args);
  return 0;
}
