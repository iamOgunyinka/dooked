// dooked.cpp : This file contains the 'main' function. Program execution begins
// and ends there.
//

#include "utils.hpp"
#include <CLI11.hpp>
#include <json.hpp>

using dooked::cli_args_t;

int main(int argc, char **argv) {
  CLI::App app{"dooked -- a CLI tool to enumerate DNS info"};
  cli_args_t cli_args{};
  app.add_option("-o,--output", cli_args.output_filename,
                 "write result to output file");
  app.add_option(
      "-ft,--file-type", cli_args.file_type,
      "the file type used as input file: stdin=0(default), txt=1, json=2");
  app.add_option(
      "-i,--input-file", cli_args.input_filename,
      "if not using stdin, this is the input file to use, type is deduceable "
      "by file extension or file type returned by linux's `file`");
  CLI11_PARSE(app, argc, argv);

  return 0;
}
