# dooked
A reconnaissance tool ... 
## Installation
- Download Boost Library from the [official website](https://www.boost.org/users/download/)
- Extract the library into any directory
- Set the environment variable BOOST_ROOT to the location of Boost
- `cd` into the directory containing `dooked` and run `cmake .` to generate the `Makefile`
- Run `make` on the `Makefile` and that is all.

## Requirements
- Boost C++ library
- cmake
- any C++ compiler (supporting C++17) or MSVC(for Windows).

## Usage

For comprehensive help:

```> dooked --help```

```
> cat names.txt
web.facebook.com
google.com

> cat resolvers.txt
1.1.1.1
8.8.8.8

// the next two commands uses the default resolver: 8.8.8.8
// when --input is not given, it expects input via stdin

> cat names.txt | ./dooked -o foo.json

// same as above
> ./dooked -i names.txt -o foo.json

// use the resolvers in resolvers.txt
> ./dooked -i names.txt -r resolvers.txt

// -f(file type) defaults 0(text file), -f is 1, it changes the expected file
// type to JSON, -f 2 means unknown(dooked will try to figure it out)

> ./dooked -i names.json -f 1 -o new_names.json

> cat names.json | ./dooked -t 1 -o new_names.json
```