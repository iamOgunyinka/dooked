# dooked

## Installation
The program is self-sufficient and do not need external libraries.

Requirements: cmake, make, a C++ compiler (supporting C++17), or MSVC(Windows).

```
> cmake .
> make
```

## Usage
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

// -t(file type) defaults 0(text file), -t is 1, it changes the expected file
// type to JSON, -t 2 means unknown(dooked will try to figure it out)

> ./dooked -i names.json -t 1 -o new_names.json

> cat names.json | ./dooked -t 1 -o new_names.json
```
