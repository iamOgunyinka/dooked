#define CATCH_CONFIG_MAIN
#include "../dooked/include/utils.hpp"
#include <catch.hpp>

namespace dooked {
using ucstring_ptr = unsigned char *;
using ucstring_cptr = unsigned char const *;

void *memdup(const void *src, int len) {
  if (len == 0) {
    return nullptr;
  }
  void *ret = malloc(len);
  memcpy(ret, src, len);
  return ret;
}

int domlen(ucstring_cptr dom) {
  int len = 1;
  while (*dom) {
    if (*dom > 63) {
      throw std::runtime_error("Unknown domain nibble");
    }
    len += *dom + 1;
    dom += *dom + 1;
    if (len > 255) {
      throw std::runtime_error("Length too long");
    }
  }
  return len;
}

ucstring_ptr domdup(ucstring_cptr dom) {
  return static_cast<ucstring_ptr>(memdup(dom, domlen(dom)));
}

#define DNS__16BIT(p)                                                          \
  ((unsigned short)((unsigned int)0xffff &                                     \
                    (((unsigned int)((unsigned char)(p)[0]) << 8U) |           \
                     ((unsigned int)((unsigned char)(p)[1])))))
/*
 * Macro DNS__32BIT reads a network long (32 bit) given in network
 * byte order, and returns its value as an unsigned int.
 */
#define DNS__SET16BIT(p, v)                                                    \
  (((p)[0] = (unsigned char)(((v) >> 8) & 0xff)),                              \
   ((p)[1] = (unsigned char)((v)&0xff)))

#if 0
     /* we cannot use this approach on systems where we can't access 16/32 bit
        data on un-aligned addresses */
#define DNS__16BIT(p) ntohs(*(unsigned short *)(p))
#define DNS__32BIT(p) ntohl(*(unsigned long *)(p))
#define DNS__SET16BIT(p, v) *(unsigned short *)(p) = htons(v)
#define DNS__SET32BIT(p, v) *(unsigned long *)(p) = htonl(v)
#endif

#define ARES_ENOMEM 15
#define ARES_EBADNAME 8
#define HEADER_FIXED_SZ 12
#define QFIXEDSZ 4
#define MAXCDNAME 255
#define MAXLABEL 63
#define QUERY 0
#define T_OPT 41
#define EDNSFIXEDSZ 11

/* Macros for constructing a DNS header */
#define DNS_HEADER_SET_QID(h, v) DNS__SET16BIT(h, v)
#define DNS_HEADER_SET_OPCODE(h, v) ((h)[2] |= (unsigned char)(((v)&0xf) << 3))
#define DNS_HEADER_SET_RD(h, v) ((h)[2] |= (unsigned char)((v)&0x1))
#define DNS_HEADER_SET_RCODE(h, v) ((h)[3] |= (unsigned char)((v)&0xf))
#define DNS_HEADER_SET_QDCOUNT(h, v) DNS__SET16BIT((h) + 4, v)
#define DNS_HEADER_SET_ANCOUNT(h, v) DNS__SET16BIT((h) + 6, v)
#define DNS_HEADER_SET_NSCOUNT(h, v) DNS__SET16BIT((h) + 8, v)

/* Macros for constructing the fixed part of a DNS question */
#define DNS_QUESTION_SET_TYPE(q, v) DNS__SET16BIT(q, v)
#define DNS_QUESTION_SET_CLASS(q, v) DNS__SET16BIT((q) + 2, v)

int create_query(const char *name, int type, unsigned short id,
                 unsigned char *bufp, int *buflenp) {
  unsigned char *q;
  const char *p;
  size_t buflen;

  /* Set our results early, in case we bail out early with an error. */
  *buflenp = 0;

  /* Allocate a memory area for the maximum size this packet might need. +2
   * is for the length byte and zero termination if no dots or ecscaping is
   * used.
   */
  size_t len = strlen(name) + 18; // 2 + 12 + 4
  std::memset(bufp, 0, len);

  /* Set up the header. */
  q = bufp;
  memset(q, 0, 12); // zero-out the first 12 bytes
  DNS_HEADER_SET_QID(q, id);
  DNS_HEADER_SET_OPCODE(q, QUERY);
  DNS_HEADER_SET_RD(q, 1);
  DNS_HEADER_SET_QDCOUNT(q, 1);

  /* A name of "." is a screw case for the loop below, so adjust it. */
  if (strcmp(name, ".") == 0)
    name++;

  /* Start writing out the name after the header. */
  q += HEADER_FIXED_SZ;

  while (*name) {
    if (*name == '.')
      return ARES_EBADNAME;

    /* Count the number of bytes in this label. */
    len = 0;
    for (p = name; *p && *p != '.'; p++) {
      if (*p == '\\' && *(p + 1) != 0)
        p++;
      len++;
    }
    if (len > MAXLABEL)
      return ARES_EBADNAME;

    /* Encode the length and copy the data. */
    *q++ = (unsigned char)len;
    for (p = name; *p && *p != '.'; p++) {
      if (*p == '\\' && *(p + 1) != 0)
        p++;
      *q++ = *p;
    }

    /* Go to the next label and repeat, unless we hit the end. */
    if (!*p)
      break;
    name = p + 1;
  }

  /* Add the zero-length label at the end. */
  *q++ = 0;

  /* Finish off the question with the type and class. */
  DNS_QUESTION_SET_TYPE(q, type);
  DNS_QUESTION_SET_CLASS(q, 1); // DNS Class IN

  q += QFIXEDSZ;
  buflen = (q - bufp);

  /* Reject names that are longer than the maximum of 255 bytes that's
   * specified in RFC 1035 ("To simplify implementations, the total length of
   * a domain name (i.e., label octets and label length octets) is restricted
   * to 255 octets or less."). */
  if (buflen > (size_t)(MAXCDNAME + HEADER_FIXED_SZ + QFIXEDSZ)) {
    return ARES_EBADNAME;
  }

  /* we know this fits in an int at this point */
  *buflenp = (int)buflen;
  return 0;
}
} // namespace dooked

namespace foo {
using ucstring = std::basic_string<unsigned char>;

template <typename Value>
constexpr void set_16bit_value(unsigned char *p, Value const value) {
  p[0] = static_cast<unsigned char>((value >> 8) & 0xFF);
  p[1] = static_cast<unsigned char>(value & 0xFF);
}

template <typename Value>
constexpr void set_qid(unsigned char *p, Value const value) {
  set_16bit_value(p, value);
}

template <typename T, typename V>
constexpr void set_opcode(T &target, V const &value) {
  target[2] |= static_cast<unsigned char>((value & 0xF) << 3);
}

template <typename T, typename V>
constexpr void set_opcode_rd(T &target, V const &value) {
  target[2] |= static_cast<unsigned char>(value & 0x1);
}

template <typename T, typename V>
constexpr void set_rcode(T &target, V const &value) {
  target[3] |= (value & 0xF);
}

template <typename V>
constexpr void set_qd_count(unsigned char *t, V const &v) {
  set_16bit_value(t + 4, v);
}

template <typename V>
constexpr void set_an_count(unsigned char *t, V const &v) {
  set_16bit_value(t + 6, v);
}

template <typename V>
constexpr void set_ns_count(unsigned char *t, V const &v) {
  set_16bit_value(t + 8, v);
}

template <typename V>
constexpr void set_question_type(unsigned char *t, V const &v) {
  set_16bit_value(t, v);
}

template <typename V>
constexpr void set_question_class(unsigned char *t, V const &v) {
  set_16bit_value(t + 2, v);
}

void set_dns_header_value(ucstring::value_type *q, std::uint16_t id) {
  set_qid(q, id);
  set_opcode(q, 0);    // set opcode to 'Query' type
  set_opcode_rd(q, 1); // set the RD flag to 1.
  set_qd_count(q, 1);
}

void create_query(std::string const &name, std::uint16_t record_type,
                  std::uint16_t request_id, ucstring &buffer) {

  constexpr static auto const max_cd_name = 255;
  constexpr static auto const max_header_size = 12;
  constexpr static auto const max_question_size = 4;
  constexpr static auto const max_label = 63;
  constexpr static auto const max_size =
      max_cd_name + max_header_size + max_question_size;

  // (query_id=2bytes, header=12bytes, question "body" = 4) == 18
  size_t len = name.size() + 18;
  buffer.resize(len, 0);

  /* Set up the header. */
  set_dns_header_value(&buffer[0], request_id);

  auto domain_name = name.c_str();
  /* A name of "." is a screw case for the loop below, so adjust it. */
  if (strcmp(domain_name, ".") == 0) {
    domain_name++;
  }

  unsigned char *question = &buffer[0] + max_header_size;
  /* Start writing out the name after the header. */
  const char *p = nullptr;

  while (*domain_name) {
    if (*domain_name == '.') {
      throw std::runtime_error{domain_name};
    }

    /* Count the number of bytes in this label. */
    len = 0;
    for (p = domain_name; *p && *p != '.'; p++) {
      if (*p == '\\' && *(p + 1) != 0) {
        p++;
      }
      len++;
    }
    if (len > max_label) {
      throw std::runtime_error{domain_name};
    }

    /* Encode the length and copy the data. */
    *question++ = (unsigned char)len;
    for (p = domain_name; *p && *p != '.'; p++) {
      if (*p == '\\' && *(p + 1) != 0) {
        p++;
      }
      *question++ = *p;
    }

    /* Go to the next label and repeat, unless we hit the end. */
    if (!*p) {
      break;
    }
    domain_name = p + 1;
  }

  /* Add the zero-length label at the end. */
  *question++ = 0;

  /* Finish off the question with the type and class. */
  set_question_type(question, record_type);
  set_question_class(question, 1); // class IN

  question += max_question_size;
  std::size_t const buflen = (question - (&buffer[0]));

  /* Reject names that are longer than the maximum of 255 bytes that's
   * specified in RFC 1035 ("To simplify implementations, the total length of
   * a domain name (i.e., label octets and label length octets) is restricted
   * to 255 octets or less."). */
  if (buflen > max_size) {
    throw std::runtime_error{domain_name};
  }

  /* we know this fits in an int at this point */
  buffer.resize(buflen);
}

} // namespace foo

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

  using dooked::get_file_extension;
  using dooked::is_json_file;
  using dooked::is_text_file;

  SECTION("Testing filenames without extension") {
    auto const extension = get_file_extension(filename_wo_extension);
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
    auto const extension = get_file_extension(filename_with_extension);
    REQUIRE(is_json_file(extension));
    REQUIRE(!is_text_file(extension));
  }

  SECTION("Testing different creation of question query") {
    auto const domain = "google.com";
    int query_len = 0;
    unsigned char query_buffer[2048];
    int const len =
        dooked::create_query(domain, 1, 123, query_buffer, &query_len);
    foo::ucstring result{};
    foo::create_query(domain, 1, 123, result);

    int const comp_result = memcmp((void const *)query_buffer,
                                   (void const *)result.data(), query_len);

    REQUIRE(query_len == result.size());
    REQUIRE(comp_result == 0);
  }
}
