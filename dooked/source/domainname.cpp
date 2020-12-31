#include "domainname.hpp"
#include "utils.hpp"

namespace dooked {
constexpr int const domain_len = 0xFF;
constexpr int const domlabel_len = 63;

template <typename T> constexpr auto hexfromint(T hex) {
  return (((hex) < 10) ? (hex) + '0' : ((hex)-10) + 'a');
}

void domcat(_domain res, _cdomain src) {
  int lenres = domlen(res), lensrc = domlen(src);
  if (lenres + lensrc - 1 > domain_len) {
    throw general_exception_t("Domain name too long");
  }
  memcpy(res + lenres - 1, src, lensrc);
}

void domfromlabel(_domain dom, const char *label, int len) {
  if (len == -1) {
    len = strlen(label);
  }
  if (len > domlabel_len) {
    throw general_exception_t(std::string("Domain name label ") + label +
                              " too long");
  }
  dom[0] = len;
  memcpy(dom + 1, label, len);
  dom[len + 1] = '\0';
}

int txt_to_ip(unsigned char ip[4], const char *_buff, bool do_portion) {
  char *buff = (char *)_buff;
  int p = 0, tmp = 0, node = 0;
  if (strcmpi(buff, "any") == 0) {
    ip[0] = 0;
    ip[1] = 0;
    ip[2] = 0;
    ip[3] = 0;
    return 4;
  } else if (strcmpi(buff, "local") == 0) {
    ip[0] = 127;
    ip[1] = 0;
    ip[2] = 0;
    ip[3] = 1;
    return 4;
  } else if (strcmpi(buff, "none") == 0) {
    ip[0] = 255;
    ip[1] = 255;
    ip[2] = 255;
    ip[3] = 255;
  }
  ip[0] = 0;
  ip[1] = 0;
  ip[2] = 0;
  ip[3] = 0;
  while (buff[p] != '\0') {
    if (isdigit(buff[p])) {
      node *= 10;
      node += buff[p] - '0';
      if (node > 255) {
        throw general_exception_t("IP node value exceeds 255");
      }
    } else if (buff[p] == '*') {
      if (do_portion) {
        return tmp;
      } else {
        return 4;
      }
    } else {
      if (buff[p] == '.') {
        if (buff[p + 1] == '.') {
          throw general_exception_t("Expecting some value after dot");
        } else if (buff[p + 1] == '\0')
          break;
        if (tmp >= 3) {
          throw general_exception_t("More than three dots in IP number");
        }
        ip[tmp++] = (char)node;
        node = 0;
      } else {
        throw general_exception_t("Unknown character in IP number");
      }
    }
    p++;
  }
  ip[tmp++] = (unsigned char)node;
  if (tmp != 4 && !do_portion) {
    throw general_exception_t("Not enough nodes in IP number");
  }
  return tmp;
}

char incr_mask[8] = {0, 128, 192, 224, 240, 248, 252, 254};

int domlen(ucstring_cptr dom) {
  int len = 1;
  while (*dom) {
    if (*dom > 63) {
      throw general_exception_t("Unknown domain nibble");
    }
    len += *dom + 1;
    dom += *dom + 1;
    if (len > 255) {
      throw general_exception_t("Length too long");
    }
  }
  return len;
}

/* converts a buffer to a long numeric value, with postfix (e.g. 68K->68*1024)
 * support */
int txt_to_int_internal(const char *_buff, bool support_negative) {
  char *buff = (char *)_buff;
  int val = 0, tmpval = 0;
  bool neg = false;
  bool have_digit = false;
  if (*buff == '-') {
    if (!support_negative) {
      throw general_exception_t(std::string("Negative number not supported: ") +
                                _buff);
    }
    neg = true;
    buff++;
  }
  while (1) {
    if (*buff >= '0' && *buff <= '9') {
      tmpval *= 10;
      tmpval += *buff - '0';
      have_digit = true;
    } else {
      if (*buff == '\0') {
        val += tmpval;
        if (!have_digit) {
          throw general_exception_t(std::string("Incorrect numeric value ") +
                                    _buff);
        }
        return neg ? -val : val;
      }
      if (*buff == 'K') {
        tmpval *= 1024;
      } else if (*buff == 'M') {
        tmpval *= 1048576;
      } else if (*buff == 'G') {
        tmpval *= 1073741824;
      } else if (*buff == 's') {
      } else if (*buff == 'm') {
        tmpval *= 60;
      } else if (*buff == 'h') {
        tmpval *= 3600;
      } else if (*buff == 'd') {
        tmpval *= 86400;
      } else if (*buff == 'w') {
        tmpval *= 604800;
      } else if (*buff == 'y') {
        tmpval *= 31536000;
      } else {
        throw general_exception_t("Incorrect numeric value " +
                                  std::string(_buff));
      }
      val += tmpval;
      tmpval = 0;
    }
    buff++;
  }
}

int txt_to_negint(const char *buff) { return txt_to_int_internal(buff, true); }

int txt_to_int(const char *buff) { return txt_to_int_internal(buff, false); }

int hextoint(char val) {
  if (val >= '0' && val <= '9') {
    return val - '0';
  } else if (val >= 'a' && val <= 'f') {
    return val - 'a' + 10;
  } else if (val >= 'A' && val <= 'F') {
    return val - 'A' + 10;
  } else
    return -1;
}

/* converts a buffer to a 128-bit ipv6 number */
int txt_to_ipv6(unsigned char ipv6[16], const char *buff, bool do_portion) {
  int multigroup_pos = -1;
  int pos = -1;
  int node = 0;      /* the pair we're working on */
  int nodeval = -1;  /* node value */
  int nodestart = 0; /* start pos of node */
  int chval;
  int x;

  memset(ipv6, 0, 16);
  if (strcmpi(buff, ":any") == 0)
    return 16;
  if (strcmpi(buff, ":local") == 0) {
    ipv6[15] = 1;
    return 16;
  }

  while (buff[++pos] != '\0') {
    if (buff[pos] == '.') {
      /* an imbedded ipv4 */
      if (node + 2 > 8) {
        throw general_exception_t("No room for embedded IPv4 in IPv6 address");
      }
      try {
        txt_to_ip(&ipv6[node * 2], &buff[nodestart]);
      } catch (std::exception const &p) {
        throw general_exception_t(
            std::string("Error in embedded IPv4 number: ") + p.what());
      }
      node++;
      if (node == 8) {
        break;
      }
      nodeval = -1;
      break;
    }
    if (buff[pos] == ':') {
      /* write the previous node */
      if (pos) {
        if (nodeval == -1) {
          throw general_exception_t("IPv6 address has empty node value");
        }
        ipv6[node * 2] = nodeval / 256;
        ipv6[node * 2 + 1] = nodeval;
      } else {
        if (buff[pos + 1] != ':') {
          throw general_exception_t("IPv6 address should have ::");
        }
        node--;
      }
      if (buff[pos + 1] == ':') {
        /* we're having a multigroup indicator here */
        multigroup_pos = node + 1;
        pos++;
      }
      node++;
      if (node > 7) {
        throw general_exception_t("IPv6 address has too much nodes");
      }
      nodeval = -1;
      nodestart = pos + 1;
    } else if (buff[pos] == '*') {
      return node * 2;
    } else {
      chval = hextoint(buff[pos]);
      if (chval < 0) {
        throw general_exception_t("Incorrect hex in IPv6 address");
      }
      if (nodeval == -1) {
        nodeval = chval;
      } else {
        nodeval = (nodeval * 16) + chval;
      }
      if (nodeval > 65535) {
        throw general_exception_t("IPv6 node val too large");
      }
    }
  }

  if (nodeval != -1) {
    ipv6[node * 2] = nodeval / 256;
    ipv6[node * 2 + 1] = nodeval;
  } else {
    if (buff[pos - 1] == ':' && buff[pos - 2] != ':') {
      throw general_exception_t("Expected :: in IPv6 address");
    }
  }

  if (multigroup_pos != -1) {
    for (x = 15; x >= 14 - 2 * (node - multigroup_pos); x--) {
      ipv6[x] = ipv6[x - 2 * (7 - node)];
    }
    memset(&ipv6[multigroup_pos * 2], 0, 14 - (2 * node));
  } else {
    if (node < 7) {
      throw general_exception_t("Too less nodes in IPv6 address");
    }
  }

  return 16;
}

void txt_to_ip6range(unsigned char *iprange, const char *val) {
  char buff[128];
  char *ptr;
  int x, z;
  if (strcmpi(val, "any") == 0) {
    memset(iprange, 0, 32);
    return;
  }
  if (strcmpi(val, "none") == 0) {
    memset(iprange, 255, 16);
    memset(iprange + 16, 0, 16);
    return;
  }
  if ((ptr = (char *)strchr(val, '/')) != NULL) {
    if (strchr(ptr, ':')) {
      /* complete IPv6 number */
      txt_to_ipv6(iprange, ptr + 1);
    } else {
      memset(iprange, 0, 16);
      x = txt_to_int(ptr + 1);
      if (x > 128) {
        throw general_exception_t("IPv6 mask value too long");
      }
      for (z = 0; x >= 8; x -= 8) {
        iprange[z++] = 255;
      }
      iprange[z] = incr_mask[x];
    }
    if ((ptr - val) >= (signed)sizeof(buff)) {
      throw general_exception_t("Ip number too long");
    }
    memcpy(buff, val, ptr - val);
    buff[ptr - val] = '\0';
    txt_to_ipv6(iprange + 16, buff);
  } else {
    memset(iprange, 0, 16);
    for (x = txt_to_ipv6(iprange + 16, val, true) - 1; x >= 0; x--)
      iprange[x] = 255;
  }
}

bool ip6range_matches(const unsigned char *iprange, const unsigned char *ip) {
  for (int x = 0; x < 16; x++)
    if ((ip[x] ^ iprange[x + 16]) & iprange[x])
      return false;
  return true;
}

void txt_to_dname(_domain target, const char *src, ucstring const &origin) {
  char *ptr;
  unsigned char label[domain_len];
  unsigned char tmp[16];
  char hex;
  int ttmp, ret;

  if (src[0] == '@' && src[1] == '\0') {
    /* nothing but the origin */
    if (origin.empty()) {
      target[0] = '\0';
    } else {
      memcpy(target, origin.data(), domlen(origin.data()));
    }
    return;
  }

  target[0] = '\0';

  if (src[0] == '.' && src[1] == '\0')
    return;

  while (*src) {
    if (src[0] == '.' && src[1] != '\0') {
      /* our extension: allow .192.168.* and .dead:beef:* */
      if (strchr(src + 1, ':')) {
        if (domlen(target) + 42 >= domain_len) {
          throw ucstring_cptr("IPv6 domainname doesn't fit");
        }
        ret = txt_to_ipv6(tmp, src + 1, true);
        for (ttmp = ret - 1; ttmp >= 0; ttmp--) {
          hex = hexfromint(tmp[ttmp] & 15);
          domfromlabel(target + domlen(target) - 1, &hex, 1);
          hex = hexfromint(tmp[ttmp] / 16);
          domfromlabel(target + domlen(target) - 1, &hex, 1);
        }
        domcat(target, (_domain) "\3ip6\3int");
        return;
      } else {
        /* ipv4 */
        if (domlen(target) + 14 >= domain_len) {
          throw general_exception_t("IPv6 domainname doesn't fit");
        }
        ret = txt_to_ip(tmp, src + 1, true);
        for (ttmp = ret - 1; ttmp >= 0; ttmp--) {
          sprintf((char *)tmp + 4, "%d", tmp[ttmp]);
          domfromlabel(target + domlen(target) - 1, (char *)tmp + 4);
        }
        domcat(target, (_domain) "\7in-addr\4arpa");
        return;
      }
    }

    ptr = (char *)strchr(src, '.');
    if (ptr) {
      if (ptr == src) {
        throw general_exception_t("Zero length label");
      }
      domfromlabel(label, src, ptr - src);
      domcat(target, label);
      src = ptr + 1;
    } else {
      /* end of relative domain name */
      domfromlabel(label, src);
      domcat(target, label);
      if (origin) {
        domcat(target, (_domain)origin);
      }
      return;
    }
  }
}

void txt_to_email(ucstring_ptr target, const char *src,
                  ucstring const &origin) {
  unsigned char dom[0xFF];
  char *cptr;

  if ((cptr = (char *)strchr(src, '@')) != NULL &&
      !(cptr[0] == '@' && cptr[1] == 0)) {
    /* contains a '@', so assume it's an email address */
    if (src[0] == '@') {
      throw invalid_dns_response_t(
          "Incorrect email adress/domain name: begins with @");
    }
    domfromlabel(target, src, cptr - src);
    txt_to_dname(dom, cptr + 1);
    domcat(target, dom);
  } else {
    /* common domain name */
    txt_to_dname(target, src, origin);
  }
}

domainname::domainname() : domain{nullptr} {}

domainname::domainname(char const *string, domainname const &origin) {
  unsigned char tmp[0xFF];

  txt_to_email(tmp, string, origin.domain);
  domain = tmp;
}

domainname::domainname(char const *string, ucstring_cptr origin) {
  unsigned char tmp[0xFF];

  txt_to_email(tmp, string, origin);
  domain = tmp;
}

domainname::domainname(ucstring &buff, int ix) {
  domain = dom_uncompress(buff, ix);
}

domainname::domainname(bool val, ucstring_cptr dom) : domain{dom} {}

domainname::domainname(const domainname &nam) { domain = domdup(nam.domain); }

domainname &domainname::operator=(domainname const &nam) {
  if (this != &nam) {
    domain = nam.domain;
  }

  return *this;
}

domainname &domainname::operator=(char const *buff) {
  unsigned char tmp[0xFF];

  txt_to_dname(tmp, buff, (unsigned char *)"");
  domain = tmp;
  return *this;
}

bool domainname::operator==(domainname const &nam) const {
  return domain == nam.domain;
}

bool domainname::operator!=(const domainname &nam) const {
  return !domcmp(domain, nam.domain);
}

domainname &domainname::operator+=(const domainname &nam) {
  int const lenres = domlen(domain.data());
  int const lensrc = domlen(nam.domain.data());

  if (lenres + lensrc - 1 > 0xFF) {
    throw general_exception_t("Domain name too long");
  }
  domain = (unsigned char *)realloc(domain, lenres + lensrc - 1);
  memcpy(domain + lenres - 1, nam.domain, lensrc);
  return *this;
}

domainname &domainname::operator+(const domainname &nam) {
  domainname *ret = new domainname(*this);
  ret->operator+=(nam);
  return *ret;
}

bool domainname::operator>=(const domainname &dom) const {
  return domisparent(dom.domain, domain);
}

bool domainname::operator>(const domainname &dom) const {
  return !domcmp(dom.domain, domain) && domisparent(dom.domain, domain);
}

_domain domainname::c_str() const {
  if (domain == NULL)
    throw PException("Domain name is empty");
  return domain;
}

int domainname::len() const { return domlen(domain); }

stl_string domainname::tostring() const { return dom_tostring(domain); }

int domainname::nlabels() const { return dom_nlabels(domain); }

stl_string domainname::label(int ix) const { return dom_label(domain, ix); }

domainname domainname::from(int ix) const {
  stl_string ret;
  unsigned char *dom = domain;
  while (ix > 0) {
    if (*dom == 0)
      throw PException("Domain label index out of bounds");
    dom += *dom + 1;
    ix--;
  }
  return domainname(true, dom);
}

domainname domainname::to(int labels) const {
  unsigned char ptr[0xFF];
  domto(ptr, domain, labels);
  return domainname(true, ptr);
}

ucstring domainname::to_rel_string(const domainname &root) const {
  if (*this == root) {
    return "@";
  } else if (*this >= root) {
    ucstring str = to(nlabels() - root.nlabels()).tostring();
    str.resize(str.size() - 1);
    return str;
  }
  return tostring();
}

int domainname::ncommon(const domainname &dom) const {
  return domncommon(domain, dom.domain);
}

} // namespace dooked
