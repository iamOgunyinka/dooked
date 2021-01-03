#pragma once
#include <string>

namespace dooked {

using ucstring = std::basic_string<unsigned char>;
using ucstring_cptr = ucstring::const_pointer;
using ucstring_ptr = ucstring::pointer;

class domainname {
public:
  /*!
   * \brief default constructor
   *
   * This constructor sets the domain name to ".", the root domain.
   */
  domainname();
  ~domainname() {
    if (domain) {
      free(domain);
    }
    domain = nullptr;
  }
  /*!
   * \brief constructor from human-readable text
   *
   * This constructor takes a domain name in human-readable notation, e.g.
   * "www.acdam.net", and an origin. If a relative domain name is given, it
   * will be considered relative to the specified origin.
   * \param text Human-readable domain name
   * \param origin Origin to which relative domain names are relative
   */
  domainname(char const *text, const domainname &origin);

  /*!
   * \brief constructor from human-readable text
   *
   * This constructor takes a domain name in human-readable notation, e.g.
   * "www.acdam.net", and optionally an origin. The origin is in the binary
   * _domain format as found in DNS messages. In case of a relative domain
   * name, it is considered relative to this origin (or to the root domain, if
   * no origin is given).
   * \param text Human-readable domain name
   * \param origin Origin, in binary format, to which relative domain names are
   *               relative
   */
  domainname(char const *text, ucstring_cptr origin = (ucstring_cptr) "");

  /*!
   * \brief constructor from data in a DNS message
   *
   * This constructor takes a DNS message, stored in a message_buff structor,
   * and an offset in this message where the domain name is to begin. This
   * function will decompress the domain name if nessecary.
   * \param buff A DNS message
   * \param ix Offset in the DNS message
   */

  domainname(ucstring &buff, int ix);

  /*!
   * \brief constructor from binary domain name
   *
   * This constructor takes a domain name in binary form. Since a domain name
   * in binary form is a char *, just like a human-readable domain name, this
   * contructor takes a boolean value as well to prevent it from being
   * ambiguous. The value of the boolean is silently ignored.
   * \param is_binary Ignored
   * \param  The binary domain name
   */
  domainname(bool is_binary, ucstring_cptr dom);

  /*!
   * \brief copy constructor
   *
   * This constructor just copies the given domainname structore.
   * \param nam The domain name
   */
  domainname(const domainname &nam);

  /*!
   * \brief equality test
   *
   * Tests whether the two domain names are the same. Comparison is done in
   * a case-insensitive way.
   * \param nam Domain name to compare with
   * \return True if the domain names are the same
   */
  bool operator==(const domainname &nam) const;

  /*!
   * \brief negatice equality test
   *
   * Tests whether the two domain names are the same. Comparison is done in
   * a case-insensitive way.
   * \param nam Domain name to compare with
   * \return True if the domain names are not the same
   */
  bool operator!=(const domainname &nam) const;

  /*!
   * \brief assignment
   *
   * Assigns another domain name
   * \param nam The domain name to assign
   * \return The assigned domain name
   */
  domainname &operator=(const domainname &nam);

  /*!
   * \brief assignment from human-readable text
   *
   * Assigns another domain name, given in human-readable text. Relative
   * domain names are considered relative to the root domain
   * \param buff The domain name in human-readable text
   * \return The assigned domain name
   */
  domainname &operator=(char const *buff);

  /*!
   * \brief concatenation using +=
   *
   * Appends another domain name to the current domain name. The current
   * domain name becomes a child domain of the appended domain name, for
   * example, domainname("www") += domainname("acdam.net") would become
   * \p www.acdam.net.
   * \param dom Domain name to append
   * \return The resulting domain name
   * \sa #operator+
   */
  domainname &operator+=(const domainname &dom);
  /*!
   * \brief concatenation using +
   *
   * Appends two domain names, returning a third. The first domain name
   * becomes a child domain of the second one.
   * \param dom The domain name to append
   * \return The result of the concaternation.
   */
  domainname &operator+(const domainname &dom);

  /*!
   * \brief parent-child test
   *
   * Tests whether we are the child domain of the given domain name. This
   * function also returns true if the child and parent domains are the same.
   * \param dom Domain name to test
   * \return True if we are the parent
   * \sa operator>
   */
  bool operator>=(const domainname &dom) const;

  /*!
   * \brief parent-child test
   *
   * Tests whether we are the child domain of the given domain name. Returns
   * false if the child and parent domain names given are the same.
   * \param dom Domain name to test
   * \return True if we are the parent
   * \sa operator>=
   */
  bool operator>(const domainname &dom) const;

  /*!
   * \brief length of binary representation
   *

   * Returns the length, in bytes, also counting the terminating \r \0
   * character, of the binary representation of the domain name.
   * \return Length of binary representation
   */
  int len() const;

  /*!
   * \brief convert to human-readable string
   *
   * Converts the domain name to a human-readable string. The string will
   * always have a trailing dot.
   * \return Human-readable domain name
   * \sa tocstr()
   */
  std::string tostring() const;

  /*!
   * \brief convert to human-readable character array
   *
   * Converts the domain name to a human-readable character array. It will
   * also have a trailing dot. This is static data, so if you want a copy,
   * use a strdup().
   * \sa tostring()
   */
  ucstring_cptr cstr() const;
  /*!
   * \brief number of labels of the domain name
   *
   * Returns the number of labels in the domain name, also counting the root
   * \p '\0' label at the end,
   * \return Number of labels
   * \sa label()
   */
  int nlabels() const;

  /*!
   * \brief label in domain name
   *
   * Returns a label in the domain name. This is just plain human-readable
   * text. It does not contain dots.
   * \param Label index (0 <= ix < nlabels())
   * \return The label at the specified index
   * \sa nlabels()
   */
  std::string label(int ix) const;

  /*!
   * \brief domain-name portion
   *
   * Returns the portion of the domain name from the label specified by ix.
   * \param ix Label index (inclusive)
   * \return The domain name portion
   * \sa nlabels(), to()
   */
  domainname from(int ix) const;

  /*!
   * \brief domain-name portion
   *
   * Returns a domain name consisting of the first \c label labels of the given
   * domain name.
   * \param labels Number of labels
   * \return The domain name portion
   * \sa from()
   */
  domainname to(int labels) const;

  /*!
   * \brief return relative representation
   *
   * Returns a string representation of the domain name, relative to the given
   * origin. If the domain is not a child of the given root, the complete,
   * absolte domain name is returned. If we are the domain name queried
   * itself, an "@" is returned.
   * \param Domain name this domain is relative to
   * \return Relative string representation
   * \sa tostring()
   */
  std::string to_rel_string(const domainname &root) const;

  /*!
   * \brief check label match count
   *
   * Returns the number of labels the two domain names have in common at their
   * ends; for example this returns 2 for \c www.acdam.net and
   * \c www.foo.acdam.net .
   * \param dom The domain name to check with
   * \return Number of common labels
   * \sa nlabels()
   */
  int ncommon(const domainname &dom) const;

private:
  ucstring_ptr domain;
};

int txt_to_ip(unsigned char ip[4], char const *, bool do_portion = false);
int txt_to_ipv6(unsigned char ipv6[16], char const *buff,
                bool do_portion = false);
void domfromlabel(ucstring_ptr dom, char const *label, int len = -1);
void txt_to_dname(ucstring_ptr target, char const *src,
                  ucstring_cptr origin = nullptr);
int domlen(ucstring_cptr dom);
} // namespace dooked
