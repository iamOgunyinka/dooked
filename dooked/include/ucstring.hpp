#pragma once

namespace dooked {

/*
we need a string type that doesn't automatically 
append a '\0' after the sequence.
*/
class ucstring {
  size_t len_{};
  unsigned char *data_ = nullptr;

public:
  using value_type = unsigned char;
  using pointer = value_type *;
  using const_pointer = value_type const *;

public:
  ucstring() {}
  ucstring(const_pointer, size_t);
  ~ucstring() { clear(); }
  pointer data() { return data_; }
  const_pointer cdata() const { return const_cast<const_pointer>(data_); }
  void resize(size_t sz);
  size_t size() const { return len_; }
  void clear();
  value_type &operator[](size_t index) { return data_[index]; }
};

class ucstring_view {
  size_t const len_;
  unsigned char const *data_;

public:
  using value_type = unsigned char const;
  using pointer = value_type *;
  using const_pointer = pointer;

public:
  ucstring_view(const_pointer d, size_t sz) : len_{sz}, data_{d} {}
  ucstring_view(ucstring const &s) : len_{s.size()}, data_{s.cdata()} {}
  size_t size() const { return len_; }
  size_t length() const { return len_; }
  pointer data() const { return data_; }
  const_pointer cdata() const { return data_; }
};
} // namespace dooked
