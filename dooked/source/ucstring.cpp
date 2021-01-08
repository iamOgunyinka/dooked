#include "ucstring.hpp"
#include <cstring>

namespace dooked {
void ucstring::resize(size_t const sz) {
  if (sz == len_)
    return;
  if (sz > len_) {
    pointer temp = new unsigned char[sz]{};
    if (len_ > 0) {
      memcpy((void *)temp, (void const *)data_, len_);
      delete[] data_;
    }
    data_ = temp;
  }
  len_ = sz;
}

void ucstring::clear() {
  if (data_) {
    delete[] data_;
  }
  len_ = 0;
  data_ = nullptr;
}

ucstring::ucstring(const_pointer data, size_t const len)
    : len_{len}, data_{new unsigned char[len_]{}} {
  memcpy((void *)data_, (void const *)data, len);
}
} // namespace dooked
