#pragma once

#include "c3/upsilon/hash.hpp"

namespace c3::upsilon {
  template<size_t HashSize>
  class pow {
  public:
    hash_algorithm halg;
    hash<HashSize> proof;
    uint64_t nonce;
  };
}
