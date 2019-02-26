#pragma once

#include "c3/upsilon/identity.hpp"

namespace c3::upsilon {
  class identity_group {
  public:
    size_t verify_ring(nu::data_const_ref);
    std::vector<size_t> verify_group(nu::data_const_ref);
    identity at(size_t);
  };

  class owned_identity_group {
  public:
    nu::data sign_ring();
    nu::data sign_group();
  };
}
