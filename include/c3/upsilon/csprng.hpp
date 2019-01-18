#pragma once

#include <random>
#include <memory>

namespace c3::upsilon {
  // A URBG compatible with C++'s `random` header
  class csprng {
  public:
    class impl;

  private:
    std::shared_ptr<impl> _impl;

  public:
    using result_type = uint8_t;

    static constexpr result_type min() { return std::numeric_limits<result_type>::min(); }
    static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }

  public:
    csprng();
    ~csprng();

    result_type operator()();

  public:
    static thread_local csprng standard;
  };
}
