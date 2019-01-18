#pragma once

#include <botan/rng.h>

#include "c3/upsilon/csprng.hpp"

namespace c3::upsilon {
  // I know this sort of loops round, but it will make code modification easier
  class csprng_wrapper : public Botan::RandomNumberGenerator {
  public:
    void add_entropy(const uint8_t*, size_t) override {}
    void clear() override {}
    bool is_seeded() const override { return false; }
    void randomize(uint8_t* output, size_t len) override {
      std::generate(output, output + len, csprng::standard);
    }
    std::string name() const override { return "upsilon_csprng"; }

  public:
    static thread_local csprng_wrapper standard;
  };
}
