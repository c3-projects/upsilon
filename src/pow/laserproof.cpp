#pragma once

#include "c3/upsilon/pow.hpp"

//! Laserproof: a self-scaling memory-hard PoW function
//!
//!

namespace c3::upsilon {
  class laserproof_verifier : public pow_verifier {
  public:
    static constexpr size_t proof_len = 32;

  public:
    nu::data difficulty(nu::data_const_ref hashed_data,
                        nu::data_const_ref proof) const noexcept override {
      try {
        if (proof.size() != proof_len)
          throw std::runtime_error("Proof size incorrect");

        // Perform the expansion

      }
      catch (...) {
        return {};
      }
    }
  };
}
