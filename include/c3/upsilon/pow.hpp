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

  enum class pow_algorithm : uint16_t {
    Laserproof = 0x0100
  };

  class pow_verifier {
  public:
    /// Returns a BE integer that describes the difficulty of the work done
    ///
    /// Shoudl return an empty array on failure
    virtual nu::data difficulty(nu::data_const_ref hashed_data,
                                nu::data_const_ref proof) const noexcept = 0;

  public:
    virtual ~pow_verifier() = default;
  };

  class laserproof_verifier : public pow_verifier {
  private:
    hasher h;

  public:
    nu::data difficulty(nu::data_const_ref hashed_data,
                        nu::data_const_ref proof) const noexcept override;
  };
}
