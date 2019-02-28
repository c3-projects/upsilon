#pragma once

#include "c3/upsilon/hash.hpp"
#include "c3/nu/bigint.hpp"

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
    /// Returns a integer that describes the difficulty of the work done
    virtual nu::biguint difficulty(nu::data_const_ref hashed_data,
                                   nu::data_const_ref proof) const noexcept = 0;

  public:
    virtual ~pow_verifier() = default;
  };

  class pow_creator {
  public:
    /// Returns a integer that describes the difficulty of the work done
    virtual nu::data work(nu::data_const_ref hashed_data,
                          nu::biguint threshold) const noexcept = 0;

  public:
    virtual ~pow_creator() = default;
  };

  class laserproof : public pow_verifier, public pow_creator {
  private:
    hasher h;
    size_t lookback_len = 4096;
    size_t backstride_len = 8192;
    /// The final hash is XORed into a single byte, and compared to threshold
    ///
    /// If it is lesser than it, we stop
    ///
    /// Therefore there is a theshold / 256 possibility of stopping
    uint8_t threshold = 128;

  public:
    static constexpr size_t proof_len = 32;

  private:
    nu::biguint check_one(nu::data_const_ref hashed_data, nu::data_const_ref proof) const;
    bool check_complete(nu::data_const_ref buf, nu::data_const_ref proof) const;

  public:
    nu::biguint difficulty(nu::data_const_ref hashed_data,
                           nu::data_const_ref proof) const noexcept override;
    nu::data work(nu::data_const_ref hashed_data,
                  nu::biguint threshold) const noexcept override;

  public:
    laserproof(hash_algorithm hash_alg) : h{get_hasher(hash_alg)} {}
  };
}
