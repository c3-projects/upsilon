#pragma once

#include <vector>
#include <map>
#include <functional>
#include <memory>

#include "c3/upsilon/except.hpp"
#include "c3/upsilon/nuker.hpp"

#include "c3/nu/data.hpp"

#include "c3/nu/data/helpers.hpp"

namespace c3::upsilon {
  struct symmetric_properties {
  public:
    size_t key_size;
    size_t iv_size;

  public:
    constexpr symmetric_properties(size_t key_size, size_t iv_size) :
      key_size{key_size}, iv_size{iv_size} {};
  };

  // Should use CTR where applicable,
  // as this prevents against padding oracle attacks, and has fast seek
  //
  // To defend agains repetition from sequenctial messages,
  // the IV (and/or the key) should be new with each message
  //
  // All of these must be stream ciphers, so that the user can easily create an output buffer
  //
  // Please be aware that none of these provide MACs, and so can be trivially modified
  // with a known-plaintext attack
  enum class symmetric_algorithm : uint16_t {
    AES128     = 0x0110,
    AES256     = 0x0120,

    ChaCha20_8  = 0x0208,
    ChaCha20_12 = 0x020c,
    ChaCha20_20 = 0x0212,
    ChaCha20    = ChaCha20_20,

    XChaCha20_8  = 0x0308,
    XChaCha20_12 = 0x030c,
    XChaCha20_20 = 0x0312,
    XChaCha20    = XChaCha20_20,
  };

  template<symmetric_algorithm Alg>
  constexpr symmetric_properties get_symmetric_properties();
  extern std::map<symmetric_algorithm, symmetric_properties> _symmetric_properties;
  inline symmetric_properties get_symmetric_properties(symmetric_algorithm alg) {
    auto iter = _symmetric_properties.find(alg);
    if (iter == _symmetric_properties.end())
      throw c3::upsilon::algorithm_not_implemented{alg};
    else
      return (iter->second);
  }

  template<symmetric_algorithm Alg>
  using symmetric_key = std::array<uint8_t, get_symmetric_properties<Alg>().key_size>;
  template<symmetric_algorithm Alg>
  using symmetric_iv = std::array<uint8_t, get_symmetric_properties<Alg>().iv_size>;

  template<symmetric_algorithm Alg>
  using key_const_ref = gsl::span<const uint8_t, get_symmetric_properties<Alg>().key_size>;
  template<symmetric_algorithm Alg>
  using iv_const_ref = gsl::span<const uint8_t, get_symmetric_properties<Alg>().iv_size>;

  class symmetric_function {
  public:
    /// Successive calls with the same plaintext should yield different results
    virtual void encrypt(nu::data_ref input_output) = 0;
    virtual uint64_t encrypt(nu::data_const_ref input, nu::data_ref output) = 0;
    inline nu::data encrypt(nu::data_const_ref input) {
      nu::data ret(static_cast<size_t>(input.size()));
      encrypt(input, ret);
      return ret;
    }

    /// Successive calls with the same cyphertext should yield different results
    virtual void decrypt(nu::data_ref input_output) = 0;
    virtual uint64_t decrypt(nu::data_const_ref input, nu::data_ref output) = 0;
    inline nu::data decrypt(nu::data_const_ref input) {
      nu::data ret(static_cast<size_t>(input.size()));
      decrypt(input, ret);
      return ret;
    }

    /// Acts as if n bytes have been encrypted
    virtual void seek(uint64_t n) = 0;
    /// Returns the position of the stream cipher
    virtual uint64_t pos() const noexcept = 0;

    virtual symmetric_algorithm alg() const noexcept = 0;

  public:
    virtual ~symmetric_function() = default;
  };

  template<symmetric_algorithm Alg>
  inline auto get_symmetric_function(key_const_ref<Alg> key, iv_const_ref<Alg> iv);

  extern std::map<symmetric_algorithm,
                  std::function<std::unique_ptr<symmetric_function>(nu::data_const_ref, nu::data_const_ref)>> _symmetric_functions;

  inline std::unique_ptr<symmetric_function> get_symmetric_function(symmetric_algorithm alg,
                                                                    nu::data_const_ref key,
                                                                    nu::data_const_ref iv) {
    auto iter = _symmetric_functions.find(alg);
    if (iter == _symmetric_functions.end())
      throw c3::upsilon::algorithm_not_implemented{alg};
    else
      return (iter->second)(key, iv);
  }

  ////////////////////////////////////////////////////////////////
  #define C3_UPSILON_SYM_ALG(ALG, KEY_SIZE, IV_SIZE) \
    template<> \
    constexpr symmetric_properties get_symmetric_properties<ALG>() { \
      return { KEY_SIZE, IV_SIZE }; \
    } \
  ////////////////////////////////////////////////////////////////
  C3_UPSILON_SYM_ALG(symmetric_algorithm::AES128, (128 / 8), (128 / 8));
  C3_UPSILON_SYM_ALG(symmetric_algorithm::AES256, (256 / 8), (128 / 8));

  // I know that 128 bit versions exist, but they are not significantly faster,
  // and I'm always a bit uncomfortable about using 128-bit encryption
  C3_UPSILON_SYM_ALG(symmetric_algorithm::ChaCha20_8 , (256 / 8), (64 / 8));
  C3_UPSILON_SYM_ALG(symmetric_algorithm::ChaCha20_12, (256 / 8), (64 / 8));
  C3_UPSILON_SYM_ALG(symmetric_algorithm::ChaCha20_20, (256 / 8), (64 / 8));

  // xchacha doesn't have to worry about iv collisions as much as chacha does
  C3_UPSILON_SYM_ALG(symmetric_algorithm::XChaCha20_8 , (256 / 8), (192 / 8));
  C3_UPSILON_SYM_ALG(symmetric_algorithm::XChaCha20_12, (256 / 8), (192 / 8));
  C3_UPSILON_SYM_ALG(symmetric_algorithm::XChaCha20_20, (256 / 8), (192 / 8));
}

#include "c3/nu/data/clean_helpers.hpp"
