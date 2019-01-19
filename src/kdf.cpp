#include "c3/upsilon/kdf.hpp"

#include <botan/hkdf.h>
#include <botan/shake.h>

#define C3_UPSILON_DEF_KDF_BOTAN(CLASS_NAME, ALG, INPUT, OUTPUT) \
  class CLASS_NAME : public kdf { \
  public: \
    kdf_algorithm alg() const noexcept override { return ALG; } \
    void expand(nu::data_const_ref input, nu::data_ref output) const override; \
  }; \
  static const CLASS_NAME CLASS_NAME##_static; \
  static auto __##CLASS_NAME##_registered = _kdfs.emplace(ALG, &CLASS_NAME##_static); \
  template<> \
  const kdf* get_kdf<ALG>() { return &CLASS_NAME##_static; } \
  void CLASS_NAME::expand(nu::data_const_ref INPUT, nu::data_ref OUTPUT) const

namespace c3::upsilon {
  std::map<kdf_algorithm, const kdf*> _kdfs;

  C3_UPSILON_DEF_KDF_BOTAN(shake128, kdf_algorithm::Shake128, input, output) {
    // Dumb idiots whomst write crypto
    // Size is in bits
    Botan::SHAKE_128 impl(output.size() * 8);
    impl.process(input.data(), input.size());
    impl.final(output.data());
  }
  C3_UPSILON_DEF_KDF_BOTAN(shake256, kdf_algorithm::Shake256, input, output) {
    // Dumb idiots whomst write crypto
    // Size is in bits
    Botan::SHAKE_256 impl(output.size() * 8);
    impl.process(input.data(), input.size());
    impl.final(output.data());
  }
}
