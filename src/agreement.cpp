#include "c3/upsilon/agreement.hpp"

#include "botan_common.hpp"

#include <botan/curve25519.h>
#include <botan/pubkey.h>
#include <botan/pkcs8.h>

#define C3_UPSILON_AGREEMENT_BOILERPLATE(CLASS_NAME, ALG) \
  template<> \
  std::unique_ptr<agreement_function> get_agreement_function<ALG>(nu::data_const_ref serialised_af) { \
    return std::make_unique<CLASS_NAME>(serialised_af); \
  } \
  template<> \
  std::unique_ptr<agreement_function> gen_agreement_function<ALG>() { \
    return std::make_unique<CLASS_NAME>(); \
  } \
  static auto __##CLASS_NAME##_gen_registered = \
    _ag_gens.emplace(ALG, [](){ return std::make_unique<CLASS_NAME>(); }); \
  static auto __##CLASS_NAME##_get_registered = \
    _agreement_functions.emplace(ALG, [](auto a){ return std::make_unique<CLASS_NAME>(a); });

namespace c3::upsilon {
  std::map<agreement_algorithm,
           std::function<std::unique_ptr<agreement_function>(nu::data_const_ref)>> _agreement_functions;

  std::map<agreement_algorithm, std::function<std::unique_ptr<agreement_function>()>> _ag_gens;

  class curve25519 : public agreement_function {
    Botan::Curve25519_PrivateKey priv;

  public:
    virtual nu::data agree(nu::data_const_ref other_public) const override {
      Botan::PK_Key_Agreement op(priv, csprng_wrapper::standard, "Raw");

      // Looked up size on cr.yp.to
      auto k = op.derive_key(32, other_public.data(), other_public.size());

      return { k.begin(), k.end() };
    }

    virtual nu::data serialise_public() const override {
      return priv.public_value();
    }

    virtual nu::data serialise_private() const  override {
      auto ret = Botan::PKCS8::BER_encode(priv);
      return { ret.begin(), ret.end() };
    }

  public:
    inline curve25519() : priv{csprng_wrapper::standard} {};
    inline curve25519(nu::data_const_ref b) : priv{Botan::SecureVector<uint8_t>{b.begin(), b.end()}} {};
  };

  C3_UPSILON_AGREEMENT_BOILERPLATE(curve25519, agreement_algorithm::Curve25519);

}
