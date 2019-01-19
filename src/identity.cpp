#include "c3/upsilon/identity.hpp"

#include "c3/upsilon/csprng.hpp"
#include "botan_common.hpp"

#include <botan/ed25519.h>
#include <botan/pubkey.h>
#include <botan/pkcs8.h>
#include <botan/ber_dec.h>
#include <botan/asn1_obj.h>

#include <iostream>

#define C3_UPSILON_DEF_SIG_BOTAN(CLASS_NAME, ALG, PUB_KEY_TYPE, PRIV_KEY_TYPE) \
  class CLASS_NAME##_verifier : public verifier { \
  public: \
    PUB_KEY_TYPE pub_key; \
    mutable Botan::PK_Verifier pub; \
  public: \
    bool verify(nu::data_const_ref input_hash, nu::data_const_ref sig) const override { \
      return pub.verify_message(input_hash.data(), input_hash.size(), sig.data(), sig.size()); \
    } \
    nu::data serialise_pub() const override { \
      return pub_key.public_key_bits(); \
    } \
  public: \
    CLASS_NAME##_verifier(nu::data_const_ref b) : \
      pub_key{std::vector<uint8_t>{b.begin(), b.end()}}, \
      pub{pub_key, ""} {} \
  }; \
  class CLASS_NAME##_signer : public signer { \
  public: \
    PRIV_KEY_TYPE priv_key; \
    mutable Botan::PK_Verifier pub; \
    mutable Botan::PK_Signer priv; \
  public: \
    nu::data sign(nu::data_const_ref input_hash) const override { \
      return priv.sign_message(input_hash.data(), input_hash.size(), csprng_wrapper::standard); \
    } \
    bool verify(nu::data_const_ref input_hash, nu::data_const_ref sig) const override { \
      return pub.verify_message(input_hash.data(), input_hash.size(), sig.data(), sig.size()); \
    } \
    nu::data serialise_priv() const override { \
      auto ret = priv_key.get_private_key(); \
      return { ret.begin(), ret.end() }; \
    } \
    nu::data serialise_pub() const override { \
      return priv_key.public_key_bits(); \
    } \
  public: \
    static inline PRIV_KEY_TYPE gen(); \
  public: \
    inline CLASS_NAME##_signer(PRIV_KEY_TYPE&& _priv_key) : \
      priv_key{std::forward<PRIV_KEY_TYPE&&>(_priv_key)}, \
      pub{priv_key, ""}, \
      priv{priv_key, csprng_wrapper::standard, ""} {} \
    inline CLASS_NAME##_signer() : \
      CLASS_NAME##_signer{gen()} {} \
    inline CLASS_NAME##_signer(nu::data_const_ref b) : \
      CLASS_NAME##_signer{PRIV_KEY_TYPE{Botan::secure_vector<uint8_t>{ b.begin(), b.end() }}} {} \
  }; \
  template<> \
  std::unique_ptr<signer> gen_signer<ALG>() { return std::make_unique<CLASS_NAME##_signer>(); } \
  template<> \
  std::unique_ptr<signer> get_signer<ALG>(nu::data_const_ref b) { \
    return std::make_unique<CLASS_NAME##_signer>(b); \
  } \
  auto __##CLASS_NAME##_signer_get_registered = \
    _signers.emplace(ALG, [](auto a) { return std::make_unique<CLASS_NAME##_signer>(a); }); \
  auto __##CLASS_NAME##_verifier_get_registered = \
    _verifiers.emplace(ALG, [](auto a) { return std::make_unique<CLASS_NAME##_verifier>(a); }); \
  auto __##CLASS_NAME##_signer_gen_registered = \
    _sig_gens.emplace(ALG, std::make_unique<CLASS_NAME##_signer>);

#define C3_UPSILON_DEF_SIG_BOTAN_GEN(CLASS_NAME) \
  inline decltype(CLASS_NAME##_signer::priv_key) CLASS_NAME##_signer::gen()


namespace c3::upsilon {
  std::map<signature_algorithm,
           std::function<std::unique_ptr<verifier>(nu::data_const_ref)>> _verifiers;
  std::map<signature_algorithm,
           std::function<std::unique_ptr<signer>(nu::data_const_ref)>> _signers;
  std::map<signature_algorithm, std::function<std::unique_ptr<signer>()>> _sig_gens;

  C3_UPSILON_DEF_SIG_BOTAN(curve25519, signature_algorithm::Curve25519,
                           Botan::Ed25519_PublicKey, Botan::Ed25519_PrivateKey);
  C3_UPSILON_DEF_SIG_BOTAN_GEN(curve25519) {
    return Botan::Ed25519_PrivateKey(csprng_wrapper::standard);
  }
}
