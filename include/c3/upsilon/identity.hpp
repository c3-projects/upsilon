#pragma once

#include "c3/upsilon/hash.hpp"
#include "c3/upsilon/data/base.hpp"

#include "c3/upsilon/data/helpers.hpp"

namespace c3::upsilon {
  enum class signature_algorithm : uint16_t {
    Curve25519 = 0x0000
  };

  class verifier {
  public:
    virtual bool verify(data_const_ref input_hashed, data_const_ref sig) const = 0;
    virtual data serialise_pub() const = 0;

  public:
    virtual ~verifier() = default;
  };
  class signer : public verifier {
  public:
    virtual bool verify(data_const_ref input_hashed, data_const_ref sig) const override = 0;
    virtual data sign(data_const_ref input) const = 0;
    virtual data serialise_pub() const override = 0;
    virtual data serialise_priv() const = 0;

  public:
    virtual ~signer() override = default;
  };

  // Either this or PImpl, which has all of the problems but is weirder
  template<signature_algorithm Alg>
  inline std::unique_ptr<verifier> get_verifier(data_const_ref serialised_verifier);

  extern std::map<signature_algorithm,
                  std::function<std::unique_ptr<verifier>(data_const_ref)>> _verifiers;

  inline std::unique_ptr<verifier> get_verifier(signature_algorithm alg, data_const_ref b) {
    auto iter = _verifiers.find(alg);
    if (iter == _verifiers.end())
      throw c3::upsilon::algorithm_not_implemented<signature_algorithm>{alg};
    else
      return (iter->second)(b);
  }
  template<signature_algorithm Alg>
  std::unique_ptr<signer> get_signer(data_const_ref serialised_signer);

  template<signature_algorithm Alg>
  std::unique_ptr<signer> gen_signer();

  extern std::map<signature_algorithm,
                  std::function<std::unique_ptr<signer>(data_const_ref)>> _signers;

  extern std::map<signature_algorithm, std::function<std::unique_ptr<signer>()>> _sig_gens;

  inline std::unique_ptr<signer> get_signer(signature_algorithm alg, data_const_ref b) {
    auto iter = _signers.find(alg);
    if (iter == _signers.end())
      throw c3::upsilon::algorithm_not_implemented<signature_algorithm>{alg};
    else
      return (iter->second)(b);
  }

  inline std::unique_ptr<signer> gen_signer(signature_algorithm alg) {
    auto iter = _sig_gens.find(alg);
    if (iter == _sig_gens.end())
      throw c3::upsilon::algorithm_not_implemented<signature_algorithm>{alg};
    else
      return (iter->second)();
  }

  class identity : public serialisable<identity> {
  private:
    signature_algorithm _sig_alg;
    hasher _msg_hasher;
    std::unique_ptr<verifier> _impl;

  public:
    inline decltype(_sig_alg) alg() { return _sig_alg; }
    inline bool verify(data_const_ref b, data_const_ref sig) {
      return _impl->verify(_msg_hasher.get_hash(b), sig);
    }

  private:
    identity(signature_algorithm sig_alg, hasher msg_hasher, decltype(_impl)&& impl) :
      _sig_alg{sig_alg}, _msg_hasher{std::move(msg_hasher)}, _impl{std::forward<decltype(impl)>(impl)} {}

  private:
    data _serialise() const override {
      return squash_hybrid(_sig_alg, _msg_hasher.properties().alg, _impl->serialise_pub());
    }

    C3_UPSILON_DEFINE_DESERIALISE(identity, b) {
      signature_algorithm sig_alg;
      hash_algorithm hash_alg;
      data_const_ref buf;

      expand_hybrid(b, sig_alg, hash_alg, buf);

      return { sig_alg, get_hasher(hash_alg), get_verifier(sig_alg, buf) };
    }
  };

  class owned_identity : public serialisable<owned_identity> {
  private:
    signature_algorithm _sig_alg;
    hasher _msg_hasher;
    std::unique_ptr<signer> _impl;

  public:
    inline data sign(data_const_ref b) const {
      return _impl->sign(_msg_hasher.get_hash(b));
    }
    inline bool verify(data_const_ref b, data_const_ref sig) const {
      return _impl->verify(_msg_hasher.get_hash(b), sig);
    }
    inline decltype(_sig_alg) alg() { return _sig_alg; }
    inline data serialise_public() {
      return squash_hybrid(_sig_alg, _msg_hasher.properties().alg, _impl->serialise_pub());
    }

  private:
    owned_identity(signature_algorithm sig_alg, hasher msg_hasher, decltype(_impl)&& impl) :
      _sig_alg{sig_alg},
      _msg_hasher{std::move(msg_hasher)},
      _impl{std::forward<decltype(impl)>(impl)} {}

  public:
    static owned_identity gen(signature_algorithm sig_alg, hash_algorithm msg_hash_alg) {
      return { sig_alg, get_hasher(msg_hash_alg), gen_signer(sig_alg) };
    }

    template<signature_algorithm SigAlg, hash_algorithm MsgHashAlg>
    static owned_identity gen() {
      return { SigAlg, get_hasher<MsgHashAlg>(), gen_signer<SigAlg>() };
    }

  private:
    data _serialise() const override {
      signature_algorithm sig_alg = _sig_alg;
      hash_algorithm msg_hash_alg = _msg_hasher.properties().alg;
      data buf = _impl->serialise_priv();

      auto ret = squash_hybrid(sig_alg, msg_hash_alg, buf);

      return ret;
    }

    C3_UPSILON_DEFINE_DESERIALISE(owned_identity, b) {
      signature_algorithm sig_alg;
      hash_algorithm msg_hash_alg;
      data_const_ref buf;

      expand_hybrid(b, sig_alg, msg_hash_alg, buf);

      return { sig_alg, get_hasher(msg_hash_alg), get_signer(sig_alg, buf) };
    }
  };
}

#include "c3/upsilon/data/clean_helpers.hpp"
