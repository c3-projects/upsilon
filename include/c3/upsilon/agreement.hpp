#pragma once

#include <memory>

#include "c3/upsilon/hash.hpp"
#include "c3/upsilon/kdf.hpp"
#include "c3/upsilon/symmetric.hpp"

#include "c3/nu/data.hpp"
#include "c3/nu/structs.hpp"

#include "c3/nu/data/helpers.hpp"

namespace c3::upsilon {
  enum class agreement_algorithm : uint16_t {
    Curve25519 = 0x0000
  };

  class agreement_function {
  public:
    /// SHOULD NOT BE USED DIRECTLY!!!
    /// Hash or kdf the result
    virtual nu::data agree(nu::data_const_ref other_public) const = 0;
    virtual nu::data serialise_public() const = 0;
    virtual nu::data serialise_private() const  = 0;
  public:
    virtual ~agreement_function() = default;
  };

  template<agreement_algorithm Alg>
  std::unique_ptr<agreement_function> get_agreement_function(nu::data_const_ref serialised_af);

  template<agreement_algorithm Alg>
  std::unique_ptr<agreement_function> gen_agreement_function();

  extern std::map<agreement_algorithm,
                  std::function<std::unique_ptr<agreement_function>(nu::data_const_ref)>> _agreement_functions;

  extern std::map<agreement_algorithm,
                  std::function<std::unique_ptr<agreement_function>()>> _ag_gens;

  inline std::unique_ptr<agreement_function> get_agreement_function(agreement_algorithm alg,
                                                                    nu::data_const_ref b) {
    auto iter = _agreement_functions.find(alg);
    if (iter == _agreement_functions.end())
      throw c3::upsilon::algorithm_not_implemented{alg};
    else
      return (iter->second)(b);
  }

  inline std::unique_ptr<agreement_function> gen_agreement_function(agreement_algorithm alg) {
    auto iter = _ag_gens.find(alg);
    if (iter == _ag_gens.end())
      throw c3::upsilon::algorithm_not_implemented{alg};
    else
      return (iter->second)();
  }

  class remote_agreer : public nu::serialisable<remote_agreer> {
  public:
    kdf_algorithm kdf_alg;
    agreement_algorithm agreement_alg;
    nu::data shared_secret;

  public:
    inline remote_agreer() = default;
    inline remote_agreer(decltype(kdf_alg) _kdf_alg,
                         decltype(agreement_alg) _agreement_alg,
                         decltype(shared_secret) _shared_secret) :
      kdf_alg{_kdf_alg}, agreement_alg{_agreement_alg}, shared_secret{_shared_secret} {}

  public:
    inline nu::data _serialise() const override {
      return nu::squash(kdf_alg, agreement_alg, shared_secret);
    }
    C3_NU_DEFINE_DESERIALISE(remote_agreer, b) {
      remote_agreer ret;
      nu::expand(b, ret.kdf_alg, ret.agreement_alg, ret.shared_secret);
      return ret;
    }
  };

  class agreer : public nu::serialisable<agreer> {
  private:
    agreement_algorithm _agreement_alg;
    std::unique_ptr<agreement_function> _agreement_func;
    const kdf* _kdf;

  public:
    template<symmetric_algorithm SymAlg>
    inline symmetric_key<SymAlg> derive_shared_key(nu::data_const_ref other) {
      nu::data raw_result = _agreement_func->agree(other);
      symmetric_key<SymAlg> ret;
      _kdf->expand(raw_result, ret);
      return ret;
    }
    inline void derive_shared_secret(nu::data_const_ref other, nu::data_ref output) {
      _kdf->expand(_agreement_func->agree(other), output);
    }
    inline nu::data derive_shared_secret(nu::data_const_ref other, size_t output_len) {
      nu::data ret(output_len);
      derive_shared_secret(_agreement_func->agree(other), ret);
      return ret;
    }
    template<size_t OutputLen>
    inline nu::static_data<OutputLen> derive_shared_secret(nu::data_const_ref other) {
      nu::static_data<OutputLen> ret;
      derive_shared_secret(_agreement_func->agree(other), ret);
      return ret;
    }

  public:
    inline agreer() : _kdf{nullptr} {}
    inline agreer(agreement_algorithm agreement_alg,
           std::unique_ptr<agreement_function>&& agreement_func,
           const kdf* _kdf) :
      _agreement_alg{agreement_alg},
      _agreement_func{std::forward<decltype(agreement_func)>(agreement_func)},
      _kdf{_kdf} {}
    inline agreer(kdf_algorithm kdf_alg, agreement_algorithm agreement_alg, nu::data_const_ref pub) :
      _agreement_alg{agreement_alg},
      _agreement_func{get_agreement_function(agreement_alg, pub)},
      _kdf{get_kdf(kdf_alg)} {}

  public:
    inline nu::data get_public() const { return _agreement_func->serialise_public(); }

  public:
    static inline agreer gen(kdf_algorithm kdf_alg, agreement_algorithm agreement_alg) {
      return { agreement_alg, gen_agreement_function(agreement_alg), get_kdf(kdf_alg) };
    }
    template<kdf_algorithm KdfAlg, agreement_algorithm AgreementAlg>
    static inline agreer gen() {
      return { AgreementAlg, gen_agreement_function<AgreementAlg>(), get_kdf<KdfAlg>() };
    }
    static inline agreer gen(const remote_agreer& base) {
      return gen(base.kdf_alg, base.agreement_alg);
    }

  public:
    nu::data _serialise() const override {
      return nu::squash(_kdf->alg(), _agreement_alg, _agreement_func->serialise_private());
    }
    C3_NU_DEFINE_DESERIALISE(agreer, b) {
      kdf_algorithm kdf_alg;
      agreement_algorithm agreement_alg;
      nu::data_const_ref pub;

      nu::expand(b, kdf_alg, agreement_alg, pub);

      return {kdf_alg, agreement_alg, pub};
    }
  };
}
