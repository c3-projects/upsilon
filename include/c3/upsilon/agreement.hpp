#pragma once

#include <memory>

#include "c3/upsilon/hash.hpp"
#include "c3/upsilon/kdf.hpp"
#include "c3/upsilon/symmetric.hpp"
#include "c3/upsilon/data/base.hpp"

#include "c3/upsilon/data/helpers.hpp"

namespace c3::upsilon {
  enum class agreement_algorithm : uint16_t {
    Curve25519 = 0x0000
  };

  class agreement_function {
  public:
    /// SHOULD NOT BE USED DIRECTLY!!!
    /// Hash or kdf the result
    virtual data agree(data_const_ref other_public) const = 0;
    virtual data serialise_public() const = 0;
    virtual data serialise_private() const  = 0;
  public:
    virtual ~agreement_function() = default;
  };

  template<agreement_algorithm Alg>
  std::unique_ptr<agreement_function> get_agreement_function(data_const_ref serialised_af);

  template<agreement_algorithm Alg>
  std::unique_ptr<agreement_function> gen_agreement_function();

  extern std::map<agreement_algorithm,
                  std::function<std::unique_ptr<agreement_function>(data_const_ref)>> _agreement_functions;

  extern std::map<agreement_algorithm,
                  std::function<std::unique_ptr<agreement_function>()>> _ag_gens;

  inline std::unique_ptr<agreement_function> get_agreement_function(agreement_algorithm alg,
                                                                    data_const_ref b) {
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

  class agreer : public serialisable<agreer> {
  private:
    agreement_algorithm _agreement_alg;
    std::unique_ptr<agreement_function> _agreement_func;
    const kdf* _kdf;

  public:
    template<symmetric_algorithm SymAlg>
    symmetric_key<SymAlg> derive_shared_key(data_const_ref other) {
      data raw_result = _agreement_func->agree(other);
      symmetric_key<SymAlg> ret;
      _kdf->expand(raw_result, ret);
      return ret;
    }
    void derive_shared_secret(data_const_ref other, data_ref output) {
      _kdf->expand(_agreement_func->agree(other), output);
    }
    data derive_shared_secret(data_const_ref other, size_t output_len) {
      data ret(output_len);
      derive_shared_secret(_agreement_func->agree(other), ret);
      return ret;
    }
    template<size_t OutputLen>
    static_data<OutputLen> derive_shared_secret(data_const_ref other) {
      static_data<OutputLen> ret;
      derive_shared_secret(_agreement_func->agree(other), ret);
      return ret;
    }

  private:
    agreer(agreement_algorithm agreement_alg,
           std::unique_ptr<agreement_function>&& agreement_func,
           const kdf* _kdf) :
      _agreement_alg{agreement_alg},
      _agreement_func{std::forward<decltype(agreement_func)>(agreement_func)},
      _kdf{_kdf} {}
  public:
    agreer(kdf_algorithm kdf_alg, agreement_algorithm agreement_alg, data_const_ref pub) :
      _agreement_alg{agreement_alg},
      _agreement_func{get_agreement_function(agreement_alg, pub)},
      _kdf{get_kdf(kdf_alg)} {}

  public:
    inline data get_public() const { return _agreement_func->serialise_public(); }

  public:
    static inline agreer gen(agreement_algorithm agreement_alg, kdf_algorithm kdf_alg) {
      return { agreement_alg, gen_agreement_function(agreement_alg), get_kdf(kdf_alg) };
    }
    template<agreement_algorithm AgreementAlg, kdf_algorithm KdfAlg>
    static inline agreer gen() {
      return { AgreementAlg, gen_agreement_function<AgreementAlg>(), get_kdf<KdfAlg>() };
    }

  public:
    data _serialise() const override {
      return squash_hybrid(_kdf->alg(), _agreement_alg, _agreement_func->serialise_private());
    }
    C3_UPSILON_DEFINE_DESERIALISE(agreer, b) {
      kdf_algorithm kdf_alg;
      agreement_algorithm agreement_alg;
      data_const_ref pub;

      expand_hybrid(b, kdf_alg, agreement_alg, pub);

      return {kdf_alg, agreement_alg, pub};
    }
  };
}
