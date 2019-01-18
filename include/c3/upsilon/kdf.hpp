#pragma once

#include "c3/upsilon/hash.hpp"
#include "c3/upsilon/data/base.hpp"

#include "c3/upsilon/data/helpers.hpp"

namespace c3::upsilon {
  enum class kdf_algorithm : uint16_t {
    Shake128 = 0x0010,
    Shake256 = 0x0020,
  };

  class kdf {
  public:
    virtual void expand(data_const_ref input, data_ref output) const = 0;
    data expand(data_const_ref input, size_t output_len);

    virtual kdf_algorithm alg() const noexcept = 0;

  public:
    virtual ~kdf() = default;
  };

  template<kdf_algorithm Alg>
  const kdf* get_kdf();

  extern std::map<kdf_algorithm, const kdf*> _kdfs;

  inline const kdf* get_kdf(kdf_algorithm alg) {
    auto iter = _kdfs.find(alg);
    if (iter == _kdfs.end())
      throw c3::upsilon::algorithm_not_implemented<kdf_algorithm>{alg};
    else
      return (iter->second);
  }
}
