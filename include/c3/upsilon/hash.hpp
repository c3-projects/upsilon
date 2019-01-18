#pragma once

#include <cstdint>
#include <array>
#include <memory>
#include <type_traits>
#include <map>
#include <functional>

#include <gsl/span>

#include "c3/upsilon/except.hpp"
#include "c3/upsilon/data.hpp"

#include "c3/upsilon/data/helpers.hpp"

namespace c3::upsilon {
  template<size_t HashSize = dynamic_size>
  class hash;

  template<size_t HashSize>
  class hash : public static_serialisable<hash<HashSize>> {
    // I mean it's technically a lie due to dynamic_size, but shhh.
    static_assert(HashSize > 0, "cannot have non-positive hash_size");

    constexpr decltype(HashSize) hash_size() const { return HashSize; }

  public:
    std::array<uint8_t, HashSize> value;

  public:
    hash() : value{} {}

  public:
    template<size_t NewHashSize>
    hash<NewHashSize> truncate() const;

    hash<dynamic_size> dynamic(size_t new_size = HashSize) const;

    template<size_t NewHashSize>
    explicit operator hash<NewHashSize>() const;
    explicit operator hash<dynamic_size>() const;
    operator data_ref() { return value; }
    operator data_const_ref() const { return value; }

  public:
    void _serialise_static(data_ref b) const override {
      if (static_cast<size_t>(b.size()) < HashSize)
        throw std::invalid_argument("Buffer too small to serialise into");
      std::copy(value.begin(), value.end(), b.begin());
    }

    C3_UPSILON_DEFINE_STATIC_DESERIALISE(hash<HashSize>, HashSize, d) {
      if (d.size() != HashSize)
        throw serialisation_failure("Invalid hash length");

      hash ret;
      std::copy(d.begin(), d.end(), ret.value.begin());
      return ret;
    }
  };

  template<>
  class hash<dynamic_size> : public serialisable<hash<dynamic_size>> {
  public:
    std::vector<uint8_t> value;

    size_t hash_size() const { return static_cast<size_t>(value.size()); }

  public:
    template<size_t NewHashSize>
    hash<NewHashSize> truncate() const;

    hash<dynamic_size> dynamic(size_t new_size);

    template<size_t NewHashSize>
    explicit operator hash<NewHashSize>() const;
    operator data_ref() { return value; }
    operator data_const_ref() const { return value; }

  public:
    hash() = default;
    template<typename... Args>
    hash(Args&&... args) : value{args...} {}

  public:
    data _serialise() const override { return { value.begin(), value.end() }; }

    C3_UPSILON_DEFINE_DESERIALISE(hash<dynamic_size>, d) {
      return { d.begin(), d.end() };
    }
  };

  template<size_t ASize, size_t BSize>
  bool operator<=(const hash<ASize>& a, const hash<BSize>& b) {
    return std::lexicographical_compare(a.value.begin(), a.value.end(),
                                        b.value.begin(), b.value.end(),
                                        std::less_equal<uint8_t>());
  }
  template<size_t ASize, size_t BSize>
  bool operator>=(const hash<ASize>& a, const hash<BSize>& b) {
    return std::lexicographical_compare(a.value.begin(), a.value.end(),
                                        b.value.begin(), b.value.end(),
                                        std::greater_equal<uint8_t>());
  }
  template<size_t ASize, size_t BSize>
  bool operator<(const hash<ASize>& a, const hash<BSize>& b) {
    return std::lexicographical_compare(a.value.begin(), a.value.end(),
                                        b.value.begin(), b.value.end(),
                                        std::less<uint8_t>());
  }
  template<size_t ASize, size_t BSize>
  bool operator>(const hash<ASize>& a, const hash<BSize>& b) {
    return std::lexicographical_compare(a.value.begin(), a.value.end(),
                                        b.value.begin(), b.value.end(),
                                        std::greater<uint8_t>());
  }

  template<size_t ASize, size_t BSize>
  bool operator==(const hash<ASize>& a, const hash<BSize>& b) {
    return std::equal(a.value.begin(), a.value.end(),
                      b.value.begin(), b.value.end());
  }
  template<size_t ASize, size_t BSize>
  bool operator!=(const hash<ASize>& a, const hash<BSize>& b) {
    return !(a == b);
  }

  enum class hash_algorithm : uint16_t {
    SHA2_224    = 0x021c,
    SHA2_256    = 0x0220,
    SHA2_384    = 0x0230,
    SHA2_512    = 0x0240,

    SHA3_224    = 0x031c,
    SHA3_256    = 0x0320,
    SHA3_384    = 0x0330,
    SHA3_512    = 0x0340,

    BLAKE2b_128 = 0x0410,
    BLAKE2b_256 = 0x0420,
    BLAKE2b_512 = 0x0440,

    BLAKE2s_128 = 0x0510,
    BLAKE2s_256 = 0x0520,
  };

  struct hash_properties {
  public:
    hash_algorithm alg;
    size_t max_output;
    size_t min_salt;
    size_t max_salt;

  public:
    constexpr hash_properties(hash_algorithm alg,
                              size_t max_output,
                              size_t min_salt = 0,
                              size_t max_salt = std::numeric_limits<size_t>::max()) :
      alg{alg}, max_output{max_output}, min_salt{min_salt}, max_salt{max_salt} {};
  };
  template<hash_algorithm Alg>
  constexpr hash_properties get_hash_properties();
  extern std::map<hash_algorithm, hash_properties> _hash_properties;
  inline hash_properties get_hash_properties(hash_algorithm alg) {
    auto iter = _hash_properties.find(alg);
    if (iter == _hash_properties.end())
      throw c3::upsilon::algorithm_not_implemented{alg};
    else
      return (iter->second);
  }

  class partial_hash {
  public:
    virtual void process(data_const_ref input) = 0;
    /// Invalidates the partial_hash function
    virtual void finish(data_ref output) = 0;
    /// Resets the partial hash to its initial state
    virtual void reset() = 0;

  public:
    virtual ~partial_hash() = default;

  public:
    class salt_wrapper;
  };

  class partial_hash::salt_wrapper : public partial_hash {
  private:
    std::unique_ptr<partial_hash> _base;
    data _salt;

  public:
    void process(data_const_ref input) override { _base->process(std::move(input)); }
    void finish(data_ref output) override { _base->finish(std::move(output)); }
    void reset() override { _base->reset(); _base->process(_salt); }

  public:
    salt_wrapper(decltype(_base)&& base, data_const_ref salt) :
      _base{std::forward<decltype(base)&&>(base)}, _salt{} {
      _salt.insert(_salt.end(), salt.begin(), salt.end());
      _base->process(_salt);
    }
  };

  class hash_function {
  public:
    // If a salt is required, it shall be zeroed an of minimum size
    virtual void compute_hash(data_const_ref input, data_ref output) const = 0;
    // If the function fdoes not have a salt paramter, the salt should be prepended
    // i.e. by using partial_hash::salt_wrapper
    virtual void compute_hash(data_const_ref input, data_const_ref salt, data_ref output) const = 0;

    virtual std::unique_ptr<partial_hash> begin_hash() const = 0;
    virtual std::unique_ptr<partial_hash> begin_hash(data_const_ref salt) const = 0;

    virtual const hash_properties& properties() const noexcept = 0;

  public:
    virtual ~hash_function() = default;
  };

  template<hash_algorithm Alg>
  const hash_function* get_hash_function();

  extern std::map<hash_algorithm, const hash_function*> _hash_funcs;
  inline const hash_function* get_hash_function(hash_algorithm alg) {
    auto iter = _hash_funcs.find(alg);
    if (iter == _hash_funcs.end())
      throw c3::upsilon::algorithm_not_implemented{alg};
    else
      return (iter->second);
  }

  class hasher {
  private:
    const hash_function* _impl;
    const hash_properties& props = _impl->properties();

  private:
    template<size_t HashSize = dynamic_size>
    inline hash<HashSize> _get_hash_base(data_const_ref b) const;
    inline hash<dynamic_size> _get_hash_base(data_const_ref b, size_t len) const;

    template<size_t HashSize = dynamic_size>
    inline hash<HashSize> _get_hash_base(data_const_ref b, data_const_ref salt) const;
    inline hash<dynamic_size> _get_hash_base(data_const_ref b, data_const_ref salt, size_t len) const;

  public:
    inline const hash_properties& properties() const noexcept { return _impl->properties(); }

    template<size_t HashSize = dynamic_size, typename T>
    hash<HashSize> get_hash(const T& t) const;
    template<typename T>
    hash<dynamic_size> get_hash(const T& t, size_t len) const;

    template<size_t HashSize = dynamic_size, typename T>
    hash<HashSize> get_hash(const T& t, data_const_ref salt) const;
    template<typename T>
    hash<dynamic_size> get_hash(const T& t, data_const_ref salt, size_t len) const;

  public:
    hasher() : _impl{} {}
    hasher(const hash_function* impl) : _impl{std::forward<decltype(impl)>(impl)} {}
  };

  template<hash_algorithm Alg>
  inline hasher get_hasher() {
    return { get_hash_function<Alg>() };
  }

  inline hasher get_hasher(hash_algorithm alg) {
    return { get_hash_function(alg) };
  }


  // Since hashers have no state, I have no qualms about statically defining them
  //
  // Use a static thread_local variable in your function if you require some external class
////////////////////////////////////////////////////////////////
#define C3_UPSILON_HASH_ALG(ALG, SIZE) \
  template<> \
  constexpr hash_properties get_hash_properties<ALG>() { return { ALG, SIZE }; };

#define C3_UPSILON_HASH_ALG_SALT(ALG, SIZE, MIN, MAX) \
  template<> \
  constexpr hash_properties get_hash_properties<ALG>() { return { ALG, SIZE, MIN, MAX }; };
////////////////////////////////////////////////////////////////

  C3_UPSILON_HASH_ALG(hash_algorithm::SHA2_224, 28);
  C3_UPSILON_HASH_ALG(hash_algorithm::SHA2_256, 32);
  C3_UPSILON_HASH_ALG(hash_algorithm::SHA2_384, 48);
  C3_UPSILON_HASH_ALG(hash_algorithm::SHA2_512, 64);

  C3_UPSILON_HASH_ALG(hash_algorithm::SHA3_224, 28);
  C3_UPSILON_HASH_ALG(hash_algorithm::SHA3_256, 32);
  C3_UPSILON_HASH_ALG(hash_algorithm::SHA3_384, 48);
  C3_UPSILON_HASH_ALG(hash_algorithm::SHA3_512, 64);

  C3_UPSILON_HASH_ALG(hash_algorithm::BLAKE2b_128, 16);
  C3_UPSILON_HASH_ALG(hash_algorithm::BLAKE2b_256, 32);
  C3_UPSILON_HASH_ALG(hash_algorithm::BLAKE2b_512, 64);

  C3_UPSILON_HASH_ALG(hash_algorithm::BLAKE2s_128, 16);
  C3_UPSILON_HASH_ALG(hash_algorithm::BLAKE2s_256, 32);

#undef C3_UPSILON_HASH_ALG
}

#include "c3/upsilon/data/clean_helpers.hpp"

#include "c3/upsilon/hash.tpp"
