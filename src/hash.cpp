#include "c3/upsilon/hash.hpp"
#include "c3/upsilon/except.hpp"

#include <botan/hash.h>

#define C3_UPSILON_DEF_HASH_BOTAN(CLASS_NAME, ALG, BOTAN_HASH_NAME) \
  thread_local static auto CLASS_NAME##_impl = Botan::HashFunction::create(BOTAN_HASH_NAME); \
  class CLASS_NAME : public hash_function { \
  public: \
    static constexpr auto props = get_hash_properties<ALG>(); \
    static constexpr auto static_props = props; \
  public: \
    void compute_hash(data_const_ref input, data_ref output) const override { \
      CLASS_NAME##_impl->update(input.data(), input.size()); \
      if (output.size() == props.max_output) \
        CLASS_NAME##_impl->final(output.data()); \
      else if (static_cast<size_t>(output.size()) > props.max_output) \
        throw std::range_error("Too many bytes requested from hash"); \
      else { \
        std::array<uint8_t, props.max_output> tmp_output; \
        CLASS_NAME##_impl->final(tmp_output.data()); \
        std::copy(tmp_output.begin(), tmp_output.begin() + output.size(), output.begin()); \
      } \
    } \
    void compute_hash(data_const_ref input, data_const_ref salt, data_ref output) const override { \
      CLASS_NAME##_impl->update(salt.data(), salt.size()); \
      CLASS_NAME##_impl->update(input.data(), input.size()); \
      if (output.size() == props.max_output) \
        CLASS_NAME##_impl->final(output.data()); \
      else if (static_cast<size_t>(output.size()) > props.max_output) \
        throw std::range_error("Too many bytes requested from hash"); \
      else { \
        std::array<uint8_t, props.max_output> tmp_output; \
        CLASS_NAME##_impl->final(tmp_output.data()); \
        std::copy(tmp_output.begin(), tmp_output.begin() + output.size(), output.begin()); \
      } \
    } \
    std::unique_ptr<partial_hash> begin_hash() const override { \
      throw std::runtime_error("Not implemented"); \
    } \
    std::unique_ptr<partial_hash> begin_hash(data_const_ref) const override{ \
      throw std::runtime_error("Not implemented"); \
    } \
    const hash_properties& properties() const noexcept override { return static_props; } \
  }; \
  static const CLASS_NAME CLASS_NAME##_static; \
  static auto __##CLASS_NAME##_registered = _hash_funcs.emplace(ALG, &CLASS_NAME##_static); \
  template<> \
  const hash_function* get_hash_function<ALG>() { return &CLASS_NAME##_static; }

namespace c3::upsilon {
  std::map<hash_algorithm, const hash_function*> _hash_funcs;

  C3_UPSILON_DEF_HASH_BOTAN(sha2_224, hash_algorithm::SHA2_224, "SHA-224");
  C3_UPSILON_DEF_HASH_BOTAN(sha2_256, hash_algorithm::SHA2_256, "SHA-256");
  C3_UPSILON_DEF_HASH_BOTAN(sha2_384, hash_algorithm::SHA2_384, "SHA-384");
  C3_UPSILON_DEF_HASH_BOTAN(sha2_512, hash_algorithm::SHA2_512, "SHA-512");

  C3_UPSILON_DEF_HASH_BOTAN(sha3_224, hash_algorithm::SHA3_224, "SHA-3(224)");
  C3_UPSILON_DEF_HASH_BOTAN(sha3_256, hash_algorithm::SHA3_256, "SHA-3(256)");
  C3_UPSILON_DEF_HASH_BOTAN(sha3_384, hash_algorithm::SHA3_384, "SHA-3(384)");
  C3_UPSILON_DEF_HASH_BOTAN(sha3_512, hash_algorithm::SHA3_512, "SHA-3(512)");

  C3_UPSILON_DEF_HASH_BOTAN(blake2b_128, hash_algorithm::BLAKE2b_128, "Blake2b(128)");
  C3_UPSILON_DEF_HASH_BOTAN(blake2b_256, hash_algorithm::BLAKE2b_256, "Blake2b(256)");
  C3_UPSILON_DEF_HASH_BOTAN(blake2b_512, hash_algorithm::BLAKE2b_512, "Blake2b(512)");
}
