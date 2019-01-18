#include "c3/upsilon/symmetric.hpp"

#include <botan/stream_cipher.h>

// Botan requires unique_ptr or manual implementation, so this is simpler

#define C3_UPSILON_DEF_SYM_BOTAN(CLASS_NAME, SYM_ALG, BOTAN_SYM_NAME) \
  class CLASS_NAME : public botan_impl<SYM_ALG> { \
  public: \
    template<typename... Args> \
    inline CLASS_NAME(key_const_ref<SYM_ALG> key, iv_const_ref<SYM_ALG> iv) : \
      botan_impl{BOTAN_SYM_NAME, key, iv} {} \
  }; \
  static auto __##CLASS_NAME##_registered = \
    _symmetric_functions.emplace(SYM_ALG, \
                                [](auto a, auto b){ \
                                    return std::make_unique<CLASS_NAME>(a, b); \
                                });

namespace c3::upsilon {
  std::map<symmetric_algorithm, symmetric_properties> _symmetric_properties;

  std::map<symmetric_algorithm,
           std::function<std::unique_ptr<symmetric_function>(data_const_ref,
                                                             data_const_ref)>> _symmetric_functions;

  // XXX: Assumes F(F(M)) = M
  template<symmetric_algorithm Alg>
  class botan_impl : public symmetric_function {
  public:
    std::unique_ptr<Botan::StreamCipher> cipher;
    uint64_t stream_pos = 0;
  public:
    inline botan_impl(const char* botan_sym_name, key_const_ref<Alg> key, iv_const_ref<Alg> iv) :
      cipher{Botan::StreamCipher::create(botan_sym_name)} {
      cipher->set_key(key.data(), key.size()); \
      cipher->set_iv(iv.data(), iv.size()); \
    }

  public:
    void encrypt(data_ref inout) override {
      size_t n_todo = static_cast<size_t>(inout.size());
      cipher->cipher(inout.data(), inout.data(), n_todo);
      stream_pos += n_todo;
    }
    uint64_t encrypt(data_const_ref input, data_ref output) override {
      size_t n_todo = static_cast<size_t>(std::min(input.size(), output.size()));
      cipher->cipher(input.data(), output.data(), n_todo);
      stream_pos += n_todo;
      return n_todo;
    }

    void decrypt(data_ref inout) override {
      size_t n_todo = static_cast<size_t>(inout.size());
      cipher->cipher(inout.data(), inout.data(), n_todo);
      stream_pos += n_todo;
    }
    uint64_t decrypt(data_const_ref input, data_ref output) override {
      size_t n_todo = static_cast<size_t>(std::min(input.size(), output.size()));
      cipher->cipher(input.data(), output.data(), n_todo);
      stream_pos += n_todo;
      return n_todo;
    }
    void seek(uint64_t new_pos) override {
      stream_pos = new_pos;
      cipher->seek(stream_pos);
    }
    size_t pos() const noexcept override { return stream_pos; }
    symmetric_algorithm alg() const noexcept override { return Alg; }
  };

  C3_UPSILON_DEF_SYM_BOTAN(aes128, symmetric_algorithm::AES128, "CTR(AES-128)");
  C3_UPSILON_DEF_SYM_BOTAN(aes256, symmetric_algorithm::AES256, "CTR(AES-256)");

  C3_UPSILON_DEF_SYM_BOTAN(chacha20_8 , symmetric_algorithm::ChaCha20_8 ,  "ChaCha(8)");
  C3_UPSILON_DEF_SYM_BOTAN(chacha20_12, symmetric_algorithm::ChaCha20_12, "ChaCha(12)");
  C3_UPSILON_DEF_SYM_BOTAN(chacha20_20, symmetric_algorithm::ChaCha20_20, "ChaCha(20)");

  // Botan differentiates based on IV,
  // so since we have set a minimum required IV size, this is abstracted away
  C3_UPSILON_DEF_SYM_BOTAN(xchacha20_8 , symmetric_algorithm::XChaCha20_8 , "ChaCha(8)");
  C3_UPSILON_DEF_SYM_BOTAN(xchacha20_12, symmetric_algorithm::XChaCha20_8 , "ChaCha(12)");
  C3_UPSILON_DEF_SYM_BOTAN(xchacha20_20, symmetric_algorithm::XChaCha20_8 , "ChaCha(20)");
}
