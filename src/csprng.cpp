#include "c3/upsilon/csprng.hpp"

#include <botan/auto_rng.h>

namespace c3::upsilon {
  class csprng::impl {
  public:
    Botan::AutoSeeded_RNG impl = {};
  };

  csprng::csprng() : _impl{std::make_unique<impl>()} {}
  csprng::~csprng() = default;

  csprng::result_type csprng::operator()() {
    return _impl->impl.next_byte();
  }

  thread_local csprng csprng::standard{};
}
