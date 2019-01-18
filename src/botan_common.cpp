#include "botan_common.hpp"

namespace c3::upsilon {
  thread_local csprng_wrapper csprng_wrapper::standard{};
}
