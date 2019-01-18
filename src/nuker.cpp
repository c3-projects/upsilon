#include "c3/upsilon/nuker.hpp"

#include <botan/mem_ops.h>

void c3::upsilon::nuke(uint8_t* bytes, size_t len) {
  // I'm not writing this myself
  Botan::secure_scrub_memory(bytes, len);
}
