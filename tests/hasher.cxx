#include "c3/upsilon/hash.hpp"

#include <memory>
#include <iostream>
#include <iomanip>

constexpr auto hash_alg = c3::upsilon::hash_algorithm::BLAKE2b_256;

int main() {
  auto static_hasher = c3::upsilon::get_hasher<hash_alg>();
  auto dynamic_hasher = c3::upsilon::get_hasher(hash_alg);

  auto test_value = c3::nu::serialise("Hello, world!");

  if (static_hasher.get_hash(test_value) != dynamic_hasher.get_hash(test_value))
    return 1;

  auto auto_value = c3::nu::serialise("Hello, World!");

  if (static_hasher.get_hash(test_value) == dynamic_hasher.get_hash(auto_value))
    return 2;

  if (static_hasher.get_hash(auto_value) == dynamic_hasher.get_hash(test_value))
    return 3;

  return 0;
}
