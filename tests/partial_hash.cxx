#include "c3/upsilon/hash.hpp"

#include "c3/nu/data/hex.hpp"
#include <iostream>

using namespace c3::upsilon;

constexpr auto hash_alg = c3::upsilon::hash_algorithm::BLAKE2b_512;

int main() {
  auto hasher = get_hasher<hash_alg>();

  auto test_value_0 = c3::nu::serialise("Hello, world!");
  auto test_value_1 = c3::nu::serialise("foobar");
  auto test_value = test_value_0;
  test_value.insert(test_value.end(), test_value_1.begin(), test_value_1.end());

  auto normal_hash = hasher.get_hash(test_value);

  auto p = hasher.begin_hash();
  p.process(test_value_0);
  p.process(test_value_1);
  auto weird_hash = p.finish();

  if (normal_hash != weird_hash)
    throw std::runtime_error("Hashes are not equal");

  return 0;

}
