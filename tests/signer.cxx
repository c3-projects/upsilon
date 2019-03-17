#include "c3/upsilon/identity.hpp"

#include <c3/nu/data.hpp>

#include <memory>
#include <iostream>
#include <iomanip>

using namespace c3::upsilon;
using namespace c3;

constexpr auto hash_alg = hash_algorithm::BLAKE2b_256;
constexpr auto sig_alg = signature_algorithm::Curve25519;

int main() {
  auto me = owned_identity::gen<sig_alg, hash_alg>();

  auto msg = nu::serialise("Hello, world!");

  auto sig = me.sign(msg);

  if (!me.verify(msg, sig))
    throw std::runtime_error("Failed to verify own signature");

  auto eve = owned_identity::gen(sig_alg, hash_alg);
  if (eve.verify(msg, sig))
    throw std::runtime_error("Incorrectly verified other's signature");

  auto bob = nu::deserialise<identity>(me.serialise_public());

  if (!bob.verify(msg, sig))
    throw std::runtime_error("Failed to deserialise and then verify");

  auto me_serialised = serialise(me);

  auto me_reloaded = nu::deserialise<owned_identity>(me_serialised);

  if (!me_reloaded.verify(msg, sig))
    throw std::runtime_error("Failed to deserialise and then verify");
}
