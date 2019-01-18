#include "c3/upsilon/agreement.hpp"

constexpr auto agreement_alg = c3::upsilon::agreement_algorithm::Curve25519;
constexpr auto kdf_alg = c3::upsilon::kdf_algorithm::Shake256;

constexpr size_t out_len = 1024;

int main() {
  auto alice = c3::upsilon::agreer::gen<agreement_alg, kdf_alg>();
  auto bob = c3::upsilon::agreer::gen(agreement_alg, kdf_alg);

  auto alice_k = alice.derive_shared_secret(bob.get_public(), out_len);
  auto bob_k = bob.derive_shared_secret<out_len>(alice.get_public());

  if (!std::equal(alice_k.begin(), alice_k.end(),
                  bob_k.begin(), bob_k.end()))
    return 1;

  return 0;
}
