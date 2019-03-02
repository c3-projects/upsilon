#pragma once

#include "c3/upsilon/pow.hpp"

//! Laserproof: a self-scaling memory-hard PoW function
//!
//!

namespace c3::upsilon {
  bool laserproof::check_complete(nu::data_const_ref buf, nu::data_const_ref proof) const {
    auto final_block_start = buf.begin() + (buf.size() % backstride_len);
    auto first_block_start = buf.end() - 1 - backstride_len;

    auto ph = h.begin_hash(proof);

    for (auto iter = first_block_start; iter != final_block_start; iter -= buf.size())
      ph.process({&*iter, static_cast<nu::data_const_ref::index_type>(backstride_len)});

    auto hash = ph.finish();

    uint8_t result = 0;
    for (auto i : hash.value)
      result ^= i;

    return result < threshold;
  }

  nu::biguint laserproof::check_one(nu::data_const_ref hashed_data, nu::data_const_ref proof) const {
    nu::data buf;
    do {
      // Add a work block
      size_t next_lookback_len = std::min(buf.size(), lookback_len);
      size_t next_lookback_offset = buf.size() - next_lookback_len;
      nu::data_const_ref next_lookback{buf.data() + next_lookback_offset,
                                       static_cast<nu::data_const_ref::index_type>(next_lookback_len)};
      auto work_block = h.get_hash(next_lookback).value;
      buf.insert(buf.end(), work_block.begin(), work_block.end());
    }
    while (!check_complete(buf, proof));

    return buf.size();
  }

  nu::biguint laserproof::difficulty(nu::data_const_ref hashed_data,
                                     nu::data_const_ref proof) const noexcept {
    try {
      if (proof.size() != proof_len)
        throw std::runtime_error("Proof size incorrect");

      return check_one(hashed_data, proof);
    }
    catch (...) {
      return 0;
    }
  }
}
