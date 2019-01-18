#pragma once

//#include "hash.hpp"

#include "c3/upsilon/data/common.hpp"

namespace c3::upsilon {
  /*
  template<size_t HashSize>
  hash<HashSize>::operator hash_ref() {
    return { value };
  }
  template<size_t HashSize>
  hash<HashSize>::operator hash_const_ref() const {
    return { value };
  }*/

  template<size_t HashSize>
  hash<dynamic_size> hash<HashSize>::dynamic(size_t new_size) const {
    if (new_size > hash_size())
      throw std::range_error("Cannot make hash larger!");
    return {value.begin(), value.begin() + new_size};
  }

  template<size_t HashSize>
  template<size_t NewHashSize>
  hash<NewHashSize> hash<HashSize>::truncate() const {
    static_assert(NewHashSize <= hash_size(), "Cannot make hash larger!");

    hash<NewHashSize> ret;
    std::copy(value.begin(), value.begin() + NewHashSize, ret.value.begin());
    return ret;
  }

  template<size_t HashSize>
  hash<HashSize>::operator hash<dynamic_size>() const {
    return dynamic();
  }

  template<size_t HashSize>
  template<size_t NewHashSize>
  hash<HashSize>::operator hash<NewHashSize>() const {
    return truncate<NewHashSize>();
  }

  template<size_t HashSize>
  inline hash<HashSize> hasher::_get_hash_base(data_const_ref b) const {
    if constexpr (HashSize == dynamic_size) {
      return _get_hash_base(b, props.max_output);
    }
    else {
      hash<HashSize> ret;
      _impl->compute_hash(input_buffer_ref(b), ret.value);
      return ret;
    }
  }
  inline hash<dynamic_size> hasher::_get_hash_base(data_const_ref b, size_t len) const {
    hash<dynamic_size> ret;
    ret.value.resize(len);
    _impl->compute_hash(b, ret.value);
    return ret;
  }

  template<size_t HashSize>
  inline hash<HashSize> hasher::_get_hash_base(data_const_ref b, data_const_ref salt) const {
    if constexpr (HashSize == dynamic_size) {
      return _get_hash_base(b, salt, props.max_output);
    }
    else {
      hash<HashSize> ret;
      _impl->compute_hash(input_buffer_ref(b), salt, ret.value);
      return ret;
    }
  }
  inline hash<dynamic_size> hasher::_get_hash_base(data_const_ref b,
                                                   data_const_ref salt,
                                                   size_t len) const {
    hash<dynamic_size> ret;
    ret.value.resize(len);
    _impl->compute_hash(b, salt, ret.value);
    return ret;
  }

  template<size_t HashSize, typename T>
  hash<HashSize> hasher::get_hash(const T& t) const {
    if constexpr (std::is_same_v<T, data>)
      return _get_hash_base<HashSize>(t);
    else
      return _get_hash_base<HashSize>(serialise(t));
  }
  template<typename T>
  hash<dynamic_size> hasher::get_hash(const T& t, size_t len) const {
    if constexpr (std::is_same_v<T, data>)
      return _get_hash_base(t, len);
    else
      return _get_hash_base(serialise(t), len);
  }

  template<size_t HashSize, typename T>
  hash<HashSize> hasher::get_hash(const T& t, data_const_ref salt) const {
    if constexpr (std::is_same_v<T, data>)
      return _get_hash_base<HashSize>(t, salt);
    else
      return _get_hash_base<HashSize>(serialise(t), salt);
  }
  template<typename T>
  hash<dynamic_size> hasher::get_hash(const T& t, data_const_ref salt, size_t len) const {
    if constexpr (std::is_same_v<T, data>)
      return _get_hash_base(t, salt, len);
    else
      return _get_hash_base(serialise(t), salt, len);
  }
}
