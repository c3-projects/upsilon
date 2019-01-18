//! An allocator that destroys the data on free
#pragma once

#include <memory>
#include <type_traits>
#include <vector>

namespace c3::upsilon {
  void nuke(uint8_t* data, size_t n_bytes);

  template<typename T>
  class nuker {
    static_assert (std::is_integral_v<T>, "Cannot safely nuke non-integral types");

  private:
    std::allocator<T> alloc;

  public:
    using value_type = typename std::allocator<T>::value_type;
    using size_type = typename std::allocator<T>::size_type;
    using difference_type = typename std::allocator<T>::difference_type;
    using propagate_on_container_move_assignment = typename std::allocator<T>::propagate_on_container_move_assignment;
    using is_always_equal = typename std::allocator<T>::is_always_equal;

  public:
    inline T* allocate(size_type len) { alloc.allocate(len); }
    inline void deallocate(T* p, size_type len) {
      nuke(p, sizeof(T) * len);
      alloc.deallocate(p, len);
    }

  public:
    nuker() = default;
  };

  using nuking_data = std::vector<uint8_t, nuker<uint8_t>>;
}
