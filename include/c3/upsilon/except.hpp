#pragma once

#include <exception>
#include <string>

namespace c3::upsilon {
  template<typename AlgType>
  class algorithm_not_implemented : public std::exception {
  public:
    std::string msg;

  public:
    const char* what() const noexcept override { return msg.c_str(); }

  public:
    algorithm_not_implemented(AlgType alg) :
      msg{std::to_string(static_cast<typename std::underlying_type<AlgType>::type>(alg))} {}
  };
}
