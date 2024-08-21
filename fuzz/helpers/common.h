// fuzzer helper functions
//
// by Paul Dreik 2024

#pragma once

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <iostream>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "simdutf.h"

#include "nameof.hpp"

/// checks that the given type is a member function pointer
template <typename T>
concept member_function_pointer = std::is_member_function_pointer_v<T>;

/// gets a list of implementations to fuzz
inline std::span<const simdutf::implementation* const>
get_supported_implementations() {
  static const auto impl = []() -> auto {
    std::vector<std::string> only;
    if (const char* onlyenv = std::getenv("FUZZ_ONLY_IMPLEMENTATIONS");
        onlyenv) {
      for (const auto word :
           std::views::split(std::string_view{onlyenv}, ':')) {
        only.emplace_back(std::begin(word), std::end(word));
      }
      std::cerr << "FUZZ_ONLY_IMPLEMENTATIONS is set to " << onlyenv << "\n";
    } else {
      std::cerr << "set FUZZ_ONLY_IMPLEMENTATIONS=impl1:impl2.... to only fuzz "
                   "a subset of the available implementations.\n";
    }
    auto is_ignored = [&only](std::string_view name) {
      return !only.empty() && std::ranges::count(only, name) == 0;
    };

    std::vector<const simdutf::implementation*> ret;
    for (auto e : simdutf::get_available_implementations()) {
      std::cerr << "implementation " << e->name() << " is available? "
                << e->supported_by_runtime_system() << " ignored? "
                << is_ignored(e->name()) << '\n';
      if (e->supported_by_runtime_system() && !is_ignored(e->name())) {
        ret.push_back(e);
      }
    }
    return ret;
  }();
  return {impl.data(), impl.size()};
}

/// this should go into the library instead
inline bool operator!=(const simdutf::result& a, const simdutf::result& b) {
  return a.count != b.count || a.error != b.error;
}
inline bool operator==(const simdutf::result& a, const simdutf::result& b) {
  return a.count == b.count && a.error == b.error;
}
auto operator<=>(const simdutf::result& a, const simdutf::result& b) {
  return std::tie(a.error, a.count) <=> std::tie(b.error, a.count);
}

inline std::ostream& operator<<(std::ostream& os, const simdutf::result& a) {
  os << "[count=" << a.count << ", error=" << NAMEOF_ENUM(a.error) << "]";
  return os;
}

template <typename Data>
constexpr bool is_hashable = std::is_arithmetic_v<Data>;

struct FNV1A_hash {
  static constexpr std::uint64_t prime = 0x00000100000001B3;
  static constexpr std::uint64_t offset = 0xcbf29ce484222325;

  static constexpr std::uint64_t
  fnv1ahash_impl(std::span<const unsigned char> bytes) {
    auto hash = offset;

    for (std::uint64_t byte : bytes) {
      hash ^= byte;
      hash *= prime;
    }

    return hash;
  }
  static constexpr std::uint64_t fnv1ahash_impl(std::span<const char> bytes) {
    auto hash = offset;

    for (auto byte : bytes) {
      hash ^= static_cast<unsigned char>(byte);
      hash *= prime;
    }

    return hash;
  }

  template <typename Basic, std::size_t N>
    requires(is_hashable<Basic> && !std::is_same_v<Basic, char> &&
             !std::is_same_v<Basic, unsigned char>)
  static constexpr std::uint64_t fnv1ahash_impl(std::span<Basic, N> data) {
    return fnv1ahash_impl({reinterpret_cast<const unsigned char*>(data.data()),
                           data.size_bytes()});
  }

  template <typename Data>
    requires is_hashable<Data>
  static constexpr std::uint64_t fnv1ahash_impl(const std::vector<Data>& data) {
    return fnv1ahash_impl(std::span(data));
  }

  template <typename... Data> static std::string as_str(const Data&... data) {
    static_assert(sizeof...(Data) > 0, "must hash with at least one argument");
    std::uint64_t h;
    if constexpr (sizeof...(Data) > 1) {
      const std::array hashes{fnv1ahash_impl(data)...};
      const auto s = std::span(hashes);
      h = fnv1ahash_impl(s);
    } else {
      h = fnv1ahash_impl(data...);
    }
    constexpr std::size_t expected_chars = 16;
    std::string ret(expected_chars, '0');
    auto c = std::to_chars(ret.data(), ret.data() + ret.size(), h, 16);
    assert(c.ec == std::errc{});
    auto nwritten = c.ptr - ret.data();
    assert(nwritten <= expected_chars);
    std::rotate(ret.data(), c.ptr, ret.data() + expected_chars);
    return ret;
  }
};

static_assert(FNV1A_hash::fnv1ahash_impl(std::string_view{""}) ==
              0xcbf29ce484222325);
static_assert(FNV1A_hash::fnv1ahash_impl(std::string_view{"xyz"}) ==
              0xbff4aa198026f420);
static_assert(FNV1A_hash::fnv1ahash_impl(std::string{"xyz"}) ==
              0xbff4aa198026f420);
static_assert(FNV1A_hash::fnv1ahash_impl(std::string_view{"\xFF"}) ==
              0xaf64724c8602eb6e);
static_assert(FNV1A_hash::fnv1ahash_impl(std::string_view{
                  "\x01\x01\x01\x01"}) == 0xb5d0e0774c7d7499);
static_assert(FNV1A_hash::fnv1ahash_impl(std::array<unsigned char, 4>{
                  0x01, 0x01, 0x01, 0x01}) == 0xb5d0e0774c7d7499);
