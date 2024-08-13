#include <cstddef>
#include <cstdint>
#include <array>

#include "helpers/common.h"
#include "simdutf.h"

// simdutf::implementation::base64_length_from_binary();
// simdutf::implementation::maximal_binary_length_from_base64();
// simdutf::implementation::binary_to_base64();
// simdutf::implementation::base64_to_binary();

#if 0
size_t maximal_binary_length_from_base64(const char* input,
                                         size_t length) noexcept;

size_t maximal_binary_length_from_base64(const char* input,
                                         size_t length) noexcept;

result base64_to_binary(const char* input, size_t length, char* output,
                        base64_options options = base64_default) noexcept;

size_t
base64_length_from_binary(size_t length,
                          base64_options options = base64_default) noexcept;

size_t binary_to_base64(const char* input, size_t length, char* output,
                        base64_options options = base64_default) noexcept;

result base64_to_binary(const char16_t* input, size_t length, char* output,
                        base64_options options = base64_default) noexcept;

result base64_to_binary_safe(const char* input, size_t length, char* output,
                             size_t& outlen,
                             base64_options options = base64_default) noexcept;

result base64_to_binary_safe(const char16_t* input, size_t length, char* output,
                             size_t& outlen,
                             base64_options options = base64_default) noexcept;
#endif
constexpr std::array options = {
    simdutf::base64_default,          simdutf::base64_url,
    simdutf::base64_reverse_padding,  simdutf::base64_default_no_padding,
    simdutf::base64_url_with_padding,
};

struct decoderesult {
  std::size_t maxbinarylength{};
  simdutf::result convertresult{};
  auto operator<=>(const decoderesult&) const = default;
};

template <typename FromChar>
void decode(std::span<const FromChar> base64, const auto selected_option) {
  const auto implementations = get_supported_implementations();
  std::vector<decoderesult> results;
  results.reserve(implementations.size());
  for (auto impl : implementations) {
    auto& r = results.emplace_back();
    r.maxbinarylength =
        impl->maximal_binary_length_from_base64(base64.data(), base64.size());
    std::vector<char> output(r.maxbinarylength);
    r.convertresult = impl->base64_to_binary(base64.data(), base64.size(),
                                             output.data(), selected_option);
  }
  auto neq = [](const auto& a, const auto& b) { return a != b; };
  if (std::ranges::adjacent_find(results, neq) != results.end()) {
    std::cerr << "output differs between implementations for decode\n";
    const auto implementations = get_supported_implementations();
    std::size_t i = 0;
    for (const auto& r : results) {
      std::cerr << "impl " << implementations[i]->name()
                << " got maxbinarylength=" << r.maxbinarylength
                << " convertresult=" << r.convertresult << "\n";
      ++i;
    }
    std::cerr << "option: " << selected_option << '\n';
    std::cerr << "data: "
              << (std::is_same_v<FromChar, char> ? "char" : "char16_t") << "{";
    for (int v : base64) {
      std::cerr << v << ", ";
    }
    std::cerr << "}\n";
    std::abort();
  }
}

struct roundtripresult {
  std::size_t length{};
  std::size_t maxbinarylength{};
  std::string outputhash;
  std::size_t written{};
  simdutf::result convertbackresult{};
  auto operator<=>(const roundtripresult&) const = default;
};

void roundtrip(std::span<const char> binary, const auto selected_option) {

  const auto inputhash = FNV1A_hash::as_str(binary);
  const auto implementations = get_supported_implementations();
  std::vector<roundtripresult> results;
  results.reserve(implementations.size());
  for (auto impl : implementations) {
    auto& r = results.emplace_back();
    r.length = impl->base64_length_from_binary(binary.size(), selected_option);
    std::vector<char> output(r.length);
    r.written = impl->binary_to_base64(binary.data(), binary.size(),
                                       output.data(), selected_option);
    if (r.length != r.written) {
      std::abort();
    }
    r.outputhash = FNV1A_hash::as_str(output);
    // convert back to binary
    r.maxbinarylength =
        impl->maximal_binary_length_from_base64(output.data(), output.size());
    std::vector<char> restored(r.maxbinarylength);
    r.convertbackresult = impl->base64_to_binary(
        output.data(), output.size(), restored.data(), selected_option);

    if (const auto restoredhash = FNV1A_hash::as_str(restored);
        inputhash != restoredhash) {
      std::abort();
    }
    if (restored.size() != binary.size()) {
      std::abort();
    }
  }

  auto neq = [](const auto& a, const auto& b) { return a != b; };
  if (std::ranges::adjacent_find(results, neq) != results.end()) {
    std::cerr << "output differs between implementations\n";
    for (const auto& r : results) {
      std::cout << "written=" << r.written << " maxlength=" << r.maxbinarylength
                << " length=" << r.length << '\n';
    }
    std::abort();
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // pick one of the function pointers, based on the fuzz data
  // the first byte is which action to take. step forward
  // several bytes so the input is aligned.
  if (size < 4) {
    return 0;
  }
  constexpr auto Ncases = 3u;
  constexpr auto actionmask = std::bit_ceil(Ncases) - 1;
  const auto action = data[0] & actionmask;

  // pick a random option
  const auto selected_option = [](auto index) {
    if (index >= options.size())
      return options[0];
    else {
      return options[index];
    }
  }(data[1] & (std::bit_ceil(options.size()) - 1));

  data += 4;
  size -= 4;

  switch (action) {
  case 0: {
    const std::span<const char> chardata{(const char*)data, size};
    roundtrip(chardata, selected_option);
  } break;
  case 1: {
    const std::span<const char> chardata{(const char*)data, size};
    decode(chardata, selected_option);
  } break;
  case 2: {
    const std::span<const char16_t> chardata{(const char16_t*)data, size / 2};
    decode(chardata, selected_option);
  } break;
  }

  return 0;
}
