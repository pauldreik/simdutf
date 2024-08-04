// this fuzzes the convert_ functions (those that do not assume valid input).
// by Paul Dreik 2024

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <iostream>
#include <span>
#include <vector>

#include "helpers/common.h"
#include "helpers/nameof.hpp"

#include "simdutf.h"

constexpr bool allow_implementations_to_differ = false;
constexpr bool use_canary_in_output = true;
constexpr bool try_different_alignment = true;

/// this is a list of types used for passing character strings around. keeping track
/// of latin1 vs utf8 or utf16 BE vs LE is not made here.
using UTFTypes = std::tuple<char, char16_t, char32_t>;
constexpr std::size_t NUTFTypes = std::tuple_size_v<UTFTypes>;
constexpr std::string_view UTFTypeNames[NUTFTypes] = {"char", "char16_t", "char32_t"};

/// keeps a pointer to a function along with a name for it - the name is useful
/// for debugging and printing a meaningful error message
template<member_function_pointer FuncPointer>
struct named_function
{
    FuncPointer pointer;
    std::string name;
};
template<member_function_pointer FuncPointer>
named_function(FuncPointer pointer, std::string name) -> named_function<FuncPointer>;

auto populate_functions()
{
    // build a tuple containing function pointers to everything we want to fuzz
    using I = simdutf::implementation;
#define ADD(x) \
    named_function \
    { \
        &I::x, std::string \
        { \
            NAMEOF(&I::x) \
        } \
    }
#define IGNORE(x) \
    named_function \
    { \
        decltype(&I::x){nullptr}, std::string \
        { \
            NAMEOF(&I::x) \
        } \
    }

    // this list was obtained by manually copying the interesting part of implementation.cpp ("class implementation") into impl.cpp and running
    // clang-17 -Xclang -ast-dump  impl.cpp  2>/dev/null|sed -e 's/\x1b\[[0-9;]*m//g' | grep -- CXXMethodDecl >tjoff
    // cat tjoff |grep --only-matching convert.* |cut -f1 -d' ' |sort  |xargs -I§ echo "ADD( " § "),"

    std::tuple nameandptr(ADD(convert_latin1_to_utf16be),
                          ADD(convert_latin1_to_utf16le),
                          ADD(convert_latin1_to_utf32),
                          ADD(convert_latin1_to_utf8),
                          ADD(convert_utf16be_to_latin1),
                          ADD(convert_utf16be_to_latin1_with_errors),
                          ADD(convert_utf16be_to_utf32),
                          ADD(convert_utf16be_to_utf32_with_errors),
                          ADD(convert_utf16be_to_utf8),
                          ADD(convert_utf16be_to_utf8_with_errors),
                          ADD(convert_utf16le_to_latin1),
                          ADD(convert_utf16le_to_latin1_with_errors),
                          ADD(convert_utf16le_to_utf32),
                          ADD(convert_utf16le_to_utf32_with_errors),
                          ADD(convert_utf16le_to_utf8),
                          ADD(convert_utf16le_to_utf8_with_errors),
                          ADD(convert_utf32_to_latin1),
                          ADD(convert_utf32_to_latin1_with_errors),
                          ADD(convert_utf32_to_utf16be),
                          ADD(convert_utf32_to_utf16be_with_errors),
                          ADD(convert_utf32_to_utf16le),
                          ADD(convert_utf32_to_utf16le_with_errors),
                          ADD(convert_utf32_to_utf8),
                          ADD(convert_utf32_to_utf8_with_errors),
                          ADD(convert_utf8_to_latin1),
                          ADD(convert_utf8_to_latin1_with_errors),
                          ADD(convert_utf8_to_utf16be),
                          ADD(convert_utf8_to_utf16be_with_errors),
                          ADD(convert_utf8_to_utf16le),
                          ADD(convert_utf8_to_utf16le_with_errors),
                          ADD(convert_utf8_to_utf32),
                          ADD(convert_utf8_to_utf32_with_errors)
    );
#undef ADD
#undef IGNORE
    return nameandptr;
}

/*
 * Helper class to simplify invoking function pointers on the correct arguments.
 * The indices refer to the element in UTFTypes
 */
template<std::size_t Index1, std::size_t Index2>
struct Invoker
{
    using InputType = std::tuple_element_t<Index1, UTFTypes>;
    using OutputType = std::tuple_element_t<Index2, UTFTypes>;

    /// this function will be invoked only if the function pointer matches
    /// the types
    template<member_function_pointer FuncPointer>
        requires(std::invocable<FuncPointer,
                                simdutf::implementation *,
                                const InputType *,
                                std::size_t,
                                OutputType *>)
    void operator()(const named_function<FuncPointer> &funcptr, std::span<const char> chardata)
    {
        // convert to the correct input type - assume the input is correctly
        // aligned
        const std::span<const InputType> typedspan{reinterpret_cast<const InputType *>(
                                                       chardata.data()),
                                                   chardata.size() / sizeof(InputType)};
        // FIXME: drop the empty check once https://github.com/simdutf/simdutf/issues/468 is fixed
        if (try_different_alignment && !typedspan.empty()) {
            std::vector<InputType> input(begin(typedspan), end(typedspan));
            compare_implementations(funcptr, std::span(input));
            // insert a bogus element to shift them one step
            input.insert(input.begin(), {});
            // the first element is now aligned differently
            compare_implementations(funcptr, std::span(input).last(typedspan.size()));
        } else {
            compare_implementations(funcptr, typedspan);
        }
    }

    /// this is just here to match cases where the input types don't match
    /// with the function pointer
    template<member_function_pointer FuncPointer>
        requires(!std::invocable<FuncPointer,
                                 simdutf::implementation *,
                                 const InputType *,
                                 std::size_t,
                                 OutputType *>)
    void operator()(const named_function<FuncPointer> &funcptr, std::span<const char> chardata)
    {
    }

    template<member_function_pointer FuncPointer>
    static void compare_implementations(const named_function<FuncPointer> &funcptr,
                                        std::span<const InputType> typedspan)
    {

        // be conservative (this might prevent us from finding write overflows)
        std::vector<OutputType> output(4 * typedspan.size());

        // find out what we get when invoking the pointer
        using R = std::invoke_result_t<FuncPointer,
                                       const simdutf::implementation *,
                                       const InputType *,
                                       std::size_t,
                                       OutputType *>;
        std::vector<R> results;

        // optionally print the test case as a unit test
        static const bool do_print_testcase = std::getenv("PRINT_FUZZ_CASE") != nullptr;

        if (do_print_testcase) {
            print_testcase<R>(funcptr, typedspan);
        }

        const auto implementations = get_supported_implementations();
        results.reserve(implementations.size());

        std::vector<std::string> outputhashes;

        for (auto impl : implementations) {
            // reset the contents to ensure it does not carry over results
            // from previous round
            const OutputType canary{42};
            std::ranges::fill(output, canary);
            results.push_back(std::invoke(funcptr.pointer,
                                          impl,
                                          typedspan.data(),
                                          typedspan.size(),
                                          output.data()));
            // find out which part of the output vector that was alledgely written to
            auto output_span = [r = results.back(),
                                s = std::span{output}]() -> std::span<const OutputType> {
                if constexpr (std::is_same_v<decltype(r), std::size_t>) {
                    if (r != 0) {
                        // success.
                        return s.first(r);
                    }
                    return {};
                } else {
                    if (r.error == simdutf::error_code::SUCCESS) {
                        return s.first(r.count);
                    } else {
                        return {};
                    }
                }
            }();
            const auto contenthash = FNV1A_hash::as_str(output_span);
            outputhashes.emplace_back(contenthash);

            // verify the canary
            if (!output_span.empty()) {
                const bool canary_is_fine = std::all_of(output.data() + output_span.size(),
                                                        output.data() + output.size(),
                                                        [](auto e) { return e == canary; });
                if (!canary_is_fine) {
                    std::cerr << "the canary died!\n";
                    std::abort();
                }
            }
        }
        if (allow_implementations_to_differ) {
            return;
        }

        auto neq = [](const auto &a, const auto &b) { return a != b; };
        if (std::ranges::adjacent_find(results, neq) != results.end()) {
            std::cerr << "begin errormessage\n";
            std::cerr << "in fuzz case for " << funcptr.name << "(const " << UTFTypeNames[Index1]
                      << "*, std::size_t, " << UTFTypeNames[Index2] << "*) invoked with "
                      << typedspan.size() << " elements:\n";
            for (std::size_t i = 0; i < results.size(); ++i) {
                std::cerr << "got return " << std::dec << results[i] << " from implementation "
                          << implementations[i]->name() << '\n';
            }
            std::cerr << "end errormessage\n";
            if (!allow_implementations_to_differ) {
                std::abort();
            }
        }
        if (std::ranges::adjacent_find(outputhashes, neq) != outputhashes.end()) {
            std::cerr << "begin errormessage\n";
            std::cerr << "in fuzz case for " << funcptr.name << "(const " << UTFTypeNames[Index1]
                      << "*, std::size_t, " << UTFTypeNames[Index2] << "*) invoked with "
                      << typedspan.size() << " elements:\n";
            for (std::size_t i = 0; i < results.size(); ++i) {
                std::cerr << "got content hash " << outputhashes[i] << " from implementation "
                          << implementations[i]->name() << '\n';
            }
            std::cerr << "end errormessage\n";
            if (!allow_implementations_to_differ) {
                std::abort();
            }
        }
    }

    template<typename R, member_function_pointer FuncPointer>
    static void print_testcase(const named_function<FuncPointer> &funcptr,
                               std::span<const InputType> typedspan)
    {
        const auto testhash = FNV1A_hash::as_str(funcptr.name, typedspan);

        std::cerr << "// begin testcase\n";
        std::cerr << "TEST(issue_" << funcptr.name << "_" << testhash << ") {\n";
        std::cerr << " const unsigned char data[]={";
        const auto first = reinterpret_cast<const unsigned char *>(typedspan.data());
        const auto last = first + typedspan.size_bytes();
        for (auto it = first; it != last; ++it) {
            std::cerr << "0x" << std::hex << std::setfill('0') << std::setw(2) << (+*it)
                      << (it + 1 == last ? "};\n" : ", ");
        }
        std::cerr << " constexpr std::size_t data_len_bytes=sizeof(data);\n";
        std::cerr << " constexpr std::size_t data_len=data_len_bytes/sizeof("
                  << UTFTypeNames[Index1] << ");\n";
        std::cerr << "std::vector<" << UTFTypeNames[Index2] << "> output(4 * data_len);\n";
        std::cerr << "const auto r = implementation." << funcptr.name << "((const "
                  << UTFTypeNames[Index1] << "*) data\n, data_len\n, output.data());\n";
        if constexpr (std::is_same_v<R, simdutf::result>) {
            std::cerr << "   ASSERT_EQUAL(r.count, 1234); \n";
            std::cerr << "   ASSERT_EQUAL(r.error, simdutf::error_code::SUCCESS);";
        } else if constexpr (std::is_same_v<R, std::size_t>) {
            std::cerr << "   ASSERT_EQUAL(r, 12345); \n";
        }
        std::cerr << "}\n";
        std::cerr << "// end testcase\n";
    }
};

/// third level of expansion.
template<member_function_pointer FuncPointer, std::size_t InputInt, std::size_t... OutputInts>
void expand_level_3(const named_function<FuncPointer> &funcptr,
                    std::index_sequence<OutputInts...>,
                    std::span<const char> chardata)
{
    (Invoker<InputInt, OutputInts>{}(funcptr, chardata), ...);
}

/// second level of expansion
template<member_function_pointer FuncPointer, std::size_t... InputInts>
void expand_level_2(named_function<FuncPointer> funcptr,
                    std::index_sequence<InputInts...>,
                    std::span<const char> chardata)
{
    (expand_level_3<FuncPointer, InputInts>(funcptr,
                                            std::make_index_sequence<NUTFTypes>(),
                                            chardata),
     ...);
}

/// first level of expansion
template<typename FuncPointer>
void expand_level_1(named_function<FuncPointer> funcptr, std::span<const char> chardata)
{
    expand_level_2(funcptr, std::make_index_sequence<NUTFTypes>(), chardata);
}

/*
 * this invokes the function pointer in the ith: element of t, but not any others
 */
template<std::size_t... Indices, typename... FuncPointer>
void pickfromtupleimpl(std::size_t i,
                       std::index_sequence<Indices...>,
                       const std::tuple<named_function<FuncPointer>...> &t,
                       std::span<const char> chardata)
    requires(sizeof...(Indices) == sizeof...(FuncPointer))
            && (member_function_pointer<FuncPointer> && ...)
{
    (
        [&]() {
            if (i == Indices) {
                const auto &c = std::get<Indices>(t);
                if (c.pointer != nullptr) {
                    expand_level_1(std::get<Indices>(t), chardata);
                }
            };
        }(),
        ...);
}

/**
 * given a dynamic index i, picks the i:th element from the tuple t and
 * passes it on for fuzzing using the provided data in chardata
 */
template<typename... FuncPointer>
    requires(member_function_pointer<FuncPointer> && ...)
void pickfromtuple(std::size_t i,
                   const std::tuple<named_function<FuncPointer>...> &t,
                   std::span<const char> chardata)
{
    constexpr std::size_t N = sizeof...(FuncPointer);
    if (i < N) {
        pickfromtupleimpl(i, std::make_index_sequence<N>(), t, chardata);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const auto fptrs = populate_functions();
    constexpr std::size_t Ncases = std::tuple_size_v<decltype(fptrs)>;

    // pick one of the function pointers, based on the fuzz data
    // the first byte is which action to take. step forward
    // several bytes so the input is aligned.
    if (size < 4) {
        return 0;
    }

    constexpr auto actionmask = std::bit_ceil(Ncases) - 1;
    const auto action = data[0] & actionmask;
    data += 4;
    size -= 4;
    std::span<const char> chardata{(const char *) data, size};
    pickfromtuple(action, fptrs, chardata);

    return 0;
}
