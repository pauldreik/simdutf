#include "simdutf.h"

#include <vector>

#include <tests/helpers/random_int.h>
#include <tests/helpers/test.h>
#include <tests/helpers/transcode_test_base.h>

TEST_MAIN

#define IGNORE return

// begin testcase
TEST(issue_convert_utf16le_to_latin1_with_errors_cbf29ce48422238a)
{
    IGNORE;
    const unsigned char data[] = {0x00,
                                  0x20,
                                  0x00,
                                  0x20,
                                  0x00,
                                  0x20,
                                  0x00,
                                  0x20,
                                  0x00,
                                  0x20,
                                  0x00,
                                  0x20,
                                  0x00,
                                  0x20,
                                  0x00,
                                  0x20};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char16_t);
    std::vector<char> output(4 * data_len);
    const auto r = implementation.convert_utf16le_to_latin1_with_errors((const char16_t *) data,
                                                                        data_len,
                                                                        output.data());
    /*
    got return [count=0, error=TOO_LARGE] from implementation icelake
    got return [count=0, error=TOO_LARGE] from implementation haswell
    got return [count=8, error=SUCCESS] from implementation westmere
    got return [count=0, error=TOO_LARGE] from implementation fallback
    */
    ASSERT_EQUAL(r.count, 0);
    ASSERT_EQUAL(r.error, simdutf::error_code::TOO_LARGE);
}

TEST(issue_convert_utf16be_to_latin1_with_errors_cbf29ce484222384)
{
    IGNORE;
    const unsigned char data[] = {0x20,
                                  0x00,
                                  0x20,
                                  0x00,
                                  0x20,
                                  0x00,
                                  0x20,
                                  0x00,
                                  0x20,
                                  0x00,
                                  0x20,
                                  0x00,
                                  0x20,
                                  0x00,
                                  0x20,
                                  0x00};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char16_t);
    std::vector<char> output(4 * data_len);
    const auto r = implementation.convert_utf16be_to_latin1_with_errors((const char16_t *) data,
                                                                        data_len,
                                                                        output.data());
    /*
    got return [count=0, error=TOO_LARGE] from implementation icelake
    got return [count=0, error=TOO_LARGE] from implementation haswell
    got return [count=8, error=SUCCESS] from implementation westmere
    got return [count=0, error=TOO_LARGE] from implementation fallback
    */

    ASSERT_EQUAL(r.count, 0);
    ASSERT_EQUAL(r.error, simdutf::error_code::TOO_LARGE);
}

TEST(issue_convert_utf32_to_utf8_with_errors_cbf29ce484222315)
{
    IGNORE;
    const unsigned char data[] = {0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
                                  0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00,
                                  0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20,
                                  0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x80,
                                  0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
                                  0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char32_t);
    std::vector<char> output(4 * data_len);
    const auto r = implementation.convert_utf32_to_utf8_with_errors((const char32_t *) data,
                                                                    data_len,
                                                                    output.data());
    /*
    got return [count=10, error=TOO_LARGE] from implementation icelake
    got return [count=10, error=TOO_LARGE] from implementation haswell
    got return [count=16, error=TOO_LARGE] from implementation westmere
    got return [count=10, error=TOO_LARGE] from implementation fallbackend errormessage
    */
    ASSERT_EQUAL(r.count, 10);
    ASSERT_EQUAL(r.error, simdutf::error_code::TOO_LARGE);
}

TEST(issue_convert_utf8_to_latin1_with_errors_cbf29ce4842223ed)
{
    IGNORE;
    const unsigned char data[] = {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0xc2};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char);
    std::vector<char> output(4 * data_len);
    const auto r = implementation.convert_utf8_to_latin1_with_errors((const char *) data,
                                                                     data_len,
                                                                     output.data());
    /*
    got return [count=63, error=SUCCESS] from implementation icelake
    got return [count=63, error=TOO_SHORT] from implementation haswell
    got return [count=63, error=TOO_SHORT] from implementation westmere
    got return [count=63, error=TOO_SHORT] from implementation fallback
    */
    ASSERT_EQUAL(r.count, 63);
    ASSERT_EQUAL(r.error, simdutf::error_code::TOO_SHORT);
}

TEST(issue_convert_utf8_to_latin1_cbf29ce4842223c9)
{
    IGNORE;
    const unsigned char data[] = {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0xc2, 0xbd, 0xc2, 0x90, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0xc2};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char);
    std::vector<char> output(4 * data_len);
    const auto r = implementation.convert_utf8_to_latin1((const char *) data,
                                                         data_len,
                                                         output.data());
    /*
    got return 61 from implementation icelake
    got return 0 from implementation haswell
    got return 0 from implementation westmere
    got return 0 from implementation fallback
    */
    ASSERT_EQUAL(r, 0);
}

TEST(issue_convert_valid_utf8_to_latin1_cbf29ce4842223f0)
{
    IGNORE;
    const unsigned char data[] = {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0xff};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char);
    const auto validation1 = implementation.validate_utf8_with_errors((const char *) data, data_len);
    /*
    got return [count=64, error=SUCCESS] from implementation icelake
    got return [count=63, error=HEADER_BITS] from implementation haswell
    got return [count=63, error=HEADER_BITS] from implementation westmere
    got return [count=63, error=HEADER_BITS] from implementation fallback
    */
    ASSERT_EQUAL(validation1.count, 63);
    ASSERT_EQUAL(validation1.error, simdutf::error_code::HEADER_BITS);

    if (validation1.error != simdutf::error_code::SUCCESS) {
        return;
    }

    std::vector<char> output(4 * data_len);
    const auto r = implementation.convert_valid_utf8_to_latin1((const char *) data,
                                                               data_len,
                                                               output.data());
    ASSERT_EQUAL(r, 1234);
}

TEST(issue_convert_utf16be_to_latin1_with_errors_xyz)
{
    IGNORE;
    const unsigned char data[] = {0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
                                  0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20,
                                  0x00, 0x20, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char16_t);
    std::vector<char> output(4 * data_len);
    const auto r = implementation.convert_utf16be_to_latin1_with_errors((const char16_t *) data,
                                                                        data_len,
                                                                        output.data());
    /*
    got return [count=13, error=TOO_LARGE] from implementation icelake
    got return [count=13, error=TOO_LARGE] from implementation haswell
    got return [count=13, error=TOO_LARGE] from implementation westmere
    got return [count=16, error=SUCCESS] from implementation fallback
    */
    ASSERT_EQUAL(r.count, 13);
    ASSERT_EQUAL(r.error, simdutf::error_code::TOO_LARGE);
}

TEST(issue_convert_utf8_to_utf32_with_errors_a8ec246845d4878e)
{
    IGNORE;
    const unsigned char data[] = {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0xf2, 0xa8, 0xa4, 0x8b, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0xf2, 0xa8,
                                  0xa4, 0x8b, 0x20, 0x20, 0x20, 0x20, 0xf2, 0xa8, 0xa4, 0x8b, 0x20,
                                  0x20, 0xf2, 0xa8, 0xa4, 0x8b, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0xf2, 0xa8, 0xa4, 0xa8, 0xa4, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char);
    std::vector<char32_t> output(4 * data_len);
    const auto r = implementation.convert_utf8_to_utf32_with_errors((const char *) data,
                                                                    data_len,
                                                                    output.data());
    /*
    got return [count=61, error=TOO_LONG] from implementation icelake
    got return [count=64, error=TOO_LONG] from implementation haswell
    got return [count=64, error=TOO_LONG] from implementation westmere
    got return [count=64, error=TOO_LONG] from implementation fallback
    */
    ASSERT_EQUAL(r.count, 64);
    ASSERT_EQUAL(r.error, simdutf::error_code::TOO_LONG);
}

TEST(issue_convert_valid_utf16be_to_latin1_0dce64acfa99c657)
{
    IGNORE;
    const unsigned char data[] = {0x20, 0x20};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char16_t);
    const auto validation1 = implementation.validate_utf16be_with_errors((const char16_t *) data,
                                                                         data_len);
    ASSERT_EQUAL(validation1.count, 1);
    ASSERT_EQUAL(validation1.error, simdutf::error_code::SUCCESS);

    if (validation1.error != simdutf::error_code::SUCCESS) {
        return;
    }
    const auto outlen = implementation.latin1_length_from_utf16(data_len);
    ASSERT_EQUAL(outlen, 1);
    std::vector<char> output(outlen);
    const auto r = implementation.convert_valid_utf16be_to_latin1((const char16_t *) data,
                                                                  data_len,
                                                                  output.data());
    /*
    got return [retval=0, output hash=c27133214e39168d] from implementation icelake
    got return [retval=0, output hash=c27133214e39168d] from implementation haswell
    got return [retval=0, output hash=c27133214e39168d] from implementation westmere
    got return [retval=1, output hash=e429605e1c6ed6a3] from implementation fallback
    */
    ASSERT_EQUAL(r, 0);
}

TEST(issue_convert_valid_utf16le_to_latin1_903167bc5e26f433)
{
    IGNORE;
    const unsigned char data[] = {0x20, 0x20};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char16_t);
    const auto validation1 = implementation.validate_utf16le_with_errors((const char16_t *) data,
                                                                         data_len);
    ASSERT_EQUAL(validation1.count, 1);
    ASSERT_EQUAL(validation1.error, simdutf::error_code::SUCCESS);

    if (validation1.error != simdutf::error_code::SUCCESS) {
        return;
    }
    const auto outlen = implementation.latin1_length_from_utf16(data_len);
    ASSERT_EQUAL(outlen, 1);
    std::vector<char> output(outlen);
    const auto r = implementation.convert_valid_utf16le_to_latin1((const char16_t *) data,
                                                                  data_len,
                                                                  output.data());
    /*
    got return [retval=0, output hash=c27133214e39168d] from implementation icelake
    got return [retval=0, output hash=c27133214e39168d] from implementation haswell
    got return [retval=0, output hash=c27133214e39168d] from implementation westmere
    got return [retval=1, output hash=e429605e1c6ed6a3] from implementation fallback
    */
    ASSERT_EQUAL(r, 0);
}

TEST(allow_empty_input)
{
    IGNORE;
    std::vector<char16_t> emptydata;
    std::vector<char32_t> output(10);

    auto ret = implementation.convert_utf16le_to_utf32_with_errors(emptydata.data(),
                                                                   emptydata.size(),
                                                                   output.data());
    ASSERT_EQUAL(ret.error, simdutf::error_code::SUCCESS);
}

TEST(issue_convert_valid_utf8_to_latin1_d4b91ecf2c5f2158)
{
    IGNORE;
    const unsigned char data[] = {0xdf, 0xaf};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char);
    const auto validation1 = implementation.validate_utf8_with_errors((const char *) data, data_len);
    ASSERT_EQUAL(validation1.count, 2);
    ASSERT_EQUAL(validation1.error, simdutf::error_code::SUCCESS);

    if (validation1.error != simdutf::error_code::SUCCESS) {
        return;
    }
    const auto outlen = implementation.latin1_length_from_utf8((const char *) data, data_len);
    ASSERT_EQUAL(outlen, 1);
    std::vector<char> output(outlen);
    const auto r = implementation.convert_valid_utf8_to_latin1((const char *) data,
                                                               data_len,
                                                               output.data());
    /*
    got return [retval=1, output hash=fc4a1b7c7f7d51e5] from implementation icelake
    got return [retval=1, output hash=55b34275898c5990] from implementation haswell
    got return [retval=1, output hash=55b34275898c5990] from implementation westmere
    got return [retval=1, output hash=55b34275898c5990] from implementation fallback
    */
    ASSERT_EQUAL(r, 1);
    const std::vector<char> expected_out{-17};
    ASSERT_TRUE(output.size() == expected_out.size());
    for (std::size_t i = 0; i < output.size(); ++i) {
        ASSERT_EQUAL(+output.at(i), +expected_out.at(i));
    };
}

TEST(issue_convert_valid_utf8_to_utf16le_91498ee0f0fe77dd)
{
    IGNORE;
    const unsigned char data[] = {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0xc0, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char);
    const auto validation1 = implementation.validate_utf8_with_errors((const char *) data, data_len);
    ASSERT_EQUAL(validation1.count, 46);
    ASSERT_EQUAL(validation1.error, simdutf::error_code::TOO_SHORT);

    const auto outlen = implementation.utf16_length_from_utf8((const char *) data, data_len);
    /*
    got return 63 from implementation icelake
    got return 64 from implementation haswell
    got return 64 from implementation westmere
    got return 64 from implementation fallback
    */
    ASSERT_EQUAL(outlen, 64);
}

TEST(issue_convert_utf8_to_utf32_8bad4f475a64f51e)
{
    IGNORE;
    const unsigned char data[] = {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                  0x20, 0x20, 0x20, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86,
                                  0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86,
                                  0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86,
                                  0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86,
                                  0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0xff, 0xff,
                                  0xff, 0xff, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86,
                                  0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86,
                                  0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x86, 0x20, 0x20,
                                  0xbb, 0x20, 0x20, 0x20, 0xbb, 0x20, 0x20};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char);

    const auto validation1 = implementation.validate_utf8_with_errors((const char *) data, data_len);
    ASSERT_EQUAL(validation1.count, 36);
    ASSERT_EQUAL(validation1.error, simdutf::error_code::TOO_LONG);

    const auto outlen = implementation.utf32_length_from_utf8((const char *) data, data_len);
    ASSERT_EQUAL(outlen, 47);
    std::vector<char32_t> output(outlen /* + 1*/);
    const auto r = implementation.convert_utf8_to_utf32((const char *) data,
                                                        data_len,
                                                        output.data());
    ASSERT_EQUAL(r, 0);
}

TEST(issue_convert_utf8_to_utf32_with_errors_48671aed05deb2eb)
{
    IGNORE;
    const unsigned char data[] = {0x20, 0xdf, 0xbb, 0xcd, 0x8d, 0xcf, 0xbb, 0x20, 0x20, 0xdf, 0xbb,
                                  0xdf, 0xbb, 0xcd, 0xbb, 0xcd, 0xbb, 0xde, 0xbb, 0xdf, 0xbb, 0xcd,
                                  0xa9, 0xdf, 0xbb, 0xdf, 0xbb, 0xdf, 0xbb, 0xdf, 0xbb, 0xcd, 0xbb,
                                  0xcd, 0xbb, 0xde, 0xbb, 0xdf, 0xbb, 0xcd, 0xa9, 0xd8, 0xbb, 0xdf,
                                  0xbb, 0xdf, 0xbb, 0xdf, 0xbb, 0xdf, 0xbb, 0xdf, 0xb3, 0xdf, 0xbb,
                                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0xb9};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char);
    const auto validation1 = implementation.validate_utf8_with_errors((const char *) data, data_len);
    ASSERT_EQUAL(validation1.count, 64);
    ASSERT_EQUAL(validation1.error, simdutf::error_code::TOO_LONG);

    const auto outlen = implementation.utf32_length_from_utf8((const char *) data, data_len);
    ASSERT_EQUAL(outlen, 38);
    std::vector<char32_t> output(outlen);
    const auto r = implementation.convert_utf8_to_utf32_with_errors((const char *) data,
                                                                    data_len,
                                                                    output.data());
    ASSERT_EQUAL(r.error, simdutf::error_code::SUCCESS);
    ASSERT_EQUAL(r.count, 1234);
    const std::vector<char32_t> expected_out{};
    ASSERT_TRUE(output.size() == expected_out.size());
    for (std::size_t i = 0; i < output.size(); ++i) {
        ASSERT_EQUAL(+output.at(i), +expected_out.at(i));
    };
}

TEST(issue_convert_utf8_to_utf16be_with_errors_b3948b7243524254)
{
    IGNORE;
    const unsigned char data[] = {0xf1, 0xa1, 0xa9, 0xa9, 0xf1, 0xa1, 0xa9, 0xa9, 0xf1, 0xa1, 0xa9,
                                  0xb2, 0xf1, 0xb9, 0xa1, 0xa9, 0xf1, 0xa1, 0xa9, 0xa9, 0xf1, 0xa1,
                                  0xa9, 0xa9, 0xf1, 0xa9, 0xa1, 0xa9, 0xf1, 0xa1, 0xae, 0xa6, 0xf1,
                                  0xa1, 0xa9, 0xa9, 0xf1, 0xa9, 0xa1, 0xa9, 0xf1, 0xa1, 0xa9, 0xa9,
                                  0xf1, 0xa1, 0xa9, 0xa9, 0xf1, 0xa1, 0xa9, 0xa9, 0xf1, 0xa1, 0xa9,
                                  0xa9, 0xf1, 0xa1, 0xa9, 0xa9, 0xf1, 0xa0, 0xa0, 0xa0, 0xa0};
    constexpr std::size_t data_len_bytes = sizeof(data);
    constexpr std::size_t data_len = data_len_bytes / sizeof(char);
    const auto validation1 = implementation.validate_utf8_with_errors((const char *) data, data_len);
    ASSERT_EQUAL(validation1.count, 64);
    ASSERT_EQUAL(validation1.error, simdutf::error_code::TOO_LONG);

    const auto outlen = implementation.utf16_length_from_utf8((const char *) data, data_len);
    ASSERT_EQUAL(outlen, 32);
    std::vector<char16_t> output(outlen);
    const auto r = implementation.convert_utf8_to_utf16be_with_errors((const char *) data,
                                                                      data_len,
                                                                      output.data());
    ASSERT_EQUAL(r.error, simdutf::error_code::SUCCESS);
    ASSERT_EQUAL(r.count, 1234);
    const std::vector<char16_t> expected_out{};
    ASSERT_TRUE(output.size() == expected_out.size());
    for (std::size_t i = 0; i < output.size(); ++i) {
        ASSERT_EQUAL(+output.at(i), +expected_out.at(i));
    };
}
// begin testcase
TEST(issue_convert_utf8_to_utf32_with_errors_3fa5955f57c6b0a0) {
    std::vector<char> input;
    std::vector<char32_t> output(4);
    const auto r = implementation.convert_utf8_to_utf32_with_errors(input.data(),
                                                                    input.size(),
                                                                    output.data());
    ASSERT_EQUAL(r.count, 1234);
    ASSERT_EQUAL(r.error, simdutf::error_code::SUCCESS);
}
