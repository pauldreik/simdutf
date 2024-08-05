# Fuzzing

Fuzzing is easiest to run on Debian or Ubuntu.
Make sure you have clang installed.

  * clang
  * xxd
  * ninja
  * cmake


## Running 


    cd fuzz
    ./build.sh
    mkdir -p corpus/conversion
    out/conversion corpus/conversion


## Minimization of a crash
In case a crash is found, do

    ./minimize_and_cleanse.sh out/conversion crash-*

You can turn it into a test case with

    PRINT_FUZZ_CASE= out/conversion cleaned_crash.conversion >blah 2>&1

## Finding functions to fuzz

    // this list was obtained by manually copying the interesting part of implementation.cpp ("class implementation") into impl.cpp and running
    // clang-17 -Xclang -ast-dump  impl.cpp  2>/dev/null|sed -e 's/\x1b\[[0-9;]*m//g' | grep -- CXXMethodDecl >tjoff
    // cat tjoff |grep --only-matching convert.* |cut -f1 -d' ' |sort  |xargs -I§ echo "ADD( " § "),"


        // these require valid input so not suitable to fuzz unless validating input before passing it
        // ADD(convert_valid_utf16be_to_latin1),
        // ADD(convert_valid_utf16be_to_utf32),
        // ADD(convert_valid_utf16be_to_utf8),
        // ADD(convert_valid_utf16le_to_latin1),
        // ADD(convert_valid_utf16le_to_utf32),
        // ADD(convert_valid_utf16le_to_utf8),
        // ADD(convert_valid_utf32_to_latin1),
        // ADD(convert_valid_utf32_to_utf16be),
        // ADD(convert_valid_utf32_to_utf16le),
        // ADD(convert_valid_utf32_to_utf8),
        // ADD(convert_valid_utf8_to_latin1),
        // ADD(convert_valid_utf8_to_utf16be),
        // ADD(convert_valid_utf8_to_utf16le),
        // ADD(convert_valid_utf8_to_utf32),

        // these have other function signatures
        // ADD(base64_length_from_binary),
        // ADD(base64_to_binary),
        // ADD(base64_to_binary),
        // ADD(binary_to_base64),
        // ADD(change_endianness_utf16),
        // ADD(count_utf16be),
        // ADD(count_utf16le),
        // ADD(count_utf8),
        // ADD(latin1_length_from_utf16),
        // ADD(latin1_length_from_utf32),
        // ADD(latin1_length_from_utf8),
        // ADD(maximal_binary_length_from_base64),
        // ADD(maximal_binary_length_from_base64),
        // ADD(utf16_length_from_latin1),
        // ADD(utf16_length_from_utf32),
        // ADD(utf16_length_from_utf8),
        // ADD(utf32_length_from_latin1),
        // ADD(utf32_length_from_utf16be),
        // ADD(utf32_length_from_utf16le),
        // ADD(utf32_length_from_utf8),
        // ADD(utf8_length_from_latin1),
        // ADD(utf8_length_from_utf16be),
        // ADD(utf8_length_from_utf16le),
        // ADD(utf8_length_from_utf32),

        // already fuzzed
        // ADD(validate_utf16be),
        // ADD(validate_utf16be_with_errors),
        // ADD(validate_utf16le),
        // ADD(validate_utf16le_with_errors),
        // ADD(validate_utf32),
        // ADD(validate_utf32_with_errors),
        // ADD(validate_utf8),
        // ADD(validate_utf8_with_errors)

## test case generation

make the reproduce build:
export CXX=/usr/lib/ccache/clang++-18
cmake -B /tmp/reproduce -S .. -DSIMDUTF_SANITIZE=On -DSIMDUTF_SANITIZE_UNDEFINED=On -DCMAKE_BUILD_TYPE=Debug -DSIMDUTF_ALWAYS_INCLUDE_FALLBACK=On -GNinja

### conversion
rm -f crash-*
./build.sh && out/conversion ../corpus/conversion/
./build.sh && out/conversion -jobs=15 -workers=15 ../corpus/conversion/
./build.sh && ./minimize_and_cleanse.sh out/conversion crash-*
./build.sh && PRINT_FUZZ_CASE= out/conversion cleaned_crash.conversion >blah 2>&1 
sed  -n '/begin testcase/,/end testcase/p' blah >> ../tests/fuzzercrashes.cpp
(echo '/*';sed  -n '/begin errormessage/,/end errormessage/p' blah ; echo '*/') >> ../tests/fuzzercrashes.cpp
mv crash-* ../corpus/conversion
cp cleaned_crash.conversion ../corpus/conversion/$(echo cleaned_crash.conversion$RANDOM)
ninja -C /tmp/reproduce && /tmp/reproduce/tests/fuzzercrashes
rm -f crash-*

### conversion_valid
rm -f crash-*
./build.sh && out/conversion_valid ../corpus/conversion_valid/
./build.sh && ./minimize_and_cleanse.sh out/conversion_valid crash-*
./build.sh && PRINT_FUZZ_CASE= out/conversion_valid cleaned_crash.conversion_valid >blah 2>&1 
sed  -n '/begin testcase/,/end testcase/p' blah >> ../tests/fuzzercrashes.cpp
(echo '/*';sed  -n '/begin errormessage/,/end errormessage/p' blah ; echo '*/') >> ../tests/fuzzercrashes.cpp
mv crash-* ../corpus/conversion_valid
cp cleaned_crash.conversion_valid ../corpus/conversion_valid/$(echo cleaned_crash.conversion_valid$RANDOM)
ninja -C /tmp/reproduce && /tmp/reproduce/tests/fuzzercrashes


## More stuff to try out

Test alignment, slide the fuzzer data and make sure it still works.

test on arm.

test the output from conversion to make sure it is the same between implementations
