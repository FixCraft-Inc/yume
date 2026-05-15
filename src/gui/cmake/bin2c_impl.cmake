# Standalone CMake script: reads a binary file, writes a .cpp file with the
# bytes as a const unsigned char[] and a matching size constant. Invoked via
# cmake -P inside an add_custom_command so the conversion is part of the
# build dependency graph and re-runs only when the input file changes.

if(NOT DEFINED INPUT_FILE OR NOT DEFINED OUTPUT_FILE OR NOT DEFINED VAR_NAME)
    message(FATAL_ERROR "bin2c_impl.cmake: requires INPUT_FILE, OUTPUT_FILE, VAR_NAME")
endif()

file(READ "${INPUT_FILE}" hex_data HEX)
string(LENGTH "${hex_data}" hex_len)
math(EXPR byte_count "${hex_len} / 2")

# Convert "aabbcc..." into "0xaa,0xbb,0xcc,..." in one regex pass. The
# trailing comma is stripped so the resulting initializer is valid C++.
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bytes "${hex_data}")
string(REGEX REPLACE ",$" "" bytes "${bytes}")

get_filename_component(input_name "${INPUT_FILE}" NAME)
file(WRITE "${OUTPUT_FILE}"
"// Generated from ${input_name} by bin2c_impl.cmake -- do not edit.\n"
"#include <cstddef>\n"
"namespace yume::gui::ui {\n"
"extern const unsigned char ${VAR_NAME}[] = { ${bytes} };\n"
"extern const std::size_t ${VAR_NAME}_len = ${byte_count};\n"
"}\n")
