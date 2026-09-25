# YUME - clean-prefix C ABI v1 installation qualification
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

cmake_minimum_required(VERSION 3.20)

foreach(_required IN ITEMS YUME_BUILD_DIR YUME_TEST_PREFIX)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "${_required} is required")
    endif()
endforeach()

cmake_path(ABSOLUTE_PATH YUME_BUILD_DIR NORMALIZE OUTPUT_VARIABLE _build_dir)
if(NOT IS_DIRECTORY "${_build_dir}" OR NOT EXISTS "${_build_dir}/CMakeCache.txt")
    message(FATAL_ERROR "YUME_BUILD_DIR must identify a configured build")
endif()
cmake_path(ABSOLUTE_PATH YUME_TEST_PREFIX NORMALIZE
           OUTPUT_VARIABLE _test_prefix)
string(FIND "${_test_prefix}" "${_build_dir}/" _prefix_position)
if(NOT _prefix_position EQUAL 0)
    message(FATAL_ERROR
        "YUME_TEST_PREFIX must be below YUME_BUILD_DIR: ${_test_prefix}")
endif()
# A lexical child reached through a symlink is not a confined staging target.
get_filename_component(_prefix_parent "${_test_prefix}" DIRECTORY)
while(NOT _prefix_parent STREQUAL _build_dir)
    if(IS_SYMLINK "${_prefix_parent}")
        message(FATAL_ERROR "SDK staging ancestors must not be symlinks")
    endif()
    get_filename_component(_prefix_parent "${_prefix_parent}" DIRECTORY)
endwhile()

if(DEFINED YUME_CONSUMER_SOURCE_DIR AND
   NOT YUME_CONSUMER_SOURCE_DIR STREQUAL "")
    cmake_path(ABSOLUTE_PATH YUME_CONSUMER_SOURCE_DIR NORMALIZE
               OUTPUT_VARIABLE _consumer_source_dir)
else()
    set(_consumer_source_dir
        "${CMAKE_CURRENT_LIST_DIR}/../tests/abi/install_consumer")
    cmake_path(NORMAL_PATH _consumer_source_dir
               OUTPUT_VARIABLE _consumer_source_dir)
endif()
foreach(_fixture IN ITEMS CMakeLists.txt consumer.c consumer.cpp loader_probe.cpp)
    if(NOT EXISTS "${_consumer_source_dir}/${_fixture}")
        message(FATAL_ERROR
            "installed-consumer fixture is missing: "
            "${_consumer_source_dir}/${_fixture}")
    endif()
endforeach()

function(yume_execute_bounded _description _timeout)
    execute_process(
        TIMEOUT ${_timeout}
        COMMAND ${ARGN}
        RESULT_VARIABLE _result
        OUTPUT_VARIABLE _output
        ERROR_VARIABLE _error
    )
    if(NOT _result STREQUAL "0")
        message(FATAL_ERROR
            "${_description} failed (${_result}):\n${_output}${_error}")
    endif()
endfunction()

function(yume_execute _description)
    yume_execute_bounded("${_description}" 60 ${ARGN})
endfunction()

if(YUME_TEST_NATIVE_TRAFFIC)
    foreach(_required IN ITEMS YUME_SOURCE_DIR YUME_PYTHON_EXECUTABLE YUME_OPENSSL_PROGRAM)
        if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "" OR
           NOT EXISTS "${${_required}}")
            message(FATAL_ERROR "native installed traffic requires ${_required}")
        endif()
    endforeach()
    if(NOT UNIX)
        message(FATAL_ERROR "native installed traffic fixtures require UNIX")
    endif()
endif()

# Never reuse or erase a prefix from an earlier test. Retained prefixes are
# bounded qualification artifacts belonging to this build directory.
string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef _suffix)
set(_test_prefix "${_test_prefix}-${_suffix}")
if(EXISTS "${_test_prefix}" OR IS_SYMLINK "${_test_prefix}")
    message(FATAL_ERROR "SDK qualification prefix already exists")
endif()
foreach(_component IN ITEMS
        libyume_runtime
        libyume_development
        yume_cli)
    set(_install_command
        "${CMAKE_COMMAND}" -E env --unset=DESTDIR
        "${CMAKE_COMMAND}" --install "${_build_dir}"
        --prefix "${_test_prefix}" --component "${_component}")
    if(DEFINED YUME_BUILD_CONFIG AND NOT YUME_BUILD_CONFIG STREQUAL "")
        list(APPEND _install_command --config "${YUME_BUILD_CONFIG}")
    endif()
    yume_execute("staged ${_component} install" ${_install_command})
endforeach()

if(NOT EXISTS "${_test_prefix}/include/yume/yume.h")
    message(FATAL_ERROR "staged install omitted include/yume/yume.h")
endif()

file(GLOB_RECURSE _pkg_config_files LIST_DIRECTORIES FALSE
    "${_test_prefix}/yume.pc")
list(LENGTH _pkg_config_files _pkg_config_count)
if(NOT _pkg_config_count EQUAL 1)
    message(FATAL_ERROR
        "staged install must contain exactly one yume.pc; found "
        "${_pkg_config_count}: ${_pkg_config_files}")
endif()
list(GET _pkg_config_files 0 _pkg_config_file)
get_filename_component(_pkg_config_dir "${_pkg_config_file}" DIRECTORY)

file(GLOB_RECURSE _cmake_config_files LIST_DIRECTORIES FALSE
    "${_test_prefix}/yumeConfig.cmake")
list(LENGTH _cmake_config_files _cmake_config_count)
if(NOT _cmake_config_count EQUAL 1)
    message(FATAL_ERROR
        "staged install must contain exactly one yumeConfig.cmake; found "
        "${_cmake_config_count}: ${_cmake_config_files}")
endif()
list(GET _cmake_config_files 0 _cmake_config_file)
get_filename_component(_cmake_config_dir "${_cmake_config_file}" DIRECTORY)

if(WIN32)
    file(GLOB_RECURSE _runtime_libraries LIST_DIRECTORIES FALSE
        "${_test_prefix}/yume.dll")
elseif(APPLE)
    file(GLOB_RECURSE _runtime_libraries LIST_DIRECTORIES FALSE
        "${_test_prefix}/libyume.dylib")
else()
    file(GLOB_RECURSE _runtime_libraries LIST_DIRECTORIES FALSE
        "${_test_prefix}/libyume.so")
endif()
list(LENGTH _runtime_libraries _runtime_library_count)
if(NOT _runtime_library_count EQUAL 1)
    message(FATAL_ERROR
        "staged install must contain exactly one experimental runtime library; "
        "found ${_runtime_library_count}: ${_runtime_libraries}")
endif()
list(GET _runtime_libraries 0 _runtime_library)
get_filename_component(_runtime_library_dir "${_runtime_library}" DIRECTORY)

set(_runtime_environment "${CMAKE_COMMAND}" -E env)
if(WIN32)
    set(_loader_path "${_runtime_library_dir}")
    if(DEFINED ENV{PATH} AND NOT "$ENV{PATH}" STREQUAL "")
        set(_loader_path "${_loader_path};$ENV{PATH}")
    endif()
    list(APPEND _runtime_environment "PATH=${_loader_path}")
elseif(APPLE)
    set(_loader_path "${_runtime_library_dir}")
    if(DEFINED ENV{DYLD_LIBRARY_PATH} AND
       NOT "$ENV{DYLD_LIBRARY_PATH}" STREQUAL "")
        set(_loader_path "${_loader_path}:$ENV{DYLD_LIBRARY_PATH}")
    endif()
    list(APPEND _runtime_environment "DYLD_LIBRARY_PATH=${_loader_path}")
else()
    set(_loader_path "${_runtime_library_dir}")
    if(DEFINED ENV{LD_LIBRARY_PATH} AND
       NOT "$ENV{LD_LIBRARY_PATH}" STREQUAL "")
        set(_loader_path "${_loader_path}:$ENV{LD_LIBRARY_PATH}")
    endif()
    list(APPEND _runtime_environment "LD_LIBRARY_PATH=${_loader_path}")
endif()

set(_native_runtime_environment ${_runtime_environment})
if(DEFINED ENV{YUME_TEST_CHILD_ASAN_OPTIONS})
    list(APPEND _native_runtime_environment "ASAN_OPTIONS=$ENV{YUME_TEST_CHILD_ASAN_OPTIONS}")
endif()

foreach(_tool IN ITEMS yume-setup yume-doctor)
    set(_tool_path "${_test_prefix}/bin/${_tool}")
    if(NOT EXISTS "${_tool_path}")
        message(FATAL_ERROR "staged install omitted ${_tool}")
    endif()
    yume_execute("installed ${_tool} --help"
        ${_runtime_environment} "${_tool_path}" --help)
endforeach()

find_program(_pkg_config_program NAMES pkg-config pkgconf)
if(NOT _pkg_config_program)
    message(FATAL_ERROR "pkg-config or pkgconf is required")
endif()
set(_pkg_config_environment
    "${CMAKE_COMMAND}" -E env
    --unset=PKG_CONFIG_PATH
    --unset=PKG_CONFIG_SYSROOT_DIR
    "PKG_CONFIG_LIBDIR=${_pkg_config_dir}")

execute_process(
    TIMEOUT 15
    COMMAND ${_pkg_config_environment} "${_pkg_config_program}"
            --variable=prefix yume
    RESULT_VARIABLE _pkg_prefix_result
    OUTPUT_VARIABLE _pkg_prefix
    ERROR_VARIABLE _pkg_prefix_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT _pkg_prefix_result STREQUAL "0")
    message(FATAL_ERROR
        "staged pkg-config prefix query failed:\n${_pkg_prefix_error}")
endif()
cmake_path(ABSOLUTE_PATH _pkg_prefix NORMALIZE
           OUTPUT_VARIABLE _normalized_pkg_prefix)
string(REGEX REPLACE "[/\\\\]+$" "" _normalized_pkg_prefix
    "${_normalized_pkg_prefix}")
string(REGEX REPLACE "[/\\\\]+$" "" _normalized_test_prefix
    "${_test_prefix}")
if(NOT _normalized_pkg_prefix STREQUAL _normalized_test_prefix)
    message(FATAL_ERROR
        "pkg-config resolved outside the staged prefix: "
        "${_normalized_pkg_prefix}")
endif()

# Embedding hosts find the resolver helper through the package metadata.
execute_process(
    TIMEOUT 15
    COMMAND ${_pkg_config_environment} "${_pkg_config_program}"
            --variable=resolver_program yume
    RESULT_VARIABLE _pkg_resolver_result
    OUTPUT_VARIABLE _pkg_resolver
    ERROR_VARIABLE _pkg_resolver_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT _pkg_resolver_result STREQUAL "0" OR _pkg_resolver STREQUAL "")
    message(FATAL_ERROR
        "staged pkg-config resolver_program query failed:\n${_pkg_resolver_error}")
endif()
cmake_path(ABSOLUTE_PATH _pkg_resolver NORMALIZE
           OUTPUT_VARIABLE _normalized_pkg_resolver)
string(FIND "${_normalized_pkg_resolver}" "${_normalized_test_prefix}/" _resolver_position)
if(NOT _resolver_position EQUAL 0 OR IS_DIRECTORY "${_normalized_pkg_resolver}" OR
   NOT EXISTS "${_normalized_pkg_resolver}")
    message(FATAL_ERROR
        "pkg-config resolver_program is not an installed file in the staged prefix: "
        "${_normalized_pkg_resolver}")
endif()
# Started by hand, without the helper socketpair, it identifies itself and
# refuses to serve.
execute_process(
    TIMEOUT 15
    COMMAND "${_normalized_pkg_resolver}"
    RESULT_VARIABLE _resolver_run_result
    OUTPUT_QUIET
    ERROR_VARIABLE _resolver_run_error
)
if(NOT _resolver_run_result STREQUAL "2" OR
   NOT _resolver_run_error MATCHES "internal helper")
    message(FATAL_ERROR
        "installed resolver helper did not refuse a manual start: "
        "${_resolver_run_result} ${_resolver_run_error}")
endif()

execute_process(
    TIMEOUT 15
    COMMAND ${_pkg_config_environment} "${_pkg_config_program}"
            --cflags yume
    RESULT_VARIABLE _pkg_cflags_result
    OUTPUT_VARIABLE _pkg_cflags_text
    ERROR_VARIABLE _pkg_cflags_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT _pkg_cflags_result STREQUAL "0")
    message(FATAL_ERROR
        "staged pkg-config Cflags query failed:\n${_pkg_cflags_error}")
endif()
separate_arguments(_pkg_cflags UNIX_COMMAND "${_pkg_cflags_text}")

execute_process(
    TIMEOUT 15
    COMMAND ${_pkg_config_environment} "${_pkg_config_program}"
            --libs yume
    RESULT_VARIABLE _pkg_libs_result
    OUTPUT_VARIABLE _pkg_libs_text
    ERROR_VARIABLE _pkg_libs_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT _pkg_libs_result STREQUAL "0")
    message(FATAL_ERROR
        "staged pkg-config Libs query failed:\n${_pkg_libs_error}")
endif()
separate_arguments(_pkg_libs UNIX_COMMAND "${_pkg_libs_text}")

function(yume_read_cached_compiler _language _output)
    if(NOT EXISTS "${_build_dir}/CMakeCache.txt")
        set(${_output} "" PARENT_SCOPE)
        return()
    endif()
    file(STRINGS "${_build_dir}/CMakeCache.txt" _compiler_lines
        REGEX "^CMAKE_${_language}_COMPILER:[^=]+=.+$")
    list(LENGTH _compiler_lines _compiler_line_count)
    if(_compiler_line_count GREATER 0)
        list(GET _compiler_lines 0 _compiler_line)
        string(REGEX REPLACE "^[^=]+=" "" _compiler "${_compiler_line}")
        set(${_output} "${_compiler}" PARENT_SCOPE)
    else()
        set(${_output} "" PARENT_SCOPE)
    endif()
endfunction()

if(DEFINED YUME_C_COMPILER AND NOT YUME_C_COMPILER STREQUAL "")
    set(_c_compiler "${YUME_C_COMPILER}")
else()
    yume_read_cached_compiler(C _c_compiler)
endif()
if(NOT _c_compiler)
    find_program(_c_compiler NAMES cc gcc clang)
endif()
if(NOT _c_compiler OR NOT EXISTS "${_c_compiler}")
    message(FATAL_ERROR "a C compiler is required")
endif()

if(DEFINED YUME_CXX_COMPILER AND NOT YUME_CXX_COMPILER STREQUAL "")
    set(_cxx_compiler "${YUME_CXX_COMPILER}")
else()
    yume_read_cached_compiler(CXX _cxx_compiler)
endif()
if(NOT _cxx_compiler)
    find_program(_cxx_compiler NAMES c++ g++ clang++)
endif()
if(NOT _cxx_compiler OR NOT EXISTS "${_cxx_compiler}")
    message(FATAL_ERROR "a C++ compiler is required")
endif()

set(_consumer_sanitizer_flags)
set(_consumer_sanitizer_flags_text "")
if(DEFINED YUME_CONSUMER_SANITIZER_FLAGS AND
   NOT YUME_CONSUMER_SANITIZER_FLAGS STREQUAL "")
    string(REPLACE ";" " " _consumer_sanitizer_flags_text
        "${YUME_CONSUMER_SANITIZER_FLAGS}")
    separate_arguments(_consumer_sanitizer_flags UNIX_COMMAND
        "${_consumer_sanitizer_flags_text}")
    list(APPEND _consumer_sanitizer_flags -fno-omit-frame-pointer -fno-sanitize-recover=all)
    string(JOIN " " _consumer_sanitizer_flags_text ${_consumer_sanitizer_flags})
endif()

set(_pkg_consumer_dir "${_test_prefix}/consumer-pkg-config")
file(MAKE_DIRECTORY "${_pkg_consumer_dir}")
set(_pkg_c_consumer "${_pkg_consumer_dir}/consumer-c")
set(_pkg_cpp_consumer "${_pkg_consumer_dir}/consumer-cpp")

yume_execute("pkg-config C consumer compile"
    "${_c_compiler}"
    ${_consumer_sanitizer_flags}
    ${_pkg_cflags}
    -std=c11 -Wall -Wextra -Wpedantic -Werror
    "${_consumer_source_dir}/consumer.c"
    ${_pkg_libs}
    -o "${_pkg_c_consumer}")
yume_execute("pkg-config C++ consumer compile"
    "${_cxx_compiler}"
    ${_consumer_sanitizer_flags}
    ${_pkg_cflags}
    -std=c++20 -Wall -Wextra -Wpedantic -Werror
    "${_consumer_source_dir}/consumer.cpp"
    ${_pkg_libs}
    -o "${_pkg_cpp_consumer}")
yume_execute("pkg-config C consumer run"
    ${_native_runtime_environment} "${_pkg_c_consumer}")
yume_execute("pkg-config C++ consumer run"
    ${_native_runtime_environment} "${_pkg_cpp_consumer}")
if(UNIX)
    set(_pkg_loader_consumer "${_pkg_consumer_dir}/loader-probe")
    set(_loader_libraries)
    if(NOT APPLE)
        list(APPEND _loader_libraries -ldl)
    endif()
    yume_execute("pkg-config loader consumer compile"
        "${_cxx_compiler}" ${_consumer_sanitizer_flags} ${_pkg_cflags}
        -std=c++20 -Wall -Wextra -Wpedantic -Werror
        "${_consumer_source_dir}/loader_probe.cpp" ${_pkg_libs} ${_loader_libraries}
        -o "${_pkg_loader_consumer}")
    yume_execute("pkg-config loader consumer run"
        ${_native_runtime_environment} "${_pkg_loader_consumer}" "${_runtime_library}")
endif()

set(_cmake_consumer_build "${_test_prefix}/consumer-cmake")
set(_consumer_build_type Release)
if(DEFINED YUME_BUILD_CONFIG AND NOT YUME_BUILD_CONFIG STREQUAL "")
    set(_consumer_build_type "${YUME_BUILD_CONFIG}")
endif()
set(_configure_command
    "${CMAKE_COMMAND}"
    -S "${_consumer_source_dir}"
    -B "${_cmake_consumer_build}"
    "-DCMAKE_BUILD_TYPE=${_consumer_build_type}"
    "-DCMAKE_C_COMPILER=${_c_compiler}"
    "-DCMAKE_CXX_COMPILER=${_cxx_compiler}"
    "-DCMAKE_C_FLAGS=${_consumer_sanitizer_flags_text}"
    "-DCMAKE_CXX_FLAGS=${_consumer_sanitizer_flags_text}"
    "-DCMAKE_EXE_LINKER_FLAGS=${_consumer_sanitizer_flags_text}"
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    "-DCMAKE_PREFIX_PATH=${_test_prefix}"
    "-Dyume_DIR=${_cmake_config_dir}"
    "-DYUME_EXPECTED_PREFIX=${_test_prefix}"
    "-DYUME_EXPECTED_LIBRARY=${_runtime_library}"
    -DBUILD_TESTING=ON
    -DCMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY=ON
    -DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF
    -DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF)
if(DEFINED ENV{YUME_TEST_CHILD_ASAN_OPTIONS})
    list(APPEND _configure_command
        "-DYUME_CHILD_ASAN_OPTIONS=$ENV{YUME_TEST_CHILD_ASAN_OPTIONS}")
endif()
if(YUME_TEST_NATIVE_TRAFFIC)
    if(NOT EXISTS "${_test_prefix}/bin/yumed")
        message(FATAL_ERROR "native installed traffic requires staged bin/yumed")
    endif()
    list(APPEND _configure_command
        -DYUME_TEST_NATIVE_TRAFFIC=ON
        "-DYUME_SOURCE_DIR=${YUME_SOURCE_DIR}"
        "-DYUME_PYTHON_EXECUTABLE=${YUME_PYTHON_EXECUTABLE}"
        "-DYUME_OPENSSL_EXECUTABLE=${YUME_OPENSSL_PROGRAM}"
        "-DYUME_INSTALLED_DAEMON=${_test_prefix}/bin/yumed")
endif()
yume_execute("installed find_package consumer configure"
    ${_configure_command})

set(_build_command "${CMAKE_COMMAND}" --build "${_cmake_consumer_build}" --parallel 2)
if(DEFINED YUME_BUILD_CONFIG AND NOT YUME_BUILD_CONFIG STREQUAL "")
    list(APPEND _build_command --config "${YUME_BUILD_CONFIG}")
endif()
yume_execute("installed find_package consumer build" ${_build_command})

set(_ctest_command
    "${CMAKE_CTEST_COMMAND}" --test-dir "${_cmake_consumer_build}"
    --output-on-failure --parallel 1 --stop-on-failure)
if(DEFINED YUME_BUILD_CONFIG AND NOT YUME_BUILD_CONFIG STREQUAL "")
    list(APPEND _ctest_command -C "${YUME_BUILD_CONFIG}")
endif()
yume_execute_bounded("installed find_package consumer and traffic runs" 480
    ${_runtime_environment} ${_ctest_command})

if(YUME_TEST_NATIVE_TRAFFIC)
    message(STATUS "staged SDK C/C++ consumers, named streams/packets, TCP/UDP routes, "
                   "and setup/doctor help passed")
else()
    message(STATUS "staged SDK C/C++ consumers and setup/doctor help passed; "
                   "native traffic was not requested by this build")
endif()
