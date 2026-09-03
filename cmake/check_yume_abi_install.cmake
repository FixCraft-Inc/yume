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
cmake_path(ABSOLUTE_PATH YUME_TEST_PREFIX NORMALIZE
           OUTPUT_VARIABLE _test_prefix)
string(FIND "${_test_prefix}" "${_build_dir}/" _prefix_position)
if(NOT _prefix_position EQUAL 0)
    message(FATAL_ERROR
        "YUME_TEST_PREFIX must be below YUME_BUILD_DIR: ${_test_prefix}")
endif()

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
foreach(_fixture IN ITEMS CMakeLists.txt consumer.c consumer.cpp)
    if(NOT EXISTS "${_consumer_source_dir}/${_fixture}")
        message(FATAL_ERROR
            "installed-consumer fixture is missing: "
            "${_consumer_source_dir}/${_fixture}")
    endif()
endforeach()

function(yume_execute _description)
    execute_process(
        COMMAND ${ARGN}
        RESULT_VARIABLE _result
        OUTPUT_VARIABLE _output
        ERROR_VARIABLE _error
    )
    if(NOT _result EQUAL 0)
        message(FATAL_ERROR
            "${_description} failed (${_result}):\n${_output}${_error}")
    endif()
endfunction()

# The removal target was constrained above to a normalized child of the
# current build tree. A fresh prefix prevents host headers or stale libraries
# from satisfying either consumer path.
file(REMOVE_RECURSE "${_test_prefix}")
foreach(_component IN ITEMS
        libyume_runtime
        libyume_development
        yume_cli)
    set(_install_command
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
        "${_test_prefix}/libyume.1.dylib")
else()
    file(GLOB_RECURSE _runtime_libraries LIST_DIRECTORIES FALSE
        "${_test_prefix}/libyume.so.1")
endif()
list(LENGTH _runtime_libraries _runtime_library_count)
if(NOT _runtime_library_count EQUAL 1)
    message(FATAL_ERROR
        "staged install must contain exactly one ABI-v1 runtime library; "
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
    COMMAND ${_pkg_config_environment} "${_pkg_config_program}"
            --variable=prefix yume
    RESULT_VARIABLE _pkg_prefix_result
    OUTPUT_VARIABLE _pkg_prefix
    ERROR_VARIABLE _pkg_prefix_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT _pkg_prefix_result EQUAL 0)
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

execute_process(
    COMMAND ${_pkg_config_environment} "${_pkg_config_program}"
            --cflags yume
    RESULT_VARIABLE _pkg_cflags_result
    OUTPUT_VARIABLE _pkg_cflags_text
    ERROR_VARIABLE _pkg_cflags_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT _pkg_cflags_result EQUAL 0)
    message(FATAL_ERROR
        "staged pkg-config Cflags query failed:\n${_pkg_cflags_error}")
endif()
separate_arguments(_pkg_cflags UNIX_COMMAND "${_pkg_cflags_text}")

execute_process(
    COMMAND ${_pkg_config_environment} "${_pkg_config_program}"
            --libs yume
    RESULT_VARIABLE _pkg_libs_result
    OUTPUT_VARIABLE _pkg_libs_text
    ERROR_VARIABLE _pkg_libs_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT _pkg_libs_result EQUAL 0)
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
endif()

set(_pkg_consumer_dir "${_test_prefix}/consumer-pkg-config")
file(MAKE_DIRECTORY "${_pkg_consumer_dir}")
set(_pkg_c_consumer "${_pkg_consumer_dir}/consumer-c")
set(_pkg_cpp_consumer "${_pkg_consumer_dir}/consumer-cpp")

yume_execute("pkg-config C consumer compile"
    "${_c_compiler}"
    ${_consumer_sanitizer_flags}
    ${_pkg_cflags}
    -std=c11
    "${_consumer_source_dir}/consumer.c"
    ${_pkg_libs}
    -o "${_pkg_c_consumer}")
yume_execute("pkg-config C++ consumer compile"
    "${_cxx_compiler}"
    ${_consumer_sanitizer_flags}
    ${_pkg_cflags}
    -std=c++20
    "${_consumer_source_dir}/consumer.cpp"
    ${_pkg_libs}
    -o "${_pkg_cpp_consumer}")
yume_execute("pkg-config C consumer run"
    ${_runtime_environment} "${_pkg_c_consumer}")
yume_execute("pkg-config C++ consumer run"
    ${_runtime_environment} "${_pkg_cpp_consumer}")

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
    "-DCMAKE_PREFIX_PATH=${_test_prefix}"
    "-Dyume_DIR=${_cmake_config_dir}"
    -DBUILD_TESTING=ON
    -DCMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY=ON
    -DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF
    -DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF)
yume_execute("installed find_package consumer configure"
    ${_configure_command})

set(_build_command "${CMAKE_COMMAND}" --build "${_cmake_consumer_build}")
if(DEFINED YUME_BUILD_CONFIG AND NOT YUME_BUILD_CONFIG STREQUAL "")
    list(APPEND _build_command --config "${YUME_BUILD_CONFIG}")
endif()
yume_execute("installed find_package consumer build" ${_build_command})

set(_ctest_command
    "${CMAKE_CTEST_COMMAND}" --test-dir "${_cmake_consumer_build}"
    --output-on-failure)
if(DEFINED YUME_BUILD_CONFIG AND NOT YUME_BUILD_CONFIG STREQUAL "")
    list(APPEND _ctest_command -C "${YUME_BUILD_CONFIG}")
endif()
yume_execute("installed find_package C/C++ consumer runs"
    ${_runtime_environment} ${_ctest_command})

message(STATUS
    "staged libyume pkg-config and CMake C/C++ consumers plus setup/doctor "
    "help passed")
