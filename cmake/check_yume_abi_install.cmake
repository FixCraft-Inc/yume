# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

cmake_minimum_required(VERSION 3.20)

foreach(_required
        YUME_BUILD_DIR
        YUME_TEST_PREFIX
        YUME_CONSUMER_TEST)
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
file(REMOVE_RECURSE "${_test_prefix}")

foreach(_component libyume_runtime libyume_development)
    set(_install_command
        "${CMAKE_COMMAND}" --install "${_build_dir}"
        --prefix "${_test_prefix}" --component "${_component}")
    if(DEFINED YUME_BUILD_CONFIG AND NOT YUME_BUILD_CONFIG STREQUAL "")
        list(APPEND _install_command --config "${YUME_BUILD_CONFIG}")
    endif()
    execute_process(
        COMMAND ${_install_command}
        RESULT_VARIABLE _install_result
        OUTPUT_VARIABLE _install_output
        ERROR_VARIABLE _install_error
    )
    if(NOT _install_result EQUAL 0)
        message(FATAL_ERROR
            "staged ${_component} install failed:\n"
            "${_install_output}${_install_error}")
    endif()
endforeach()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env
            --unset=PKG_CONFIG_PATH
            "YUME_TEST_PREFIX=${_test_prefix}"
            sh "${YUME_CONSUMER_TEST}"
    RESULT_VARIABLE _consumer_result
    OUTPUT_VARIABLE _consumer_output
    ERROR_VARIABLE _consumer_error
)
if(NOT _consumer_result EQUAL 0)
    message(FATAL_ERROR
        "staged libyume consumer validation failed:\n"
        "${_consumer_output}${_consumer_error}")
endif()

message(STATUS "staged libyume pkg-config and CMake consumers passed")
