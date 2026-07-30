# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

cmake_minimum_required(VERSION 3.20)

foreach(_required
        YUME_BUILD_DIR
        YUME_TEST_PREFIX
        YUME_PYTHON
        YUME_INSTALL_BINDIR
        YUME_INSTALL_DATADIR
        YUME_DEBIAN_INSTALL_MANIFEST
        YUME_COVER_MANIFEST)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "${_required} is required")
    endif()
endforeach()

# This test removes only its own build-tree staging directory. Refuse to run if
# a caller points it anywhere else.
cmake_path(ABSOLUTE_PATH YUME_BUILD_DIR NORMALIZE OUTPUT_VARIABLE _build_dir)
cmake_path(ABSOLUTE_PATH YUME_TEST_PREFIX NORMALIZE
           OUTPUT_VARIABLE _test_prefix)
string(FIND "${_test_prefix}" "${_build_dir}/" _prefix_position)
if(NOT _prefix_position EQUAL 0)
    message(FATAL_ERROR
        "YUME_TEST_PREFIX must be below YUME_BUILD_DIR: ${_test_prefix}")
endif()
file(REMOVE_RECURSE "${_test_prefix}")

set(_install_command
    "${CMAKE_COMMAND}" --install "${_build_dir}"
    --prefix "${_test_prefix}" --component yume_cli)
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
        "staged yume_cli install failed:\n${_install_output}${_install_error}")
endif()

set(_setup "${_test_prefix}/${YUME_INSTALL_BINDIR}/yume-setup")
set(_required_artifacts
    "${_setup}"
    "${_test_prefix}/${YUME_INSTALL_BINDIR}/yume-packet-quick"
    "${_test_prefix}/${YUME_INSTALL_DATADIR}/yume/cover-node/backend.mjs"
    "${_test_prefix}/${YUME_INSTALL_DATADIR}/yume/cover-profile/manifest.json")
foreach(_artifact IN LISTS _required_artifacts)
    if(NOT EXISTS "${_artifact}")
        message(FATAL_ERROR "installed YUME helper artifact not found: ${_artifact}")
    endif()
endforeach()

file(STRINGS "${YUME_DEBIAN_INSTALL_MANIFEST}" _debian_install_lines)
set(_required_assignments
    "usr/bin/yume-setup"
    "usr/bin/yume-packet-quick"
    "usr/share/yume/cover-node/*"
    "usr/share/yume/cover-profile/*")
foreach(_assignment IN LISTS _required_assignments)
    list(FIND _debian_install_lines "${_assignment}" _assignment_index)
    if(_assignment_index EQUAL -1)
        message(FATAL_ERROR
            "debian/yume.install does not assign ${_assignment}")
    endif()
endforeach()

execute_process(
    COMMAND "${_setup}" --help
    RESULT_VARIABLE _help_result
    OUTPUT_QUIET
    ERROR_VARIABLE _help_error
)
if(NOT _help_result EQUAL 0)
    message(FATAL_ERROR "installed yume-setup --help failed: ${_help_error}")
endif()

execute_process(
    COMMAND "${YUME_PYTHON}" -c
            "import runpy, sys
ns = runpy.run_path(sys.argv[1])
print(ns['pinned_node_version']())"
            "${_setup}"
    RESULT_VARIABLE _version_result
    OUTPUT_VARIABLE _installed_version
    ERROR_VARIABLE _version_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT _version_result EQUAL 0)
    message(FATAL_ERROR
        "installed yume-setup could not load its cover manifest: "
        "${_version_error}")
endif()

file(READ "${YUME_COVER_MANIFEST}" _manifest)
string(JSON _expected_version GET "${_manifest}" server version)
if(NOT "${_installed_version}" STREQUAL "${_expected_version}")
    message(FATAL_ERROR
        "installed Node version ${_installed_version} does not match "
        "fixture ${_expected_version}")
endif()

message(STATUS
    "installed yume-setup resolved Node ${_installed_version} from staged data")
