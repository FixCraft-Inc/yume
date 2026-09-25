# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

# Stages the yume_cli install component and checks the installed native
# layout: the programs, manuals and cover-profile data are present, the setup
# tools start, source-only registries stay out of the examples, and the
# Debian install lists assign every installed program and manual.

cmake_minimum_required(VERSION 3.20)

foreach(_required
        YUME_BUILD_DIR
        YUME_TEST_PREFIX
        YUME_PYTHON
        YUME_INSTALL_BINDIR
        YUME_INSTALL_DATADIR
        YUME_INSTALL_MANDIR
        YUME_DEBIAN_DIR)
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

set(_bin "${_test_prefix}/${YUME_INSTALL_BINDIR}")
set(_man "${_test_prefix}/${YUME_INSTALL_MANDIR}")
set(_required_artifacts
    "${_bin}/yume"
    "${_bin}/yumed"
    "${_bin}/yume-setup"
    "${_bin}/yume-doctor"
    "${_man}/man1/yume.1"
    "${_man}/man8/yumed.8"
    "${_test_prefix}/${YUME_INSTALL_DATADIR}/yume/cover-profile/manifest.json")
foreach(_artifact IN LISTS _required_artifacts)
    if(NOT EXISTS "${_artifact}")
        message(FATAL_ERROR "installed YUME artifact not found: ${_artifact}")
    endif()
endforeach()

foreach(_tool IN ITEMS yume-setup yume-doctor)
    execute_process(
        COMMAND "${YUME_PYTHON}" "${_bin}/${_tool}" --help
        RESULT_VARIABLE _help_result
        OUTPUT_QUIET
        ERROR_VARIABLE _help_error
    )
    if(NOT _help_result EQUAL 0)
        message(FATAL_ERROR "installed ${_tool} --help failed: ${_help_error}")
    endif()
endforeach()

foreach(_source_registry IN ITEMS dependencies.json transport_profiles.json)
    if(EXISTS
       "${_test_prefix}/${YUME_INSTALL_DATADIR}/doc/yume/examples/${_source_registry}")
        message(FATAL_ERROR
            "source-only registry was installed as runtime example: ${_source_registry}")
    endif()
endforeach()

# Each Debian binary package must claim the installed files it ships.
function(yume_require_debian_assignments package)
    file(STRINGS "${YUME_DEBIAN_DIR}/${package}.install" _lines)
    foreach(_assignment IN LISTS ARGN)
        list(FIND _lines "${_assignment}" _index)
        if(_index EQUAL -1)
            message(FATAL_ERROR
                "debian/${package}.install does not assign ${_assignment}")
        endif()
    endforeach()
endfunction()

yume_require_debian_assignments(yume
    "usr/bin/yume"
    "usr/bin/yume-setup"
    "usr/bin/yume-doctor"
    "usr/share/man/man1/yume.1"
    "usr/share/yume/cover-profile/*")
yume_require_debian_assignments(yume-daemon
    "usr/bin/yumed"
    "usr/share/man/man8/yumed.8")

message(STATUS "installed native layout matches the Debian install lists")
