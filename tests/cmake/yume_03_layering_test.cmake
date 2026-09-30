# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

foreach(_required YUME_LAYERING_MODULE YUME_BUILD_DIR YUME_TEST_ROOT)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "${_required} is required")
    endif()
endforeach()
if(NOT EXISTS "${YUME_LAYERING_MODULE}")
    message(FATAL_ERROR
        "Layering module does not exist: ${YUME_LAYERING_MODULE}")
endif()

get_filename_component(_build_dir "${YUME_BUILD_DIR}" ABSOLUTE)
get_filename_component(_test_root "${YUME_TEST_ROOT}" ABSOLUTE)
string(FIND "${_test_root}" "${_build_dir}/" _root_position)
if(NOT _root_position EQUAL 0)
    message(FATAL_ERROR
        "YUME_TEST_ROOT must stay below YUME_BUILD_DIR: ${_test_root}")
endif()
set(YUME_TEST_ROOT "${_test_root}")

file(REMOVE_RECURSE "${YUME_TEST_ROOT}")
file(MAKE_DIRECTORY
    "${YUME_TEST_ROOT}/src/engine"
    "${YUME_TEST_ROOT}/src/ytp"
    "${YUME_TEST_ROOT}/src/config/v1"
    "${YUME_TEST_ROOT}/src/common"
    "${YUME_TEST_ROOT}/src/fs"
    "${YUME_TEST_ROOT}/src/stealth"
    "${YUME_TEST_ROOT}/src/abi"
    "${YUME_TEST_ROOT}/src/runtime"
    "${YUME_TEST_ROOT}/src/providers"
    "${YUME_TEST_ROOT}/src/admission"
    "${YUME_TEST_ROOT}/src/gui")
file(WRITE "${YUME_TEST_ROOT}/src/engine/clean.hpp" "#include <vector>\n")
file(WRITE "${YUME_TEST_ROOT}/src/ytp/clean.hpp" "#include <span>\n")
file(WRITE "${YUME_TEST_ROOT}/src/config/v1/clean.hpp" "#include <string>\n")

function(run_layering_check expect_success expected_text)
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            "-DYUME_SOURCE_DIR=${YUME_TEST_ROOT}"
            -P "${YUME_LAYERING_MODULE}"
        RESULT_VARIABLE _result
        OUTPUT_VARIABLE _output
        ERROR_VARIABLE _error)
    set(_combined "${_output}${_error}")
    if(expect_success)
        if(NOT _result EQUAL 0)
            message(FATAL_ERROR
                "Clean layering fixture was rejected:\n${_combined}")
        endif()
    else()
        if(_result EQUAL 0)
            message(FATAL_ERROR "Forbidden layering fixture was accepted")
        endif()
        if(NOT _combined MATCHES "${expected_text}")
            message(FATAL_ERROR
                "Layering failure omitted '${expected_text}':\n${_combined}")
        endif()
    endif()
endfunction()

run_layering_check(TRUE "")

file(WRITE "${YUME_TEST_ROOT}/src/runtime/forbidden.hpp"
    "#include <basefwx/crypto.hpp>\n")
run_layering_check(FALSE "Layering violation")
file(REMOVE "${YUME_TEST_ROOT}/src/runtime/forbidden.hpp")
file(WRITE "${YUME_TEST_ROOT}/src/providers/forbidden.hpp"
    "#include \"runtime/native_endpoint.hpp\"\n")
run_layering_check(FALSE "Layering violation")
file(REMOVE "${YUME_TEST_ROOT}/src/providers/forbidden.hpp")

file(WRITE "${YUME_TEST_ROOT}/src/engine/forbidden.hpp"
    "#include <openssl/ssl.h>\n")
run_layering_check(FALSE "dependency-clean engine")
file(REMOVE "${YUME_TEST_ROOT}/src/engine/forbidden.hpp")

# Dependency-clean layers must not gain a bypass merely by using a C-style
# header extension.
file(WRITE "${YUME_TEST_ROOT}/src/engine/forbidden.h"
    "#include <openssl/ssl.h>\n")
run_layering_check(FALSE "dependency-clean engine")
file(REMOVE "${YUME_TEST_ROOT}/src/engine/forbidden.h")

file(WRITE "${YUME_TEST_ROOT}/src/engine/forbidden.hpp"
    "#include \"ytp/protocol.hpp\"\n")
run_layering_check(FALSE "Only SessionEngine")
file(REMOVE "${YUME_TEST_ROOT}/src/engine/forbidden.hpp")

file(WRITE "${YUME_TEST_ROOT}/src/ytp/forbidden.hpp"
    "#include \"engine/status.hpp\"\n")
run_layering_check(FALSE "must not depend upward")
file(REMOVE "${YUME_TEST_ROOT}/src/ytp/forbidden.hpp")

file(WRITE "${YUME_TEST_ROOT}/src/ytp/forbidden.hpp"
    "#include <nlohmann/json.hpp>\n")
run_layering_check(FALSE "dependency-clean ytp")
file(REMOVE "${YUME_TEST_ROOT}/src/ytp/forbidden.hpp")

file(WRITE "${YUME_TEST_ROOT}/src/common/forbidden.hpp"
    "#include <filesystem>\n")
run_layering_check(FALSE "dependency-clean common")
file(REMOVE "${YUME_TEST_ROOT}/src/common/forbidden.hpp")

file(WRITE "${YUME_TEST_ROOT}/src/config/v1/forbidden.hpp"
    "#include <sys/socket.h>\n")
run_layering_check(FALSE "config-v1 public header")
file(REMOVE "${YUME_TEST_ROOT}/src/config/v1/forbidden.hpp")

# Directional rules. Both include spellings must be caught, because a quoted
# include is the common form and an angled one is what someone reaches for
# when the quoted form is rejected.
file(WRITE "${YUME_TEST_ROOT}/src/stealth/forbidden.hpp"
    "#include \"providers/h2_duplex_carrier.hpp\"\n")
run_layering_check(FALSE "forbidden.hpp includes providers/")
file(REMOVE "${YUME_TEST_ROOT}/src/stealth/forbidden.hpp")

file(WRITE "${YUME_TEST_ROOT}/src/common/forbidden.hpp"
    "#include <stealth/cover_profile.hpp>\n")
run_layering_check(FALSE "forbidden.hpp includes stealth/")
file(REMOVE "${YUME_TEST_ROOT}/src/common/forbidden.hpp")

file(WRITE "${YUME_TEST_ROOT}/src/abi/forbidden.cpp"
    "#include \"gui/app.hpp\"\n")
run_layering_check(FALSE "forbidden.cpp includes gui/")
file(REMOVE "${YUME_TEST_ROOT}/src/abi/forbidden.cpp")

foreach(_forbidden IN ITEMS abi/endpoint_backend.hpp modules/relay/record.hpp)
    file(WRITE "${YUME_TEST_ROOT}/src/runtime/forbidden.cpp"
        "#include \"${_forbidden}\"\n")
    run_layering_check(FALSE "Layering violation: src/runtime/")
    file(REMOVE "${YUME_TEST_ROOT}/src/runtime/forbidden.cpp")
endforeach()

# A C source under a guarded layer must be checked too. The glob previously
# covered only .cpp and .hpp, so a .c file slipped past the rule entirely.
file(WRITE "${YUME_TEST_ROOT}/src/fs/forbidden.c"
    "#include \"runtime/native_endpoint.hpp\"\n")
run_layering_check(FALSE "forbidden.c includes runtime/")
file(REMOVE "${YUME_TEST_ROOT}/src/fs/forbidden.c")

foreach(_forbidden IN ITEMS fs/secret_file.hpp providers/ytp1_h2_admission.hpp)
    file(WRITE "${YUME_TEST_ROOT}/src/admission/forbidden.hpp"
        "#include \"${_forbidden}\"\n")
    run_layering_check(FALSE "Layering violation: src/admission/")
    file(REMOVE "${YUME_TEST_ROOT}/src/admission/forbidden.hpp")
endforeach()

# The GUI talks to yume through the control socket only, so it includes no
# transport layer, and Qt stays inside the GUI.
file(WRITE "${YUME_TEST_ROOT}/src/gui/clean.cpp"
    "#include <QObject>\n#include \"common/version.hpp\"\n")
run_layering_check(TRUE "")
foreach(_forbidden IN ITEMS runtime/control_socket.hpp engine/status.hpp config/v1/config.hpp)
    file(WRITE "${YUME_TEST_ROOT}/src/gui/forbidden.cpp"
        "#include \"${_forbidden}\"\n")
    run_layering_check(FALSE "Layering violation: src/gui/")
    file(REMOVE "${YUME_TEST_ROOT}/src/gui/forbidden.cpp")
endforeach()
foreach(_layer IN ITEMS runtime engine abi)
    file(WRITE "${YUME_TEST_ROOT}/src/${_layer}/forbidden.cpp"
        "#include <QtCore/QString>\n")
    run_layering_check(FALSE "Qt header outside the GUI")
    file(REMOVE "${YUME_TEST_ROOT}/src/${_layer}/forbidden.cpp")
endforeach()
file(REMOVE "${YUME_TEST_ROOT}/src/gui/clean.cpp")

# The layer list is closed. A directory nobody declared, or a source sitting
# directly under src/, fails instead of escaping every rule.
file(MAKE_DIRECTORY "${YUME_TEST_ROOT}/src/presence")
file(WRITE "${YUME_TEST_ROOT}/src/presence/names.hpp" "#include <string>\n")
run_layering_check(FALSE "src/presence/ is not a declared layer")
file(REMOVE_RECURSE "${YUME_TEST_ROOT}/src/presence")
file(WRITE "${YUME_TEST_ROOT}/src/stray.cpp" "#include <string>\n")
run_layering_check(FALSE "Source outside a layer: src/stray.cpp")
file(REMOVE "${YUME_TEST_ROOT}/src/stray.cpp")

# Each layer includes only what it declares, including the layers the older
# denylist never covered.
file(MAKE_DIRECTORY
    "${YUME_TEST_ROOT}/src/circuit"
    "${YUME_TEST_ROOT}/src/modules/relay"
    "${YUME_TEST_ROOT}/src/test_support")
foreach(_case IN ITEMS
        "engine/forbidden.hpp|runtime/native_endpoint.hpp"
        "engine/forbidden.hpp|providers/control_task.hpp"
        "ytp/forbidden.hpp|providers/ytp1_crypto.hpp"
        "circuit/forbidden.hpp|stealth/cover_profile.hpp"
        "config/v1/forbidden.hpp|runtime/native_credentials.hpp"
        "modules/relay/forbidden.cpp|runtime/native_endpoint.hpp"
        "modules/relay/forbidden.cpp|providers/composite_keys.hpp"
        "providers/forbidden.cpp|test_support/tls_identity.hpp"
        "runtime/forbidden.cpp|test_support/allocation_failure.hpp"
        "abi/yume_c.cpp|runtime/native_endpoint.hpp"
        "test_support/forbidden.hpp|runtime/native_endpoint.hpp")
    string(REPLACE "|" ";" _parts "${_case}")
    list(GET _parts 0 _file)
    list(GET _parts 1 _include)
    string(REGEX MATCH "^[^/]+" _layer "${_file}")
    file(WRITE "${YUME_TEST_ROOT}/src/${_file}" "#include \"${_include}\"\n")
    run_layering_check(FALSE "Layering violation: src/${_layer}/")
    file(REMOVE "${YUME_TEST_ROOT}/src/${_file}")
endforeach()

# The embedding seam's one implementation may reach the runtime, and a test
# may reach across layers to build its fixture.
file(WRITE "${YUME_TEST_ROOT}/src/abi/native_backend.cpp"
    "#include \"runtime/native_endpoint.hpp\"\n#include \"yume/yume.h\"\n")
file(WRITE "${YUME_TEST_ROOT}/src/providers/fixture_test.cpp"
    "#include \"runtime/native_endpoint.hpp\"\n")
file(WRITE "${YUME_TEST_ROOT}/src/modules/relay/record.cpp"
    "#include <basefwx/crypto.hpp>\n#include \"fs/secret_file.hpp\"\n")
run_layering_check(TRUE "")
file(REMOVE
    "${YUME_TEST_ROOT}/src/abi/native_backend.cpp"
    "${YUME_TEST_ROOT}/src/providers/fixture_test.cpp"
    "${YUME_TEST_ROOT}/src/modules/relay/record.cpp")

# A library without an exact link assertion fails configuration.
function(run_link_assertion_check expect_success with_unasserted)
    set(_project "${YUME_TEST_ROOT}/link-project")
    file(REMOVE_RECURSE "${_project}")
    file(MAKE_DIRECTORY "${_project}")
    file(WRITE "${_project}/a.c" "int yume_fixture_a(void) { return 1; }\n")
    set(_unasserted "")
    if(with_unasserted)
        set(_unasserted "add_library(unasserted STATIC a.c)\n")
    endif()
    file(WRITE "${_project}/CMakeLists.txt"
        "cmake_minimum_required(VERSION 3.20)\n"
        "project(yume_link_fixture LANGUAGES C)\n"
        "include(\"${YUME_LAYERING_MODULE}\")\n"
        "add_library(asserted STATIC a.c)\n"
        "yume_assert_exact_link_dependencies(asserted)\n"
        "add_library(interface_only INTERFACE)\n"
        "${_unasserted}"
        "yume_require_link_assertions(\"\${CMAKE_CURRENT_SOURCE_DIR}\")\n")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -S "${_project}" -B "${_project}/build"
        RESULT_VARIABLE _result
        OUTPUT_VARIABLE _output
        ERROR_VARIABLE _error)
    set(_combined "${_output}${_error}")
    if(expect_success AND NOT _result EQUAL 0)
        message(FATAL_ERROR "Asserted fixture project was rejected:\n${_combined}")
    endif()
    if(NOT expect_success)
        if(_result EQUAL 0)
            message(FATAL_ERROR "A library without a link assertion was accepted")
        endif()
        if(NOT _combined MATCHES "unasserted has no exact link assertion")
            message(FATAL_ERROR
                "Missing link assertion failure omitted its target:\n${_combined}")
        endif()
    endif()
endfunction()
run_link_assertion_check(TRUE FALSE)
run_link_assertion_check(FALSE TRUE)

file(REMOVE_RECURSE "${YUME_TEST_ROOT}")
