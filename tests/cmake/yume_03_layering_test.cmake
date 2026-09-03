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
    "${YUME_TEST_ROOT}/src/core"
    "${YUME_TEST_ROOT}/src/outbound"
    "${YUME_TEST_ROOT}/src/client"
    "${YUME_TEST_ROOT}/src/server"
    "${YUME_TEST_ROOT}/src/facade")
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

file(WRITE "${YUME_TEST_ROOT}/src/engine/forbidden.hpp"
    "#include <openssl/ssl.h>\n")
run_layering_check(FALSE "dependency-clean engine")
file(REMOVE "${YUME_TEST_ROOT}/src/engine/forbidden.hpp")

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

file(WRITE "${YUME_TEST_ROOT}/src/config/v1/forbidden.hpp"
    "#include <sys/socket.h>\n")
run_layering_check(FALSE "config-v1 public header")
file(REMOVE "${YUME_TEST_ROOT}/src/config/v1/forbidden.hpp")

# Directional rules for the transport-v2 stack. Each of these was verified by
# hand once; pinning them here is what keeps them true. Both include spellings
# must be caught, because a quoted include is the common form and an angled one
# is what someone reaches for when the quoted form is rejected.
file(WRITE "${YUME_TEST_ROOT}/src/core/forbidden.hpp"
    "#include \"server/config/config.hpp\"\n")
run_layering_check(FALSE "forbidden.hpp includes server/")
file(REMOVE "${YUME_TEST_ROOT}/src/core/forbidden.hpp")

file(WRITE "${YUME_TEST_ROOT}/src/core/forbidden.hpp"
    "#include <client/cli/entry.hpp>\n")
run_layering_check(FALSE "forbidden.hpp includes client/")
file(REMOVE "${YUME_TEST_ROOT}/src/core/forbidden.hpp")

file(WRITE "${YUME_TEST_ROOT}/src/client/forbidden.cpp"
    "#include \"server/session/session.hpp\"\n")
run_layering_check(FALSE "forbidden.cpp includes server/")
file(REMOVE "${YUME_TEST_ROOT}/src/client/forbidden.cpp")

file(WRITE "${YUME_TEST_ROOT}/src/server/forbidden.cpp"
    "#include \"client/cli/entry.hpp\"\n")
run_layering_check(FALSE "forbidden.cpp includes client/")
file(REMOVE "${YUME_TEST_ROOT}/src/server/forbidden.cpp")

file(WRITE "${YUME_TEST_ROOT}/src/facade/forbidden.cpp"
    "#include \"gui/app.hpp\"\n")
run_layering_check(FALSE "forbidden.cpp includes gui/")
file(REMOVE "${YUME_TEST_ROOT}/src/facade/forbidden.cpp")

file(WRITE "${YUME_TEST_ROOT}/src/outbound/forbidden.cpp"
    "#include \"abi/yume_c.hpp\"\n")
run_layering_check(FALSE "forbidden.cpp includes abi/")
file(REMOVE "${YUME_TEST_ROOT}/src/outbound/forbidden.cpp")

# A C source under a guarded layer must be checked too. The glob previously
# covered only .cpp and .hpp, so a .c file slipped past the rule entirely.
file(WRITE "${YUME_TEST_ROOT}/src/core/forbidden.c"
    "#include \"server/config/config.hpp\"\n")
run_layering_check(FALSE "forbidden.c includes server/")
file(REMOVE "${YUME_TEST_ROOT}/src/core/forbidden.c")

file(REMOVE_RECURSE "${YUME_TEST_ROOT}")
