# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
# ------------------------------------------------------------------------
# Audits the built libyume against the canonical export list.
#
# This is the gate that catches two distinct failures: a public function that
# was added or removed without updating the version script, and an internal
# static library or absorbed third-party archive leaking symbols into the
# public namespace because symbol control was not applied on this platform.
#
# Required: YUME_ABI_LIBRARY, YUME_NM, YUME_ABI_MAP
# Optional: YUME_ABI_FORMAT (elf | macho, default elf)
# ------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.20)

include("${CMAKE_CURRENT_LIST_DIR}/YumeAbiSymbols.cmake")

if(NOT DEFINED YUME_ABI_LIBRARY OR YUME_ABI_LIBRARY STREQUAL "")
    message(FATAL_ERROR "YUME_ABI_LIBRARY is required")
endif()
if(NOT DEFINED YUME_NM OR YUME_NM STREQUAL "")
    message(FATAL_ERROR "YUME_NM is required")
endif()
if(NOT DEFINED YUME_ABI_MAP OR YUME_ABI_MAP STREQUAL "")
    message(FATAL_ERROR "YUME_ABI_MAP is required")
endif()
if(NOT DEFINED YUME_ABI_FORMAT OR YUME_ABI_FORMAT STREQUAL "")
    set(YUME_ABI_FORMAT "elf")
endif()

yume_read_abi_symbols("${YUME_ABI_MAP}" _expected)

if(YUME_ABI_FORMAT STREQUAL "macho")
    # Mach-O has no separate dynamic symbol table; -g -U is "global, defined".
    set(_nm_args -g -U)
else()
    set(_nm_args -D --defined-only)
endif()

execute_process(
    COMMAND "${YUME_NM}" ${_nm_args} "${YUME_ABI_LIBRARY}"
    RESULT_VARIABLE _nm_result
    OUTPUT_VARIABLE _nm_output
    ERROR_VARIABLE _nm_error
)

if(NOT _nm_result EQUAL 0)
    message(FATAL_ERROR "failed to inspect ${YUME_ABI_LIBRARY}: ${_nm_error}")
endif()

string(REPLACE "\r\n" "\n" _nm_output "${_nm_output}")
string(REPLACE "\n" ";" _nm_lines "${_nm_output}")

set(_actual)
foreach(_line IN LISTS _nm_lines)
    if(_line STREQUAL "")
        continue()
    endif()
    string(REGEX MATCH "[^ \t]+$" _symbol "${_line}")
    if(_symbol STREQUAL "")
        continue()
    endif()
    if(YUME_ABI_FORMAT STREQUAL "macho")
        # Strip the Mach-O underscore so both platforms compare against the
        # same canonical names.
        string(REGEX REPLACE "^_" "" _symbol "${_symbol}")
        # Apple's toolchain may report these dylib/runtime symbols; they are
        # not part of the public surface and cannot be controlled by the C
        # export list.
        if(_symbol MATCHES "^(_mh_dylib_header|dyld_stub_binder)$")
            continue()
        endif()
    endif()
    list(APPEND _actual "${_symbol}")
endforeach()

list(SORT _actual)
list(REMOVE_DUPLICATES _actual)

if(NOT "${_actual}" STREQUAL "${_expected}")
    set(_unexpected ${_actual})
    list(REMOVE_ITEM _unexpected ${_expected})
    set(_missing ${_expected})
    list(REMOVE_ITEM _missing ${_actual})

    set(_report "")
    if(_missing)
        string(REPLACE ";" "\n  " _missing_text "${_missing}")
        string(APPEND _report "\ndeclared in ${YUME_ABI_MAP} but not exported:\n  ${_missing_text}")
    endif()
    if(_unexpected)
        string(REPLACE ";" "\n  " _unexpected_text "${_unexpected}")
        string(APPEND _report "\nexported but not declared (leaked or undeclared symbol):\n  ${_unexpected_text}")

        set(_unexpected_nm_lines)
        foreach(_line IN LISTS _nm_lines)
            foreach(_symbol IN LISTS _unexpected)
                if(_line MATCHES "(^|[ \t])${_symbol}$")
                    list(APPEND _unexpected_nm_lines "${_line}")
                endif()
            endforeach()
        endforeach()
        if(_unexpected_nm_lines)
            string(REPLACE ";" "\n  " _unexpected_nm_text
                "${_unexpected_nm_lines}")
            string(APPEND _report
                "\nraw nm records (address, binding, symbol):\n  "
                "${_unexpected_nm_text}")
        endif()
    endif()

    message(FATAL_ERROR "libyume exported symbol mismatch${_report}")
endif()

list(LENGTH _expected _count)
message(STATUS "libyume exports exactly ${_count} declared symbols (${YUME_ABI_FORMAT})")
