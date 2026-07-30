# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
# ------------------------------------------------------------------------
# Checks Debian's ABI tracking metadata against the canonical version script.
#
# Required: YUME_ABI_MAP, YUME_DEBIAN_SYMBOLS
# ------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.20)

include("${CMAKE_CURRENT_LIST_DIR}/YumeAbiSymbols.cmake")

if(NOT DEFINED YUME_ABI_MAP OR YUME_ABI_MAP STREQUAL "")
    message(FATAL_ERROR "YUME_ABI_MAP is required")
endif()
if(NOT DEFINED YUME_DEBIAN_SYMBOLS OR YUME_DEBIAN_SYMBOLS STREQUAL "")
    message(FATAL_ERROR "YUME_DEBIAN_SYMBOLS is required")
endif()
if(NOT EXISTS "${YUME_DEBIAN_SYMBOLS}")
    message(FATAL_ERROR "Debian symbols file not found: ${YUME_DEBIAN_SYMBOLS}")
endif()

yume_read_abi_symbols("${YUME_ABI_MAP}" _map_symbols)
file(STRINGS "${YUME_DEBIAN_SYMBOLS}" _debian_lines)

set(_debian_symbols)
foreach(_line IN LISTS _debian_lines)
    if(_line MATCHES "^[ \t]+(yume_[A-Za-z0-9_]+)@")
        list(APPEND _debian_symbols "${CMAKE_MATCH_1}")
    endif()
endforeach()

if(NOT _debian_symbols)
    message(FATAL_ERROR
        "No libyume symbols parsed from ${YUME_DEBIAN_SYMBOLS}")
endif()

list(SORT _debian_symbols)
list(REMOVE_DUPLICATES _debian_symbols)

if(NOT "${_debian_symbols}" STREQUAL "${_map_symbols}")
    set(_debian_only ${_debian_symbols})
    list(REMOVE_ITEM _debian_only ${_map_symbols})
    set(_map_only ${_map_symbols})
    list(REMOVE_ITEM _map_only ${_debian_symbols})

    set(_report "")
    if(_map_only)
        string(REPLACE ";" "\n  " _text "${_map_only}")
        string(APPEND _report
            "\nmissing from ${YUME_DEBIAN_SYMBOLS}:\n  ${_text}")
    endif()
    if(_debian_only)
        string(REPLACE ";" "\n  " _text "${_debian_only}")
        string(APPEND _report
            "\nnot present in ${YUME_ABI_MAP}:\n  ${_text}")
    endif()
    message(FATAL_ERROR "Debian libyume symbol metadata mismatch${_report}")
endif()

list(LENGTH _map_symbols _count)
message(STATUS
    "Debian libyume metadata and version script agree on ${_count} symbols")
