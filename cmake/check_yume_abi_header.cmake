# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
# ------------------------------------------------------------------------
# Checks that the public header and the version script describe the same ABI.
#
# These two files are edited by different reflexes: you add a function to the
# header while writing the feature, and you remember the version script later
# (or not at all). A symbol in the header but not the map is hidden at link
# time on ELF/Mach-O and fails only for the embedder; a symbol in the map but
# not the header is an undeclared export. Both are caught here, without
# needing a built library.
#
# Required: YUME_ABI_MAP, YUME_ABI_HEADER
# ------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.20)

include("${CMAKE_CURRENT_LIST_DIR}/YumeAbiSymbols.cmake")

if(NOT DEFINED YUME_ABI_MAP OR YUME_ABI_MAP STREQUAL "")
    message(FATAL_ERROR "YUME_ABI_MAP is required")
endif()
if(NOT DEFINED YUME_ABI_HEADER OR YUME_ABI_HEADER STREQUAL "")
    message(FATAL_ERROR "YUME_ABI_HEADER is required")
endif()
if(NOT EXISTS "${YUME_ABI_HEADER}")
    message(FATAL_ERROR "Public header not found: ${YUME_ABI_HEADER}")
endif()

yume_read_abi_symbols("${YUME_ABI_MAP}" _map_symbols)

# file(STRINGS) keeps the trailing semicolons of each declaration inside their
# own list element instead of splitting on them.
file(STRINGS "${YUME_ABI_HEADER}" _header_lines)

set(_header_symbols)
foreach(_line IN LISTS _header_lines)
    # A declaration is `YUME_API <return type> <name>(`, where the return type
    # may carry pointers and qualifiers. Anchor on the identifier that
    # immediately precedes the opening parenthesis.
    if(_line MATCHES "YUME_API[ \t].*[ \t*]([A-Za-z_][A-Za-z0-9_]*)[ \t]*\\(")
        list(APPEND _header_symbols "${CMAKE_MATCH_1}")
    endif()
endforeach()

if(NOT _header_symbols)
    message(FATAL_ERROR "No YUME_API declarations parsed from ${YUME_ABI_HEADER}")
endif()

list(SORT _header_symbols)
list(REMOVE_DUPLICATES _header_symbols)

if(NOT "${_header_symbols}" STREQUAL "${_map_symbols}")
    set(_header_only ${_header_symbols})
    list(REMOVE_ITEM _header_only ${_map_symbols})
    set(_map_only ${_map_symbols})
    list(REMOVE_ITEM _map_only ${_header_symbols})

    set(_report "")
    if(_header_only)
        string(REPLACE ";" "\n  " _text "${_header_only}")
        string(APPEND _report
            "\ndeclared YUME_API in the header but missing from the version script"
            " (will not link for embedders):\n  ${_text}")
    endif()
    if(_map_only)
        string(REPLACE ";" "\n  " _text "${_map_only}")
        string(APPEND _report
            "\nexported by the version script but not declared in the header:\n  ${_text}")
    endif()

    message(FATAL_ERROR "libyume header/version-script mismatch${_report}")
endif()

list(LENGTH _map_symbols _count)
message(STATUS "libyume header and version script agree on ${_count} symbols")
