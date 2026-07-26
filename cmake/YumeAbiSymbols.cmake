# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
# ------------------------------------------------------------------------
# Single source of truth for the public libyume symbol set.
#
# src/abi/yume.map is the canonical list. Everything else that needs to know
# the exported surface -- the macOS -exported_symbols_list, the post-build
# symbol audit -- derives it from here, so the platforms cannot drift apart
# the way a second hand-maintained list would.
# ------------------------------------------------------------------------

# Reads the `global:` section of a GNU version script into a sorted list.
function(yume_read_abi_symbols map_file out_var)
    if(NOT EXISTS "${map_file}")
        message(FATAL_ERROR "ABI version script not found: ${map_file}")
    endif()

    # file(STRINGS) rather than READ + split: the version script is full of
    # semicolons, which a manual "\n" -> ";" split would turn into extra list
    # elements. file(STRINGS) escapes them and yields one element per line.
    file(STRINGS "${map_file}" _map_lines)

    set(_symbols)
    set(_in_global FALSE)
    foreach(_line IN LISTS _map_lines)
        if(_line MATCHES "global:")
            set(_in_global TRUE)
            continue()
        endif()
        if(_line MATCHES "local:")
            set(_in_global FALSE)
            continue()
        endif()
        if(NOT _in_global)
            continue()
        endif()
        if(_line MATCHES "^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*;")
            list(APPEND _symbols "${CMAKE_MATCH_1}")
        endif()
    endforeach()

    if(NOT _symbols)
        message(FATAL_ERROR "No exported symbols parsed from ${map_file}")
    endif()

    list(SORT _symbols)
    list(REMOVE_DUPLICATES _symbols)
    set(${out_var} "${_symbols}" PARENT_SCOPE)
endfunction()

# Writes a Mach-O -exported_symbols_list file. Mach-O prefixes C symbols with
# an underscore, so the linker will silently export nothing if the prefix is
# omitted -- which would leave the library with a default-visible surface.
function(yume_write_macho_symbol_list map_file out_file)
    yume_read_abi_symbols("${map_file}" _symbols)
    set(_content "")
    foreach(_symbol IN LISTS _symbols)
        string(APPEND _content "_${_symbol}\n")
    endforeach()
    file(GENERATE OUTPUT "${out_file}" CONTENT "${_content}")
endfunction()
