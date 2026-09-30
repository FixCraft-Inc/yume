# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

# Run as a script (`cmake -P`), this file sets the project's policies itself.
if(CMAKE_SCRIPT_MODE_FILE)
    cmake_minimum_required(VERSION 3.20)
endif()

function(yume_assert_exact_link_dependencies target)
    set(_expected ${ARGN})
    get_target_property(_actual "${target}" LINK_LIBRARIES)
    if(NOT _actual OR _actual STREQUAL "_actual-NOTFOUND")
        set(_actual "")
    endif()
    if(NOT "${_actual}" STREQUAL "${_expected}")
        message(FATAL_ERROR
            "${target} has unexpected direct link dependencies. "
            "Expected '${_expected}', got '${_actual}'.")
    endif()
    set_property(GLOBAL APPEND PROPERTY YUME_LINK_ASSERTED_TARGETS "${target}")
endfunction()

# Every static or shared library defined in the given source directories must
# have passed yume_assert_exact_link_dependencies, so a new library cannot
# enter the graph with an unreviewed dependency list. Call it after the last
# library of those directories is defined.
function(yume_require_link_assertions)
    get_property(_asserted GLOBAL PROPERTY YUME_LINK_ASSERTED_TARGETS)
    foreach(_directory IN LISTS ARGN)
        get_property(_targets DIRECTORY "${_directory}" PROPERTY BUILDSYSTEM_TARGETS)
        foreach(_target IN LISTS _targets)
            get_target_property(_type "${_target}" TYPE)
            if(NOT _type MATCHES "^(STATIC|SHARED|MODULE)_LIBRARY$")
                continue()
            endif()
            if(NOT _target IN_LIST _asserted)
                message(FATAL_ERROR
                    "${_target} has no exact link assertion. Add "
                    "yume_assert_exact_link_dependencies(${_target} ...) "
                    "listing its direct dependencies.")
            endif()
        endforeach()
    endforeach()
endfunction()

function(yume_check_03_source_layering source_dir)
    if(NOT IS_DIRECTORY "${source_dir}/src")
        message(FATAL_ERROR "Invalid YUME source directory: ${source_dir}")
    endif()

    # The engine, YTP/1 and the circuit 1 codec include common/, so it stays as
    # clean as they are.
    set(_dependency_clean_patterns
        [=[(^|[/<"])(boost|openssl|nghttp2|nlohmann|filesystem)([/\.>"]|$)]=]
        [=[(^|[/<"])(asio|json\.hpp|json_fwd\.hpp)([/>"]|$)]=]
        [=[(^|[/<"])(sys/socket\.h|winsock2\.h)([>"]|$)]=])

    foreach(_layer IN ITEMS engine ytp circuit common)
        file(GLOB_RECURSE _sources
            "${source_dir}/src/${_layer}/*.cpp"
            "${source_dir}/src/${_layer}/*.hpp"
            "${source_dir}/src/${_layer}/*.cc"
            "${source_dir}/src/${_layer}/*.c"
            "${source_dir}/src/${_layer}/*.h")
        foreach(_source IN LISTS _sources)
            file(READ "${_source}" _contents)
            string(TOLOWER "${_contents}" _lower_contents)
            foreach(_pattern IN LISTS _dependency_clean_patterns)
                if(_lower_contents MATCHES "${_pattern}")
                    file(RELATIVE_PATH _relative "${source_dir}" "${_source}")
                    message(FATAL_ERROR
                        "Forbidden dependency in dependency-clean ${_layer} "
                        "source ${_relative}: pattern '${_pattern}'")
                endif()
            endforeach()
            if(_layer STREQUAL "ytp" AND
               _lower_contents MATCHES [=[#[ 	]*include[ 	]*[<"]engine/]=])
                file(RELATIVE_PATH _relative "${source_dir}" "${_source}")
                message(FATAL_ERROR
                    "YTP/1 must not depend upward on the engine: ${_relative}")
            endif()
            if(_layer STREQUAL "circuit" AND
               _lower_contents MATCHES [=[#[ 	]*include[ 	]*[<"](engine|providers|runtime)/]=])
                file(RELATIVE_PATH _relative "${source_dir}" "${_source}")
                message(FATAL_ERROR
                    "The circuit 1 codec builds only on YTP/1 and common/: ${_relative}")
            endif()
            get_filename_component(_name "${_source}" NAME)
            if(_layer STREQUAL "engine" AND
               NOT _name STREQUAL "session_engine.cpp" AND
               NOT _name MATCHES "_test\\.cpp$" AND
               _lower_contents MATCHES [=[#[ 	]*include[ 	]*[<"]ytp/]=])
                file(RELATIVE_PATH _relative "${source_dir}" "${_source}")
                message(FATAL_ERROR
                    "Only SessionEngine may depend on YTP/1 inside the engine "
                    "layer: ${_relative}")
            endif()
            if(_layer STREQUAL "engine" AND
               _lower_contents MATCHES [=[#[ 	]*include[ 	]*[<"]config/]=])
                file(RELATIVE_PATH _relative "${source_dir}" "${_source}")
                message(FATAL_ERROR
                    "The session engine must remain independent of JSON/config: "
                    "${_relative}")
            endif()
        endforeach()
    endforeach()

    # Directional check. Exact link assertions cannot cover every target, but
    # the direction a layer may include in does not change with build options.
    # Every directory under src/ is a layer, and each layer names the layers
    # its production sources may include. The list is closed: an include of a
    # layer that is not named here, or a new directory that is not declared,
    # fails until someone decides where it belongs. `basefwx` stands for the
    # separate BaseFWX checkout and `yume` for the public header directory.
    set(_layers
        common ytp circuit engine config fs stealth admission providers
        runtime abi modules gui test_support)
    set(_include_targets ${_layers} basefwx yume)
    # common/ holds std-only helpers every layer may use.
    set(_common_may_include "")
    set(_ytp_may_include common)
    set(_circuit_may_include common ytp)
    # Inside the engine only SessionEngine includes YTP/1, checked above.
    set(_engine_may_include common ytp)
    set(_config_may_include common)
    set(_fs_may_include common)
    set(_stealth_may_include common)
    # Admission mechanics sit below the protocol and the providers, so neither
    # may become their owner.
    set(_admission_may_include common)
    set(_providers_may_include common ytp circuit engine fs stealth admission)
    # Native runtime composition owns policy and configuration above the
    # providers and stays independent of the embedding layer, modules and
    # BaseFWX.
    set(_runtime_may_include
        common ytp circuit engine config fs stealth providers)
    # The C ABI validates schema-1 documents and reaches the runtime only
    # through the embedding seam, whose one implementation is yume_embed.
    set(_abi_may_include common config yume)
    set(_abi_embed_source "src/abi/native_backend.cpp")
    set(_abi_embed_may_include common config yume engine providers runtime)
    # Module programs link no YUME library. Their libraries build on BaseFWX.
    set(_modules_may_include common fs basefwx)
    # The GUI is a client of the control socket. It may use common/'s
    # std-only helpers and nothing that holds transport state or secrets.
    set(_gui_may_include common)
    # Fixtures for tests only. No production layer lists test_support.
    set(_test_support_may_include
        common ytp circuit engine fs stealth admission providers)

    file(GLOB_RECURSE _layer_sources RELATIVE "${source_dir}"
        "${source_dir}/src/*.cpp"
        "${source_dir}/src/*.hpp"
        "${source_dir}/src/*.cc"
        "${source_dir}/src/*.c"
        "${source_dir}/src/*.h")
    list(SORT _layer_sources)
    foreach(_relative IN LISTS _layer_sources)
        if(NOT _relative MATCHES "^src/([^/]+)/")
            message(FATAL_ERROR
                "Source outside a layer: ${_relative}. Put it in a directory "
                "under src/ that cmake/YumeLayering.cmake declares.")
        endif()
        set(_layer "${CMAKE_MATCH_1}")
        if(NOT _layer IN_LIST _layers)
            message(FATAL_ERROR
                "src/${_layer}/ is not a declared layer (${_relative}). "
                "Declare it in cmake/YumeLayering.cmake with the layers it "
                "may include.")
        endif()
        # A test may legitimately reach across layers to build a fixture.
        get_filename_component(_name "${_relative}" NAME)
        if(_name MATCHES "_test\\.cpp$" OR _relative MATCHES "/tests/")
            continue()
        endif()
        if(_relative STREQUAL _abi_embed_source)
            set(_allowed ${_abi_embed_may_include})
        else()
            set(_allowed ${_${_layer}_may_include})
        endif()
        file(READ "${source_dir}/${_relative}" _contents)
        string(REGEX MATCHALL "#[ \t]*include[ \t]*[<\"][A-Za-z0-9_]+/"
            _includes "${_contents}")
        foreach(_include IN LISTS _includes)
            string(REGEX REPLACE ".*[<\"]([A-Za-z0-9_]+)/$" "\\1"
                _target "${_include}")
            if(_target STREQUAL _layer OR NOT _target IN_LIST _include_targets)
                continue()
            endif()
            if(NOT _target IN_LIST _allowed)
                string(REPLACE ";" " " _allowed_text "${_allowed}")
                if(_allowed_text STREQUAL "")
                    set(_allowed_text "no other layer")
                endif()
                message(FATAL_ERROR
                    "Layering violation: ${_relative} includes "
                    "${_target}/. The ${_layer} layer may include only: "
                    "${_allowed_text}.")
            endif()
        endforeach()
    endforeach()

    # Qt stays in the GUI: no other source includes a Qt header.
    file(GLOB_RECURSE _all_sources
        "${source_dir}/src/*.cpp"
        "${source_dir}/src/*.hpp"
        "${source_dir}/src/*.cc"
        "${source_dir}/src/*.c"
        "${source_dir}/src/*.h")
    foreach(_source IN LISTS _all_sources)
        file(RELATIVE_PATH _relative "${source_dir}" "${_source}")
        if(_relative MATCHES "^src/gui/")
            continue()
        endif()
        file(READ "${_source}" _contents)
        if(_contents MATCHES "#[ \t]*include[ \t]*<Q[A-Za-z0-9_]*(/[A-Za-z0-9_]+)?>")
            message(FATAL_ERROR
                "Qt header outside the GUI: ${_relative}. Only src/gui may use Qt.")
        endif()
    endforeach()

    file(GLOB_RECURSE _config_headers
        "${source_dir}/src/config/v1/*.hpp")
    foreach(_header IN LISTS _config_headers)
        file(READ "${_header}" _contents)
        string(TOLOWER "${_contents}" _lower_contents)
        if(_lower_contents MATCHES
           [=[(^|[/<"])(openssl|nghttp2|boost|asio|sys/socket\.h|winsock2\.h)([/\.>"]|$)]=])
            file(RELATIVE_PATH _relative "${source_dir}" "${_header}")
            message(FATAL_ERROR
                "Forbidden runtime dependency in config-v1 public header: "
                "${_relative}")
        endif()
    endforeach()
endfunction()

if(CMAKE_SCRIPT_MODE_FILE)
    if(NOT DEFINED YUME_SOURCE_DIR OR YUME_SOURCE_DIR STREQUAL "")
        message(FATAL_ERROR "YUME_SOURCE_DIR is required")
    endif()
    yume_check_03_source_layering("${YUME_SOURCE_DIR}")
    message(STATUS "YUME 0.3 source layering check passed")
endif()
