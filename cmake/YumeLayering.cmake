# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

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
endfunction()

function(yume_check_03_source_layering source_dir)
    if(NOT IS_DIRECTORY "${source_dir}/src")
        message(FATAL_ERROR "Invalid YUME source directory: ${source_dir}")
    endif()

    set(_engine_forbidden
        [=[(^|[/<"])(boost|openssl|nghttp2|nlohmann|filesystem)([/\.>"]|$)]=]
        [=[(^|[/<"])(asio|json\.hpp|json_fwd\.hpp)([/>"]|$)]=]
        [=[(^|[/<"])(sys/socket\.h|winsock2\.h)([>"]|$)]=])
    set(_ytp_forbidden ${_engine_forbidden})

    foreach(_layer IN ITEMS engine ytp)
        file(GLOB_RECURSE _sources
            "${source_dir}/src/${_layer}/*.cpp"
            "${source_dir}/src/${_layer}/*.hpp")
        foreach(_source IN LISTS _sources)
            file(READ "${_source}" _contents)
            string(TOLOWER "${_contents}" _lower_contents)
            foreach(_pattern IN LISTS _${_layer}_forbidden)
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

    # Directional check for the transport-v2 stack. Exact link assertions
    # cannot cover these targets because their third-party dependencies change
    # with build options, but the direction a layer may include in does not.
    # Each entry is "layer" followed by the directories it must never include.
    set(_core_forbidden      client server facade gui abi)
    set(_outbound_forbidden  client server facade gui abi)
    set(_client_forbidden    server facade gui abi)
    set(_server_forbidden    client facade gui abi)
    set(_facade_forbidden    gui abi)

    foreach(_layer IN ITEMS core outbound client server facade)
        file(GLOB_RECURSE _layer_sources
            "${source_dir}/src/${_layer}/*.cpp"
            "${source_dir}/src/${_layer}/*.hpp"
            "${source_dir}/src/${_layer}/*.cc"
            "${source_dir}/src/${_layer}/*.c"
            "${source_dir}/src/${_layer}/*.h")
        foreach(_source IN LISTS _layer_sources)
            # A test may legitimately reach across layers to build a fixture.
            get_filename_component(_name "${_source}" NAME)
            if(_name MATCHES "_test\\.cpp$")
                continue()
            endif()
            file(READ "${_source}" _contents)
            foreach(_forbidden IN LISTS _${_layer}_forbidden)
                if(_contents MATCHES
                   "#[ \t]*include[ \t]*[<\"]${_forbidden}/")
                    file(RELATIVE_PATH _relative "${source_dir}" "${_source}")
                    message(FATAL_ERROR
                        "Layering violation: ${_relative} includes "
                        "${_forbidden}/. The ${_layer} layer must not depend "
                        "on ${_forbidden}.")
                endif()
            endforeach()
        endforeach()
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
