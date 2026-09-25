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

    # The engine and YTP/1 include common/, so it stays as clean as they are.
    set(_dependency_clean_patterns
        [=[(^|[/<"])(boost|openssl|nghttp2|nlohmann|filesystem)([/\.>"]|$)]=]
        [=[(^|[/<"])(asio|json\.hpp|json_fwd\.hpp)([/>"]|$)]=]
        [=[(^|[/<"])(sys/socket\.h|winsock2\.h)([>"]|$)]=])

    foreach(_layer IN ITEMS engine ytp common)
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
    # Each entry is "layer" followed by the directories it must never include.
    # common/ holds std-only helpers every layer may use, so it includes no
    # other layer. fs/ and stealth/ build only on it.
    set(_common_forbidden    admission engine ytp stealth fs providers runtime config abi gui modules basefwx)
    set(_fs_forbidden        admission engine ytp stealth providers runtime config abi gui modules basefwx)
    set(_stealth_forbidden   admission engine ytp fs providers runtime config abi gui modules basefwx)
    # Admission mechanics sit below the protocol and the providers, so neither
    # may become their owner.
    set(_admission_forbidden engine ytp stealth fs providers runtime config abi gui modules basefwx)
    # Native runtime composition owns policy and configuration above the
    # providers and stays independent of the embedding layer, modules and
    # BaseFWX.
    set(_runtime_forbidden abi gui modules basefwx)
    set(_providers_forbidden runtime config abi gui modules basefwx)
    # The C ABI must not acquire the desktop application's dependencies.
    set(_abi_forbidden gui modules basefwx)

    foreach(_layer IN ITEMS common fs stealth admission runtime providers abi)
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
