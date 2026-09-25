# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
cmake_minimum_required(VERSION 3.20)
project(YUME LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)

if(POLICY CMP0167)
    # Debian 13 currently ships Boost headers/libs without upstream
    # BoostConfig.cmake, so keep CMake's FindBoost module path available.
    cmake_policy(SET CMP0167 OLD)
endif()

option(YUME_BUILD_NATIVE_APPLICATION
    "Build the native YTP/1 yume client and yumed daemon" ON)
# Module libraries built on BaseFWX, such as the end-to-end relay channel.
# They need the pinned BaseFWX checkout and liboqs, so an ordinary yume and
# yumed build leaves them out. No core target links BaseFWX.
option(YUME_BUILD_BASEFWX_MODULES
    "Build module libraries that use BaseFWX, such as the end-to-end relay channel"
    OFF)
option(YUME_USE_SYSTEM_BASEFWX "Prefer a system-installed BaseFWX (find_package basefwx CONFIG) over the bundled tree" OFF)
set(YUME_DEPENDENCY_MANIFEST
    "${CMAKE_CURRENT_SOURCE_DIR}/config/dependencies.json")
if(NOT EXISTS "${YUME_DEPENDENCY_MANIFEST}")
    message(FATAL_ERROR "Missing dependency manifest: ${YUME_DEPENDENCY_MANIFEST}")
endif()
file(READ "${YUME_DEPENDENCY_MANIFEST}" _yume_dependency_json)
string(JSON _yume_dependency_schema GET "${_yume_dependency_json}" schema)
if(NOT _yume_dependency_schema EQUAL 1)
    message(FATAL_ERROR "Unsupported dependency manifest schema")
endif()
string(JSON YUME_REQUIRED_BASEFWX_VERSION GET "${_yume_dependency_json}"
    dependencies basefwx minimum_version)

# Browser/cover identities are registered once and generated into immutable
# C++ data. CMake resolves the active fixture from the same registry used by
# the generator and packaging checks; profile-specific paths must not spread
# through build logic.
set(YUME_TRANSPORT_PROFILE_REGISTRY
    "${CMAKE_CURRENT_SOURCE_DIR}/config/transport_profiles.json")
if(NOT EXISTS "${YUME_TRANSPORT_PROFILE_REGISTRY}")
    message(FATAL_ERROR "Missing transport profile registry: ${YUME_TRANSPORT_PROFILE_REGISTRY}")
endif()
file(READ "${YUME_TRANSPORT_PROFILE_REGISTRY}" _yume_profile_registry_json)
string(JSON _yume_profile_registry_schema GET "${_yume_profile_registry_json}" schema)
if(NOT _yume_profile_registry_schema EQUAL 1)
    message(FATAL_ERROR "Unsupported transport profile registry schema")
endif()
string(JSON YUME_ACTIVE_TRANSPORT_PROFILE GET
    "${_yume_profile_registry_json}" active_profile)
string(JSON _yume_profile_count LENGTH
    "${_yume_profile_registry_json}" profiles)
if(_yume_profile_count LESS 1)
    message(FATAL_ERROR "Transport profile registry is empty")
endif()
math(EXPR _yume_profile_last "${_yume_profile_count} - 1")
set(_yume_active_profile_fixture "")
set(_yume_active_profile_manifest "")
set(_yume_active_profile_http2 "")
set(_yume_active_profile_tls_wire "")
set(_yume_active_profile_tls_candidates "")
foreach(_yume_profile_index RANGE 0 ${_yume_profile_last})
    string(JSON _yume_profile_id GET "${_yume_profile_registry_json}"
        profiles ${_yume_profile_index} id)
    if(_yume_profile_id STREQUAL YUME_ACTIVE_TRANSPORT_PROFILE)
        string(JSON _yume_active_profile_fixture GET
            "${_yume_profile_registry_json}"
            profiles ${_yume_profile_index} fixture)
        string(JSON _yume_active_profile_manifest GET
            "${_yume_profile_registry_json}"
            profiles ${_yume_profile_index} artifacts manifest)
        string(JSON _yume_active_profile_http2 GET
            "${_yume_profile_registry_json}"
            profiles ${_yume_profile_index} artifacts http2_profile)
        string(JSON _yume_active_profile_tls_wire GET
            "${_yume_profile_registry_json}"
            profiles ${_yume_profile_index} artifacts tls_wire_profile)
        string(JSON _yume_tls_candidate_count LENGTH
            "${_yume_profile_registry_json}"
            profiles ${_yume_profile_index} artifacts tls_wire_candidates)
        if(_yume_tls_candidate_count LESS 1)
            message(FATAL_ERROR "Active transport profile has no TLS wire candidates")
        endif()
        math(EXPR _yume_tls_candidate_last "${_yume_tls_candidate_count} - 1")
        foreach(_yume_tls_candidate_index RANGE 0 ${_yume_tls_candidate_last})
            string(JSON _yume_tls_candidate GET
                "${_yume_profile_registry_json}"
                profiles ${_yume_profile_index} artifacts tls_wire_candidates
                ${_yume_tls_candidate_index})
            list(APPEND _yume_active_profile_tls_candidates
                "${_yume_tls_candidate}")
        endforeach()
    endif()
endforeach()
if(_yume_active_profile_fixture STREQUAL "")
    message(FATAL_ERROR
        "Active transport profile ${YUME_ACTIVE_TRANSPORT_PROFILE} is not registered")
endif()
if(IS_ABSOLUTE "${_yume_active_profile_fixture}" OR
   _yume_active_profile_fixture MATCHES "(^|/)\\.\\.(/|$)")
    message(FATAL_ERROR "Transport profile fixture must stay inside the source tree")
endif()
set(YUME_ACTIVE_PROFILE_FIXTURE
    "${CMAKE_CURRENT_SOURCE_DIR}/${_yume_active_profile_fixture}")
foreach(_yume_artifact IN ITEMS
        "${_yume_active_profile_manifest}"
        "${_yume_active_profile_http2}"
        "${_yume_active_profile_tls_wire}"
        ${_yume_active_profile_tls_candidates})
    if(IS_ABSOLUTE "${_yume_artifact}" OR
       _yume_artifact MATCHES "(^|/)\\.\\.(/|$)")
        message(FATAL_ERROR
            "Transport profile artifact must stay inside its fixture: ${_yume_artifact}")
    endif()
    if(NOT EXISTS "${YUME_ACTIVE_PROFILE_FIXTURE}/${_yume_artifact}")
        message(FATAL_ERROR
            "Active transport profile is missing ${_yume_artifact}")
    endif()
endforeach()
set(YUME_ACTIVE_PROFILE_MANIFEST
    "${YUME_ACTIVE_PROFILE_FIXTURE}/${_yume_active_profile_manifest}")
set(YUME_ACTIVE_PROFILE_HTTP2
    "${YUME_ACTIVE_PROFILE_FIXTURE}/${_yume_active_profile_http2}")
set(YUME_ACTIVE_PROFILE_TLS_WIRE
    "${YUME_ACTIVE_PROFILE_FIXTURE}/${_yume_active_profile_tls_wire}")
set(YUME_ACTIVE_PROFILE_TLS_CANDIDATES "")
set(YUME_ACTIVE_PROFILE_TLS_CANDIDATE_ARGS "")
foreach(_yume_tls_candidate IN LISTS _yume_active_profile_tls_candidates)
    set(_yume_tls_candidate_path
        "${YUME_ACTIVE_PROFILE_FIXTURE}/${_yume_tls_candidate}")
    list(APPEND YUME_ACTIVE_PROFILE_TLS_CANDIDATES
        "${_yume_tls_candidate_path}")
    list(APPEND YUME_ACTIVE_PROFILE_TLS_CANDIDATE_ARGS
        --candidate "${_yume_tls_candidate_path}")
endforeach()
option(YUME_USE_BUNDLED_NLOHMANN "Allow bundled nlohmann_json fallback" ON)
option(YUME_STATIC "Attempt static build (requires static deps)" OFF)
option(YUME_STATIC_OPENSSL
    "Link the pinned OpenSSL into YUME binaries so native Chrome TLS has no runtime libssl dependency"
    ON)
option(YUME_NATIVE_OPT "Enable host-specific -march/-mtune=native CPU tuning; disables portable binaries" OFF)
option(YUME_LTO "Enable link-time optimization for yume builds" ON)
option(YUME_FAST_MATH "Enable fast-math (unsafe for crypto)" OFF)
option(YUME_DEB_SHLIBDEPS "Use dpkg-shlibdeps when building Debian packages" ON)
option(YUME_BUILD_TESTING "Build optional YUME unit test executables" OFF)
option(YUME_TEST_LINUX_NAMESPACES "Run native TUN tests in unprivileged Linux network namespaces" OFF)
# libFuzzer harnesses for the parsers an untrusted peer or file reaches.
# Clang-only and never installed; the corpora live outside the tree.
option(YUME_BUILD_FUZZERS "Build libFuzzer harnesses (requires Clang)" OFF)
option(YUME_BUILD_SHARED_ABI
    "Build the experimental ABI v1 candidate and contract tests"
    OFF)
option(YUME_INSTALL_EXPERIMENTAL_SDK
    "Install the unfrozen SDK candidate for development consumers" OFF)
if(YUME_INSTALL_EXPERIMENTAL_SDK AND NOT YUME_BUILD_SHARED_ABI)
    message(FATAL_ERROR "YUME_INSTALL_EXPERIMENTAL_SDK requires YUME_BUILD_SHARED_ABI")
endif()
option(YUME_BUILD_YTP1_OPENSSL_PROVIDER
    "Build the OpenSSL 3.5 YTP/1 session-security provider"
    ${YUME_BUILD_NATIVE_APPLICATION})
option(YUME_BUILD_YTP1_TLS13_PROVIDER
    "Build the browser-shaped YTP/1 TLS 1.3 provider"
    ${YUME_BUILD_NATIVE_APPLICATION})
option(YUME_BUILD_YTP1_ASIO_ROUTE_PROVIDER
    "Build the Boost.Asio YTP/1 direct TCP/UDP route provider"
    ${YUME_BUILD_NATIVE_APPLICATION})
option(YUME_BUILD_YTP1_ASIO_TCP_BYTE_CHANNEL_PROVIDER
    "Build client and accepted TCP ByteChannel support for YTP/1"
    ${YUME_BUILD_NATIVE_APPLICATION})
option(YUME_BUILD_YTP1_H2_CARRIER
    "Build the libnghttp2 YTP/1 duplex carrier provider"
    ${YUME_BUILD_NATIVE_APPLICATION})
option(YUME_BUILD_YTP1_FRONT_DOOR
    "Build the TLS/HTTP cover and YTP/1 admission listener"
    ${YUME_BUILD_NATIVE_APPLICATION})
if(YUME_BUILD_YTP1_FRONT_DOOR AND
   NOT (YUME_BUILD_YTP1_TLS13_PROVIDER AND
        YUME_BUILD_YTP1_H2_CARRIER AND
        YUME_BUILD_YTP1_ASIO_TCP_BYTE_CHANNEL_PROVIDER))
    message(FATAL_ERROR "YTP/1 FrontDoor requires its TLS13, H2_CARRIER and ASIO_TCP_BYTE_CHANNEL providers")
endif()
if(YUME_BUILD_NATIVE_APPLICATION)
    foreach(_provider IN ITEMS OPENSSL_PROVIDER TLS13_PROVIDER ASIO_ROUTE_PROVIDER
            ASIO_TCP_BYTE_CHANNEL_PROVIDER H2_CARRIER FRONT_DOOR)
        if(NOT YUME_BUILD_YTP1_${_provider})
            message(FATAL_ERROR "Native application requires YUME_BUILD_YTP1_${_provider}=ON; use a fresh build directory or enable the provider")
        endif()
    endforeach()
endif()

# Compile at least one consumer as C whenever the experimental ABI contract is
# enabled. Keeping C conditional avoids imposing a second compiler on normal
# product and foundation-only builds.
if(YUME_BUILD_SHARED_ABI)
    enable_language(C)
endif()

# Developer build accelerators. Both default OFF on purpose: this project has a
# reproducibility gate (two clean helper builds must be byte-identical) and an
# exact-artifact provenance discipline, so nothing that can perturb the emitted
# object may be on by default. CI, sanitizer, shared-ABI, and exact-artifact
# lanes configure CMake directly and leave them disabled. Developer trees may
# enable them explicitly when build provenance is not being measured.
option(YUME_COMPILER_LAUNCHER "Use ccache/sccache when available (developer trees only)" OFF)
option(YUME_PCH "Precompile the heavy asio/json headers (developer trees only)" OFF)

if(YUME_COMPILER_LAUNCHER AND NOT CMAKE_CXX_COMPILER_LAUNCHER)
    find_program(YUME_CCACHE_EXECUTABLE NAMES ccache sccache)
    if(YUME_CCACHE_EXECUTABLE)
        set(CMAKE_C_COMPILER_LAUNCHER "${YUME_CCACHE_EXECUTABLE}" CACHE STRING "" FORCE)
        set(CMAKE_CXX_COMPILER_LAUNCHER "${YUME_CCACHE_EXECUTABLE}" CACHE STRING "" FORCE)
        message(STATUS "YUME: compiler launcher ${YUME_CCACHE_EXECUTABLE}")
    else()
        message(STATUS "YUME: YUME_COMPILER_LAUNCHER=ON but no ccache/sccache found")
    endif()
endif()

# Warnings are part of the security posture, not a style preference: this tree
# parses untrusted wire input and hand-manages buffers, and the default GCC/MSVC
# warning set is silent about the mistakes that matter there. Applied only to
# first-party targets (see yume_apply_warnings in src/CMakeLists.txt) so bundled
# dependencies cannot fail or pollute the build.
option(YUME_WARNINGS "Compile first-party targets with the project warning set" ON)
option(YUME_WARNINGS_AS_ERRORS "Promote first-party compiler warnings to errors" OFF)

# Sanitizer selection. Directory-level flags instrument every source-built
# target added below, including bundled BaseFWX sources. Prebuilt archives and
# system libraries remain outside our control. Never ship a sanitized binary.
set(YUME_SANITIZE "none" CACHE STRING
    "Sanitizers to instrument this build with: none, address, undefined, address+undefined, thread")
set_property(CACHE YUME_SANITIZE PROPERTY STRINGS
    none address undefined address+undefined thread)

# Fine-grained timing diagnostics are compiled only for explicit developer
# configurations. Release and MinSizeRel binaries contain no diagnostic
# counters or clock reads. The H2 carrier's timing is also off until a caller
# asks it to collect, so an instrumented build costs nothing by default.
set(YUME_DEV_DIAGNOSTICS_EXPRESSION
    "$<IF:$<OR:$<CONFIG:Debug>,$<CONFIG:RelWithDebInfo>>,1,0>")

set(BUILD_TESTING ${YUME_BUILD_TESTING} CACHE BOOL "Build YUME unit tests" FORCE)
include(CTest)

if(YUME_BUILD_TESTING AND CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    add_test(
        NAME yume_default_build_type_test
        COMMAND ${CMAKE_COMMAND}
            -DYUME_BUILD_TYPE_MODULE=${PROJECT_SOURCE_DIR}/cmake/YumeBuildType.cmake
            -P ${PROJECT_SOURCE_DIR}/tests/cmake/default_build_type_test.cmake
    )

    find_program(YUME_BASH_EXECUTABLE bash)
    if(YUME_BASH_EXECUTABLE)
        add_test(
            NAME yume_build_helpers_test
            COMMAND "${YUME_BASH_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/shell/build_helpers_test.sh"
        )
    endif()
endif()

include("${CMAKE_CURRENT_LIST_DIR}/cmake/YumeBuildType.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/cmake/YumeAbiSymbols.cmake")
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    yume_configure_default_build_type()
endif()

# The desktop GUI in src/gui was built on the transport-v2 client runtime,
# which YUME no longer contains. Its source waits for a native facade.
option(YUME_BUILD_GUI "Build the yume-gui desktop app" OFF)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/src/common/version.hpp" _yume_version_line
    REGEX "kVersion\\[\\][ \\t]*=[ \\t]*\"")
string(REGEX MATCH "\"([^\"]+)\"" _yume_version_match "${_yume_version_line}")
if(CMAKE_MATCH_1)
    set(YUME_PACKAGE_VERSION "${CMAKE_MATCH_1}")
else()
    set(YUME_PACKAGE_VERSION "0.0.0")
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# If a fully-static build is requested, ensure a static zlib is available; otherwise
# fall back to dynamic to avoid confusing link errors like:
#   "attempted static link of dynamic object `/path/to/libz.so`"
if(YUME_STATIC)
    set(_yume_static_zlib_ok OFF)

    if(DEFINED ZLIB_LIBRARY AND EXISTS "${ZLIB_LIBRARY}" AND ZLIB_LIBRARY MATCHES "\\.a$")
        set(_yume_static_zlib_ok ON)
    endif()

    # Prefer sysroot zlib for cross builds.
    if(NOT _yume_static_zlib_ok AND DEFINED CMAKE_SYSROOT)
        set(_yume_zlib_candidates
            "${CMAKE_SYSROOT}/usr/lib/libz.a"
            "${CMAKE_SYSROOT}/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}/libz.a"
            "${CMAKE_SYSROOT}/lib/libz.a"
            "${CMAKE_SYSROOT}/lib/${CMAKE_LIBRARY_ARCHITECTURE}/libz.a"
        )
        foreach(_yume_zlib_path IN LISTS _yume_zlib_candidates)
            if(_yume_zlib_path AND EXISTS "${_yume_zlib_path}")
                set(_yume_static_zlib_ok ON)
                set(ZLIB_LIBRARY "${_yume_zlib_path}" CACHE FILEPATH "zlib library" FORCE)
                if((NOT DEFINED ZLIB_INCLUDE_DIR OR ZLIB_INCLUDE_DIR STREQUAL "") AND EXISTS "${CMAKE_SYSROOT}/usr/include/zlib.h")
                    set(ZLIB_INCLUDE_DIR "${CMAKE_SYSROOT}/usr/include" CACHE PATH "zlib include dir" FORCE)
                endif()
                break()
            endif()
        endforeach()
    endif()

    # Host builds: try to locate libz.a via CMake search.
    if(NOT _yume_static_zlib_ok AND NOT CMAKE_CROSSCOMPILING)
        set(_yume_saved_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
        set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
        find_library(_yume_zlib_static NAMES z zlib)
        set(CMAKE_FIND_LIBRARY_SUFFIXES "${_yume_saved_suffixes}")
        if(_yume_zlib_static AND EXISTS "${_yume_zlib_static}")
            set(_yume_static_zlib_ok ON)
            set(ZLIB_LIBRARY "${_yume_zlib_static}" CACHE FILEPATH "zlib library" FORCE)
            if(NOT DEFINED ZLIB_INCLUDE_DIR OR ZLIB_INCLUDE_DIR STREQUAL "" OR NOT EXISTS "${ZLIB_INCLUDE_DIR}/zlib.h")
                find_path(_yume_zlib_include_dir NAMES zlib.h)
                if(_yume_zlib_include_dir)
                    set(ZLIB_INCLUDE_DIR "${_yume_zlib_include_dir}" CACHE PATH "zlib include dir" FORCE)
                endif()
            endif()
        endif()
    endif()

    if(NOT _yume_static_zlib_ok)
        message(WARNING "Static link requested but libz.a not found (set ZLIB_LIBRARY or install static libs); disabling static link.")
        set(YUME_STATIC OFF CACHE BOOL "Attempt static build (requires static deps)" FORCE)
    endif()
endif()

if(YUME_STATIC AND YUME_BUILD_SHARED_ABI)
    message(FATAL_ERROR "YUME_BUILD_SHARED_ABI requires a dynamic build; disable YUME_STATIC")
endif()
if(YUME_BUILD_GUI)
    message(FATAL_ERROR
        "YUME_BUILD_GUI is not available: the GUI in src/gui needs a native "
        "YTP/1 facade before it builds again")
endif()

# A static library absorbed into libyume must be PIC, hidden, and an ordinary
# native object archive. A version script is still the final export allowlist,
# but GCC 11 LTO can materialize default-visible weak libstdc++ definitions
# after GNU ld has applied that script. Do not perturb unrelated engine targets.
function(yume_prepare_static_for_shared_abi target)
    get_target_property(_yume_target_type ${target} TYPE)
    if(YUME_BUILD_SHARED_ABI AND _yume_target_type STREQUAL "STATIC_LIBRARY")
        set_target_properties(${target} PROPERTIES
            POSITION_INDEPENDENT_CODE ON
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON
            INTERPROCEDURAL_OPTIMIZATION OFF
            INTERPROCEDURAL_OPTIMIZATION_RELEASE OFF
            INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO OFF
            INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL OFF
            YUME_SHARED_ABI_INPUT ON
        )
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            # Override any directory-level -flto on the archive. The shared
            # target consuming it inherits the same policy: GCC 14 cannot
            # reliably resolve hidden inline/template definitions when an LTO
            # object links a deliberately non-LTO archive.
            target_compile_options(${target}
                PRIVATE -fno-lto
                INTERFACE -fno-lto)
            target_link_options(${target} INTERFACE -fno-lto)
        endif()
    endif()
endfunction()

if(YUME_STATIC OR YUME_STATIC_OPENSSL)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
else()
    set(OPENSSL_USE_STATIC_LIBS FALSE)
endif()

if(YUME_STATIC)
    set(BUILD_SHARED_LIBS OFF)
    set(Boost_USE_STATIC_LIBS ON)
    add_compile_definitions(YUME_STATIC_BUILD=1)
else()
    set(Boost_USE_STATIC_LIBS OFF)
endif()

if(CMAKE_CROSSCOMPILING)
    set(YUME_NATIVE_OPT OFF CACHE BOOL "Enable host-specific -march/-mtune=native CPU tuning; disables portable binaries" FORCE)
    set(YUME_LTO OFF CACHE BOOL "Enable link-time optimization for yume builds" FORCE)
endif()

# ---------------------------------------------------------------------------
# Sanitizers
#
# Set before any add_subdirectory() so source-built bundled dependencies are
# instrumented too. LTO is forced off: it reorders and inlines across the
# sanitizers report against, which turns a precise finding into an unusable
# stack. -fno-sanitize-recover=all makes UBSan abort instead of printing and
# continuing, so a CI run actually fails on the first violation.
# ---------------------------------------------------------------------------
string(TOLOWER "${YUME_SANITIZE}" _yume_sanitize)
if(_yume_sanitize STREQUAL "" OR _yume_sanitize STREQUAL "off")
    set(_yume_sanitize "none")
endif()

# Instrument parser libraries as well as their harnesses. Instrumenting only
# LLVMFuzzerTestOneInput leaves out-of-line parser bodies without coverage or
# sanitizer checks. The harness alone links libFuzzer's main; every compiled
# dependency gets coverage and the ordinary ASan/UBSan configuration below.
if(YUME_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "YUME_BUILD_FUZZERS requires Clang")
    endif()
    if(NOT _yume_sanitize STREQUAL "none" AND
       NOT _yume_sanitize STREQUAL "address+undefined")
        message(FATAL_ERROR
            "YUME_BUILD_FUZZERS requires address+undefined sanitizers; use a separate build for other sanitizer selections")
    endif()
    set(YUME_SANITIZE "address+undefined" CACHE STRING
        "Sanitizers to instrument this build with: none, address, undefined, address+undefined, thread" FORCE)
    set(_yume_sanitize "address+undefined")
    add_compile_options(-fsanitize=fuzzer-no-link)
endif()

if(NOT _yume_sanitize STREQUAL "none")
    if(_yume_sanitize STREQUAL "address")
        set(_yume_sanitize_flags "-fsanitize=address")
    elseif(_yume_sanitize STREQUAL "undefined")
        set(_yume_sanitize_flags "-fsanitize=undefined")
    elseif(_yume_sanitize STREQUAL "address+undefined")
        set(_yume_sanitize_flags "-fsanitize=address,undefined")
    elseif(_yume_sanitize STREQUAL "thread")
        set(_yume_sanitize_flags "-fsanitize=thread")
    else()
        message(FATAL_ERROR
            "Unknown YUME_SANITIZE='${YUME_SANITIZE}'. Valid: none, address, undefined, address+undefined, thread")
    endif()

    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "YUME_SANITIZE requires GCC or Clang; got ${CMAKE_CXX_COMPILER_ID}")
    endif()
    if(YUME_STATIC)
        message(FATAL_ERROR "YUME_SANITIZE cannot be combined with YUME_STATIC; the sanitizer runtime must stay dynamic")
    endif()

    set(YUME_LTO OFF CACHE BOOL "Enable link-time optimization for yume builds" FORCE)

    add_compile_options(${_yume_sanitize_flags} -fno-omit-frame-pointer -g)
    add_link_options(${_yume_sanitize_flags})
    if(_yume_sanitize MATCHES "undefined")
        add_compile_options(-fno-sanitize-recover=all)
    endif()

    # The strict-C ABI integration is orchestrated by Python and loads the
    # instrumented shared library through ctypes. Unlike the C/C++ test
    # executables, that Python process is not linked by this build, so Linux
    # ASan must be preloaded before ctypes opens libyume. Resolve the compiler's
    # own runtime instead of guessing a GCC-versioned system path. The test
    # property is applied where the integration test is declared.
    if(_yume_sanitize MATCHES "address" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        execute_process(
            COMMAND "${CMAKE_CXX_COMPILER}" -print-file-name=libasan.so
            OUTPUT_VARIABLE _yume_asan_runtime
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE _yume_asan_runtime_result)
        if(NOT _yume_asan_runtime_result EQUAL 0 OR
           NOT IS_ABSOLUTE "${_yume_asan_runtime}" OR
           NOT EXISTS "${_yume_asan_runtime}")
            message(FATAL_ERROR
                "Unable to resolve the compiler ASan runtime for ctypes integration: '${_yume_asan_runtime}'")
        endif()
        execute_process(
            COMMAND "${CMAKE_CXX_COMPILER}" -print-file-name=libstdc++.so.6
            OUTPUT_VARIABLE _yume_cxx_runtime
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE _yume_cxx_runtime_result)
        if(NOT _yume_cxx_runtime_result EQUAL 0 OR
           NOT IS_ABSOLUTE "${_yume_cxx_runtime}" OR
           NOT EXISTS "${_yume_cxx_runtime}")
            message(FATAL_ERROR
                "Unable to resolve the compiler C++ runtime for ctypes integration: '${_yume_cxx_runtime}'")
        endif()
        # ASan must be first, while libstdc++ must already be present when ASan
        # installs its __cxa_throw interceptor. Python normally loads neither.
        set(_yume_asan_preload "${_yume_asan_runtime}:${_yume_cxx_runtime}")
    endif()

    message(STATUS "YUME sanitizers: ${_yume_sanitize} (LTO forced OFF; do not distribute this build)")
else()
    message(STATUS "YUME sanitizers: none")
endif()

if(YUME_NATIVE_OPT)
    message(STATUS "YUME native CPU tuning: ON (host-specific binary; do not copy across different CPUs)")
else()
    message(STATUS "YUME native CPU tuning: OFF (portable CPU baseline)")
endif()

# The TLS client consumes the browser-profile emitter. Session-security-only
# builds still need just upstream OpenSSL primitives.
if(YUME_BUILD_YTP1_TLS13_PROVIDER)
    if(YUME_STATIC_OPENSSL)
        # The pinned CONFIG target carries Brotli/Zstd through static linkage.
        find_package(OpenSSL 3.5 REQUIRED CONFIG)
    else()
        find_package(OpenSSL 3.5 REQUIRED)
    endif()
elseif(YUME_BUILD_YTP1_OPENSSL_PROVIDER AND
       NOT TARGET OpenSSL::Crypto)
    find_package(OpenSSL 3.5 REQUIRED)
endif()

if((YUME_BUILD_YTP1_ASIO_ROUTE_PROVIDER OR
    YUME_BUILD_YTP1_ASIO_TCP_BYTE_CHANNEL_PROVIDER OR
    YUME_BUILD_YTP1_H2_CARRIER) AND
   NOT TARGET Boost::system)
    find_package(Boost CONFIG QUIET COMPONENTS system)
    if(NOT Boost_FOUND)
        find_package(Boost REQUIRED COMPONENTS system)
    endif()
endif()

if(YUME_BUILD_YTP1_H2_CARRIER)
    find_package(PkgConfig REQUIRED)
    if(YUME_STATIC)
        # FindPkgConfig's generated imported target resolves -lnghttp2 to the
        # shared object even when libnghttp2.a is installed. Passing that
        # absolute .so path to a -static link fails late with "attempted static
        # link of dynamic object". Resolve and expose the archive explicitly
        # so a static request either configures truthfully or fails here.
        pkg_check_modules(NGHTTP2 REQUIRED libnghttp2>=1.64)
        set(_yume_saved_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
        set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
        find_library(YUME_NGHTTP2_STATIC_LIBRARY
            NAMES nghttp2
            HINTS ${NGHTTP2_LIBRARY_DIRS}
        )
        set(CMAKE_FIND_LIBRARY_SUFFIXES "${_yume_saved_suffixes}")
        if(NOT YUME_NGHTTP2_STATIC_LIBRARY OR
           NOT YUME_NGHTTP2_STATIC_LIBRARY MATCHES "\\.a$")
            message(FATAL_ERROR
                "YUME_STATIC requires libnghttp2.a; install the static "
                "nghttp2 development archive or disable YUME_STATIC")
        endif()
        add_library(yume_nghttp2_static STATIC IMPORTED GLOBAL)
        set_target_properties(yume_nghttp2_static PROPERTIES
            IMPORTED_LOCATION "${YUME_NGHTTP2_STATIC_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${NGHTTP2_INCLUDE_DIRS}"
            INTERFACE_COMPILE_OPTIONS "${NGHTTP2_CFLAGS_OTHER}"
        )
        set(YUME_NGHTTP2_TARGET yume_nghttp2_static)
    else()
        if(NOT TARGET PkgConfig::NGHTTP2)
            pkg_check_modules(NGHTTP2 REQUIRED IMPORTED_TARGET libnghttp2>=1.64)
        endif()
        set(YUME_NGHTTP2_TARGET PkgConfig::NGHTTP2)
    endif()
    if(NOT TARGET OpenSSL::Crypto)
        find_package(OpenSSL 3.5 REQUIRED)
    endif()
endif()

if(YUME_BUILD_YTP1_TLS13_PROVIDER)
    include(CheckCXXSourceCompiles)
    set(_yume_saved_required_libraries "${CMAKE_REQUIRED_LIBRARIES}")
    set(CMAKE_REQUIRED_LIBRARIES OpenSSL::SSL)
    unset(YUME_OPENSSL_HAS_CHROME_CLIENTHELLO_PATCH CACHE)
    check_cxx_source_compiles([=[
        #include <openssl/ssl.h>
        #ifndef SSL_OP_YUME_CHROME_CLIENT_HELLO
        # error "YUME OpenSSL ClientHello patch is missing"
        #endif
        #ifndef SSL_CTRL_YUME_CHROME_CLIENT_HELLO
        # error "YUME OpenSSL ClientHello control is missing"
        #endif
        int main() { return SSL_CTRL_YUME_CHROME_CLIENT_HELLO == 0; }
    ]=] YUME_OPENSSL_HAS_CHROME_CLIENTHELLO_PATCH)
    set(CMAKE_REQUIRED_LIBRARIES "${_yume_saved_required_libraries}")
    unset(_yume_saved_required_libraries)
    if(NOT YUME_OPENSSL_HAS_CHROME_CLIENTHELLO_PATCH)
        message(FATAL_ERROR
            "YUME's default openssl-chrome151 backend requires the pinned "
            "default-off OpenSSL patch. Run ezbuild.sh, or source "
            "scripts/ensure-openssl.sh and call yume_openssl_ensure before "
            "configuring CMake. Stock libssl is not accepted for native TLS.")
    endif()
endif()

if(YUME_BUILD_BASEFWX_MODULES)
    # The relay channel's ML-KEM-1024 comes from BaseFWX's liboqs support.
    # Without this BaseFWX would build without it and fail only at run time.
    set(BASEFWX_REQUIRE_OQS ON CACHE BOOL
        "Require liboqs with ML-KEM-768 and ML-KEM-1024 support" FORCE)
    if(NOT CMAKE_CROSSCOMPILING)
        set(BASEFWX_NATIVE_OPT ${YUME_NATIVE_OPT} CACHE BOOL "Enable -march/-mtune native optimizations" FORCE)
    endif()
    if(CMAKE_CROSSCOMPILING)
        set(BASEFWX_NATIVE_OPT OFF CACHE BOOL "Disable native tuning for cross builds" FORCE)
    endif()

    set(_yume_basefwx_via_system OFF)
    if(YUME_USE_SYSTEM_BASEFWX)
        find_package(basefwx ${YUME_REQUIRED_BASEFWX_VERSION} CONFIG QUIET)
        if(basefwx_FOUND)
            if(NOT TARGET basefwxcpp)
                add_library(basefwxcpp ALIAS basefwx::basefwxcpp)
            endif()
            set(_yume_basefwx_via_system ON)
            message(STATUS "Using system BaseFWX ${basefwx_VERSION}")
        elseif(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/basefwx/cpp/CMakeLists.txt")
            message(FATAL_ERROR
                "YUME_USE_SYSTEM_BASEFWX=ON but BaseFWX "
                "${YUME_REQUIRED_BASEFWX_VERSION} or newer was not found "
                "and no bundled basefwx/cpp tree is available")
        endif()
    endif()

    if(NOT _yume_basefwx_via_system)
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/basefwx/cpp/CMakeLists.txt")
            set(BASEFWX_BUILD_CLI OFF CACHE BOOL "Disable BaseFWX CLI build" FORCE)
            add_subdirectory(basefwx/cpp EXCLUDE_FROM_ALL)
            if(TARGET basefwxcpp)
                if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
                    target_compile_options(basefwxcpp PRIVATE
                        -Wno-deprecated-declarations
                        $<$<CXX_COMPILER_ID:GNU>:-Wno-psabi>
                    )
                elseif(MSVC)
                    target_compile_options(basefwxcpp PRIVATE /wd4996)
                endif()
            endif()
        else()
            message(FATAL_ERROR "BaseFWX sources not found at basefwx/cpp")
        endif()
    endif()
endif()

add_subdirectory(src)

# The installed tools and examples use the same schema as the application.
if(YUME_BUILD_NATIVE_APPLICATION)
    set(YUME_DOC_INSTALL_DIR "${CMAKE_INSTALL_DATAROOTDIR}/doc/yume")
    install(PROGRAMS tools/yume_setup.py
        DESTINATION "${CMAKE_INSTALL_BINDIR}" RENAME yume-setup COMPONENT yume_cli)
    install(PROGRAMS tools/yume_doctor.py
        DESTINATION "${CMAKE_INSTALL_BINDIR}" RENAME yume-doctor COMPONENT yume_cli)

    install(FILES
        README.md
        CONTRIBUTING.md
        docs/ABI.md
        docs/DIAGNOSTICS.md
        docs/EXPLAINED.md
        docs/ARCHITECTURE.md
        docs/OPERATIONS.md
        docs/PACKAGING.md
        docs/PERMISSIONS.md
        docs/QUICKSTART.md
        docs/STEALTH.md
        docs/THREAT_MODEL.md
        docs/IMPLEMENTATION_STATUS.md
        docs/SELFTEST.md
        docs/LEAK_TIGHT.md
        docs/PACKET_NATIVE_BULK.md
        docs/release/CHANGELOG.md
        DESTINATION "${YUME_DOC_INSTALL_DIR}"
        COMPONENT yume_cli
    )

    # Keep the complete Markdown hierarchy as well as the established flat
    # install paths above. docs/README.md and nested protocol/release links are
    # authored relative to that hierarchy and must remain usable after install.
    install(DIRECTORY docs/
        DESTINATION "${YUME_DOC_INSTALL_DIR}/docs"
        COMPONENT yume_cli
        FILES_MATCHING
        PATTERN "*.md"
        PATTERN "man" EXCLUDE
    )
    install(DIRECTORY docs/protocol/
        DESTINATION "${YUME_DOC_INSTALL_DIR}/protocol"
        COMPONENT yume_cli
        FILES_MATCHING PATTERN "*.md"
    )

    install(FILES
        config/ytp1/yume.json
        config/ytp1/yumed.json
        DESTINATION "${YUME_DOC_INSTALL_DIR}/examples"
        COMPONENT yume_cli
    )

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/debian/copyright")
        install(FILES debian/copyright
            DESTINATION "${YUME_DOC_INSTALL_DIR}"
            RENAME copyright
            COMPONENT yume_cli
        )
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog")
        install(FILES debian/changelog
            DESTINATION "${YUME_DOC_INSTALL_DIR}"
            RENAME changelog.Debian
            COMPONENT yume_cli
        )
    endif()

    install(FILES docs/man/yume.1
        DESTINATION "${CMAKE_INSTALL_MANDIR}/man1"
        COMPONENT yume_cli
    )
    install(FILES
        "${YUME_ACTIVE_PROFILE_MANIFEST}"
        "${YUME_ACTIVE_PROFILE_HTTP2}"
        "${YUME_ACTIVE_PROFILE_TLS_WIRE}"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/yume/cover-profile"
        COMPONENT yume_cli
    )
    install(FILES docs/man/yumed.8
        DESTINATION "${CMAKE_INSTALL_MANDIR}/man8"
        COMPONENT yume_cli
    )
    set(CPACK_PACKAGE_NAME "yume")
    set(CPACK_PACKAGE_VENDOR "FixCraft")
    set(CPACK_PACKAGE_CONTACT "https://github.com/FixCraft-Inc/yume/issues")
    set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/FixCraft-Inc/yume")
    set(CPACK_PACKAGE_VERSION "${YUME_PACKAGE_VERSION}")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Post-quantum stealth transport client and server")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "yume")
    set(CPACK_COMPONENT_YUME_CLI_DISPLAY_NAME "YUME CLI and server")
    set(CPACK_COMPONENT_YUME_CLI_DESCRIPTION "YUME command-line client, yumed server daemon, man pages, and documentation.")
    set(CPACK_COMPONENTS_ALL yume_cli)
    if(UNIX AND NOT APPLE)
        set(CPACK_GENERATOR "TGZ;DEB")
        set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
        set(CPACK_DEBIAN_PACKAGE_SECTION "net")
        set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
        set(CPACK_DEBIAN_PACKAGE_MAINTAINER "FixCraft")
        # Generic EVP provider lookups do not carry a 3.5 symbol version, so
        # dpkg-shlibdeps cannot infer the ML-DSA runtime floor by itself.
        set(CPACK_DEBIAN_PACKAGE_DEPENDS "python3, openssl (>= 3.5.0)")
        if(NOT YUME_STATIC_OPENSSL)
            string(APPEND CPACK_DEBIAN_PACKAGE_DEPENDS ", libssl3t64 (>= 3.5.0)")
        endif()
        set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ${YUME_DEB_SHLIBDEPS})
        set(CPACK_DEBIAN_PACKAGE_DESCRIPTION
"YUME is an authenticated TLS 1.3 HTTP/2 transport with
hybrid post-quantum identity, directional session epochs, SOCKS TCP/UDP
and a native server daemon. Wider application migration is unfinished.")
    else()
        set(CPACK_GENERATOR "TGZ")
    endif()
    include(CPack)
endif()
