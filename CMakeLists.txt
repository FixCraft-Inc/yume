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
# CMP0091: MSVC runtime library selection via CMAKE_MSVC_RUNTIME_LIBRARY
# and the equivalent per-target property. Required for YUME_GUI_PORTABLE
# to switch the GUI to /MT(d) without affecting other targets.
if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()

option(YUME_BUILD_TRANSPORT_V2
    "Build the current transport-v2 yume/yumed product while YTP/1 reaches parity"
    ON)
option(YUME_USE_BASEFWX "Enable BaseFWX inner crypto support" ${YUME_BUILD_TRANSPORT_V2})
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
option(YUME_USE_SPDLOG "Enable spdlog logging backend" ${YUME_BUILD_TRANSPORT_V2})
option(YUME_USE_BUNDLED_NLOHMANN "Allow bundled nlohmann_json fallback" ON)
option(YUME_MINIMAL "Build for minimal systems (disable heavy deps/features)" OFF)
option(YUME_STATIC "Attempt static build (requires static deps)" OFF)
option(YUME_STATIC_OPENSSL
    "Link the pinned OpenSSL into YUME binaries so native Chrome TLS has no runtime libssl dependency"
    ${YUME_BUILD_TRANSPORT_V2})
option(YUME_NATIVE_OPT "Enable host-specific -march/-mtune=native CPU tuning; disables portable binaries" OFF)
option(YUME_LTO "Enable link-time optimization for yume builds" ON)
option(YUME_FAST_MATH "Enable fast-math (unsafe for crypto)" OFF)
option(YUME_TRANSPORT_CORE_ONLY "Build only the shared transport core target" OFF)
option(YUME_DEB_SHLIBDEPS "Use dpkg-shlibdeps when building Debian packages" ON)
option(YUME_BUILD_SELFTEST "Build optional localhost benchmark self-test tool for desktop developers" OFF)
option(YUME_BUILD_TESTING "Build optional YUME unit test executables" OFF)
# libFuzzer harnesses for the parsers an untrusted peer or file reaches.
# Clang-only and never installed; the corpora live outside the tree.
option(YUME_BUILD_FUZZERS "Build libFuzzer harnesses (requires Clang)" OFF)
option(YUME_BUILD_TOOLS "Build optional helper tools such as yume-net-map" OFF)
option(YUME_BUILD_SHARED_ABI
    "Build the experimental, uninstalled ABI v1 candidate and contract tests"
    OFF)
option(YUME_BUILD_EXPERIMENTAL_YTP1_OPENSSL_PROVIDER
    "Build the unqualified OpenSSL 3.5 YTP/1 session-security provider"
    OFF)
option(YUME_BUILD_EXPERIMENTAL_YTP1_TLS13_PROVIDER
    "Build the unqualified OpenSSL 3.5 YTP/1 TLS 1.3 secure-channel provider"
    OFF)
option(YUME_BUILD_EXPERIMENTAL_YTP1_ASIO_ROUTE_PROVIDER
    "Build the unqualified Boost.Asio YTP/1 direct TCP/UDP route provider"
    OFF)
option(YUME_BUILD_EXPERIMENTAL_YTP1_ASIO_TCP_BYTE_CHANNEL_PROVIDER
    "Build the unqualified client TCP ByteChannel provider for YTP/1"
    OFF)
option(YUME_BUILD_EXPERIMENTAL_YTP1_H2_CARRIER
    "Build the unqualified libnghttp2 YTP/1 duplex carrier provider"
    OFF)
option(YUME_INSTALL_EXPERIMENTAL_YTP1_TOOLS
    "Install the schema-1 YTP/1 setup and doctor previews (not usable with transport-v2)"
    OFF)
option(YUME_ABI_CLIENT_ONLY
    "Trim the current transport-v2 graph to its client-only sources"
    OFF)

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
# counters, handlers, event strings, or environment-variable activation path.
#
# This now includes clocks. The stream-lifecycle sites that used to call
# util::now_ms() unconditionally - feeding a YUME_TIMING_LOG that compiled away,
# so the read happened and the result was discarded - go through
# diagnostics::timing_now_ms() / diagnostics::elapsed_ms_since(), which are
# constexpr 0 when YUME_ENABLE_DEV_DIAGNOSTICS is 0 and read no clock even in a
# diagnostics build until collection is switched on. Verified by symbol: no
# Release session or proxy object references yume::util::now_ms().
# tests/test_release_diagnostics_cost.py guards it.
#
# Two gates, deliberately: this build-time switch decides whether the code
# exists at all, and --timing / YUME_TIMING decides whether an instrumented
# build collects. Neither costs a normal user anything.
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
if(YUME_BUILD_SELFTEST AND NOT CMAKE_CONFIGURATION_TYPES AND CMAKE_BUILD_TYPE MATCHES "^[Dd]ebug$")
    message(WARNING "YUME_BUILD_SELFTEST=ON with CMAKE_BUILD_TYPE=Debug will produce misleading throughput numbers")
endif()

# Dangerous-feature build gates. Each gate must be explicitly turned ON at
# configure time to compile the feature. The runtime CLI flag and the per-key
# meta entry are the second and third locks. Stock builds ship with all three
# OFF; the corresponding flags are still recognised but warn and stay disabled.
option(YUME_FEATURE_EXEC "Compile in server-side command execution path" OFF)
option(YUME_FEATURE_LAN_BRIDGE "Compile in LAN/private-IP bridging path" OFF)
option(YUME_FEATURE_FULL_CONTROL "Compile in unrestricted address bridging" OFF)

# Optional GUI build (Dear ImGui + GLFW + ImPlot). Disabled by default so
# stock builds and minimal/embedded builds remain unaffected.
option(YUME_BUILD_GUI "Build the optional Dear ImGui-based yume-gui desktop app" OFF)

# Optional Linux desktop comparison helper. Normal runtime uses the in-process
# openssl-chrome151 backend and does not discover or require this executable.
# Enabling the comparison backend requires the exact reviewed Go toolchain
# rather than silently using another compiler or downloading one through Go's
# toolchain selection.
option(YUME_BUILD_CHROME_TLS_HELPER
    "Build the pinned Chrome 151 uTLS helper with Go 1.26.5" OFF)

# Portable static GUI: link libgcc/libstdc++ statically on g++/clang, and
# the static MSVC runtime on Windows so the binary runs without a
# matching redistributable. Does NOT, on its own, make every transitive
# dep static — that still needs the underlying packages (OpenSSL, Boost,
# liboqs) to be present in static form on the host (use the vcpkg
# x64-windows-static triplet, or build static OpenSSL on Linux).
option(YUME_GUI_PORTABLE "Statically link the C/C++ runtime into yume-gui" OFF)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/src/core/version.hpp" _yume_version_line
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
if(YUME_ABI_CLIENT_ONLY AND NOT YUME_BUILD_TRANSPORT_V2)
    message(FATAL_ERROR
        "YUME_ABI_CLIENT_ONLY is available only with YUME_BUILD_TRANSPORT_V2=ON")
endif()
if(NOT YUME_BUILD_TRANSPORT_V2 AND
   (YUME_TRANSPORT_CORE_ONLY OR YUME_BUILD_GUI OR
    YUME_BUILD_CHROME_TLS_HELPER OR YUME_BUILD_SELFTEST OR YUME_BUILD_TOOLS))
    message(FATAL_ERROR
        "A transport-v2 build option was enabled while "
        "YUME_BUILD_TRANSPORT_V2=OFF. The YTP/1 foundation-only graph does "
        "not build yume, yumed, the facade, GUI, helper, or benchmark tools.")
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

# The fuzz harnesses carry their own instrumentation rather than going through
# YUME_SANITIZE, so they miss the forcing below. They need it for the same
# reason: LTO rewrites across the boundaries the instrumentation reports
# against, and under Clang it also leaves every archive as bitcode that a
# non-IPO target cannot link.
if(YUME_BUILD_FUZZERS)
    set(YUME_LTO OFF CACHE BOOL "Enable link-time optimization for yume builds" FORCE)
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

if((YUME_BUILD_EXPERIMENTAL_YTP1_OPENSSL_PROVIDER OR
    YUME_BUILD_EXPERIMENTAL_YTP1_TLS13_PROVIDER) AND
   NOT (YUME_BUILD_TRANSPORT_V2 AND NOT YUME_TRANSPORT_CORE_ONLY) AND
   NOT TARGET OpenSSL::Crypto)
    # These providers use upstream OpenSSL 3.5 APIs. They are intentionally
    # independent of the patched TLS emitter required by the runnable
    # transport-v2 product and remain explicit build-tree opt-ins.
    find_package(OpenSSL 3.5 REQUIRED)
endif()

if((YUME_BUILD_EXPERIMENTAL_YTP1_ASIO_ROUTE_PROVIDER OR
    YUME_BUILD_EXPERIMENTAL_YTP1_ASIO_TCP_BYTE_CHANNEL_PROVIDER) AND
   NOT TARGET Boost::system)
    find_package(Boost CONFIG QUIET COMPONENTS system)
    if(NOT Boost_FOUND)
        find_package(Boost REQUIRED COMPONENTS system)
    endif()
endif()

if(YUME_BUILD_EXPERIMENTAL_YTP1_H2_CARRIER)
    find_package(PkgConfig REQUIRED)
    if(NOT TARGET PkgConfig::NGHTTP2)
        pkg_check_modules(NGHTTP2 REQUIRED IMPORTED_TARGET libnghttp2>=1.64)
    endif()
    set(YUME_NGHTTP2_TARGET PkgConfig::NGHTTP2)
    if(NOT TARGET OpenSSL::Crypto)
        find_package(OpenSSL 3.5 REQUIRED)
    endif()
endif()

if(YUME_BUILD_TRANSPORT_V2 AND NOT YUME_TRANSPORT_CORE_ONLY)
    # Composite AUTH depends on primitives first provided by OpenSSL 3.5
    # (ML-DSA and X25519MLKEM768), while the default native TLS emitter also
    # requires YUME's additive ClientHello patch.
    if(YUME_STATIC_OPENSSL)
        # The pinned source install exports compression and system libraries
        # on its static targets; CMake's generic FindOpenSSL module does not
        # reliably carry Brotli/Zstd through a static link.
        find_package(OpenSSL 3.5 REQUIRED CONFIG)
    else()
        find_package(OpenSSL 3.5 REQUIRED)
    endif()
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
            "configuring CMake. Stock libssl is not accepted for a normal build.")
    endif()
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
        pkg_check_modules(NGHTTP2 REQUIRED IMPORTED_TARGET libnghttp2>=1.64)
        set(YUME_NGHTTP2_TARGET PkgConfig::NGHTTP2)
    endif()
    find_package(Boost CONFIG QUIET COMPONENTS system)
    if(NOT Boost_FOUND)
        find_package(Boost REQUIRED COMPONENTS system)
    endif()
    find_package(Threads REQUIRED)
endif()

if(YUME_BUILD_TRANSPORT_V2 AND YUME_MINIMAL)
    set(YUME_USE_BASEFWX ON CACHE BOOL "Enable BaseFWX for minimal builds" FORCE)
    set(YUME_USE_SPDLOG OFF CACHE BOOL "Disable spdlog for minimal builds" FORCE)
endif()


# ----------------------------------------------------------------------
# liboqs — YUME's own dependency edge
# ----------------------------------------------------------------------
# src/core/security/inner_crypto.cpp calls OQS_KEM_new/OQS_KEM_keypair
# directly and src/core/release/version_report.cpp reads OQS_VERSION_TEXT.
# That is YUME's own code implementing a YUME protocol decision, so it must
# not be gated on BaseFWX's BASEFWX_HAS_OQS build macro nor reach the headers
# only through basefwxcpp's PUBLIC link interface. Both projects may link
# liboqs; neither is hostage to the other's configuration, and the liboqs row
# in config/dependencies.json now has build meaning on this side too.
#
# Discovery deliberately honours the same cache variables the existing build
# scripts already pass to BaseFWX (ezbuild.sh, fullau.sh, the vcpkg and
# vendored cross prefixes), so no build script changes to keep working:
#   1. YUME_OQS_ROOT                (explicit prefix, YUME-owned)
#   2. OQS_INCLUDE_DIR/OQS_LIBRARY  (explicit paths; what ezbuild.sh passes)
#   3. BASEFWX_VENDOR_DIR           (vendored cross prefixes)
#   4. vcpkg installed triplet
#   5. liboqs CMake config package
#   6. pkg-config liboqs
#   7. plain find_path/find_library
if(YUME_BUILD_TRANSPORT_V2)
    option(YUME_REQUIRE_OQS
        "Fail configuration when liboqs is not found for YUME's ML-KEM code"
        OFF)
    set(YUME_OQS_ROOT "" CACHE PATH
        "Prefix holding include/oqs/oqs.h and lib/liboqs.{a,so,dylib,dll.a}")

    set(_yume_oqs_include "")
    set(_yume_oqs_libraries "")

    # A fully static link must not be handed a .so; resolve the archive first
    # so a static request either configures truthfully or falls through.
    if(YUME_STATIC)
        set(_yume_oqs_libnames liboqs.a liboqs.dll.a liboqs.so liboqs.dylib)
    else()
        set(_yume_oqs_libnames liboqs.so liboqs.dylib liboqs.a liboqs.dll.a)
    endif()
    set(_yume_oqs_libdirs
        "lib"
        "lib/${CMAKE_LIBRARY_ARCHITECTURE}"
        "lib64"
    )

    # (2) Explicit paths win over every search. These are the variables the
    # cross/vcpkg branches of ezbuild.sh and fullau.sh already set.
    if(OQS_INCLUDE_DIR AND OQS_LIBRARY AND
       EXISTS "${OQS_INCLUDE_DIR}/oqs/oqs.h" AND EXISTS "${OQS_LIBRARY}")
        set(_yume_oqs_include "${OQS_INCLUDE_DIR}")
        set(_yume_oqs_libraries "${OQS_LIBRARY}")
    endif()

    # (1), (3), (4): prefix-shaped installs.
    if(NOT _yume_oqs_include)
        set(_yume_oqs_prefixes "")
        if(YUME_OQS_ROOT)
            list(APPEND _yume_oqs_prefixes "${YUME_OQS_ROOT}")
        endif()
        if(BASEFWX_VENDOR_DIR)
            list(APPEND _yume_oqs_prefixes "${BASEFWX_VENDOR_DIR}")
        endif()
        if(VCPKG_INSTALLED_DIR AND VCPKG_TARGET_TRIPLET)
            list(APPEND _yume_oqs_prefixes
                "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
        endif()
        foreach(_yume_oqs_prefix IN LISTS _yume_oqs_prefixes)
            if(_yume_oqs_include)
                break()
            endif()
            if(NOT EXISTS "${_yume_oqs_prefix}/include/oqs/oqs.h")
                continue()
            endif()
            foreach(_yume_oqs_libdir IN LISTS _yume_oqs_libdirs)
                foreach(_yume_oqs_libname IN LISTS _yume_oqs_libnames)
                    set(_yume_oqs_candidate
                        "${_yume_oqs_prefix}/${_yume_oqs_libdir}/${_yume_oqs_libname}")
                    if(NOT _yume_oqs_libraries AND EXISTS "${_yume_oqs_candidate}")
                        set(_yume_oqs_include "${_yume_oqs_prefix}/include")
                        set(_yume_oqs_libraries "${_yume_oqs_candidate}")
                    endif()
                endforeach()
            endforeach()
        endforeach()
    endif()

    # (5) Upstream liboqs installs a CMake config package exporting OQS::oqs.
    if(NOT _yume_oqs_include)
        find_package(liboqs CONFIG QUIET)
        if(liboqs_FOUND AND TARGET OQS::oqs)
            set(_yume_oqs_libraries OQS::oqs)
            set(_yume_oqs_include "")
            set(_yume_oqs_via_config ON)
        endif()
    endif()

    # (6) pkg-config, then (7) the plain search. Neither is meaningful when
    # cross-compiling, where an explicit prefix is mandatory.
    if(NOT _yume_oqs_libraries AND NOT CMAKE_CROSSCOMPILING)
        find_package(PkgConfig QUIET)
        if(PKG_CONFIG_FOUND)
            pkg_check_modules(YUME_OQS_PC QUIET liboqs)
        endif()
        if(YUME_OQS_PC_FOUND)
            set(_yume_oqs_include "${YUME_OQS_PC_INCLUDE_DIRS}")
            # -loqs with a bare -L is not usable on a static link and not
            # reliable when several prefixes are installed; resolve it.
            set(_yume_saved_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
            if(YUME_STATIC)
                set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
            endif()
            find_library(YUME_OQS_LIBRARY
                NAMES oqs
                HINTS ${YUME_OQS_PC_LIBRARY_DIRS}
            )
            set(CMAKE_FIND_LIBRARY_SUFFIXES "${_yume_saved_suffixes}")
            unset(_yume_saved_suffixes)
            if(YUME_OQS_LIBRARY)
                set(_yume_oqs_libraries "${YUME_OQS_LIBRARY}")
            else()
                set(_yume_oqs_include "")
            endif()
        endif()
    endif()

    if(NOT _yume_oqs_libraries AND NOT CMAKE_CROSSCOMPILING)
        set(_yume_saved_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
        if(YUME_STATIC)
            set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
        endif()
        find_path(YUME_OQS_INCLUDE_DIR NAMES oqs/oqs.h)
        find_library(YUME_OQS_LIBRARY NAMES oqs)
        set(CMAKE_FIND_LIBRARY_SUFFIXES "${_yume_saved_suffixes}")
        unset(_yume_saved_suffixes)
        if(YUME_OQS_INCLUDE_DIR AND YUME_OQS_LIBRARY)
            set(_yume_oqs_include "${YUME_OQS_INCLUDE_DIR}")
            set(_yume_oqs_libraries "${YUME_OQS_LIBRARY}")
        endif()
    endif()

    # A prefix that merely has the header is not enough: YUME's inner crypto
    # needs the ML-KEM-768 identifier. Compile-only so cross builds can be
    # validated without running the target.
    if(_yume_oqs_libraries)
        include(CheckCXXSourceCompiles)
        set(_yume_saved_required_includes "${CMAKE_REQUIRED_INCLUDES}")
        set(_yume_saved_required_libraries "${CMAKE_REQUIRED_LIBRARIES}")
        if(_yume_oqs_include)
            set(CMAKE_REQUIRED_INCLUDES "${_yume_oqs_include}")
        endif()
        if(_yume_oqs_via_config)
            set(CMAKE_REQUIRED_LIBRARIES OQS::oqs)
        endif()
        unset(YUME_OQS_HAS_ML_KEM_768 CACHE)
        check_cxx_source_compiles([=[
            #include <oqs/oqs.h>
            int main() {
                const char* name = OQS_KEM_alg_ml_kem_768;
                return name == nullptr;
            }
        ]=] YUME_OQS_HAS_ML_KEM_768)
        set(CMAKE_REQUIRED_INCLUDES "${_yume_saved_required_includes}")
        set(CMAKE_REQUIRED_LIBRARIES "${_yume_saved_required_libraries}")
        unset(_yume_saved_required_includes)
        unset(_yume_saved_required_libraries)
        if(NOT YUME_OQS_HAS_ML_KEM_768)
            message(STATUS
                "YUME: liboqs found but it does not expose ML-KEM-768; "
                "treating PQ keypair generation as unavailable")
            set(_yume_oqs_libraries "")
            set(_yume_oqs_include "")
        endif()
    endif()

    if(_yume_oqs_libraries)
        add_library(yume_liboqs INTERFACE)
        if(_yume_oqs_include)
            target_include_directories(yume_liboqs INTERFACE "${_yume_oqs_include}")
        endif()
        target_link_libraries(yume_liboqs INTERFACE ${_yume_oqs_libraries})
        message(STATUS "YUME: liboqs -> ${_yume_oqs_libraries}")
    elseif(YUME_REQUIRE_OQS)
        message(FATAL_ERROR
            "YUME_REQUIRE_OQS is ON but liboqs was not found. Pass "
            "-DYUME_OQS_ROOT=<prefix>, or -DOQS_INCLUDE_DIR=/-DOQS_LIBRARY=, "
            "or install liboqs >= 0.16.0 (see config/dependencies.json).")
    else()
        message(STATUS
            "YUME: liboqs not found; ML-KEM keypair generation will report "
            "itself unavailable at runtime")
    endif()

    unset(_yume_oqs_include)
    unset(_yume_oqs_libraries)
    unset(_yume_oqs_libnames)
    unset(_yume_oqs_libdirs)
    unset(_yume_oqs_prefixes)
    unset(_yume_oqs_via_config)
endif()

if(YUME_BUILD_TRANSPORT_V2 AND YUME_USE_BASEFWX)
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

# Schema-1 provisioning currently targets the unwired YTP/1 provider graph,
# not the runnable transport-v2 binaries. Keep the tools available for focused
# development without placing a nonfunctional quick start in normal installs.
if(YUME_INSTALL_EXPERIMENTAL_YTP1_TOOLS)
    install(PROGRAMS tools/yume_setup_ytp1.py
        DESTINATION "${CMAKE_INSTALL_BINDIR}"
        RENAME yume-setup-ytp1
        COMPONENT ytp1_experimental
    )
    install(PROGRAMS tools/yume_doctor_ytp1.py
        DESTINATION "${CMAKE_INSTALL_BINDIR}"
        RENAME yume-doctor-ytp1
        COMPONENT ytp1_experimental
    )
    install(FILES
        config/ytp1/yume.json
        config/ytp1/yumed.json
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/doc/yume/examples/ytp1"
        COMPONENT ytp1_experimental
    )
endif()

if(YUME_BUILD_TRANSPORT_V2 AND NOT YUME_TRANSPORT_CORE_ONLY)
    set(YUME_DOC_INSTALL_DIR "${CMAKE_INSTALL_DATAROOTDIR}/doc/yume")

    # Keep the runnable transport-v2 product provisionable while the schema-1
    # setup tool targets an experimental provider graph with no live endpoint.
    install(PROGRAMS tools/yume_setup_transport_v2.py
        DESTINATION "${CMAKE_INSTALL_BINDIR}"
        RENAME yume-setup
        COMPONENT yume_cli
    )

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
        config/security-ultimate.example.json
        config/yume.json
        config/yumed.json
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
    install(PROGRAMS tools/yume_packet_quick.py
        DESTINATION "${CMAKE_INSTALL_BINDIR}"
        RENAME yume-packet-quick
        COMPONENT yume_cli
    )
    install(FILES tools/cover-node/backend.mjs
        DESTINATION "${CMAKE_INSTALL_DATADIR}/yume/cover-node"
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
    if(YUME_BUILD_GUI)
        install(FILES docs/man/yume-gui.1
            DESTINATION "${CMAKE_INSTALL_MANDIR}/man1"
            COMPONENT yume_gui
        )
    endif()
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
    set(CPACK_COMPONENT_YUME_GUI_DISPLAY_NAME "YUME desktop GUI")
    set(CPACK_COMPONENT_YUME_GUI_DESCRIPTION "Optional desktop GUI for YUME.")
    set(CPACK_COMPONENTS_ALL yume_cli)
    if(YUME_BUILD_GUI)
        list(APPEND CPACK_COMPONENTS_ALL yume_gui)
        set(CPACK_COMPONENT_YUME_GUI_DEPENDS yume_cli)
    endif()
    if(UNIX AND NOT APPLE)
        set(CPACK_GENERATOR "TGZ;DEB")
        set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
        set(CPACK_DEBIAN_PACKAGE_SECTION "net")
        set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
        set(CPACK_DEBIAN_PACKAGE_MAINTAINER "FixCraft")
        # Generic EVP provider lookups do not carry a 3.5 symbol version, so
        # dpkg-shlibdeps cannot infer the ML-DSA runtime floor by itself.
        set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl3t64 (>= 3.5.0)")
        set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ${YUME_DEB_SHLIBDEPS})
        set(CPACK_DEBIAN_PACKAGE_DESCRIPTION
"YUME is an authenticated TLS 1.3 HTTP/2/WebSocket transport with
hybrid post-quantum identity, forward-secure session ratchets, SOCKS,
forwarding, relay, and server daemon modes.")
    else()
        set(CPACK_GENERATOR "TGZ")
    endif()
    include(CPack)
endif()
