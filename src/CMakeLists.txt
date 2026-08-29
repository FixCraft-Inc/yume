# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
include(FetchContent)

set(_nlohmann_vendor_candidates
    "${CMAKE_SOURCE_DIR}/third_party/nlohmann_json"
    "${CMAKE_CURRENT_LIST_DIR}/../third_party/nlohmann_json"
)
if(YUME_USE_BUNDLED_NLOHMANN)
    foreach(_nlohmann_vendor IN LISTS _nlohmann_vendor_candidates)
        if(EXISTS "${_nlohmann_vendor}/nlohmann/json.hpp" AND NOT TARGET nlohmann_json::nlohmann_json)
            add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
            target_include_directories(nlohmann_json::nlohmann_json INTERFACE "${_nlohmann_vendor}")
            set(nlohmann_json_FOUND TRUE)
            break()
        endif()
    endforeach()
endif()

if(NOT nlohmann_json_FOUND)
    find_package(nlohmann_json QUIET)
endif()
if(NOT nlohmann_json_FOUND)
    if(YUME_OFFLINE)
        message(FATAL_ERROR "nlohmann_json not found; set YUME_OFFLINE=OFF or provide ${_nlohmann_vendor}")
    endif()
    message(STATUS "nlohmann_json not found, fetching...")
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# zstd can be provided either via a config package (commonly exports zstd::libzstd)
# or via a FindZSTD module (often only sets variables). Try config first.
find_package(zstd CONFIG QUIET)
if(NOT TARGET zstd::libzstd AND NOT TARGET zstd::libzstd_shared AND NOT TARGET zstd::libzstd_static)
    find_package(ZSTD QUIET)
endif()
if(CMAKE_CROSSCOMPILING AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    find_library(ATOMIC_LIBRARY atomic)
endif()

function(yume_link_atomic_if_needed target scope)
    if(CMAKE_CROSSCOMPILING AND ATOMIC_LIBRARY AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_libraries(${target} ${scope} ${ATOMIC_LIBRARY})
    endif()
endfunction()

set(YUME_SPDLOG_TARGET "")
if(YUME_USE_SPDLOG)
    set(_fmt_vendor_candidates
        "${CMAKE_SOURCE_DIR}/third_party/fmt/include"
        "${CMAKE_CURRENT_LIST_DIR}/../third_party/fmt/include"
        "/usr/include"
    )
    set(_spdlog_vendor_candidates
        "${CMAKE_SOURCE_DIR}/third_party/spdlog/include"
        "${CMAKE_CURRENT_LIST_DIR}/../third_party/spdlog/include"
        "/usr/include"
    )
    foreach(_spdlog_vendor IN LISTS _spdlog_vendor_candidates)
        if(EXISTS "${_spdlog_vendor}/spdlog/spdlog.h")
            if(NOT TARGET spdlog::spdlog_header_only)
                add_library(spdlog::spdlog_header_only INTERFACE IMPORTED)
                target_include_directories(spdlog::spdlog_header_only INTERFACE "${_spdlog_vendor}")
                if(EXISTS "${_spdlog_vendor}/spdlog/tweakme.h")
                    file(READ "${_spdlog_vendor}/spdlog/tweakme.h" _spdlog_tweakme)
                    if(_spdlog_tweakme MATCHES "#define[ \t]+SPDLOG_FMT_EXTERNAL[ \t]+1")
                        foreach(_fmt_vendor IN LISTS _fmt_vendor_candidates)
                            if(EXISTS "${_fmt_vendor}/fmt/format.h")
                                if(NOT TARGET fmt::fmt-header-only)
                                    add_library(fmt::fmt-header-only INTERFACE IMPORTED)
                                    target_include_directories(fmt::fmt-header-only INTERFACE "${_fmt_vendor}")
                                    target_compile_definitions(fmt::fmt-header-only INTERFACE FMT_HEADER_ONLY=1)
                                endif()
                                target_link_libraries(spdlog::spdlog_header_only INTERFACE fmt::fmt-header-only)
                                break()
                            endif()
                        endforeach()
                    endif()
                endif()
            endif()
            set(spdlog_FOUND TRUE)
            set(YUME_SPDLOG_TARGET spdlog::spdlog_header_only)
            break()
        endif()
    endforeach()
    if(NOT spdlog_FOUND)
        find_package(spdlog QUIET)
    endif()
    if(NOT spdlog_FOUND)
        message(STATUS "spdlog not found, fetching...")
        FetchContent_Declare(
            spdlog
            GIT_REPOSITORY https://github.com/gabime/spdlog.git
            GIT_TAG v1.14.1
        )
        FetchContent_MakeAvailable(spdlog)
    endif()
    if(YUME_SPDLOG_TARGET STREQUAL "")
        if(TARGET spdlog::spdlog_header_only)
            set(YUME_SPDLOG_TARGET spdlog::spdlog_header_only)
        elseif(TARGET spdlog::spdlog)
            set(YUME_SPDLOG_TARGET spdlog::spdlog)
        endif()
    endif()
endif()

# The project warning set, applied to first-party targets only.
#
# Bundled dependencies (basefwx, imgui, implot, nlohmann, spdlog) are built as
# their own targets and never call this, so a warning here is always about code
# this tree owns and can fix.
#
# Deliberately not enabled yet, because each needs a dedicated cleanup pass
# rather than a blanket suppression: -Wconversion, -Wsign-conversion, -Wshadow,
# -Wcast-qual, -Wold-style-cast.
function(yume_apply_warnings target)
    # Record every target that went through here, so the audit at the bottom
    # of this file can prove none were missed. This is not bookkeeping for its
    # own sake: yume_abi, yume_abi_test and yume_secure_materials_test each
    # silently escaped the warning set once, and yume_abi is the single file
    # in the tree where warnings matter most.
    set_property(GLOBAL APPEND PROPERTY YUME_WARNED_TARGETS "${target}")
    if(NOT YUME_WARNINGS)
        return()
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            -Wall
            -Wextra
            # Attacker-influenced format strings and stack sizes are the two
            # cheapest memory-safety mistakes to make in this codebase.
            -Wformat-security
            -Wvla
            $<$<COMPILE_LANGUAGE:CXX>:-Wnon-virtual-dtor>
            $<$<BOOL:${YUME_WARNINGS_AS_ERRORS}>:-Werror>
        )
    elseif(MSVC)
        target_compile_options(${target} PRIVATE
            /W4
            $<$<COMPILE_LANGUAGE:CXX>:/permissive->
            $<$<BOOL:${YUME_WARNINGS_AS_ERRORS}>:/WX>
        )
    endif()
endfunction()

# Single per-target hook. Every first-party target already calls this, so
# warnings ride along with the optimisation settings instead of needing a
# second call site added to ~50 targets.
function(yume_apply_perf_opts target)
    yume_apply_warnings(${target})
    get_target_property(_yume_shared_abi_input
        ${target} YUME_SHARED_ABI_INPUT)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            $<$<CXX_COMPILER_ID:GNU>:-Wno-psabi>
            $<$<CONFIG:Release>:-O3>
            $<$<CONFIG:RelWithDebInfo>:-O3>
            $<$<CONFIG:MinSizeRel>:-O3>
            $<$<CONFIG:Release>:-fomit-frame-pointer>
            $<$<CONFIG:RelWithDebInfo>:-fomit-frame-pointer>
            $<$<CONFIG:MinSizeRel>:-fomit-frame-pointer>
            $<$<CONFIG:Release>:-funroll-loops>
            $<$<CONFIG:RelWithDebInfo>:-funroll-loops>
            $<$<CONFIG:MinSizeRel>:-funroll-loops>
            $<$<CONFIG:Release>:-finline-functions>
            $<$<CONFIG:RelWithDebInfo>:-finline-functions>
            $<$<CONFIG:MinSizeRel>:-finline-functions>
        )
        if(YUME_NATIVE_OPT)
            target_compile_options(${target} PRIVATE
                $<$<CONFIG:Release>:-march=native>
                $<$<CONFIG:RelWithDebInfo>:-march=native>
                $<$<CONFIG:MinSizeRel>:-march=native>
                $<$<CONFIG:Release>:-mtune=native>
                $<$<CONFIG:RelWithDebInfo>:-mtune=native>
                $<$<CONFIG:MinSizeRel>:-mtune=native>
            )
        endif()
        if(YUME_FAST_MATH)
            target_compile_options(${target} PRIVATE
                $<$<CONFIG:Release>:-ffast-math>
                $<$<CONFIG:RelWithDebInfo>:-ffast-math>
                $<$<CONFIG:MinSizeRel>:-ffast-math>
            )
        endif()
        if(YUME_LTO AND NOT _yume_shared_abi_input)
            # GCC's plain -flto defaults to serial LTRANS partitions unless
            # invoked through a make jobserver. Ninja therefore emits
            # lto-wrapper warnings and leaves cores idle at the most expensive
            # link step. `auto` lets GCC select parallel partitions itself.
            # Clang has no `auto` spelling; its existing -flto behavior stays
            # unchanged.
            if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
                set(_yume_lto_flag -flto=auto)
            else()
                set(_yume_lto_flag -flto)
            endif()
            target_compile_options(${target} PRIVATE
                $<$<CONFIG:Release>:${_yume_lto_flag}>
                $<$<CONFIG:RelWithDebInfo>:${_yume_lto_flag}>
                $<$<CONFIG:MinSizeRel>:${_yume_lto_flag}>
            )
            target_link_options(${target} PRIVATE
                $<$<CONFIG:Release>:${_yume_lto_flag}>
                $<$<CONFIG:RelWithDebInfo>:${_yume_lto_flag}>
                $<$<CONFIG:MinSizeRel>:${_yume_lto_flag}>
            )
        endif()
    elseif(MSVC)
        target_compile_options(${target} PRIVATE
            $<$<CONFIG:Release>:/O2>
            $<$<CONFIG:RelWithDebInfo>:/O2>
            $<$<CONFIG:MinSizeRel>:/O2>
            $<$<CONFIG:Release>:/Oi>
            $<$<CONFIG:RelWithDebInfo>:/Oi>
            $<$<CONFIG:MinSizeRel>:/Oi>
            $<$<CONFIG:Release>:/Ot>
            $<$<CONFIG:RelWithDebInfo>:/Ot>
            $<$<CONFIG:MinSizeRel>:/Ot>
            $<$<CONFIG:Release>:/Oy>
            $<$<CONFIG:RelWithDebInfo>:/Oy>
            $<$<CONFIG:MinSizeRel>:/Oy>
        )
        if(YUME_FAST_MATH)
            target_compile_options(${target} PRIVATE
                $<$<CONFIG:Release>:/fp:fast>
                $<$<CONFIG:RelWithDebInfo>:/fp:fast>
                $<$<CONFIG:MinSizeRel>:/fp:fast>
            )
        endif()
        if(YUME_LTO AND NOT _yume_shared_abi_input)
            target_compile_options(${target} PRIVATE
                $<$<CONFIG:Release>:/GL>
                $<$<CONFIG:RelWithDebInfo>:/GL>
                $<$<CONFIG:MinSizeRel>:/GL>
            )
            target_link_options(${target} PRIVATE
                $<$<CONFIG:Release>:/LTCG>
                $<$<CONFIG:RelWithDebInfo>:/LTCG>
                $<$<CONFIG:MinSizeRel>:/LTCG>
            )
        endif()
    endif()
endfunction()

function(yume_apply_dev_diagnostics target visibility)
    target_compile_definitions(${target} ${visibility}
        YUME_ENABLE_DEV_DIAGNOSTICS=${YUME_DEV_DIAGNOSTICS_EXPRESSION})
endfunction()

# Optional developer-only precompiled header. Measured on this tree with GCC:
# <boost/asio.hpp> costs about 1.8 s and <nlohmann/json.hpp> about 1.0 s of
# front-end time *per translation unit*, and roughly 90 TUs pull one or both.
# Only third-party headers are listed. CMake builds a separate PCH for each
# target using that target's compile definitions; no YUME header is frozen into
# the developer cache.
#
# PRIVATE on purpose: a PCH must never leak into consumers. Never enabled in
# CI, release, sanitizer, or shared-ABI lanes (see YUME_PCH in the root file).
function(yume_apply_pch target)
    if(NOT YUME_PCH)
        return()
    endif()
    target_precompile_headers(${target} PRIVATE
        <boost/asio.hpp>
        <boost/asio/ssl.hpp>
        <nlohmann/json.hpp>
    )
endfunction()

if(YUME_STATIC AND YUME_USE_SPDLOG AND NOT YUME_SPDLOG_TARGET STREQUAL "spdlog::spdlog_header_only")
    message(WARNING "Static link requested but only compiled spdlog was found; disabling spdlog.")
    set(YUME_USE_SPDLOG OFF CACHE BOOL "Disable spdlog for static builds" FORCE)
endif()

# ----------------------------------------------------------------------
# Shared protocol/security core
# ----------------------------------------------------------------------
# These eight sources are needed by both the full yume_core and the reduced
# yume_transport_core (the mobile/ABI slice). They used to be listed in both
# targets, so every full build compiled them twice and both archives defined
# the same symbols - harmless for ordinary static resolution, but a real
# duplicate-symbol hazard on the --whole-archive shared-ABI path, where
# yume_server and yume_client_lib link *both* libraries.
#
# They depend only on BaseFWX (plus advapi32 on Windows for the protected-file
# DACL). Deliberately no OpenSSL/Boost/nlohmann/spdlog here: keeping the link
# interface this narrow is what lets the transport-only slice stay small.
add_library(yume_secure_core STATIC
    core/security/inner_crypto.cpp
    core/security/auth_v2.cpp
    core/security/ratchet.cpp
    core/security/session_ratchet.cpp
    core/security/secret_file.cpp
    core/protocol/protocol.cpp
    core/protocol/packet_bulk.cpp
    core/runtime/system_profile.cpp
)

target_include_directories(yume_secure_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
yume_apply_dev_diagnostics(yume_secure_core PUBLIC)

if(TARGET basefwxcpp)
    target_link_libraries(yume_secure_core PUBLIC basefwxcpp)
    target_compile_definitions(yume_secure_core PUBLIC YUME_USE_BASEFWX=1)
else()
    target_compile_definitions(yume_secure_core PUBLIC YUME_USE_BASEFWX=0)
endif()
if(WIN32)
    # ConvertStringSecurityDescriptorToSecurityDescriptorW, used by
    # secret_file.cpp to install its protected DACL at creation time.
    target_link_libraries(yume_secure_core PUBLIC advapi32)
endif()
yume_link_atomic_if_needed(yume_secure_core PUBLIC)
if(YUME_BUILD_SHARED_ABI)
    yume_prepare_static_for_shared_abi(yume_secure_core)
endif()
yume_apply_perf_opts(yume_secure_core)

if(NOT YUME_TRANSPORT_CORE_ONLY)
    set(YUME_GITHUB_CLIENT_SOURCE core/release/github_client.cpp)
    if(YUME_ABI_CLIENT_ONLY)
        # The public mobile ABI does not expose or invoke desktop update
        # checks. Keep Boost.Beast and outbound GitHub traffic out of that
        # runtime while preserving an honest unavailable result if shared
        # version-report code is reached indirectly.
        set(YUME_GITHUB_CLIENT_SOURCE core/release/github_client_disabled.cpp)
    endif()

    # Per-OS platform abstraction (src/platform/). Exactly one executable_*.cpp
    # is compiled per target; the rest are platform-specific and would not even
    # parse elsewhere. Add new os-split helpers (paths, daemonization, …) the
    # same way so the rest of the tree stays #ifdef-free.
    if(WIN32)
        set(YUME_PLATFORM_SOURCES platform/executable_windows.cpp)
    elseif(APPLE)
        set(YUME_PLATFORM_SOURCES platform/executable_macos.cpp)
    else()
        set(YUME_PLATFORM_SOURCES platform/executable_linux.cpp)
    endif()

    add_library(yume_core
        core/app_codec/codec.cpp
        core/app_codec/builtin/monero_rpc.cpp
        core/diagnostics/timing.cpp
        ${YUME_GITHUB_CLIENT_SOURCE}
        core/release/terminal.cpp
        core/release/version_report.cpp
        core/release/version_status.cpp
        core/protocol/control_protocol.cpp
        core/protocol/control_command_policy.cpp
        core/protocol/directory_policy.cpp
        core/protocol/relay_policy.cpp
        core/security/crypto.cpp
        core/security/channel_binding.cpp
        core/stealth/cover_profile.cpp
        core/stealth/http_profile.cpp
        core/stealth/h2_carrier.cpp
        core/stealth/h2_wire_profile.cpp
        core/stealth/outer_carrier_observer.cpp
        core/security/identity.cpp
        core/runtime/atomic_file.cpp
        core/runtime/file_transaction_lock.cpp
        core/runtime/local_runtime.cpp
        core/runtime/service_stream.cpp
        core/stealth/obfs.cpp
        core/stealth/obfs_h2.cpp
        core/stealth/obfs_signal.cpp
        core/stealth/websocket_codec.cpp
        core/stealth/tls_fingerprint.cpp
        core/stealth/tls_stealth.cpp
        core/stealth/tls_metrics.cpp
        util.cpp
        ${YUME_PLATFORM_SOURCES}
    )

    target_include_directories(yume_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    yume_apply_dev_diagnostics(yume_core PUBLIC)

    target_link_libraries(yume_core
        PUBLIC
            yume_secure_core
            OpenSSL::SSL
            OpenSSL::Crypto
            Threads::Threads
            nlohmann_json::nlohmann_json
            ${YUME_NGHTTP2_TARGET}
    )
    if(TARGET Boost::system)
        target_link_libraries(yume_core PUBLIC Boost::system)
    elseif(DEFINED Boost_SYSTEM_LIBRARY AND EXISTS "${Boost_SYSTEM_LIBRARY}")
        target_link_libraries(yume_core PUBLIC "${Boost_SYSTEM_LIBRARY}")
    else()
        target_compile_definitions(yume_core PUBLIC BOOST_ERROR_CODE_HEADER_ONLY=1)
    endif()
    if(TARGET Boost::headers)
        target_link_libraries(yume_core PUBLIC Boost::headers)
    elseif(TARGET Boost::asio)
        target_link_libraries(yume_core PUBLIC Boost::asio)
    elseif(TARGET Boost::boost)
        target_link_libraries(yume_core PUBLIC Boost::boost)
    elseif(Boost_INCLUDE_DIR)
        target_include_directories(yume_core PUBLIC ${Boost_INCLUDE_DIR})
    elseif(Boost_INCLUDE_DIRS)
        target_include_directories(yume_core PUBLIC ${Boost_INCLUDE_DIRS})
    endif()
    if(WIN32)
        target_link_libraries(yume_core PUBLIC ws2_32 mswsock advapi32)
        target_compile_definitions(yume_core PUBLIC
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            WINVER=0x0600
            _WIN32_WINNT=0x0600
        )
    endif()
    yume_link_atomic_if_needed(yume_core PUBLIC)

    if(NOT YUME_STATIC AND TARGET zstd::libzstd_shared)
        target_link_libraries(yume_core PUBLIC zstd::libzstd_shared)
    elseif(TARGET zstd::libzstd)
        target_link_libraries(yume_core PUBLIC zstd::libzstd)
    elseif(TARGET zstd::libzstd_static)
        target_link_libraries(yume_core PUBLIC zstd::libzstd_static)
    elseif(TARGET ZSTD::ZSTD)
        target_link_libraries(yume_core PUBLIC ZSTD::ZSTD)
    elseif(ZSTD_LIBRARY)
        target_link_libraries(yume_core PUBLIC ${ZSTD_LIBRARY})
        if(ZSTD_INCLUDE_DIR)
            target_include_directories(yume_core PUBLIC ${ZSTD_INCLUDE_DIR})
        elseif(ZSTD_INCLUDE_DIRS)
            target_include_directories(yume_core PUBLIC ${ZSTD_INCLUDE_DIRS})
        endif()
    elseif(ZSTD_LIBRARIES)
        target_link_libraries(yume_core PUBLIC ${ZSTD_LIBRARIES})
        if(ZSTD_INCLUDE_DIRS)
            target_include_directories(yume_core PUBLIC ${ZSTD_INCLUDE_DIRS})
        elseif(ZSTD_INCLUDE_DIR)
            target_include_directories(yume_core PUBLIC ${ZSTD_INCLUDE_DIR})
        endif()
    elseif(YUME_STATIC)
        message(WARNING "ZSTD not found; static OpenSSL builds may fail to link")
    endif()

    if(YUME_USE_SPDLOG)
        target_link_libraries(yume_core PUBLIC ${YUME_SPDLOG_TARGET})
        target_compile_definitions(yume_core PUBLIC YUME_USE_SPDLOG=1)
    else()
        target_compile_definitions(yume_core PUBLIC YUME_USE_SPDLOG=0)
    endif()

    if(YUME_USE_BASEFWX AND NOT TARGET basefwxcpp)
        message(FATAL_ERROR "YUME_USE_BASEFWX is ON but basefwxcpp target was not found")
    endif()

    if(TARGET basefwxcpp)
        target_link_libraries(yume_core PUBLIC basefwxcpp)
        target_compile_definitions(yume_core PUBLIC YUME_USE_BASEFWX=1)
    else()
        target_compile_definitions(yume_core PUBLIC YUME_USE_BASEFWX=0)
    endif()

    if(YUME_FEATURE_EXEC)
        target_compile_definitions(yume_core PUBLIC YUME_FEATURE_EXEC=1)
    else()
        target_compile_definitions(yume_core PUBLIC YUME_FEATURE_EXEC=0)
    endif()
    if(YUME_FEATURE_LAN_BRIDGE)
        target_compile_definitions(yume_core PUBLIC YUME_FEATURE_LAN_BRIDGE=1)
    else()
        target_compile_definitions(yume_core PUBLIC YUME_FEATURE_LAN_BRIDGE=0)
    endif()
    if(YUME_FEATURE_FULL_CONTROL)
        target_compile_definitions(yume_core PUBLIC YUME_FEATURE_FULL_CONTROL=1)
    else()
        target_compile_definitions(yume_core PUBLIC YUME_FEATURE_FULL_CONTROL=0)
    endif()

    if(CMAKE_CROSSCOMPILING OR YUME_FORCE_CROSS OR CMAKE_SYSTEM_NAME STREQUAL "Windows" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        get_target_property(_yume_includes yume_core INCLUDE_DIRECTORIES)
        if(_yume_includes)
            list(REMOVE_ITEM _yume_includes "/usr/include" "/usr/include/")
            set_target_properties(yume_core PROPERTIES INCLUDE_DIRECTORIES "${_yume_includes}")
        endif()
    endif()

    if(YUME_BUILD_SHARED_ABI)
        yume_prepare_static_for_shared_abi(yume_core)
    endif()

    yume_apply_perf_opts(yume_core)
    yume_apply_pch(yume_core)

endif()

add_library(yume_transport_core
    client/packet/engine.cpp
    client/transport/chrome_tls_protocol.cpp
    client/transport/core.cpp
    client/transport/write.cpp
    client/transport/dispatch.cpp
    client/transport/crypto.cpp
)

target_include_directories(yume_transport_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
yume_apply_dev_diagnostics(yume_transport_core PUBLIC)
target_link_libraries(yume_transport_core
    PUBLIC
        yume_secure_core
        nlohmann_json::nlohmann_json
)
if(YUME_USE_SPDLOG)
    target_link_libraries(yume_transport_core PUBLIC ${YUME_SPDLOG_TARGET})
    target_compile_definitions(yume_transport_core PUBLIC YUME_USE_SPDLOG=1)
else()
    target_compile_definitions(yume_transport_core PUBLIC YUME_USE_SPDLOG=0)
endif()
if(TARGET basefwxcpp)
    target_link_libraries(yume_transport_core PUBLIC basefwxcpp)
    target_compile_definitions(yume_transport_core PUBLIC YUME_USE_BASEFWX=1)
else()
    target_compile_definitions(yume_transport_core PUBLIC YUME_USE_BASEFWX=0)
endif()
if(WIN32)
    # The protected private-file writer that needs advapi32 now lives in
    # yume_secure_core, which links it PUBLIC. Kept here so the transport-only
    # slice keeps an explicit, self-describing Windows link line.
    target_link_libraries(yume_transport_core PUBLIC advapi32)
endif()
yume_link_atomic_if_needed(yume_transport_core PUBLIC)
if(YUME_BUILD_SHARED_ABI)
    yume_prepare_static_for_shared_abi(yume_transport_core)
endif()
yume_apply_perf_opts(yume_transport_core)
yume_apply_pch(yume_transport_core)

if(NOT YUME_TRANSPORT_CORE_ONLY)
    # ------------------------------------------------------------------
    # Shared outbound/federation transport
    # ------------------------------------------------------------------
    # Federation is a server feature, but it dials another yumed through the
    # same authenticated transport primitives used by the client.  Keep that
    # deliberately small common slice separate from yume_client_lib: linking
    # the full client library into yume_server used to pull CLI/runtime/share
    # code across the server boundary and also compiled outbound_proxy.cpp in
    # both archives.
    add_library(yume_outbound_transport STATIC
        client/transport/client_stream.cpp
        client/transport/tunnel.cpp
        client/proxy/forward.cpp
        client/proxy/outbound_proxy.cpp
        client/cli/connect/auth.cpp
    )
    target_include_directories(yume_outbound_transport
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(yume_outbound_transport
        PUBLIC yume_core yume_transport_core)
    if(YUME_BUILD_SHARED_ABI)
        yume_prepare_static_for_shared_abi(yume_outbound_transport)
    endif()
    yume_apply_perf_opts(yume_outbound_transport)
    yume_apply_pch(yume_outbound_transport)
    if(WIN32)
        target_link_libraries(yume_outbound_transport PUBLIC ws2_32 mswsock)
        target_compile_definitions(yume_outbound_transport PUBLIC
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            WINVER=0x0600
            _WIN32_WINNT=0x0600
        )
    endif()

    # ------------------------------------------------------------------
    # Server library
    # ------------------------------------------------------------------
    # Extracted so both the yumed executable and the optional yume_facade
    # library (consumed by yume-gui) can link a single source-of-truth
    # server implementation. The executable below contains only main().
    add_library(yume_server STATIC
        server/runtime/local_runtime.cpp
        server/federation/link.cpp
        server/federation/manager.cpp
        server/federation/topology.cpp
        server/federation/topology_render.cpp
        server/filter/ip_filter.cpp
        server/filter/ip_filter_mmdb.cpp
        server/host/host_types.cpp
        server/host/socket_util.cpp
        server/host/host_routes.cpp
        server/host/exposure_check.cpp
        server/host/http_proxy.cpp
        server/host/http_backend_client.cpp
        server/host/extra_listeners.cpp
        server/runtime/identity_admission.cpp
        server/runtime/weighted_egress_limiter.cpp
        server/runtime/admin_relationships.cpp
        server/runtime/manager.cpp
        server/runtime/manager_relay.cpp
        server/runtime/security_config.cpp
        server/packet/tun_egress.cpp
        server/auth/auth.cpp
        server/session/session.cpp
        server/session/control.cpp
        server/session/codecs.cpp
        server/session/services.cpp
        server/session/net.cpp
        server/session/carrier.cpp
        server/session/streams.cpp
        server/session/ext.cpp
        server/session/open.cpp
        server/session/open_transport.cpp
        server/session/reverse_listener.cpp
        server/session/auth.cpp
        server/session/authorization.cpp
        server/session/static_site.cpp
        server/session/http_masq.cpp
        server/runtime/controller.cpp
    )
    target_include_directories(yume_server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(yume_server PUBLIC yume_core yume_transport_core
        yume_outbound_transport)
    if(YUME_BUILD_SHARED_ABI)
        yume_prepare_static_for_shared_abi(yume_server)
    endif()
    yume_apply_perf_opts(yume_server)
    yume_apply_pch(yume_server)
    if(WIN32)
        target_link_libraries(yume_server PUBLIC ws2_32 mswsock)
        target_compile_definitions(yume_server PUBLIC
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            WINVER=0x0600
            _WIN32_WINNT=0x0600
        )
    endif()

    add_executable(yumed
        main_server.cpp
        server/cli/anonym.cpp
        server/cli/curl_json_transport.cpp
        server/cli/args.cpp
        server/cli/cluster.cpp
        server/cli/config_load.cpp
        server/cli/entry.cpp
        server/cli/key.cpp
        server/cli/local.cpp
        server/cli/misc.cpp
        server/cli/runtime_prep.cpp
        server/cli/startup_checks.cpp
        server/cli/help.cpp
    )
    target_link_libraries(yumed PRIVATE yume_server)
    yume_apply_perf_opts(yumed)
    if(YUME_STATIC AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_options(yumed PRIVATE -static)
    endif()
    if(WIN32)
        target_link_libraries(yumed PRIVATE ws2_32 mswsock)
        target_compile_definitions(yumed PRIVATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            WINVER=0x0600
            _WIN32_WINNT=0x0600
        )
    endif()

    if(YUME_BUILD_TESTING AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_executable(yume_anonym_curl_transport_test
            server/cli/curl_json_transport.cpp
            server/cli/curl_json_transport_test.cpp)
        target_include_directories(yume_anonym_curl_transport_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_libraries(yume_anonym_curl_transport_test PRIVATE yume_core)
        target_compile_definitions(yume_anonym_curl_transport_test PRIVATE
            YUME_CURL_TRANSPORT_TESTING=1)
        yume_apply_warnings(yume_anonym_curl_transport_test)
        add_test(NAME yume_anonym_curl_transport_test
            COMMAND yume_anonym_curl_transport_test)
    endif()

    # ------------------------------------------------------------------
    # Client library
    # ------------------------------------------------------------------
    # Mirror of yume_server: every client primitive except main() lives
    # here so the facade can construct a client session without
    # duplicating the transport stack.
    add_library(yume_client_lib STATIC
        client/relay/file_receiver.cpp
        client/relay/history.cpp
        client/relay/outbound_source.cpp
        client/relay/peer_trust.cpp
        client/relay/relay_v2_crypto.cpp
        client/relay/relay_v2_record.cpp
        client/runtime/local_runtime.cpp
        client/relay/secret.cpp
        client/relay/runtime.cpp
        client/relay/runtime_control.cpp
        client/runtime/controller.cpp
        client/transport/chrome_tls_helper.cpp
        client/transport/tunnel_pool.cpp
        client/codec/monero_rpc.cpp
        client/packet/channel.cpp
        client/packet/tun_adapter.cpp
        client/proxy/socks.cpp
        client/transfer/share_file.cpp
        client/cli/entry.cpp
        client/cli/display/anonym_proof.cpp
        client/cli/commands/attach.cpp
        client/cli/config/args.cpp
        client/cli/commands/bench.cpp
        client/cli/commands/connected_session.cpp
        client/cli/connect/capabilities.cpp
        client/cli/display/help.cpp
        client/cli/connect/cert.cpp
        client/cli/commands/console.cpp
        client/cli/config/config.cpp
        client/cli/connect/diagnostics.cpp
        client/cli/connect/outer_carrier_capture.cpp
        client/cli/config/files.cpp
        client/cli/config/input.cpp
        client/cli/config/platform.cpp
        client/cli/commands/proxy.cpp
        client/cli/commands/relay_secret.cpp
        client/cli/parse/endpoints.cpp
        client/cli/commands/io_runtime.cpp
        client/cli/connect/server_info.cpp
        client/cli/connect/secondary_tunnel.cpp
        client/cli/commands/share.cpp
        client/cli/display/status.cpp
    )
    target_include_directories(yume_client_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(yume_client_lib PUBLIC yume_core yume_transport_core
        yume_outbound_transport)
    if(YUME_BUILD_SHARED_ABI)
        yume_prepare_static_for_shared_abi(yume_client_lib)
    endif()
    yume_apply_perf_opts(yume_client_lib)
    yume_apply_pch(yume_client_lib)
    if(WIN32)
        target_link_libraries(yume_client_lib PUBLIC ws2_32 mswsock)
        target_compile_definitions(yume_client_lib PUBLIC
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            WINVER=0x0600
            _WIN32_WINNT=0x0600
        )
    endif()

    add_executable(yume
        main_client.cpp
    )
    target_link_libraries(yume PRIVATE yume_client_lib)
    yume_apply_perf_opts(yume)

    if(YUME_BUILD_CHROME_TLS_HELPER)
        if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_CROSSCOMPILING)
            message(FATAL_ERROR
                "YUME_BUILD_CHROME_TLS_HELPER currently supports native Linux builds only")
        endif()
        find_program(YUME_GO_EXECUTABLE NAMES go REQUIRED)
        execute_process(
            COMMAND "${YUME_GO_EXECUTABLE}" version
            OUTPUT_VARIABLE _yume_go_version
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE _yume_go_version_result
        )
        if(NOT _yume_go_version_result EQUAL 0 OR
           NOT _yume_go_version MATCHES "^go version go1\\.26\\.5 ")
            message(FATAL_ERROR
                "Chrome TLS helper requires exact Go 1.26.5; got '${_yume_go_version}'")
        endif()
        set(_yume_chrome_tls_helper
            "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/yume-chrome-tls-helper")
        add_custom_command(
            OUTPUT "${_yume_chrome_tls_helper}"
            COMMAND "${CMAKE_COMMAND}" -E env
                CGO_ENABLED=0
                GOTOOLCHAIN=local
                "${YUME_GO_EXECUTABLE}" build
                -mod=readonly
                -trimpath
                -buildvcs=false
                "-ldflags=-buildid="
                -o "${_yume_chrome_tls_helper}"
                .
            COMMAND chmod 0755 "${_yume_chrome_tls_helper}"
            DEPENDS
                "${CMAKE_SOURCE_DIR}/helper/chrome_tls/go.mod"
                "${CMAKE_SOURCE_DIR}/helper/chrome_tls/go.sum"
                "${CMAKE_SOURCE_DIR}/helper/chrome_tls/ipc.go"
                "${CMAKE_SOURCE_DIR}/helper/chrome_tls/main.go"
                "${CMAKE_SOURCE_DIR}/helper/chrome_tls/profile.go"
                "${CMAKE_SOURCE_DIR}/helper/chrome_tls/transport_profiles_generated.go"
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/helper/chrome_tls"
            COMMENT "Building pinned Chrome 151 TLS helper"
            VERBATIM
        )
        add_custom_target(yume_chrome_tls_helper ALL
            DEPENDS "${_yume_chrome_tls_helper}")
        add_dependencies(yume yume_chrome_tls_helper)
        target_compile_definitions(yume_client_lib PUBLIC
            YUME_HAS_CHROME_TLS_HELPER=1)
        install(PROGRAMS "${_yume_chrome_tls_helper}"
            DESTINATION "${CMAKE_INSTALL_BINDIR}"
            COMPONENT yume_cli)
    else()
        target_compile_definitions(yume_client_lib PUBLIC
            YUME_HAS_CHROME_TLS_HELPER=0)
    endif()
    if(YUME_STATIC AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_options(yume PRIVATE -static)
    endif()

    set(_yume_install_targets yume yumed)

    if(YUME_BUILD_TOOLS)
        # Read-only ASCII visualization of the local yumed federation topology.
        add_executable(yume-net-map
            tools/net_map.cpp
        )
        target_link_libraries(yume-net-map PRIVATE yume_server)
        yume_apply_perf_opts(yume-net-map)
        if(YUME_STATIC AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
            target_link_options(yume-net-map PRIVATE -static)
        endif()
        list(APPEND _yume_install_targets yume-net-map)
    endif()
    if(WIN32)
        target_link_libraries(yume PRIVATE ws2_32 mswsock)
        target_compile_definitions(yume PRIVATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            WINVER=0x0600
            _WIN32_WINNT=0x0600
        )
    endif()

    if(YUME_BUILD_SELFTEST)
        if(WIN32)
            message(FATAL_ERROR "YUME_BUILD_SELFTEST currently supports POSIX desktop hosts only")
        endif()
        if(NOT TARGET basefwxcpp)
            message(FATAL_ERROR "YUME_BUILD_SELFTEST requires BaseFWX for the mandatory 2.0 ratchet")
        endif()
        if(NOT YUME_FEATURE_LAN_BRIDGE)
            message(WARNING
                "yume-selftest can be built, but routed loopback benchmarks require "
                "-DYUME_FEATURE_LAN_BRIDGE=ON in the yume/yumed binaries under test")
        endif()
        add_library(yume_selftest_lib STATIC
            tools/benchmark/v2_crypto_bench.cpp
            tools/selftest.cpp
            tools/selftest/runtime.cpp
            tools/selftest/render.cpp
            tools/selftest/sizing.cpp
            tools/selftest/hotpath.cpp
            tools/selftest/scoring.cpp
            tools/selftest/json.cpp
            tools/selftest/telemetry.cpp
        )
        target_include_directories(yume_selftest_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_libraries(yume_selftest_lib PUBLIC yume_core OpenSSL::Crypto Threads::Threads)
        yume_prepare_static_for_shared_abi(yume_selftest_lib)
        yume_apply_perf_opts(yume_selftest_lib)
        # The definition and the link must live on the same target. When the
        # link was only on the `yume` executable, every other consumer of
        # yume_client_lib - yume_facade, and through it the yume_abi shared
        # library - compiled the call in client/cli/entry.cpp but had nothing
        # to resolve it against, so -DYUME_BUILD_SELFTEST=ON with
        # -DYUME_BUILD_SHARED_ABI=ON failed to link with
        # "undefined reference to yume::tools::selftest::run_cli".
        target_compile_definitions(yume_client_lib PUBLIC YUME_HAS_SELFTEST=1)
        target_link_libraries(yume_client_lib PUBLIC yume_selftest_lib)

        add_executable(yume-selftest
            tools/selftest_main.cpp
        )
        target_link_libraries(yume-selftest PRIVATE yume_selftest_lib)
        yume_apply_perf_opts(yume-selftest)
        add_executable(yume-basefwx-bench
            tools/basefwx_bench.cpp
            tools/benchmark/v2_crypto_bench.cpp
        )
        target_link_libraries(yume-basefwx-bench PRIVATE yume_core)
        yume_apply_perf_opts(yume-basefwx-bench)
        add_executable(yume-relay-bench
            tools/relay_bench.cpp
        )
        target_link_libraries(yume-relay-bench PRIVATE yume_transport_core OpenSSL::SSL OpenSSL::Crypto)
        yume_apply_perf_opts(yume-relay-bench)
        if(YUME_STATIC AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
            target_link_options(yume-selftest PRIVATE -static)
            target_link_options(yume-basefwx-bench PRIVATE -static)
            target_link_options(yume-relay-bench PRIVATE -static)
        endif()
        list(APPEND _yume_install_targets
            yume-selftest
            yume-basefwx-bench
            yume-relay-bench
        )
    endif()

    install(TARGETS ${_yume_install_targets}
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        COMPONENT yume_cli
    )

    # ------------------------------------------------------------------
    # Optional GUI components
    # ------------------------------------------------------------------
    # The facade library has no GUI dependency and is small enough to
    # build unconditionally; the executable is gated on YUME_BUILD_GUI.
    add_subdirectory(facade)
    if(YUME_BUILD_SHARED_ABI)
        include(CMakePackageConfigHelpers)

        add_library(yume_abi SHARED
            abi/yume_c.cpp
        )
        set_target_properties(yume_abi PROPERTIES
            OUTPUT_NAME yume
            EXPORT_NAME yume
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON
            POSITION_INDEPENDENT_CODE ON
            PUBLIC_HEADER "${CMAKE_SOURCE_DIR}/include/yume/yume.h"
        )
        # Android's package manager only recognizes unversioned *.so entries.
        # The ABI line remains YUME_ABI_VERSION=1; desktop platforms retain the
        # public libyume.so.1 SONAME and normal versioned symlink chain.
        if(NOT ANDROID)
            set_target_properties(yume_abi PROPERTIES
                VERSION "${YUME_PACKAGE_VERSION}"
                SOVERSION 1
            )
        endif()
        # Warnings, but deliberately NOT yume_apply_perf_opts: this target is
        # the installed shared library, and changing its optimisation/LTO
        # settings is a shipped-artifact decision, separate from wanting the
        # C boundary compiled with -Wall -Wextra like everything else.
        #
        # yume_c.cpp is the highest-value file in the tree for warnings - it is
        # the only place untyped void* from arbitrary embedders is
        # dereferenced - and until this line existed it was compiled with no
        # warning flags at all.
        yume_apply_warnings(yume_abi)
        target_compile_definitions(yume_abi PRIVATE
            YUME_ABI_BUILD=1
            YUME_ABI_CLIENT_ONLY=$<BOOL:${YUME_ABI_CLIENT_ONLY}>)
        target_include_directories(yume_abi
            PUBLIC
                $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}
        )
        if(YUME_ABI_CLIENT_ONLY)
            target_link_libraries(yume_abi PRIVATE yume_client_facade)
        else()
            target_link_libraries(yume_abi PRIVATE yume_facade)
        endif()
        # Symbol control. Without it, implementation symbols from YUME's
        # internal static libraries and any absorbed third-party archives leak
        # into the public namespace. That both breaks the "exactly these
        # functions" contract and lets an embedder bind to an internal detail.
        #
        #   ELF     version script.
        #   Mach-O  -exported_symbols_list, generated from the same map so the
        #           two platforms cannot drift.
        #   PE      nothing to do: symbols are private unless declared
        #           __declspec(dllexport), which only YUME_API carries. The
        #           presence of explicit exports also disables MinGW's
        #           export-everything fallback.
        set(_yume_abi_version_script "${CMAKE_CURRENT_SOURCE_DIR}/abi/yume.map")
        if(UNIX AND NOT APPLE)
            target_link_options(yume_abi PRIVATE
                "LINKER:--version-script=${_yume_abi_version_script}"
                # The facade/core arrive through non-LTO static archives.
                # Hidden input visibility is the primary control; exclude-libs
                # contains any remaining archive-level implementation symbols.
                "LINKER:--exclude-libs,ALL"
            )
            set_property(TARGET yume_abi APPEND PROPERTY
                LINK_DEPENDS "${_yume_abi_version_script}"
            )
        elseif(APPLE)
            set(_yume_abi_symbol_list "${CMAKE_CURRENT_BINARY_DIR}/yume.exported_symbols")
            yume_write_macho_symbol_list(
                "${_yume_abi_version_script}" "${_yume_abi_symbol_list}")
            target_link_options(yume_abi PRIVATE
                "LINKER:-exported_symbols_list,${_yume_abi_symbol_list}"
            )
            set_property(TARGET yume_abi APPEND PROPERTY
                LINK_DEPENDS "${_yume_abi_version_script}"
            )
        endif()

        install(TARGETS yume_abi
            EXPORT yumeTargets
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
                COMPONENT libyume_runtime
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
                COMPONENT libyume_runtime
                NAMELINK_COMPONENT libyume_development
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
                COMPONENT libyume_development
            PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/yume"
                COMPONENT libyume_development
        )
        install(EXPORT yumeTargets
            FILE yumeTargets.cmake
            NAMESPACE yume::
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/yume"
            COMPONENT libyume_development
        )

        configure_package_config_file(
            "${CMAKE_SOURCE_DIR}/cmake/yumeConfig.cmake.in"
            "${CMAKE_BINARY_DIR}/yumeConfig.cmake"
            INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/yume"
        )
        write_basic_package_version_file(
            "${CMAKE_BINARY_DIR}/yumeConfigVersion.cmake"
            VERSION "${YUME_PACKAGE_VERSION}"
            COMPATIBILITY SameMajorVersion
        )
        install(FILES
            "${CMAKE_BINARY_DIR}/yumeConfig.cmake"
            "${CMAKE_BINARY_DIR}/yumeConfigVersion.cmake"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/yume"
            COMPONENT libyume_development
        )

        set(_yume_pc_install_dir "/${CMAKE_INSTALL_LIBDIR}/pkgconfig")
        file(RELATIVE_PATH YUME_PC_PREFIX_FROM_PKGCONFIG
            "${_yume_pc_install_dir}" "/")
        configure_file(
            "${CMAKE_SOURCE_DIR}/cmake/yume.pc.in"
            "${CMAKE_BINARY_DIR}/yume.pc"
            @ONLY
        )
        install(FILES "${CMAKE_BINARY_DIR}/yume.pc"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
            COMPONENT libyume_development
        )

        if(YUME_BUILD_TOOLS AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
            add_executable(yume-abi-tun tools/abi_tun.cpp)
            target_link_libraries(yume-abi-tun PRIVATE yume_abi Threads::Threads)
            target_include_directories(yume-abi-tun PRIVATE ${CMAKE_SOURCE_DIR}/include)
            yume_apply_perf_opts(yume-abi-tun)
            install(TARGETS yume-abi-tun
                RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
                COMPONENT yume_cli
            )
        endif()
    endif()
    if(YUME_BUILD_GUI)
        add_subdirectory(gui)
    endif()
endif()

if(YUME_BUILD_TESTING)

# Most of the focused native tests use the standard assert() facility. CMake
# defines NDEBUG for Release and RelWithDebInfo, which would otherwise turn
# those checks into no-ops while still reporting a passing test executable.
# This directory's production targets are all declared above this block, so
# the undefinition applies only to test targets created below.
if(MSVC)
    add_compile_options(/UNDEBUG)
else()
    add_compile_options(-UNDEBUG)
endif()

add_executable(yume_secure_materials_test
    facade/security/secure_materials_test.cpp
)
target_link_libraries(yume_secure_materials_test PRIVATE yume_facade)
yume_apply_perf_opts(yume_secure_materials_test)
add_test(NAME yume_secure_materials_test COMMAND yume_secure_materials_test)

add_executable(yume_facade_lifecycle_test
    facade/session/lifecycle_test.cpp
)
target_link_libraries(yume_facade_lifecycle_test PRIVATE yume_facade)
yume_apply_perf_opts(yume_facade_lifecycle_test)
add_test(NAME yume_facade_lifecycle_test COMMAND yume_facade_lifecycle_test)
set_tests_properties(yume_facade_lifecycle_test PROPERTIES TIMEOUT 30)

add_executable(yume_composite_signature_test
    core/security/composite_signature_test.cpp
)
target_link_libraries(yume_composite_signature_test PRIVATE yume_core)
yume_apply_perf_opts(yume_composite_signature_test)
add_test(NAME yume_composite_signature_test COMMAND yume_composite_signature_test)

add_executable(yume_dual_key_auth_test
    server/auth/dual_key_auth_test.cpp
    server/cli/key.cpp
)
target_link_libraries(yume_dual_key_auth_test PRIVATE yume_facade)
yume_apply_perf_opts(yume_dual_key_auth_test)
add_test(NAME yume_dual_key_auth_test COMMAND yume_dual_key_auth_test)

add_executable(yume_server_config_io_test
    server/cli/config_load_test.cpp
    server/cli/args.cpp
    server/cli/cluster.cpp
    server/cli/config_load.cpp
    server/cli/help.cpp
    server/cli/misc.cpp
)
target_link_libraries(yume_server_config_io_test PRIVATE yume_facade)
yume_apply_perf_opts(yume_server_config_io_test)
add_test(NAME yume_server_config_io_test COMMAND yume_server_config_io_test)

add_executable(yume_signal_dispatch_test util_signal_test.cpp)
target_link_libraries(yume_signal_dispatch_test PRIVATE yume_core)
yume_apply_perf_opts(yume_signal_dispatch_test)
add_test(NAME yume_signal_dispatch_test COMMAND yume_signal_dispatch_test)
set_tests_properties(yume_signal_dispatch_test PROPERTIES TIMEOUT 10)

add_executable(yume_client_config_io_test
    facade/config/client_config_io_test.cpp
)
target_link_libraries(yume_client_config_io_test PRIVATE yume_facade)
yume_apply_perf_opts(yume_client_config_io_test)
add_test(NAME yume_client_config_io_test COMMAND yume_client_config_io_test)

add_executable(yume_transport_core_test
    client/transport/core_test.cpp
)

target_link_libraries(yume_transport_core_test PRIVATE yume_transport_core)
yume_link_atomic_if_needed(yume_transport_core_test PRIVATE)
yume_apply_perf_opts(yume_transport_core_test)

add_test(NAME yume_transport_core_test COMMAND yume_transport_core_test)

add_executable(yume_relay_channel_policy_test
    core/protocol/relay_policy_test.cpp)
target_link_libraries(yume_relay_channel_policy_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_relay_channel_policy_test PRIVATE)
yume_apply_perf_opts(yume_relay_channel_policy_test)
add_test(NAME yume_relay_channel_policy_test
    COMMAND yume_relay_channel_policy_test)

add_executable(yume_directory_policy_test
    core/protocol/directory_policy_test.cpp)
target_link_libraries(yume_directory_policy_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_directory_policy_test PRIVATE)
yume_apply_perf_opts(yume_directory_policy_test)
add_test(NAME yume_directory_policy_test
    COMMAND yume_directory_policy_test)

add_executable(yume_control_command_policy_test
    core/protocol/control_command_policy_test.cpp)
target_link_libraries(yume_control_command_policy_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_control_command_policy_test PRIVATE)
yume_apply_perf_opts(yume_control_command_policy_test)
add_test(NAME yume_control_command_policy_test
    COMMAND yume_control_command_policy_test)

add_executable(yume_chrome_tls_protocol_test
    client/transport/chrome_tls_protocol_test.cpp
)
target_link_libraries(yume_chrome_tls_protocol_test PRIVATE yume_transport_core)
yume_link_atomic_if_needed(yume_chrome_tls_protocol_test PRIVATE)
yume_apply_perf_opts(yume_chrome_tls_protocol_test)
add_test(NAME yume_chrome_tls_protocol_test COMMAND yume_chrome_tls_protocol_test)

if(YUME_BUILD_CHROME_TLS_HELPER)
    add_test(
        NAME yume_chrome_tls_helper_go_test
        COMMAND "${CMAKE_COMMAND}" -E env
            GOTOOLCHAIN=local
            GOPROXY=off
            "${YUME_GO_EXECUTABLE}" test
            -mod=readonly
            -count=1
            .
    )
    set_tests_properties(yume_chrome_tls_helper_go_test PROPERTIES
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/helper/chrome_tls"
        TIMEOUT 120
    )

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET yume_client_lib)
        add_executable(yume_chrome_tls_fake_helper
            client/transport/chrome_tls_fake_helper.cpp
        )
        target_link_libraries(yume_chrome_tls_fake_helper PRIVATE yume_transport_core)
        yume_apply_perf_opts(yume_chrome_tls_fake_helper)
        add_custom_command(TARGET yume_chrome_tls_fake_helper POST_BUILD
            COMMAND chmod 0755 "$<TARGET_FILE:yume_chrome_tls_fake_helper>"
            VERBATIM
        )

        add_executable(yume_chrome_tls_helper_test
            client/transport/chrome_tls_helper_test.cpp
        )
        target_link_libraries(yume_chrome_tls_helper_test PRIVATE yume_client_lib)
        yume_apply_perf_opts(yume_chrome_tls_helper_test)
        add_dependencies(yume_chrome_tls_helper_test yume_chrome_tls_fake_helper)
        add_test(
            NAME yume_chrome_tls_helper_test
            COMMAND yume_chrome_tls_helper_test
                "$<TARGET_FILE:yume_chrome_tls_fake_helper>"
        )
        set_tests_properties(yume_chrome_tls_helper_test PROPERTIES TIMEOUT 15)
    endif()
endif()

add_executable(yume_timing_diagnostics_test
    core/diagnostics/timing_test.cpp
)
target_link_libraries(yume_timing_diagnostics_test PRIVATE yume_core)
yume_apply_perf_opts(yume_timing_diagnostics_test)
add_test(NAME yume_timing_diagnostics_test COMMAND yume_timing_diagnostics_test)

add_executable(yume_packet_bulk_test core/protocol/packet_bulk_test.cpp)
target_link_libraries(yume_packet_bulk_test PRIVATE yume_transport_core)
yume_link_atomic_if_needed(yume_packet_bulk_test PRIVATE)
yume_apply_perf_opts(yume_packet_bulk_test)
add_test(NAME yume_packet_bulk_test COMMAND yume_packet_bulk_test)

add_executable(yume_packet_engine_test client/packet/engine_test.cpp)
target_link_libraries(yume_packet_engine_test PRIVATE yume_transport_core)
yume_link_atomic_if_needed(yume_packet_engine_test PRIVATE)
yume_apply_perf_opts(yume_packet_engine_test)
add_test(NAME yume_packet_engine_test COMMAND yume_packet_engine_test)

if(TARGET yume_client_lib)
    add_executable(yume_share_file_test
        client/transfer/share_file_test.cpp)
    target_link_libraries(yume_share_file_test PRIVATE yume_client_lib)
    yume_link_atomic_if_needed(yume_share_file_test PRIVATE)
    yume_apply_perf_opts(yume_share_file_test)
    add_test(NAME yume_share_file_test COMMAND yume_share_file_test)

    add_executable(yume_packet_channel_contract_test
        client/packet/channel_contract_test.cpp)
    target_link_libraries(yume_packet_channel_contract_test PRIVATE yume_client_lib)
    yume_link_atomic_if_needed(yume_packet_channel_contract_test PRIVATE)
    yume_apply_perf_opts(yume_packet_channel_contract_test)
    add_test(NAME yume_packet_channel_contract_test
        COMMAND yume_packet_channel_contract_test)

    add_executable(yume_tunnel_exec_policy_test
        client/transport/tunnel_exec_policy_test.cpp)
    target_link_libraries(yume_tunnel_exec_policy_test PRIVATE yume_client_lib)
    yume_link_atomic_if_needed(yume_tunnel_exec_policy_test PRIVATE)
    yume_apply_perf_opts(yume_tunnel_exec_policy_test)
    add_test(NAME yume_tunnel_exec_policy_test
        COMMAND yume_tunnel_exec_policy_test)

    add_executable(yume_relay_persistence_test
        client/relay/relay_persistence_test.cpp)
    target_link_libraries(yume_relay_persistence_test PRIVATE yume_client_lib)
    yume_link_atomic_if_needed(yume_relay_persistence_test PRIVATE)
    yume_apply_perf_opts(yume_relay_persistence_test)
    add_test(NAME yume_relay_persistence_test
        COMMAND yume_relay_persistence_test)

    add_executable(yume_relay_runtime_lifecycle_test
        client/relay/relay_runtime_lifecycle_test.cpp)
    target_link_libraries(yume_relay_runtime_lifecycle_test PRIVATE
        yume_client_lib)
    yume_link_atomic_if_needed(yume_relay_runtime_lifecycle_test PRIVATE)
    yume_apply_perf_opts(yume_relay_runtime_lifecycle_test)
    add_test(NAME yume_relay_runtime_lifecycle_test
        COMMAND yume_relay_runtime_lifecycle_test)

    add_executable(yume_relay_file_receiver_test
        client/relay/file_receiver_test.cpp)
    target_link_libraries(yume_relay_file_receiver_test PRIVATE yume_client_lib)
    yume_link_atomic_if_needed(yume_relay_file_receiver_test PRIVATE)
    yume_apply_perf_opts(yume_relay_file_receiver_test)
    add_test(NAME yume_relay_file_receiver_test
        COMMAND yume_relay_file_receiver_test)

    add_executable(yume_relay_outbound_source_test
        client/relay/outbound_source_test.cpp)
    target_link_libraries(yume_relay_outbound_source_test PRIVATE
        yume_client_lib)
    yume_link_atomic_if_needed(yume_relay_outbound_source_test PRIVATE)
    yume_apply_perf_opts(yume_relay_outbound_source_test)
    add_test(NAME yume_relay_outbound_source_test
        COMMAND yume_relay_outbound_source_test)

    add_executable(yume_relay_v2_crypto_test
        client/relay/relay_v2_crypto_test.cpp)
    target_link_libraries(yume_relay_v2_crypto_test PRIVATE yume_client_lib)
    yume_link_atomic_if_needed(yume_relay_v2_crypto_test PRIVATE)
    yume_apply_perf_opts(yume_relay_v2_crypto_test)
    add_test(NAME yume_relay_v2_crypto_test
        COMMAND yume_relay_v2_crypto_test)

    add_executable(yume_relay_peer_trust_test
        client/relay/peer_trust_test.cpp
        client/relay/peer_trust.cpp)
    target_link_libraries(yume_relay_peer_trust_test PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_relay_peer_trust_test PRIVATE)
    yume_apply_perf_opts(yume_relay_peer_trust_test)
    add_test(NAME yume_relay_peer_trust_test
        COMMAND yume_relay_peer_trust_test)

    add_executable(yume_relay_v2_record_test
        client/relay/relay_v2_record_test.cpp
        client/relay/relay_v2_record.cpp)
    target_link_libraries(yume_relay_v2_record_test PRIVATE yume_secure_core)
    yume_link_atomic_if_needed(yume_relay_v2_record_test PRIVATE)
    yume_apply_perf_opts(yume_relay_v2_record_test)
    add_test(NAME yume_relay_v2_record_test
        COMMAND yume_relay_v2_record_test)

    add_executable(yume_relay_cli_config_test
        client/cli/config/relay_config_test.cpp)
    target_link_libraries(yume_relay_cli_config_test PRIVATE yume_client_lib)
    yume_link_atomic_if_needed(yume_relay_cli_config_test PRIVATE)
    yume_apply_perf_opts(yume_relay_cli_config_test)
    add_test(NAME yume_relay_cli_config_test
        COMMAND yume_relay_cli_config_test)

    add_executable(yume_reverse_forward_write_test
        client/proxy/forward_test.cpp)
    target_link_libraries(yume_reverse_forward_write_test PRIVATE yume_client_lib)
    yume_link_atomic_if_needed(yume_reverse_forward_write_test PRIVATE)
    yume_apply_perf_opts(yume_reverse_forward_write_test)
    add_test(NAME yume_reverse_forward_write_test
        COMMAND yume_reverse_forward_write_test)
endif()

add_executable(yume_fair_frame_budget_test
    server/session/fair_frame_budget_test.cpp)
target_include_directories(yume_fair_frame_budget_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(yume_fair_frame_budget_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_fair_frame_budget_test PRIVATE)
yume_apply_perf_opts(yume_fair_frame_budget_test)
add_test(NAME yume_fair_frame_budget_test COMMAND yume_fair_frame_budget_test)

add_executable(yume_server_write_policy_test
    server/session/write_policy_test.cpp)
target_include_directories(yume_server_write_policy_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_apply_perf_opts(yume_server_write_policy_test)
add_test(NAME yume_server_write_policy_test COMMAND yume_server_write_policy_test)

add_executable(yume_relay_read_buf_test util_test.cpp)
target_include_directories(yume_relay_read_buf_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(yume_relay_read_buf_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_relay_read_buf_test PRIVATE)
yume_apply_perf_opts(yume_relay_read_buf_test)
add_test(NAME yume_relay_read_buf_test COMMAND yume_relay_read_buf_test)

add_executable(yume_app_codec_test core/app_codec/codec_test.cpp)
target_link_libraries(yume_app_codec_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_app_codec_test PRIVATE)
yume_apply_perf_opts(yume_app_codec_test)
add_test(NAME yume_app_codec_test COMMAND yume_app_codec_test)

add_executable(yume_version_status_test
    core/release/version_status_test.cpp
    core/release/version_status.cpp
)
target_include_directories(yume_version_status_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_apply_perf_opts(yume_version_status_test)
add_test(NAME yume_version_status_test COMMAND yume_version_status_test)

add_executable(yume_terminal_test core/release/terminal_test.cpp)
target_link_libraries(yume_terminal_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_terminal_test PRIVATE)
yume_apply_perf_opts(yume_terminal_test)
add_test(NAME yume_terminal_test COMMAND yume_terminal_test)

add_executable(yume_tls_fingerprint_test core/stealth/tls_fingerprint_test.cpp)
target_link_libraries(yume_tls_fingerprint_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_tls_fingerprint_test PRIVATE)
yume_apply_perf_opts(yume_tls_fingerprint_test)
add_test(NAME yume_tls_fingerprint_test COMMAND yume_tls_fingerprint_test)

add_executable(yume_identity_admission_test
    server/runtime/identity_admission_test.cpp
    server/runtime/identity_admission.cpp
)
target_include_directories(yume_identity_admission_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(yume_identity_admission_test PRIVATE Threads::Threads)
yume_link_atomic_if_needed(yume_identity_admission_test PRIVATE)
yume_apply_perf_opts(yume_identity_admission_test)
add_test(NAME yume_identity_admission_test COMMAND yume_identity_admission_test)

add_executable(yume_weighted_egress_limiter_test
    server/runtime/weighted_egress_limiter_test.cpp
    server/runtime/weighted_egress_limiter.cpp
)
target_include_directories(yume_weighted_egress_limiter_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_link_atomic_if_needed(yume_weighted_egress_limiter_test PRIVATE)
yume_apply_perf_opts(yume_weighted_egress_limiter_test)
add_test(NAME yume_weighted_egress_limiter_test
    COMMAND yume_weighted_egress_limiter_test)

add_executable(yume_session_authorization_test
    server/session/authorization_test.cpp
    server/session/authorization.cpp
)
target_include_directories(yume_session_authorization_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_link_atomic_if_needed(yume_session_authorization_test PRIVATE)
yume_apply_perf_opts(yume_session_authorization_test)
add_test(NAME yume_session_authorization_test COMMAND yume_session_authorization_test)

add_executable(yume_admin_relationships_test
    server/runtime/admin_relationships_test.cpp
    server/runtime/admin_relationships.cpp
)
target_include_directories(yume_admin_relationships_test
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_link_atomic_if_needed(yume_admin_relationships_test PRIVATE)
yume_apply_perf_opts(yume_admin_relationships_test)
add_test(NAME yume_admin_relationships_test
    COMMAND yume_admin_relationships_test)

add_executable(yume_runtime_session_selector_test
    server/runtime/session_selector_test.cpp)
target_include_directories(yume_runtime_session_selector_test
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_apply_perf_opts(yume_runtime_session_selector_test)
add_test(NAME yume_runtime_session_selector_test
    COMMAND yume_runtime_session_selector_test)

# The topology/status builders are deliberately pure functions over snapshot
# vectors, so the reporting contract -- redaction, peer merging, and the
# single-hop route claim -- is provable without launching a cluster.
add_executable(yume_federation_topology_test
    server/federation/topology_test.cpp
    server/federation/topology.cpp
    server/federation/topology_render.cpp
    core/protocol/control_protocol.cpp
)
target_include_directories(yume_federation_topology_test
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_link_atomic_if_needed(yume_federation_topology_test PRIVATE)
yume_apply_perf_opts(yume_federation_topology_test)
add_test(NAME yume_federation_topology_test
    COMMAND yume_federation_topology_test)

if(TARGET yume_server)
    add_executable(yume_server_local_runtime_test
        server/runtime/local_runtime_test.cpp)
    target_link_libraries(yume_server_local_runtime_test
        PRIVATE yume_server Threads::Threads)
    yume_link_atomic_if_needed(yume_server_local_runtime_test PRIVATE)
    yume_apply_perf_opts(yume_server_local_runtime_test)
    add_test(NAME yume_server_local_runtime_test
        COMMAND yume_server_local_runtime_test)

    add_executable(yume_server_control_survival_test
        server/session/control_survival_test.cpp)
    target_link_libraries(yume_server_control_survival_test
        PRIVATE yume_server Threads::Threads)
    yume_link_atomic_if_needed(yume_server_control_survival_test PRIVATE)
    yume_apply_perf_opts(yume_server_control_survival_test)
    add_test(NAME yume_server_control_survival_test
        COMMAND yume_server_control_survival_test)

    add_executable(yume_federation_link_lifecycle_test
        server/federation/link_lifecycle_test.cpp)
    target_link_libraries(yume_federation_link_lifecycle_test
        PRIVATE yume_server Threads::Threads)
    yume_link_atomic_if_needed(yume_federation_link_lifecycle_test PRIVATE)
    yume_apply_perf_opts(yume_federation_link_lifecycle_test)
    add_test(NAME yume_federation_link_lifecycle_test
        COMMAND yume_federation_link_lifecycle_test)

    add_executable(yume_reverse_listener_lifecycle_test
        server/session/reverse_listener_lifecycle_test.cpp)
    target_link_libraries(yume_reverse_listener_lifecycle_test
        PRIVATE yume_server Threads::Threads)
    yume_link_atomic_if_needed(yume_reverse_listener_lifecycle_test PRIVATE)
    yume_apply_perf_opts(yume_reverse_listener_lifecycle_test)
    add_test(NAME yume_reverse_listener_lifecycle_test
        COMMAND yume_reverse_listener_lifecycle_test)

    add_executable(yume_stream_id_reservation_test
        server/session/stream_id_reservation_test.cpp)
    target_link_libraries(yume_stream_id_reservation_test
        PRIVATE yume_server Threads::Threads)
    yume_link_atomic_if_needed(yume_stream_id_reservation_test PRIVATE)
    yume_apply_perf_opts(yume_stream_id_reservation_test)
    add_test(NAME yume_stream_id_reservation_test
        COMMAND yume_stream_id_reservation_test)

    add_executable(yume_http_backend_client_test
        server/host/http_backend_client_test.cpp)
    target_link_libraries(yume_http_backend_client_test
        PRIVATE yume_server Threads::Threads)
    yume_link_atomic_if_needed(yume_http_backend_client_test PRIVATE)
    yume_apply_perf_opts(yume_http_backend_client_test)
    add_test(NAME yume_http_backend_client_test
        COMMAND yume_http_backend_client_test)

    add_executable(yume_auth_policy_values_test
        server/auth/auth_policy_values_test.cpp)
    target_link_libraries(yume_auth_policy_values_test
        PRIVATE yume_server Threads::Threads)
    yume_link_atomic_if_needed(yume_auth_policy_values_test PRIVATE)
    yume_apply_perf_opts(yume_auth_policy_values_test)
    add_test(NAME yume_auth_policy_values_test
        COMMAND yume_auth_policy_values_test)

    add_executable(yume_auth_policy_concurrency_test
        server/auth/auth_policy_concurrency_test.cpp)
    target_link_libraries(yume_auth_policy_concurrency_test
        PRIVATE yume_server Threads::Threads)
    yume_link_atomic_if_needed(yume_auth_policy_concurrency_test PRIVATE)
    yume_apply_perf_opts(yume_auth_policy_concurrency_test)
    add_test(NAME yume_auth_policy_concurrency_test
        COMMAND yume_auth_policy_concurrency_test)
endif()

add_executable(yume_h2_cover_fetches_test
    server/session/h2_cover_fetches_test.cpp)
target_include_directories(yume_h2_cover_fetches_test
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_link_atomic_if_needed(yume_h2_cover_fetches_test PRIVATE)
yume_apply_perf_opts(yume_h2_cover_fetches_test)
add_test(NAME yume_h2_cover_fetches_test
    COMMAND yume_h2_cover_fetches_test)

add_executable(yume_static_site_test
    server/session/static_site_test.cpp
    server/session/static_site.cpp
)
target_include_directories(yume_static_site_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_link_atomic_if_needed(yume_static_site_test PRIVATE)
yume_apply_perf_opts(yume_static_site_test)
add_test(NAME yume_static_site_test COMMAND yume_static_site_test)

add_executable(yume_http_masq_test
    server/session/http_masq_test.cpp
    server/session/http_masq.cpp
)
target_include_directories(yume_http_masq_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_link_atomic_if_needed(yume_http_masq_test PRIVATE)
yume_apply_perf_opts(yume_http_masq_test)
add_test(NAME yume_http_masq_test COMMAND yume_http_masq_test)

add_executable(yume_server_security_policy_test
    server/cli/security_policy_test.cpp
)
target_include_directories(yume_server_security_policy_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_apply_perf_opts(yume_server_security_policy_test)
add_test(NAME yume_server_security_policy_test COMMAND yume_server_security_policy_test)

add_executable(yume_service_queue_policy_test
    server/runtime/service_queue_policy_test.cpp
)
target_include_directories(yume_service_queue_policy_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_apply_perf_opts(yume_service_queue_policy_test)
add_test(NAME yume_service_queue_policy_test COMMAND yume_service_queue_policy_test)

add_executable(yume_server_config_values_test
    server/cli/config_values_test.cpp
)
target_include_directories(yume_server_config_values_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(yume_server_config_values_test PRIVATE
    nlohmann_json::nlohmann_json
)
yume_apply_perf_opts(yume_server_config_values_test)
add_test(NAME yume_server_config_values_test COMMAND yume_server_config_values_test)

add_executable(yume_inner_crypto_limits_test core/security/inner_crypto_limits_test.cpp)
target_link_libraries(yume_inner_crypto_limits_test PRIVATE yume_transport_core)
yume_link_atomic_if_needed(yume_inner_crypto_limits_test PRIVATE)
yume_apply_perf_opts(yume_inner_crypto_limits_test)
add_test(NAME yume_inner_crypto_limits_test COMMAND yume_inner_crypto_limits_test)

add_executable(yume_ratchet_test core/security/ratchet_test.cpp)
target_link_libraries(yume_ratchet_test PRIVATE yume_transport_core)
yume_link_atomic_if_needed(yume_ratchet_test PRIVATE)
yume_apply_perf_opts(yume_ratchet_test)
add_test(NAME yume_ratchet_test COMMAND yume_ratchet_test)

add_executable(yume_ratchet_profile_json_test
    config/ratchet_profile_json_test.cpp)
target_link_libraries(yume_ratchet_profile_json_test PRIVATE yume_transport_core)
yume_link_atomic_if_needed(yume_ratchet_profile_json_test PRIVATE)
yume_apply_perf_opts(yume_ratchet_profile_json_test)
add_test(NAME yume_ratchet_profile_json_test
    COMMAND yume_ratchet_profile_json_test)

add_executable(yume_auth_v2_test core/security/auth_v2_test.cpp)
target_link_libraries(yume_auth_v2_test PRIVATE yume_transport_core)
yume_link_atomic_if_needed(yume_auth_v2_test PRIVATE)
yume_apply_perf_opts(yume_auth_v2_test)
add_test(NAME yume_auth_v2_test COMMAND yume_auth_v2_test)

# Compiled directly rather than through an aggregate library: the test needs
# only the exporter helper plus OpenSSL, and drives real TLS 1.3 handshakes.
add_executable(yume_channel_binding_test
    core/security/channel_binding_test.cpp
    core/security/channel_binding.cpp)
target_include_directories(yume_channel_binding_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(yume_channel_binding_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
yume_link_atomic_if_needed(yume_channel_binding_test PRIVATE)
yume_apply_perf_opts(yume_channel_binding_test)
add_test(NAME yume_channel_binding_test COMMAND yume_channel_binding_test)

add_executable(yume_session_ratchet_test core/security/session_ratchet_test.cpp)
target_link_libraries(yume_session_ratchet_test PRIVATE yume_transport_core)
yume_link_atomic_if_needed(yume_session_ratchet_test PRIVATE)
yume_apply_perf_opts(yume_session_ratchet_test)
add_test(NAME yume_session_ratchet_test COMMAND yume_session_ratchet_test)

add_executable(yume_stream_queue_limits_test core/runtime/stream_queue_limits_test.cpp)
target_include_directories(yume_stream_queue_limits_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_link_atomic_if_needed(yume_stream_queue_limits_test PRIVATE)
yume_apply_perf_opts(yume_stream_queue_limits_test)
add_test(NAME yume_stream_queue_limits_test COMMAND yume_stream_queue_limits_test)

add_executable(yume_service_stream_test
    core/runtime/service_stream_test.cpp
    core/runtime/service_stream.cpp
)
target_include_directories(yume_service_stream_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(yume_service_stream_test PRIVATE Threads::Threads)
yume_link_atomic_if_needed(yume_service_stream_test PRIVATE)
yume_apply_perf_opts(yume_service_stream_test)
add_test(NAME yume_service_stream_test COMMAND yume_service_stream_test)

add_executable(yume_ip_filter_test server/filter/ip_filter_test.cpp server/filter/ip_filter.cpp server/filter/ip_filter_mmdb.cpp)
add_executable(yume_host_types_test
    server/host/host_types_test.cpp
    server/host/host_types.cpp
    server/host/host_routes.cpp
)
target_link_libraries(yume_host_types_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_host_types_test PRIVATE)
yume_apply_perf_opts(yume_host_types_test)
add_test(NAME yume_host_types_test COMMAND yume_host_types_test)
target_link_libraries(yume_ip_filter_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_ip_filter_test PRIVATE)
yume_apply_perf_opts(yume_ip_filter_test)
add_test(NAME yume_ip_filter_test COMMAND yume_ip_filter_test)

add_executable(yume_cli_endpoint_parse_test
    client/cli/parse/endpoints_test.cpp
    client/cli/parse/endpoints.cpp
)
target_include_directories(yume_cli_endpoint_parse_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_link_atomic_if_needed(yume_cli_endpoint_parse_test PRIVATE)
yume_apply_perf_opts(yume_cli_endpoint_parse_test)
add_test(NAME yume_cli_endpoint_parse_test COMMAND yume_cli_endpoint_parse_test)

add_executable(yume_bench_echo_test server/session/bench_echo_test.cpp)
target_include_directories(yume_bench_echo_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
yume_apply_perf_opts(yume_bench_echo_test)
add_test(NAME yume_bench_echo_test COMMAND yume_bench_echo_test)

if(NOT YUME_TRANSPORT_CORE_ONLY)
    add_executable(yume_socket_protection_test
        client/cli/connect/io_socket_protection_test.cpp)
    target_include_directories(yume_socket_protection_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(yume_socket_protection_test PRIVATE
        yume_core Boost::system OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
    yume_link_atomic_if_needed(yume_socket_protection_test PRIVATE)
    yume_apply_perf_opts(yume_socket_protection_test)
    add_test(NAME yume_socket_protection_test COMMAND yume_socket_protection_test)
endif()

if(NOT YUME_TRANSPORT_CORE_ONLY)
    add_executable(yume_websocket_codec_test core/stealth/websocket_codec_test.cpp)
    target_link_libraries(yume_websocket_codec_test PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_websocket_codec_test PRIVATE)
    yume_apply_perf_opts(yume_websocket_codec_test)
    add_test(NAME yume_websocket_codec_test COMMAND yume_websocket_codec_test)

    add_executable(yume_secret_file_test core/security/secret_file_test.cpp)
    target_link_libraries(yume_secret_file_test PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_secret_file_test PRIVATE)
    yume_apply_perf_opts(yume_secret_file_test)
    add_test(NAME yume_secret_file_test COMMAND yume_secret_file_test)

    add_executable(yume_h2_carrier_test core/stealth/h2_carrier_test.cpp)
    target_link_libraries(yume_h2_carrier_test PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_h2_carrier_test PRIVATE)
    yume_apply_perf_opts(yume_h2_carrier_test)
    add_test(NAME yume_h2_carrier_test COMMAND yume_h2_carrier_test)

    if(UNIX)
        add_executable(yume_auth_h2_credit_test
            client/cli/connect/auth_h2_credit_test.cpp)
        target_link_libraries(yume_auth_h2_credit_test PRIVATE
            yume_client_lib)
        yume_link_atomic_if_needed(yume_auth_h2_credit_test PRIVATE)
        yume_apply_perf_opts(yume_auth_h2_credit_test)
        add_test(NAME yume_auth_h2_credit_test
            COMMAND yume_auth_h2_credit_test)

        add_executable(yume_outer_carrier_capture_test
            client/cli/connect/outer_carrier_capture_test.cpp)
        target_link_libraries(yume_outer_carrier_capture_test PRIVATE
            yume_client_lib)
        yume_link_atomic_if_needed(yume_outer_carrier_capture_test PRIVATE)
        yume_apply_perf_opts(yume_outer_carrier_capture_test)
        add_test(NAME yume_outer_carrier_capture_test
            COMMAND yume_outer_carrier_capture_test)
    endif()

    add_executable(yume_cover_profile_test core/stealth/cover_profile_test.cpp)
    target_link_libraries(yume_cover_profile_test PRIVATE yume_core)
    target_compile_definitions(yume_cover_profile_test PRIVATE
        YUME_COVER_MANIFEST="${YUME_ACTIVE_PROFILE_MANIFEST}"
        YUME_COVER_HTTP2_PROFILE="${YUME_ACTIVE_PROFILE_HTTP2}")
    yume_link_atomic_if_needed(yume_cover_profile_test PRIVATE)
    yume_apply_perf_opts(yume_cover_profile_test)
    add_test(NAME yume_cover_profile_test COMMAND yume_cover_profile_test)

    add_executable(yume_h2_opening_probe core/stealth/h2_opening_probe.cpp)
    target_link_libraries(yume_h2_opening_probe PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_h2_opening_probe PRIVATE)
    yume_apply_perf_opts(yume_h2_opening_probe)

    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME yume_transport_profile_generation_check
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/generate_transport_profiles.py"
            --registry "${YUME_TRANSPORT_PROFILE_REGISTRY}"
            --check
    )
    add_test(NAME yume_project_metadata_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_project_metadata.py"
    )
    add_test(NAME yume_socket_autotuning_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_socket_autotuning.py"
    )
    add_test(NAME yume_release_diagnostics_cost_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_release_diagnostics_cost.py"
    )
    if(UNIX AND TARGET yume AND TARGET yumed)
        add_test(NAME yume_federation_v2_integration_test
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/tests/test_yume_federation_v2.py"
                --yume "$<TARGET_FILE:yume>"
                --yumed "$<TARGET_FILE:yumed>"
        )
        set_tests_properties(yume_federation_v2_integration_test PROPERTIES
            TIMEOUT 90)
        # Three nodes in a line. Proves multi-peer link fan-out and pins the
        # single-hop boundary: the far end must stay invisible and unroutable.
        add_test(NAME yume_federation_cluster_integration_test
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/tests/test_yume_federation_cluster.py"
                --yume "$<TARGET_FILE:yume>"
                --yumed "$<TARGET_FILE:yumed>"
        )
        set_tests_properties(yume_federation_cluster_integration_test PROPERTIES
            TIMEOUT 180)
    endif()
    add_test(NAME yume_h2_fingerprint_check
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/yume_h2_fingerprint.py"
            --emitter "$<TARGET_FILE:yume_h2_opening_probe>"
            --check chrome
    )
    add_test(NAME yume_chrome151_evidence_check
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/yume_chrome_evidence.py"
            --fixture "${YUME_ACTIVE_PROFILE_FIXTURE}"
    )
    add_test(NAME yume_browser_sandbox_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/test_yume_browser_sandbox.py"
    )
    find_program(YUME_NODE_EXECUTABLE NAMES node nodejs)
    if(YUME_NODE_EXECUTABLE)
        add_test(NAME yume_cover_node_workload_test
            COMMAND "${YUME_NODE_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/tools/cover-node/workload_test.mjs"
        )
        add_test(NAME yume_chrome_navigation_test
            COMMAND "${YUME_NODE_EXECUTABLE}" --test
                "${CMAKE_SOURCE_DIR}/tools/cover-node/test_capture_chrome_navigation.mjs"
        )
        add_test(NAME yume_cover_server_protocols_test
            COMMAND "${YUME_NODE_EXECUTABLE}" --test
                "${CMAKE_SOURCE_DIR}/tools/cover-node/test_cover_server_protocols.mjs"
        )
    endif()
    add_test(NAME yume_classifier_evidence_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/test_yume_classifier_evidence.py"
    )
    add_test(NAME yume_classifier_gate_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/test_yume_classifier_gate.py"
    )
    add_test(NAME yume_constrained_host_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/test_yume_constrained_host.py"
    )
    add_test(NAME yume_capture_manifest_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/test_yume_capture_manifest.py"
    )
    add_test(NAME yume_capture_binary_provenance_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/test_yume_capture_binary_provenance.py"
    )
    add_test(NAME yume_capture_finalize_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/test_yume_capture_finalize.py"
    )
    add_test(NAME yume_tls_wire_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_yume_tls_wire.py"
    )
    # Compares the ClientHello the production backend actually emits against the
    # committed browser capture, rather than comparing config to config.
    add_executable(yume_tls_clienthello_dump core/stealth/clienthello_dump.cpp)
    target_link_libraries(yume_tls_clienthello_dump PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_tls_clienthello_dump PRIVATE)
    yume_apply_perf_opts(yume_tls_clienthello_dump)
    add_test(NAME yume_native_tls_wire_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_yume_native_tls_wire.py"
    )
    set_tests_properties(yume_native_tls_wire_test PROPERTIES
        ENVIRONMENT
            "YUME_CLIENTHELLO_DUMP=$<TARGET_FILE:yume_tls_clienthello_dump>")
    add_test(NAME yume_tls_wire_profile_check
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/yume_tls_wire.py"
            check-profile
            --profile "${YUME_ACTIVE_PROFILE_TLS_WIRE}"
            ${YUME_ACTIVE_PROFILE_TLS_CANDIDATE_ARGS}
    )
    add_test(NAME yume_setup_installed_layout
        COMMAND "${CMAKE_COMMAND}"
            "-DYUME_BUILD_DIR=${CMAKE_BINARY_DIR}"
            "-DYUME_BUILD_CONFIG=$<CONFIG>"
            "-DYUME_TEST_PREFIX=${CMAKE_BINARY_DIR}/test-install/yume-setup-$<CONFIG>"
            "-DYUME_PYTHON=${Python3_EXECUTABLE}"
            "-DYUME_INSTALL_BINDIR=${CMAKE_INSTALL_BINDIR}"
            "-DYUME_INSTALL_DATADIR=${CMAKE_INSTALL_DATADIR}"
            "-DYUME_DEBIAN_INSTALL_MANIFEST=${CMAKE_SOURCE_DIR}/debian/yume.install"
            "-DYUME_COVER_MANIFEST=${YUME_ACTIVE_PROFILE_MANIFEST}"
            -P "${CMAKE_SOURCE_DIR}/cmake/check_yume_setup_install.cmake"
    )

    add_executable(yume_obfs_test core/stealth/obfs_test.cpp)
    target_link_libraries(yume_obfs_test PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_obfs_test PRIVATE)
    yume_apply_perf_opts(yume_obfs_test)
    add_test(NAME yume_obfs_test COMMAND yume_obfs_test)
endif()

if(YUME_BUILD_SHARED_ABI AND TARGET yume_abi)
    add_executable(yume_abi_stream_open_transaction_test
        abi/service_open_transaction_test.cpp)
    target_include_directories(yume_abi_stream_open_transaction_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})
    yume_apply_warnings(yume_abi_stream_open_transaction_test)
    add_test(NAME yume_abi_stream_open_transaction_test
        COMMAND yume_abi_stream_open_transaction_test)

    add_executable(yume_abi_test abi/yume_c_test.cpp)
    target_include_directories(yume_abi_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(yume_abi_test PRIVATE yume_abi)
    yume_apply_warnings(yume_abi_test)
    target_compile_definitions(yume_abi_test PRIVATE
        YUME_ABI_CLIENT_ONLY=$<BOOL:${YUME_ABI_CLIENT_ONLY}>)
    add_test(NAME yume_abi_test COMMAND yume_abi_test)
    if(NOT YUME_ABI_CLIENT_ONLY AND TARGET yumed)
        add_executable(yume_abi_stream_probe
            abi/stream_integration_probe.c)
        set_target_properties(yume_abi_stream_probe PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF)
        target_link_libraries(yume_abi_stream_probe PRIVATE yume_abi)
        yume_apply_warnings(yume_abi_stream_probe)
        add_test(NAME yume_abi_stream_integration
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/tests/test_yume_abi_stream.py"
                --probe "$<TARGET_FILE:yume_abi_stream_probe>"
                --yumed "$<TARGET_FILE:yumed>"
                --library "$<TARGET_FILE:yume_abi>")
        set_tests_properties(yume_abi_stream_integration PROPERTIES
            TIMEOUT 90)
        if(DEFINED _yume_asan_preload AND NOT _yume_asan_preload STREQUAL "")
            # Python must preload ASan before ctypes opens libyume, but
            # LeakSanitizer cannot distinguish CPython's process-lifetime
            # allocations from leaks. Disable leak checking only in the host
            # interpreter; the harness restores it for every spawned YUME
            # executable through YUME_TEST_CHILD_ASAN_OPTIONS.
            set_property(TEST yume_abi_stream_integration APPEND PROPERTY
                ENVIRONMENT
                    "LD_PRELOAD=${_yume_asan_preload}"
                    "ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1"
                    "YUME_TEST_CHILD_ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1")
        endif()
    endif()
    if(UNIX AND CMAKE_NM)
        if(APPLE)
            set(_yume_abi_format macho)
        else()
            set(_yume_abi_format elf)
        endif()
        add_test(NAME yume_abi_exports
            COMMAND "${CMAKE_COMMAND}"
                "-DYUME_ABI_LIBRARY=$<TARGET_FILE:yume_abi>"
                "-DYUME_NM=${CMAKE_NM}"
                "-DYUME_ABI_MAP=${CMAKE_CURRENT_SOURCE_DIR}/abi/yume.map"
                "-DYUME_ABI_FORMAT=${_yume_abi_format}"
                -P "${CMAKE_SOURCE_DIR}/cmake/check_yume_abi_exports.cmake"
        )
    endif()

    # The version script is the contract; the header is what embedders read.
    # This catches a function declared in one and forgotten in the other.
    add_test(NAME yume_abi_header_matches_map
        COMMAND "${CMAKE_COMMAND}"
            "-DYUME_ABI_MAP=${CMAKE_CURRENT_SOURCE_DIR}/abi/yume.map"
            "-DYUME_ABI_HEADER=${CMAKE_SOURCE_DIR}/include/yume/yume.h"
            -P "${CMAKE_SOURCE_DIR}/cmake/check_yume_abi_header.cmake"
    )
    add_test(NAME yume_abi_debian_symbols_match_map
        COMMAND "${CMAKE_COMMAND}"
            "-DYUME_ABI_MAP=${CMAKE_CURRENT_SOURCE_DIR}/abi/yume.map"
            "-DYUME_DEBIAN_SYMBOLS=${CMAKE_SOURCE_DIR}/debian/libyume1.symbols"
            -P "${CMAKE_SOURCE_DIR}/cmake/check_yume_abi_debian_symbols.cmake"
    )
    if(UNIX AND NOT APPLE AND EXISTS "/usr/bin/dpkg-architecture")
        add_test(NAME yume_abi_installed_consumer
            COMMAND "${CMAKE_COMMAND}"
                "-DYUME_BUILD_DIR=${CMAKE_BINARY_DIR}"
                "-DYUME_BUILD_CONFIG=$<CONFIG>"
                "-DYUME_TEST_PREFIX=${CMAKE_BINARY_DIR}/test-install/libyume-$<CONFIG>"
                "-DYUME_CONSUMER_TEST=${CMAKE_SOURCE_DIR}/debian/tests/libyume-dev"
                "-DYUME_CONSUMER_SANITIZER_FLAGS=${_yume_sanitize_flags}"
                -P "${CMAKE_SOURCE_DIR}/cmake/check_yume_abi_install.cmake"
        )
        set_tests_properties(yume_abi_installed_consumer PROPERTIES
            ENVIRONMENT
                "PKG_CONFIG_PATH=${CMAKE_SOURCE_DIR}/tests/fixtures/pkgconfig-hostile"
        )
    endif()
endif()
endif()

# ---------------------------------------------------------------------------
# Warning-coverage audit.
#
# Every first-party target compiled from this directory or a first-party
# subdirectory must have gone through yume_apply_warnings(), whether directly
# or via yume_apply_perf_opts(). A target that forgets it compiles with no
# warning flags at all and nothing says so - which is exactly how the public
# ABI library ended up as the one unwarned target in the tree.
#
# Add a genuinely exempt target to YUME_WARNING_EXEMPT_TARGETS with a comment
# saying why. Recursion stays below this source directory, so FetchContent and
# BaseFWX targets are outside the audit even when CMake builds them.
# ---------------------------------------------------------------------------
set(YUME_WARNING_EXEMPT_TARGETS
    # These targets compile upstream sources under our GUI build file. The
    # first-party yume-gui target uses SYSTEM includes and is still audited.
    yume_imgui
    yume_implot
)

function(yume_collect_first_party_targets directory project_root out_var)
    get_property(_local_targets DIRECTORY "${directory}"
                 PROPERTY BUILDSYSTEM_TARGETS)
    set(_all_targets ${_local_targets})

    get_property(_subdirectories DIRECTORY "${directory}"
                 PROPERTY SUBDIRECTORIES)
    foreach(_subdirectory IN LISTS _subdirectories)
        # FetchContent source trees live below the build directory, not src/.
        # Do not audit their compiler policy as if they were first-party code.
        string(FIND "${_subdirectory}" "${project_root}/" _project_prefix)
        if(NOT _project_prefix EQUAL 0)
            continue()
        endif()
        yume_collect_first_party_targets(
            "${_subdirectory}" "${project_root}" _subdirectory_targets)
        list(APPEND _all_targets ${_subdirectory_targets})
    endforeach()

    set(${out_var} "${_all_targets}" PARENT_SCOPE)
endfunction()

yume_collect_first_party_targets(
    "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}"
    _yume_dir_targets)
list(REMOVE_DUPLICATES _yume_dir_targets)
get_property(_yume_warned GLOBAL PROPERTY YUME_WARNED_TARGETS)
list(REMOVE_DUPLICATES _yume_warned)

set(_yume_unwarned "")
foreach(_t IN LISTS _yume_dir_targets)
    get_target_property(_type "${_t}" TYPE)
    # INTERFACE and UTILITY targets compile nothing, so there is nothing to warn about.
    if(NOT _type MATCHES "^(EXECUTABLE|STATIC_LIBRARY|SHARED_LIBRARY|MODULE_LIBRARY|OBJECT_LIBRARY)$")
        continue()
    endif()
    if(_t IN_LIST YUME_WARNING_EXEMPT_TARGETS)
        continue()
    endif()
    if(NOT _t IN_LIST _yume_warned)
        list(APPEND _yume_unwarned "${_t}")
    endif()
endforeach()

if(_yume_unwarned)
    string(REPLACE ";" "\n  " _yume_unwarned_text "${_yume_unwarned}")
    message(FATAL_ERROR
        "These targets compile first-party code but never received the project "
        "warning set:\n  ${_yume_unwarned_text}\n"
        "Call yume_apply_perf_opts(<target>) (preferred - it applies warnings too) "
        "or yume_apply_warnings(<target>) for targets whose optimisation settings "
        "must not change, such as the installed shared library. If a target is "
        "genuinely exempt, add it to YUME_WARNING_EXEMPT_TARGETS with a reason.")
endif()

list(LENGTH _yume_warned _yume_warned_count)
message(STATUS "YUME warning set applied to ${_yume_warned_count} first-party targets")
