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

# zstd belongs to the current transport-v2 graph. The dependency-clean YTP/1
# foundations must configure without discovering it.
if(YUME_BUILD_TRANSPORT_V2)
    find_package(zstd CONFIG QUIET)
    if(NOT TARGET zstd::libzstd AND NOT TARGET zstd::libzstd_shared AND NOT TARGET zstd::libzstd_static)
        find_package(ZSTD QUIET)
    endif()
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
if(YUME_BUILD_TRANSPORT_V2 AND YUME_USE_SPDLOG)
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
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
           CMAKE_CXX_COMPILER_VERSION VERSION_LESS 12)
            # GCC 11 propagates an exact string length proved at the call site
            # into libstdc++'s std::string move assignment, then reports
            # -Wstringop-overread against the short-string branch that a
            # string of that length can never take. The diagnostic's location
            # is inside the system header, so a pragma at the call site does
            # not suppress it, and GCC 12 and later do not emit it at all.
            # Demote rather than disable, so the release toolchain still
            # prints it if it ever fires on something real.
            target_compile_options(${target} PRIVATE
                -Wno-error=stringop-overread)
        endif()
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
           _yume_sanitize STREQUAL "thread")
            # GCC diagnoses the atomic fences used by Boost.Asio as not being
            # modeled by TSan. Keep that limitation visible without allowing
            # a third-party header diagnostic to prevent the sanitizer lane
            # from compiling any first-party translation unit.
            target_compile_options(${target} PRIVATE -Wno-error=tsan)
        endif()
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
            $<$<AND:$<STREQUAL:${_yume_sanitize},none>,$<CONFIG:Release,RelWithDebInfo,MinSizeRel>>:-fomit-frame-pointer>
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

# ----------------------------------------------------------------------
# YUME 0.3 dependency-clean foundations
# ----------------------------------------------------------------------
# C++ providers remain internal. The experimental C ABI can be installed by
# explicit opt-in; schema-1 endpoints use the native provider graph. Enabling
# transport v2 also links its reference embedding backend.
include("${CMAKE_SOURCE_DIR}/cmake/YumeLayering.cmake")

add_library(yume_engine STATIC
    engine/buffer.cpp
    engine/buffer.hpp
    engine/byte_channel.hpp
    engine/cancellation.cpp
    engine/cancellation.hpp
    engine/carrier.cpp
    engine/carrier.hpp
    engine/engine_builder.cpp
    engine/engine_builder.hpp
    engine/front_door.hpp
    engine/route_provider.cpp
    engine/route_provider.hpp
    engine/secure_channel.cpp
    engine/secure_channel.hpp
    engine/secure_erase.hpp
    engine/status.cpp
    engine/status.hpp
    engine/stream_handler.cpp
    engine/stream_handler.hpp
    engine/stream_id.cpp
    engine/stream_id.hpp
    engine/transport_suite.cpp
    engine/transport_suite.hpp
    engine/types.hpp
)
add_library(yume::engine ALIAS yume_engine)
target_include_directories(yume_engine PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
yume_apply_perf_opts(yume_engine)

add_library(yume_ytp1 STATIC
    ytp/detail/byte_order.hpp
    ytp/protocol.cpp
    ytp/protocol.hpp
    ytp/security.cpp
    ytp/security.hpp
)
add_library(yume::ytp1 ALIAS yume_ytp1)
target_include_directories(yume_ytp1 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
yume_apply_perf_opts(yume_ytp1)

add_library(yume_session_engine STATIC
    engine/session_engine.cpp
    engine/session_engine.hpp
)
add_library(yume::session_engine ALIAS yume_session_engine)
target_include_directories(yume_session_engine
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(yume_session_engine
    PUBLIC yume_engine
    PRIVATE yume_ytp1)
yume_apply_perf_opts(yume_session_engine)

add_library(yume_session_bootstrap STATIC
    engine/session_bootstrap.cpp
    engine/session_bootstrap.hpp
)
add_library(yume::session_bootstrap ALIAS yume_session_bootstrap)
target_include_directories(yume_session_bootstrap
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(yume_session_bootstrap
    PUBLIC yume_session_engine)
yume_apply_perf_opts(yume_session_bootstrap)

add_library(yume_direct_route_handler STATIC
    providers/direct_route_handler.cpp
    providers/direct_route_handler.hpp)
add_library(yume::direct_route_handler ALIAS yume_direct_route_handler)
target_include_directories(yume_direct_route_handler
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(yume_direct_route_handler PUBLIC yume_engine)
# Only the native endpoint brings this archive into the shared ABI closure.
# Without that backend, propagating -fno-lto breaks consumers that also link
# the LTO-built session/engine archives (including the direct-route test).
if(YUME_BUILD_YTP1_OPENSSL_PROVIDER AND
   YUME_BUILD_YTP1_TLS13_PROVIDER AND
   YUME_BUILD_YTP1_FRONT_DOOR)
    yume_prepare_static_for_shared_abi(yume_direct_route_handler)
endif()
yume_apply_perf_opts(yume_direct_route_handler)

# Packet validation is independent of device attachment and network privilege.
# A caller supplies the device channel and both directional address policies.
add_library(yume_ip_packet_channel STATIC
    common/ip_packet.hpp
    providers/ip_packet_channel.cpp
    providers/ip_packet_channel.hpp)
target_include_directories(yume_ip_packet_channel PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(yume_ip_packet_channel PUBLIC yume_engine)
yume_apply_perf_opts(yume_ip_packet_channel)
yume_assert_exact_link_dependencies(yume_ip_packet_channel yume_engine)

if(YUME_BUILD_YTP1_ASIO_ROUTE_PROVIDER OR
   YUME_BUILD_YTP1_ASIO_TCP_BYTE_CHANNEL_PROVIDER)
    add_library(yume_asio_execution_context STATIC
        providers/asio_execution_context.cpp
        providers/asio_execution_context.hpp
        providers/control_task.hpp)
    target_include_directories(yume_asio_execution_context PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_asio_execution_context PUBLIC yume_engine Boost::system)
    yume_apply_perf_opts(yume_asio_execution_context)
    yume_assert_exact_link_dependencies(yume_asio_execution_context yume_engine Boost::system)

    # System name lookup runs in a killable helper process: getaddrinfo cannot
    # be interrupted, so an in-process lookup could hold final shutdown. The
    # helper side links nothing but libc and threads. yume and yumed serve as
    # their own helper, and yume-resolver serves embedding hosts.
    find_package(Threads REQUIRED)
    # Helpers and modules drop privileges before serving. It links nothing.
    add_library(yume_process_privileges STATIC
        providers/process_privileges.cpp providers/process_privileges.hpp)
    target_include_directories(yume_process_privileges PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    yume_apply_perf_opts(yume_process_privileges)
    yume_prepare_static_for_shared_abi(yume_process_privileges)
    yume_assert_exact_link_dependencies(yume_process_privileges)

    add_library(yume_system_resolver_helper STATIC
        providers/system_resolver_helper.cpp
        providers/system_resolver_helper.hpp
        providers/system_resolver_protocol.hpp)
    target_include_directories(yume_system_resolver_helper PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_system_resolver_helper PRIVATE yume_process_privileges Threads::Threads)
    yume_apply_perf_opts(yume_system_resolver_helper)
    # yume and yumed link without LTO when a shared-ABI build makes their
    # other archives non-LTO, so this archive must not hold LTO-only objects.
    yume_prepare_static_for_shared_abi(yume_system_resolver_helper)
    yume_assert_exact_link_dependencies(yume_system_resolver_helper
        yume_process_privileges Threads::Threads)

    # Spawning, signalling and reaping helper and module processes.
    add_library(yume_child_process STATIC
        providers/child_process.cpp providers/child_process.hpp)
    target_include_directories(yume_child_process PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_child_process PUBLIC yume_engine)
    yume_apply_perf_opts(yume_child_process)
    yume_assert_exact_link_dependencies(yume_child_process yume_engine)

    add_library(yume_system_resolver STATIC
        providers/system_resolver.cpp
        providers/system_resolver.hpp
        providers/system_resolver_protocol.hpp)
    target_include_directories(yume_system_resolver PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_system_resolver
        PUBLIC yume_engine yume_asio_execution_context Boost::system
        PRIVATE yume_child_process)
    yume_apply_perf_opts(yume_system_resolver)
    yume_assert_exact_link_dependencies(yume_system_resolver
        yume_engine yume_asio_execution_context Boost::system yume_child_process)

    if(NOT WIN32)
        add_executable(yume-resolver providers/system_resolver_main.cpp)
        target_link_libraries(yume-resolver PRIVATE yume_system_resolver_helper)
        yume_apply_perf_opts(yume-resolver)
        # SystemResolver refuses a helper that group or others may modify,
        # whatever the build's umask.
        add_custom_command(TARGET yume-resolver POST_BUILD
            COMMAND chmod 0755 "$<TARGET_FILE:yume-resolver>" VERBATIM)
    endif()
endif()

# Concrete direct TCP/connected-UDP egress remains an opt-in provider until
# the replacement endpoint graph is wired and qualified. Its public header is
# a source-level C++20 provider contract; it is not part of the C ABI.
if(YUME_BUILD_YTP1_ASIO_ROUTE_PROVIDER)
    add_library(yume_asio_direct_route_provider STATIC
        providers/asio_direct_route_provider.cpp
        providers/asio_direct_route_provider.hpp)
    add_library(yume::asio_direct_route_provider ALIAS
        yume_asio_direct_route_provider)
    target_include_directories(yume_asio_direct_route_provider
        PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_asio_direct_route_provider
        PUBLIC yume_engine yume_asio_execution_context yume_system_resolver Boost::system)
    yume_apply_perf_opts(yume_asio_direct_route_provider)
endif()

# Client connections and adopted server sockets share one bounded TCP channel
# implementation. Listening and ingress policy belong to the native FrontDoor.
if(YUME_BUILD_YTP1_ASIO_TCP_BYTE_CHANNEL_PROVIDER)
    add_library(yume_asio_tcp_byte_channel_provider STATIC
        providers/asio_tcp_byte_channel_provider.cpp
        providers/asio_tcp_byte_channel_provider.hpp)
    add_library(yume::asio_tcp_byte_channel_provider ALIAS
        yume_asio_tcp_byte_channel_provider)
    target_include_directories(yume_asio_tcp_byte_channel_provider
        PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_asio_tcp_byte_channel_provider
        PUBLIC yume_engine yume_asio_execution_context yume_system_resolver Boost::system)
    yume_apply_perf_opts(yume_asio_tcp_byte_channel_provider)

    # A server reached through a SOCKS5 proxy. Any byte channel provider
    # reaches the proxy, and this one asks it to CONNECT to the target.
    add_library(yume_socks5_upstream STATIC
        providers/socks5_upstream.cpp
        providers/socks5_upstream.hpp)
    target_include_directories(yume_socks5_upstream PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_socks5_upstream
        PUBLIC yume_engine yume_asio_execution_context PRIVATE Boost::system)
    yume_apply_perf_opts(yume_socks5_upstream)
    yume_assert_exact_link_dependencies(yume_socks5_upstream
        yume_engine yume_asio_execution_context Boost::system)
endif()

# Profile data and fingerprint interpretation are shared by TLS and H2. Keep
# the SSL_CTX emitter separate so the H2 carrier never acquires a TLS edge.
if((YUME_BUILD_TRANSPORT_V2 AND NOT YUME_TRANSPORT_CORE_ONLY) OR
   YUME_BUILD_YTP1_H2_CARRIER OR
   YUME_BUILD_YTP1_TLS13_PROVIDER)
    add_library(yume_cover_profile STATIC
        core/stealth/cover_profile.cpp
        core/stealth/cover_profile.hpp
        core/stealth/tls_fingerprint.cpp
        core/stealth/tls_fingerprint.hpp
        core/stealth/transport_profiles.inc)
    target_include_directories(yume_cover_profile PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_cover_profile PRIVATE OpenSSL::Crypto)
    yume_apply_perf_opts(yume_cover_profile)
    yume_assert_exact_link_dependencies(yume_cover_profile OpenSSL::Crypto)
endif()

if((YUME_BUILD_TRANSPORT_V2 AND NOT YUME_TRANSPORT_CORE_ONLY) OR
   YUME_BUILD_YTP1_TLS13_PROVIDER)
    add_library(yume_tls_client_profile STATIC
        core/stealth/tls_client_profile.cpp
        core/stealth/tls_client_profile.hpp)
    target_include_directories(yume_tls_client_profile PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_tls_client_profile
        PUBLIC yume_cover_profile PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    yume_apply_perf_opts(yume_tls_client_profile)
    yume_assert_exact_link_dependencies(yume_tls_client_profile
        yume_cover_profile OpenSSL::SSL OpenSSL::Crypto)
endif()

# Shared admission owns path/authority parsing, the HMAC primitive, and
# replay reservations. Protocol encodings remain with their separate owners.
if((YUME_BUILD_TRANSPORT_V2 AND NOT YUME_TRANSPORT_CORE_ONLY) OR
   YUME_BUILD_YTP1_H2_CARRIER)
    add_library(yume_h2_admission STATIC
        admission/h2_admission.cpp
        admission/h2_admission.hpp)
    target_include_directories(yume_h2_admission PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_h2_admission PRIVATE Boost::headers OpenSSL::Crypto)
    yume_apply_perf_opts(yume_h2_admission)
    yume_assert_exact_link_dependencies(yume_h2_admission Boost::headers OpenSSL::Crypto)
endif()

if(YUME_BUILD_YTP1_H2_CARRIER)
    add_library(yume_ytp1_h2_admission STATIC
        providers/ytp1_h2_admission.cpp
        providers/ytp1_h2_admission.hpp)
    target_include_directories(yume_ytp1_h2_admission PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_ytp1_h2_admission
        PUBLIC yume_h2_admission PRIVATE OpenSSL::Crypto)
    yume_apply_perf_opts(yume_ytp1_h2_admission)
    yume_assert_exact_link_dependencies(yume_ytp1_h2_admission
        yume_h2_admission OpenSSL::Crypto)
endif()

# One HTTP/2/WebSocket state machine serves native YTP and the remaining v2
# callers. It owns framing and receive credit, not TLS or session admission.
if((YUME_BUILD_TRANSPORT_V2 AND NOT YUME_TRANSPORT_CORE_ONLY) OR
   YUME_BUILD_YTP1_H2_CARRIER)
    find_package(Threads REQUIRED)
    add_library(yume_h2_carrier STATIC
        core/stealth/h2_carrier.cpp
        core/stealth/h2_carrier.hpp
        core/stealth/h2_wire_profile.cpp
        core/stealth/h2_wire_profile.hpp
        core/stealth/outer_carrier_observer.cpp
        core/stealth/outer_carrier_observer.hpp
        core/stealth/websocket_codec.cpp
        core/stealth/websocket_codec.hpp)
    target_include_directories(yume_h2_carrier PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_h2_carrier
        PUBLIC yume_cover_profile
        PRIVATE ${YUME_NGHTTP2_TARGET} OpenSSL::Crypto Threads::Threads)
    # H2Carrier and timing.hpp expose conditional declarations. Every caller
    # must see the same configuration; Release/MinSizeRel keep diagnostics off.
    yume_apply_dev_diagnostics(yume_h2_carrier PUBLIC)
    yume_prepare_static_for_shared_abi(yume_h2_carrier)
    yume_apply_perf_opts(yume_h2_carrier)
    yume_assert_exact_link_dependencies(yume_h2_carrier
        yume_cover_profile ${YUME_NGHTTP2_TARGET} OpenSSL::Crypto Threads::Threads)
endif()

if(YUME_BUILD_YTP1_H2_CARRIER)
    add_library(yume_ytp1_h2_carrier STATIC
        providers/ytp1_h2_carrier.cpp
        providers/ytp1_h2_carrier.hpp
        providers/control_task.hpp)
    add_library(yume::ytp1_h2_carrier ALIAS yume_ytp1_h2_carrier)
    target_include_directories(yume_ytp1_h2_carrier
        PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_ytp1_h2_carrier
        PUBLIC yume_engine yume_h2_carrier
        PRIVATE yume_ytp1_h2_admission OpenSSL::Crypto)
    yume_apply_perf_opts(yume_ytp1_h2_carrier)
endif()

# The first concrete YTP/1 security-provider candidate is deliberately an
# opt-in, build-tree-only target. It uses upstream OpenSSL 3.5 primitives but
# is not part of the runnable transport-v2 graph and is not release-qualified.
if(YUME_BUILD_YTP1_OPENSSL_PROVIDER)
    add_library(yume_ytp1_openssl_security STATIC
        providers/ytp1_crypto.cpp
        providers/ytp1_crypto.hpp
        providers/ytp1_security_provider.cpp
        providers/ytp1_security_provider.hpp)
    add_library(yume::ytp1_openssl_security ALIAS
        yume_ytp1_openssl_security)
    target_include_directories(yume_ytp1_openssl_security
        PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_ytp1_openssl_security
        PUBLIC yume_session_engine yume_ytp1
        PRIVATE OpenSSL::Crypto)
    yume_apply_perf_opts(yume_ytp1_openssl_security)
endif()

# Memory-BIO TLS wraps the engine ByteChannel contract and therefore has no
# socket dependency. Its client applies the shared browser TLS profile; it
# does not implement the HTTP front door or H2 carrier.
if(YUME_BUILD_YTP1_TLS13_PROVIDER)
    add_library(yume_ytp1_tls13_secure_channel STATIC
        providers/ytp1_tls13_secure_channel.cpp
        providers/ytp1_tls13_secure_channel.hpp)
    add_library(yume::ytp1_tls13_secure_channel ALIAS
        yume_ytp1_tls13_secure_channel)
    target_include_directories(yume_ytp1_tls13_secure_channel
        PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_ytp1_tls13_secure_channel
        PUBLIC yume_engine PRIVATE yume_tls_client_profile OpenSSL::SSL OpenSSL::Crypto)
    yume_apply_perf_opts(yume_ytp1_tls13_secure_channel)
endif()

# Bounded, confined file reads are shared by native cover, v2 stores/sites and
# the share module. Keep their handle ownership independent of any runtime.
if((YUME_BUILD_TRANSPORT_V2 AND NOT YUME_TRANSPORT_CORE_ONLY) OR
   YUME_BUILD_YTP1_FRONT_DOOR OR YUME_BUILD_BASEFWX_MODULES)
    add_library(yume_bounded_files STATIC
        core/runtime/bounded_file.cpp
        core/runtime/bounded_file.hpp)
    target_include_directories(yume_bounded_files PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    yume_prepare_static_for_shared_abi(yume_bounded_files)
    yume_apply_perf_opts(yume_bounded_files)
    yume_assert_exact_link_dependencies(yume_bounded_files)
endif()

if(YUME_BUILD_YTP1_FRONT_DOOR)
    add_library(yume_ytp1_cover_site STATIC
        providers/ytp1_cover_site.cpp
        providers/ytp1_cover_site.hpp)
    target_include_directories(yume_ytp1_cover_site PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_ytp1_cover_site PUBLIC yume_engine PRIVATE yume_bounded_files)
    yume_apply_perf_opts(yume_ytp1_cover_site)
    yume_assert_exact_link_dependencies(yume_ytp1_cover_site yume_engine yume_bounded_files)

    # Bounded GET/HEAD fetches from a loopback web server, for a cover site
    # that a local backend provides.
    add_library(yume_loopback_http_fetch STATIC
        providers/loopback_http_fetch.cpp
        providers/loopback_http_fetch.hpp)
    target_include_directories(yume_loopback_http_fetch PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_loopback_http_fetch
        PUBLIC yume_engine yume_asio_execution_context PRIVATE Boost::system)
    yume_apply_perf_opts(yume_loopback_http_fetch)
    yume_assert_exact_link_dependencies(yume_loopback_http_fetch
        yume_engine yume_asio_execution_context Boost::system)

    add_library(yume_ytp1_front_door STATIC
        providers/ytp1_front_door.cpp
        providers/ytp1_front_door.hpp)
    add_library(yume::ytp1_front_door ALIAS yume_ytp1_front_door)
    target_include_directories(yume_ytp1_front_door PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_ytp1_front_door PUBLIC
        yume_engine yume_asio_execution_context yume_asio_tcp_byte_channel_provider
        yume_ytp1_tls13_secure_channel yume_ytp1_h2_carrier
        yume_ytp1_cover_site yume_h2_admission
        PRIVATE yume_ytp1_h2_admission Boost::system OpenSSL::Crypto)
    yume_apply_perf_opts(yume_ytp1_front_door)
    yume_assert_exact_link_dependencies(yume_ytp1_front_door
        yume_engine yume_asio_execution_context yume_asio_tcp_byte_channel_provider
        yume_ytp1_tls13_secure_channel yume_ytp1_h2_carrier
        yume_ytp1_cover_site yume_h2_admission
        yume_ytp1_h2_admission Boost::system OpenSSL::Crypto)
endif()

add_library(yume_config_v1 STATIC
    config/v1/config.cpp
    config/v1/config.hpp
)
add_library(yume::config_v1 ALIAS yume_config_v1)
target_include_directories(yume_config_v1 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(yume_config_v1 PUBLIC nlohmann_json::nlohmann_json)
yume_prepare_static_for_shared_abi(yume_config_v1)
yume_apply_perf_opts(yume_config_v1)

add_library(yume_private_files STATIC core/security/secret_file.cpp)
target_include_directories(yume_private_files PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
if(WIN32)
    target_link_libraries(yume_private_files PRIVATE advapi32)
endif()
yume_apply_perf_opts(yume_private_files)
if(WIN32)
    yume_assert_exact_link_dependencies(yume_private_files advapi32)
else()
    yume_assert_exact_link_dependencies(yume_private_files)
endif()

if(YUME_BUILD_YTP1_OPENSSL_PROVIDER AND
   YUME_BUILD_YTP1_TLS13_PROVIDER)
    add_library(yume_native_credentials STATIC
        runtime/native_credentials.cpp runtime/native_credentials.hpp)
    target_include_directories(yume_native_credentials PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_native_credentials
        PUBLIC yume_config_v1 yume_engine
        PRIVATE yume_private_files yume_ytp1_openssl_security
            yume_ytp1_tls13_secure_channel OpenSSL::Crypto)
    yume_apply_perf_opts(yume_native_credentials)
    yume_assert_exact_link_dependencies(yume_native_credentials
        yume_config_v1 yume_engine yume_private_files yume_ytp1_openssl_security
        yume_ytp1_tls13_secure_channel OpenSSL::Crypto)

    if(YUME_BUILD_YTP1_FRONT_DOOR)
        # Operator egress lists: JSON lists, the VPN provider database and
        # MaxMind country databases, swept into disjoint ranges at load.
        add_library(yume_egress_lists STATIC
            runtime/egress_lists.cpp runtime/egress_lists.hpp)
        target_include_directories(yume_egress_lists PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
        target_link_libraries(yume_egress_lists
            PUBLIC yume_engine PRIVATE nlohmann_json::nlohmann_json)
        yume_apply_perf_opts(yume_egress_lists)
        yume_assert_exact_link_dependencies(yume_egress_lists
            yume_engine nlohmann_json::nlohmann_json)

        # Destination authority from schema-1 direct adapters, narrowed by
        # their egress lists. The endpoint and standalone route providers share
        # one instance of this evaluator.
        add_library(yume_native_egress_policy STATIC
            runtime/native_egress_policy.cpp runtime/native_egress_policy.hpp
            common/egress_address.hpp common/ip_network.hpp)
        target_include_directories(yume_native_egress_policy PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
        target_link_libraries(yume_native_egress_policy
            PUBLIC yume_config_v1 yume_engine
            PRIVATE yume_egress_lists yume_bounded_files)
        yume_apply_perf_opts(yume_native_egress_policy)
        yume_assert_exact_link_dependencies(yume_native_egress_policy
            yume_config_v1 yume_engine yume_egress_lists yume_bounded_files)

        # Weighted egress pacing. The endpoint wraps each served stream in it
        # when the server configuration sets limits.max_egress_mbps.
        add_library(yume_egress_pacing STATIC
            runtime/egress_limiter.cpp runtime/egress_limiter.hpp
            runtime/paced_stream.cpp runtime/paced_stream.hpp)
        target_include_directories(yume_egress_pacing PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
        target_link_libraries(yume_egress_pacing
            PUBLIC yume_engine yume_asio_execution_context PRIVATE Boost::system)
        yume_apply_perf_opts(yume_egress_pacing)
        yume_assert_exact_link_dependencies(yume_egress_pacing
            yume_engine yume_asio_execution_context Boost::system)

        add_library(yume_native_endpoint STATIC
            runtime/native_endpoint.cpp runtime/native_endpoint.hpp
            runtime/accept_scheduler.hpp)
        target_include_directories(yume_native_endpoint PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
        target_link_libraries(yume_native_endpoint
            PUBLIC yume_config_v1 yume_session_bootstrap yume_asio_execution_context yume_asio_tcp_byte_channel_provider
            PRIVATE yume_native_credentials yume_ytp1_front_door yume_ytp1_openssl_security
                yume_ytp1_h2_carrier yume_ytp1_tls13_secure_channel yume_cover_profile
                yume_direct_route_handler yume_native_egress_policy yume_egress_pacing Boost::system)
        yume_apply_perf_opts(yume_native_endpoint)
        yume_assert_exact_link_dependencies(yume_native_endpoint
            yume_config_v1 yume_session_bootstrap yume_asio_execution_context yume_asio_tcp_byte_channel_provider
            yume_native_credentials yume_ytp1_front_door yume_ytp1_openssl_security
            yume_ytp1_h2_carrier yume_ytp1_tls13_secure_channel yume_cover_profile
            yume_direct_route_handler yume_native_egress_policy yume_egress_pacing Boost::system)

        if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET yume_asio_direct_route_provider)
            find_package(PkgConfig REQUIRED)
            pkg_check_modules(YUME_SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
            add_library(yume_linux_tun_packet_channel STATIC
                providers/linux_tun_packet_channel.cpp providers/linux_tun_packet_channel.hpp)
            target_include_directories(yume_linux_tun_packet_channel PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
            target_link_libraries(yume_linux_tun_packet_channel PUBLIC yume_engine yume_asio_execution_context PRIVATE Boost::system)
            yume_apply_perf_opts(yume_linux_tun_packet_channel)
            yume_assert_exact_link_dependencies(yume_linux_tun_packet_channel yume_engine yume_asio_execution_context Boost::system)
            add_library(yume_linux_tun_network STATIC
                runtime/linux_tun_network.cpp runtime/linux_tun_network.hpp)
            target_include_directories(yume_linux_tun_network PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
            target_link_libraries(yume_linux_tun_network PUBLIC yume_config_v1 yume_linux_tun_packet_channel yume_asio_execution_context yume_engine PRIVATE PkgConfig::YUME_SYSTEMD)
            yume_apply_perf_opts(yume_linux_tun_network)
            yume_assert_exact_link_dependencies(yume_linux_tun_network yume_config_v1 yume_linux_tun_packet_channel yume_asio_execution_context yume_engine PkgConfig::YUME_SYSTEMD)
        endif()

        add_library(yume_native_packet_adapter STATIC
            runtime/native_packet_adapter.cpp runtime/native_packet_adapter.hpp)
        target_include_directories(yume_native_packet_adapter PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
        target_link_libraries(yume_native_packet_adapter PUBLIC yume_config_v1 yume_engine yume_asio_execution_context
            PRIVATE yume_ip_packet_channel yume_direct_route_handler)
        yume_apply_perf_opts(yume_native_packet_adapter)
        yume_assert_exact_link_dependencies(yume_native_packet_adapter
            yume_config_v1 yume_engine yume_asio_execution_context yume_ip_packet_channel yume_direct_route_handler)
        set(_yume_native_network_libraries yume_native_packet_adapter)
        if(TARGET yume_linux_tun_network)
            list(APPEND _yume_native_network_libraries yume_linux_tun_network)
        endif()

        # yume and yumed run as yume-module to launch a module after dropping
        # privileges. Like the resolver helper it links almost nothing.
        add_library(yume_module_launcher STATIC
            runtime/module_launcher.cpp runtime/module_launcher.hpp)
        target_include_directories(yume_module_launcher PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
        target_link_libraries(yume_module_launcher PRIVATE yume_process_privileges)
        yume_apply_perf_opts(yume_module_launcher)
        yume_prepare_static_for_shared_abi(yume_module_launcher)
        yume_assert_exact_link_dependencies(yume_module_launcher yume_process_privileges)

        # One application composition owns the normal client and daemon.
        # Reference transport-v2 programs below are never installed.
        if(TARGET yume_asio_direct_route_provider)
            add_library(yume_native_runtime STATIC
                runtime/native_cli.cpp runtime/native_cli.hpp
                runtime/native_client_runtime.cpp runtime/native_client_runtime.hpp
                runtime/native_server_runtime.cpp runtime/native_server_runtime.hpp
                runtime/local_listener.cpp runtime/local_listener.hpp
                runtime/module_supervisor.cpp runtime/module_supervisor.hpp
                runtime/native_forward.cpp runtime/native_forward.hpp
                runtime/native_session_source.hpp
                runtime/native_socks5.cpp runtime/native_socks5.hpp
                runtime/native_socks5_udp.cpp runtime/native_socks5_udp.hpp
                runtime/socks5_request.cpp runtime/socks5_request.hpp)
            target_include_directories(yume_native_runtime PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
            target_link_libraries(yume_native_runtime
                PUBLIC yume_config_v1 yume_session_bootstrap yume_asio_execution_context
                PRIVATE yume_native_endpoint yume_native_egress_policy yume_native_credentials
                    yume_asio_direct_route_provider yume_asio_tcp_byte_channel_provider
                    yume_system_resolver yume_system_resolver_helper
                    yume_child_process yume_module_launcher
                    yume_direct_route_handler yume_ytp1_openssl_security yume_bounded_files ${_yume_native_network_libraries}
                    Boost::system)
            yume_apply_perf_opts(yume_native_runtime)
            yume_assert_exact_link_dependencies(yume_native_runtime
                yume_config_v1 yume_session_bootstrap yume_asio_execution_context
                yume_native_endpoint yume_native_egress_policy yume_native_credentials
                yume_asio_direct_route_provider yume_asio_tcp_byte_channel_provider
                yume_system_resolver yume_system_resolver_helper
                yume_child_process yume_module_launcher
                yume_direct_route_handler yume_ytp1_openssl_security yume_bounded_files ${_yume_native_network_libraries}
                Boost::system)
            # The example module. It links nothing of YUME.
            add_executable(yume-echo-module modules/echo/echo_module.cpp)
            target_link_libraries(yume-echo-module PRIVATE Threads::Threads)
            yume_apply_perf_opts(yume-echo-module)
            add_custom_command(TARGET yume-echo-module POST_BUILD
                COMMAND chmod 0755 "$<TARGET_FILE:yume-echo-module>" VERBATIM)
            if(YUME_BUILD_NATIVE_APPLICATION)
                add_executable(yumed runtime/yumed_main.cpp)
                add_executable(yume runtime/yume_main.cpp)
                foreach(_yume_native_program IN ITEMS yumed yume)
                    target_link_libraries(${_yume_native_program} PRIVATE yume_native_runtime)
                    yume_apply_perf_opts(${_yume_native_program})
                endforeach()
                install(TARGETS yume yumed
                    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT yume_cli)
            endif()
        endif()

        # The YTP/1 embedding backend adapts the native endpoint to the
        # blocking seam behind the C ABI. The exact list keeps the
        # transport-v2 graph and BaseFWX out of it.
        find_package(Threads REQUIRED)
        add_library(yume_embed_ytp1 STATIC
            facade/session/ytp1_backend.cpp facade/session/endpoint_backend.hpp)
        target_include_directories(yume_embed_ytp1 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
        # The backend reports the security provider's identity and OpenSSL
        # release, so it names that provider rather than reaching it through
        # the runtime's private links.
        target_link_libraries(yume_embed_ytp1 PRIVATE
            yume_native_endpoint yume_ytp1_openssl_security Threads::Threads Boost::system)
        yume_apply_perf_opts(yume_embed_ytp1)
        yume_assert_exact_link_dependencies(yume_embed_ytp1
            yume_native_endpoint yume_ytp1_openssl_security Threads::Threads Boost::system)
    endif()
endif()

# Module libraries built on BaseFWX. They link nothing of the transport core,
# and the exact link lists above keep BaseFWX out of every core target.
if(YUME_BUILD_BASEFWX_MODULES)
    if(NOT TARGET basefwxcpp)
        message(FATAL_ERROR
            "YUME_BUILD_BASEFWX_MODULES needs the BaseFWX checkout in basefwx/ "
            "at the revision config/dependencies.json pins")
    endif()
    if(NOT UNIX)
        message(FATAL_ERROR
            "YUME_BUILD_BASEFWX_MODULES needs POSIX descriptor-relative file access")
    endif()
    # The relay v2 end-to-end channel between two users: handshake, records
    # and the hybrid ratchet, the protected chat history, relay secret and
    # peer trust stores its users keep, and the invite and directory records
    # with the policies that check them.
    add_library(yume_module_relay STATIC
        modules/relay/base64.cpp modules/relay/base64.hpp
        modules/relay/channel_kind.hpp
        modules/relay/control.cpp modules/relay/control.hpp
        modules/relay/control_fields.hpp
        modules/relay/directory_policy.cpp modules/relay/directory_policy.hpp
        modules/relay/frame.hpp
        modules/relay/handshake.cpp modules/relay/handshake.hpp
        modules/relay/history.cpp modules/relay/history.hpp
        modules/relay/identity.cpp modules/relay/identity.hpp
        modules/relay/json_policy.hpp
        modules/relay/peer_trust.cpp modules/relay/peer_trust.hpp
        modules/relay/ratchet.cpp modules/relay/ratchet.hpp
        modules/relay/ratchet_policy.hpp
        modules/relay/record.cpp modules/relay/record.hpp
        modules/relay/rekey_record.cpp modules/relay/rekey_record.hpp
        modules/relay/relay_limits.hpp
        modules/relay/relay_policy.cpp modules/relay/relay_policy.hpp
        modules/relay/secret.cpp modules/relay/secret.hpp
        modules/relay/session_ratchet.cpp modules/relay/session_ratchet.hpp
        modules/relay/storage_crypto.cpp modules/relay/storage_crypto.hpp)
    target_include_directories(yume_module_relay PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    # Public so its consumers also get the non-LTO compile option a shared-ABI
    # build puts on yume_private_files. A private edge would pass on only the
    # link option, and LTO-only test objects would then fail to link.
    target_link_libraries(yume_module_relay
        PUBLIC basefwxcpp OpenSSL::Crypto nlohmann_json::nlohmann_json yume_private_files)
    yume_apply_perf_opts(yume_module_relay)
    yume_assert_exact_link_dependencies(yume_module_relay
        basefwxcpp OpenSSL::Crypto nlohmann_json::nlohmann_json yume_private_files)

    # Relay file transfer for the planned file module: an outbound source
    # pinned to one opened file, and a confined receiver that publishes only
    # a verified file.
    add_library(yume_module_files STATIC
        modules/files/file_receiver.cpp modules/files/file_receiver.hpp
        modules/files/outbound_source.cpp modules/files/outbound_source.hpp)
    target_include_directories(yume_module_files PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_module_files PUBLIC yume_module_relay PRIVATE basefwxcpp)
    yume_apply_perf_opts(yume_module_files)
    yume_assert_exact_link_dependencies(yume_module_files yume_module_relay basefwxcpp)

    # The password-sealed .yss container, for a planned kit import format.
    # Public edges for the same non-LTO reason as the relay library.
    add_library(yume_module_share STATIC
        modules/share/bundle_file.cpp modules/share/bundle_file.hpp)
    target_include_directories(yume_module_share PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_module_share PUBLIC
        basefwxcpp nlohmann_json::nlohmann_json yume_bounded_files yume_private_files)
    yume_apply_perf_opts(yume_module_share)
    yume_assert_exact_link_dependencies(yume_module_share
        basefwxcpp nlohmann_json::nlohmann_json yume_bounded_files yume_private_files)
endif()

# The application codec core for the planned codec module: the HTTP request
# and response envelope, backend dialing rules and the Monero RPC descriptor.
# It needs no BaseFWX and links nothing of the transport core.
if(TARGET Boost::headers)
    add_library(yume_module_codecs STATIC
        modules/codecs/codec.cpp modules/codecs/codec.hpp
        modules/codecs/internal.hpp
        modules/codecs/monero_rpc.cpp modules/codecs/monero_rpc.hpp)
    target_include_directories(yume_module_codecs PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_module_codecs PRIVATE Boost::headers nlohmann_json::nlohmann_json)
    yume_apply_perf_opts(yume_module_codecs)
    yume_assert_exact_link_dependencies(yume_module_codecs
        Boost::headers nlohmann_json::nlohmann_json)
endif()

# The 0.3 ABI is intentionally build-tree-only and unfrozen. Each configuration
# dialect reaches its own backend through the embed seam. Transport v2 links
# yume_embed. Schema 1 starts only when the native provider graph supplies
# yume_embed_ytp1, and otherwise fails closed. It has no install, export or
# package rule.
if(YUME_BUILD_SHARED_ABI)
    # One translation unit. The shell owns handles, validation, diagnostics,
    # and callback rules; every runtime lives behind the embed seam.
    add_library(yume_abi SHARED abi/yume_c.cpp)
    add_library(yume::yume ALIAS yume_abi)
    set_target_properties(yume_abi PROPERTIES
        OUTPUT_NAME yume
        EXPORT_NAME yume
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
    )
    yume_apply_warnings(yume_abi)
    target_compile_definitions(yume_abi PRIVATE YUME_ABI_BUILD=1)
    target_include_directories(yume_abi
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}"
    )
    if(YUME_BUILD_TRANSPORT_V2 AND NOT YUME_TRANSPORT_CORE_ONLY)
        target_compile_definitions(yume_abi PRIVATE YUME_ABI_TRANSPORT_V2=1)
        # yume_embed, not yume_facade: the shared library must not carry the
        # GUI's session objects, traffic meter, profile switching, or CA
        # material import.
        target_link_libraries(yume_abi PRIVATE yume_config_v1 yume_embed)
    else()
        target_link_libraries(yume_abi PRIVATE yume_config_v1)
    endif()
    if(TARGET yume_embed_ytp1)
        target_compile_definitions(yume_abi PRIVATE YUME_ABI_YTP1=1)
        target_link_libraries(yume_abi PRIVATE yume_embed_ytp1)
        # Every archive absorbed into libyume must be PIC, hidden and non-LTO,
        # including the whole native chain behind the schema-1 backend.
        foreach(_yume_absorbed IN ITEMS
                yume_embed_ytp1 yume_native_endpoint yume_native_egress_policy yume_native_credentials
                yume_egress_pacing yume_session_bootstrap yume_session_engine yume_engine yume_ytp1
                yume_asio_execution_context yume_asio_tcp_byte_channel_provider yume_system_resolver
                yume_child_process
                yume_ytp1_front_door yume_ytp1_cover_site yume_ytp1_h2_carrier
                yume_ytp1_h2_admission yume_h2_admission
                yume_ytp1_tls13_secure_channel yume_tls_client_profile
                yume_cover_profile yume_ytp1_openssl_security yume_private_files)
            yume_prepare_static_for_shared_abi(${_yume_absorbed})
        endforeach()
    endif()

    if(YUME_INSTALL_EXPERIMENTAL_SDK)
        include(CMakePackageConfigHelpers)
        install(TARGETS yume_abi EXPORT yumeTargets
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT libyume_runtime
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT libyume_runtime
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT libyume_development)
        install(FILES "${CMAKE_SOURCE_DIR}/include/yume/yume.h"
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/yume" COMPONENT libyume_development)
        install(EXPORT yumeTargets NAMESPACE yume::
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/yume" COMPONENT libyume_development)
        # Embedding hosts pass this helper as the runtime's resolver program.
        # The package metadata names its installed location.
        set(YUME_RESOLVER_INSTALL_PATH "${CMAKE_INSTALL_LIBEXECDIR}/yume/yume-resolver")
        install(TARGETS yume-resolver
            RUNTIME DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/yume" COMPONENT libyume_runtime)
        configure_package_config_file("${CMAKE_SOURCE_DIR}/cmake/yumeConfig.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/yumeConfig.cmake"
            INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/yume"
            PATH_VARS YUME_RESOLVER_INSTALL_PATH)
        install(FILES "${CMAKE_CURRENT_BINARY_DIR}/yumeConfig.cmake"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/yume" COMPONENT libyume_development)
        file(RELATIVE_PATH YUME_PC_PREFIX_FROM_PKGCONFIG
            "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig" "${CMAKE_INSTALL_PREFIX}")
        configure_file("${CMAKE_SOURCE_DIR}/cmake/yume.pc.in"
            "${CMAKE_CURRENT_BINARY_DIR}/yume.pc" @ONLY)
        install(FILES "${CMAKE_CURRENT_BINARY_DIR}/yume.pc"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig" COMPONENT libyume_development)
    endif()

    # The canonical map is the only exported-symbol allowlist on ELF and the
    # source for the equivalent Mach-O list. PE exports only YUME_API symbols.
    set(_yume_abi_version_script "${CMAKE_CURRENT_SOURCE_DIR}/abi/yume.map")
    if(UNIX AND NOT APPLE)
        target_link_options(yume_abi PRIVATE
            "LINKER:--version-script=${_yume_abi_version_script}"
            "LINKER:--exclude-libs,ALL"
        )
        set_property(TARGET yume_abi APPEND PROPERTY
            LINK_DEPENDS "${_yume_abi_version_script}")
    elseif(APPLE)
        set(_yume_abi_symbol_list
            "${CMAKE_CURRENT_BINARY_DIR}/yume.exported_symbols")
        yume_write_macho_symbol_list(
            "${_yume_abi_version_script}" "${_yume_abi_symbol_list}")
        target_link_options(yume_abi PRIVATE
            "LINKER:-exported_symbols_list,${_yume_abi_symbol_list}")
        set_property(TARGET yume_abi APPEND PROPERTY
            LINK_DEPENDS "${_yume_abi_version_script}")
    endif()

endif()

# Make accidental dependency creep fail at configure time. Source-layer checks
# are also registered with CTest so edits are rechecked without relying on an
# already-configured build tree.
yume_assert_exact_link_dependencies(yume_engine)
yume_assert_exact_link_dependencies(yume_ytp1)
yume_assert_exact_link_dependencies(
    yume_session_engine yume_engine yume_ytp1)
yume_assert_exact_link_dependencies(
    yume_session_bootstrap yume_session_engine)
if(YUME_BUILD_YTP1_OPENSSL_PROVIDER)
    yume_assert_exact_link_dependencies(
        yume_ytp1_openssl_security
        yume_session_engine yume_ytp1 OpenSSL::Crypto)
endif()
if(YUME_BUILD_YTP1_TLS13_PROVIDER)
    yume_assert_exact_link_dependencies(
        yume_ytp1_tls13_secure_channel
        yume_engine yume_tls_client_profile OpenSSL::SSL OpenSSL::Crypto)
endif()
yume_assert_exact_link_dependencies(
    yume_config_v1 nlohmann_json::nlohmann_json)
yume_assert_exact_link_dependencies(
    yume_direct_route_handler yume_engine)
# Both network providers resolve names only through the SystemResolver helper
# process, never an in-process getaddrinfo.
if(YUME_BUILD_YTP1_ASIO_ROUTE_PROVIDER)
    yume_assert_exact_link_dependencies(
        yume_asio_direct_route_provider yume_engine yume_asio_execution_context
        yume_system_resolver Boost::system)
endif()
if(YUME_BUILD_YTP1_ASIO_TCP_BYTE_CHANNEL_PROVIDER)
    yume_assert_exact_link_dependencies(
        yume_asio_tcp_byte_channel_provider yume_engine yume_asio_execution_context
        yume_system_resolver Boost::system)
endif()
if(YUME_BUILD_YTP1_H2_CARRIER)
    yume_assert_exact_link_dependencies(
        yume_ytp1_h2_carrier
        yume_engine yume_h2_carrier yume_ytp1_h2_admission OpenSSL::Crypto)
endif()
if(YUME_BUILD_SHARED_ABI)
    set(_yume_abi_backends)
    if(YUME_BUILD_TRANSPORT_V2 AND NOT YUME_TRANSPORT_CORE_ONLY)
        list(APPEND _yume_abi_backends yume_embed)
    endif()
    if(TARGET yume_embed_ytp1)
        list(APPEND _yume_abi_backends yume_embed_ytp1)
    endif()
    yume_assert_exact_link_dependencies(
        yume_abi yume_config_v1 ${_yume_abi_backends})
endif()
yume_check_03_source_layering("${CMAKE_SOURCE_DIR}")

if(YUME_BUILD_TESTING)
    # Schema-1 provisioning is part of the native application contract. Keep
    # these tests outside the optional transport-v2 reference graph.
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME yume_setup_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_yume_setup.py")
    add_test(NAME yume_doctor_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_yume_doctor.py")
    set_tests_properties(yume_setup_test yume_doctor_test PROPERTIES
        TIMEOUT 300 LABELS "native-runtime;provisioning")

    if(TARGET yume_module_relay)
        foreach(_yume_relay_test IN ITEMS ratchet rekey_record session_ratchet record handshake
                identity persistence peer_trust relay_policy directory_policy)
            set(_yume_relay_target yume_module_relay_${_yume_relay_test}_test)
            add_executable(${_yume_relay_target} modules/relay/${_yume_relay_test}_test.cpp)
            target_link_libraries(${_yume_relay_target} PRIVATE yume_module_relay)
            yume_apply_perf_opts(${_yume_relay_target})
            # These tests check with assert, which must stay on in release builds.
            if(MSVC)
                target_compile_options(${_yume_relay_target} PRIVATE /UNDEBUG)
            else()
                target_compile_options(${_yume_relay_target} PRIVATE -UNDEBUG)
            endif()
            add_test(NAME ${_yume_relay_target} COMMAND ${_yume_relay_target})
            set_tests_properties(${_yume_relay_target} PROPERTIES
                TIMEOUT 120 LABELS "module;relay")
        endforeach()
        target_compile_definitions(yume_module_relay_identity_test PRIVATE
            YUME_RELAY_TESTDATA="${CMAKE_CURRENT_SOURCE_DIR}/modules/relay/testdata")
    endif()
    if(TARGET yume_module_codecs)
        add_executable(yume_module_codecs_codec_test modules/codecs/codec_test.cpp)
        target_link_libraries(yume_module_codecs_codec_test
            PRIVATE yume_module_codecs nlohmann_json::nlohmann_json)
        yume_apply_perf_opts(yume_module_codecs_codec_test)
        # The test checks with assert, which must stay on in release builds.
        if(MSVC)
            target_compile_options(yume_module_codecs_codec_test PRIVATE /UNDEBUG)
        else()
            target_compile_options(yume_module_codecs_codec_test PRIVATE -UNDEBUG)
        endif()
        add_test(NAME yume_module_codecs_codec_test COMMAND yume_module_codecs_codec_test)
        set_tests_properties(yume_module_codecs_codec_test PROPERTIES
            TIMEOUT 60 LABELS "module;codecs")
    endif()
    if(TARGET yume_module_files)
        foreach(_yume_files_test IN ITEMS file_receiver outbound_source)
            set(_yume_files_target yume_module_files_${_yume_files_test}_test)
            add_executable(${_yume_files_target} modules/files/${_yume_files_test}_test.cpp)
            target_link_libraries(${_yume_files_target} PRIVATE yume_module_files)
            yume_apply_perf_opts(${_yume_files_target})
            # These tests check with assert, which must stay on in release builds.
            if(MSVC)
                target_compile_options(${_yume_files_target} PRIVATE /UNDEBUG)
            else()
                target_compile_options(${_yume_files_target} PRIVATE -UNDEBUG)
            endif()
            add_test(NAME ${_yume_files_target} COMMAND ${_yume_files_target})
            set_tests_properties(${_yume_files_target} PROPERTIES
                TIMEOUT 120 LABELS "module;files")
        endforeach()
    endif()
    if(TARGET yume_module_share)
        foreach(_yume_share_test IN ITEMS bundle_file bundle_file_lifetime)
            set(_yume_share_target yume_module_share_${_yume_share_test}_test)
            add_executable(${_yume_share_target} modules/share/${_yume_share_test}_test.cpp)
            target_link_libraries(${_yume_share_target} PRIVATE yume_module_share)
            yume_apply_perf_opts(${_yume_share_target})
            # These tests check with assert, which must stay on in release builds.
            if(MSVC)
                target_compile_options(${_yume_share_target} PRIVATE /UNDEBUG)
            else()
                target_compile_options(${_yume_share_target} PRIVATE -UNDEBUG)
            endif()
            add_test(NAME ${_yume_share_target} COMMAND ${_yume_share_target})
            set_tests_properties(${_yume_share_target} PROPERTIES
                TIMEOUT 120 LABELS "module;share")
        endforeach()
    endif()
    if(YUME_BUILD_NATIVE_APPLICATION)
        add_test(NAME yume_setup_installed_layout
            COMMAND "${CMAKE_COMMAND}"
                "-DYUME_BUILD_DIR=${CMAKE_BINARY_DIR}"
                "-DYUME_BUILD_CONFIG=$<CONFIG>"
                "-DYUME_TEST_PREFIX=${CMAKE_BINARY_DIR}/test-install/yume-cli-$<CONFIG>"
                "-DYUME_PYTHON=${Python3_EXECUTABLE}"
                "-DYUME_INSTALL_BINDIR=${CMAKE_INSTALL_BINDIR}"
                "-DYUME_INSTALL_DATADIR=${CMAKE_INSTALL_DATADIR}"
                "-DYUME_INSTALL_MANDIR=${CMAKE_INSTALL_MANDIR}"
                "-DYUME_DEBIAN_DIR=${CMAKE_SOURCE_DIR}/debian"
                -P "${CMAKE_SOURCE_DIR}/cmake/check_yume_setup_install.cmake")
        set_tests_properties(yume_setup_installed_layout PROPERTIES
            TIMEOUT 120 LABELS "native-runtime;packaging")
    endif()
    add_test(NAME yume_project_metadata_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_project_metadata.py")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_test(NAME yume_linux_release_package_test
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/scripts/test_package_linux_release.py")
        set_tests_properties(yume_linux_release_package_test PROPERTIES
            TIMEOUT 60 LABELS "native-runtime;packaging")
    endif()

    if(TARGET yume_native_packet_adapter)
        add_executable(yume_native_packet_adapter_test runtime/native_packet_adapter_test.cpp)
        target_link_libraries(yume_native_packet_adapter_test PRIVATE yume_native_packet_adapter)
        yume_apply_perf_opts(yume_native_packet_adapter_test)
        add_test(NAME yume_native_packet_adapter_test COMMAND yume_native_packet_adapter_test)
        set_tests_properties(yume_native_packet_adapter_test PROPERTIES TIMEOUT 60 LABELS "native;packet;tun")
    endif()

    if(TARGET yume_linux_tun_packet_channel)
        add_executable(yume_linux_tun_packet_channel_test providers/linux_tun_packet_channel_test.cpp)
        target_link_libraries(yume_linux_tun_packet_channel_test PRIVATE yume_linux_tun_packet_channel)
        yume_apply_perf_opts(yume_linux_tun_packet_channel_test)
        foreach(_wrapped IN ITEMS open fstat ioctl socket write)
            target_link_options(yume_linux_tun_packet_channel_test PRIVATE "LINKER:--wrap=${_wrapped}")
        endforeach()
        add_test(NAME yume_linux_tun_packet_channel_test COMMAND yume_linux_tun_packet_channel_test)
        set_tests_properties(yume_linux_tun_packet_channel_test PROPERTIES TIMEOUT 60 LABELS "native;packet;tun")
    endif()

    if(TARGET yume_linux_tun_network)
        add_executable(yume_linux_tun_network_test runtime/linux_tun_network_test.cpp)
        target_link_libraries(yume_linux_tun_network_test PRIVATE yume_linux_tun_network PkgConfig::YUME_SYSTEMD)
        yume_apply_perf_opts(yume_linux_tun_network_test)
        foreach(_wrapped IN ITEMS open fstat stat ioctl socket bind sendto recvmsg poll
                sd_bus_open_system sd_bus_unref sd_bus_set_method_call_timeout sd_bus_get_name_creds sd_bus_get_owner_creds
                sd_bus_creds_unref sd_bus_creds_get_pid sd_bus_creds_get_unique_name
                sd_bus_message_new_method_call sd_bus_message_unref sd_bus_message_set_allow_interactive_authorization
                sd_bus_message_append sd_bus_message_open_container sd_bus_message_close_container
                sd_bus_message_append_array sd_bus_call)
            target_link_options(yume_linux_tun_network_test PRIVATE "LINKER:--wrap=${_wrapped}")
        endforeach()
        add_test(NAME yume_linux_tun_network_test COMMAND yume_linux_tun_network_test)
        set_tests_properties(yume_linux_tun_network_test PROPERTIES TIMEOUT 60 LABELS "native;packet;tun")
    endif()

    add_executable(yume_ip_packet_channel_test providers/ip_packet_channel_test.cpp)
    target_link_libraries(yume_ip_packet_channel_test
        PRIVATE yume_ip_packet_channel yume_direct_route_handler)
    yume_apply_perf_opts(yume_ip_packet_channel_test)
    add_test(NAME yume_ip_packet_channel_test COMMAND yume_ip_packet_channel_test)
    set_tests_properties(yume_ip_packet_channel_test PROPERTIES
        TIMEOUT 15 LABELS "foundation;packet")
    if(TARGET yume_h2_carrier)
        add_executable(yume_websocket_codec_test core/stealth/websocket_codec_test.cpp)
        target_link_libraries(yume_websocket_codec_test PRIVATE yume_h2_carrier)
        yume_link_atomic_if_needed(yume_websocket_codec_test PRIVATE)
        yume_apply_perf_opts(yume_websocket_codec_test)
        add_test(NAME yume_websocket_codec_test COMMAND yume_websocket_codec_test)
    endif()
    if(TARGET yume_bounded_files)
        add_executable(yume_bounded_file_test core/runtime/bounded_file_test.cpp)
        target_link_libraries(yume_bounded_file_test PRIVATE yume_bounded_files)
        yume_apply_perf_opts(yume_bounded_file_test)
        add_test(NAME yume_bounded_file_test COMMAND yume_bounded_file_test)
    endif()
    if(TARGET yume_cover_profile)
        # The active profile must match its capture manifest byte for byte.
        add_executable(yume_cover_profile_test core/stealth/cover_profile_test.cpp)
        target_link_libraries(yume_cover_profile_test
            PRIVATE yume_cover_profile nlohmann_json::nlohmann_json)
        target_compile_definitions(yume_cover_profile_test PRIVATE
            YUME_COVER_MANIFEST="${YUME_ACTIVE_PROFILE_MANIFEST}"
            YUME_COVER_HTTP2_PROFILE="${YUME_ACTIVE_PROFILE_HTTP2}")
        yume_apply_perf_opts(yume_cover_profile_test)
        add_test(NAME yume_cover_profile_test COMMAND yume_cover_profile_test)

        add_executable(yume_tls_fingerprint_test core/stealth/tls_fingerprint_test.cpp)
        target_link_libraries(yume_tls_fingerprint_test PRIVATE yume_cover_profile)
        yume_apply_perf_opts(yume_tls_fingerprint_test)
        add_test(NAME yume_tls_fingerprint_test COMMAND yume_tls_fingerprint_test)
    endif()
    add_executable(yume_secret_file_test core/security/secret_file_test.cpp)
    target_link_libraries(yume_secret_file_test PRIVATE yume_private_files)
    yume_apply_perf_opts(yume_secret_file_test)
    add_test(NAME yume_secret_file_test COMMAND yume_secret_file_test)

    add_executable(yume_hex_test core/encoding/hex_test.cpp)
    target_include_directories(yume_hex_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    yume_apply_perf_opts(yume_hex_test)
    add_test(NAME yume_hex_test COMMAND yume_hex_test)
    foreach(_shared_test IN ITEMS yume_websocket_codec_test yume_bounded_file_test
            yume_cover_profile_test yume_tls_fingerprint_test yume_secret_file_test
            yume_hex_test)
        if(TARGET ${_shared_test})
            if(MSVC)
                target_compile_options(${_shared_test} PRIVATE /UNDEBUG)
            else()
                target_compile_options(${_shared_test} PRIVATE -UNDEBUG)
            endif()
            set_tests_properties(${_shared_test} PROPERTIES LABELS "shared-component")
        endif()
    endforeach()
    if(YUME_BUILD_YTP1_FRONT_DOOR)
        add_executable(yume_ytp1_cover_site_test providers/ytp1_cover_site_test.cpp)
        target_link_libraries(yume_ytp1_cover_site_test PRIVATE yume_ytp1_cover_site)
        yume_apply_perf_opts(yume_ytp1_cover_site_test)
        add_test(NAME yume_ytp1_cover_site_test COMMAND yume_ytp1_cover_site_test)
        if(UNIX)
            add_executable(yume_ytp1_front_door_test providers/ytp1_front_door_test.cpp)
            target_link_libraries(yume_ytp1_front_door_test PRIVATE
                yume_ytp1_front_door yume_asio_execution_context yume_ytp1_h2_admission
                ${YUME_NGHTTP2_TARGET} OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
            if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
                # Inject OS bind errors in this test process without changing
                # privileges, host limits or the production provider interface.
                target_compile_definitions(yume_ytp1_front_door_test PRIVATE YUME_TEST_WRAP_BIND=1)
                target_link_options(yume_ytp1_front_door_test PRIVATE "-Wl,--wrap=bind")
            endif()
            yume_apply_perf_opts(yume_ytp1_front_door_test)
            add_test(NAME yume_ytp1_front_door_test COMMAND yume_ytp1_front_door_test)
            set_tests_properties(yume_ytp1_front_door_test PROPERTIES
                TIMEOUT 60 LABELS "foundation;0.3;front-door;integration")
        endif()
    endif()
    # Canonical destination networks and address classes are header-only.
    add_executable(yume_common_ip_network_test common/ip_network_test.cpp)
    target_include_directories(yume_common_ip_network_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    yume_apply_perf_opts(yume_common_ip_network_test)
    yume_assert_exact_link_dependencies(yume_common_ip_network_test)
    add_test(NAME yume_common_ip_network_test COMMAND yume_common_ip_network_test
        "${CMAKE_CURRENT_SOURCE_DIR}/common/testdata/ip_network_vectors.txt")
    set_tests_properties(yume_common_ip_network_test PROPERTIES
        TIMEOUT 10 LABELS "foundation;0.3")
    # Server accept pacing is dependency-pure, so every test lane runs it.
    add_executable(yume_native_accept_scheduler_test runtime/accept_scheduler_test.cpp)
    target_link_libraries(yume_native_accept_scheduler_test PRIVATE yume_engine)
    yume_apply_perf_opts(yume_native_accept_scheduler_test)
    yume_assert_exact_link_dependencies(yume_native_accept_scheduler_test yume_engine)
    add_test(NAME yume_native_accept_scheduler_test COMMAND yume_native_accept_scheduler_test)
    set_tests_properties(yume_native_accept_scheduler_test PROPERTIES
        TIMEOUT 10 LABELS "foundation;0.3;native-runtime")
    add_executable(yume_engine_in_memory_contract_test
        engine/in_memory_contract_test.cpp)
    target_link_libraries(yume_engine_in_memory_contract_test
        PRIVATE yume_engine)
    yume_apply_perf_opts(yume_engine_in_memory_contract_test)
    yume_assert_exact_link_dependencies(
        yume_engine_in_memory_contract_test yume_engine)
    add_test(NAME yume_engine_in_memory_contract_test
        COMMAND yume_engine_in_memory_contract_test)

    add_executable(yume_session_engine_test
        engine/session_engine_test.cpp)
    target_link_libraries(yume_session_engine_test
        PRIVATE yume_session_engine yume_ytp1)
    yume_apply_perf_opts(yume_session_engine_test)
    yume_assert_exact_link_dependencies(
        yume_session_engine_test yume_session_engine yume_ytp1)
    add_test(NAME yume_session_engine_test COMMAND yume_session_engine_test)

    add_executable(yume_session_bootstrap_test
        engine/session_bootstrap_test.cpp)
    target_link_libraries(yume_session_bootstrap_test
        PRIVATE yume_session_bootstrap yume_ytp1)
    yume_apply_perf_opts(yume_session_bootstrap_test)
    yume_assert_exact_link_dependencies(
        yume_session_bootstrap_test yume_session_bootstrap yume_ytp1)
    add_test(NAME yume_session_bootstrap_test
        COMMAND yume_session_bootstrap_test)

    add_executable(yume_direct_route_handler_test
        providers/direct_route_handler_test.cpp)
    target_link_libraries(yume_direct_route_handler_test
        PRIVATE yume_direct_route_handler yume_session_engine yume_ytp1)
    yume_apply_perf_opts(yume_direct_route_handler_test)
    yume_assert_exact_link_dependencies(
        yume_direct_route_handler_test
        yume_direct_route_handler yume_session_engine yume_ytp1)
    add_test(NAME yume_direct_route_handler_test
        COMMAND yume_direct_route_handler_test)

    if(TARGET yume-resolver)
        # The same helper source with one test-only name that never resolves,
        # standing in for a system lookup that does not return.
        add_executable(yume_resolver_stall_helper
            providers/system_resolver_helper.cpp providers/system_resolver_main.cpp)
        target_include_directories(yume_resolver_stall_helper PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
        target_compile_definitions(yume_resolver_stall_helper PRIVATE YUME_SYSTEM_RESOLVER_TEST_STALL=1)
        target_link_libraries(yume_resolver_stall_helper PRIVATE yume_process_privileges Threads::Threads)
        yume_apply_perf_opts(yume_resolver_stall_helper)
        add_custom_command(TARGET yume_resolver_stall_helper POST_BUILD
            COMMAND chmod 0755 "$<TARGET_FILE:yume_resolver_stall_helper>" VERBATIM)
        set(YUME_TEST_RESOLVER_DEFINITIONS
            YUME_TEST_RESOLVER_PROGRAM="$<TARGET_FILE:yume-resolver>"
            YUME_TEST_STALL_RESOLVER_PROGRAM="$<TARGET_FILE:yume_resolver_stall_helper>")

        add_executable(yume_child_process_test providers/child_process_test.cpp)
        target_link_libraries(yume_child_process_test PRIVATE yume_child_process)
        yume_apply_perf_opts(yume_child_process_test)
        yume_assert_exact_link_dependencies(yume_child_process_test yume_child_process)
        add_test(NAME yume_child_process_test COMMAND yume_child_process_test)
        set_tests_properties(yume_child_process_test PROPERTIES
            TIMEOUT 30 LABELS "foundation;0.3;native-runtime")

        add_executable(yume_system_resolver_test providers/system_resolver_test.cpp)
        target_link_libraries(yume_system_resolver_test
            PRIVATE yume_system_resolver yume_system_resolver_helper)
        target_compile_definitions(yume_system_resolver_test PRIVATE ${YUME_TEST_RESOLVER_DEFINITIONS})
        add_dependencies(yume_system_resolver_test yume-resolver yume_resolver_stall_helper)
        yume_apply_perf_opts(yume_system_resolver_test)
        add_test(NAME yume_system_resolver_test COMMAND yume_system_resolver_test)
        set_tests_properties(yume_system_resolver_test PROPERTIES
            TIMEOUT 30 LABELS "foundation;0.3;resolver")
    endif()

    if(YUME_BUILD_YTP1_ASIO_ROUTE_PROVIDER)
        add_executable(yume_asio_direct_route_provider_test
            providers/asio_direct_route_provider_test.cpp)
        target_link_libraries(yume_asio_direct_route_provider_test
            PRIVATE yume_asio_direct_route_provider yume_asio_execution_context
                    yume_system_resolver yume_session_engine yume_ytp1)
        target_compile_definitions(yume_asio_direct_route_provider_test
            PRIVATE ${YUME_TEST_RESOLVER_DEFINITIONS})
        add_dependencies(yume_asio_direct_route_provider_test
            yume-resolver yume_resolver_stall_helper)
        yume_apply_perf_opts(yume_asio_direct_route_provider_test)
        yume_assert_exact_link_dependencies(
            yume_asio_direct_route_provider_test
            yume_asio_direct_route_provider yume_asio_execution_context yume_system_resolver
            yume_session_engine yume_ytp1)
        add_test(NAME yume_asio_direct_route_provider_test
            COMMAND yume_asio_direct_route_provider_test)
        set_tests_properties(yume_asio_direct_route_provider_test PROPERTIES
            LABELS "foundation;0.3;route-provider")
    endif()

    if(TARGET yume_h2_admission)
        find_package(Threads REQUIRED)
        add_executable(yume_h2_admission_test admission/h2_admission_test.cpp)
        target_link_libraries(yume_h2_admission_test
            PRIVATE yume_h2_admission Threads::Threads OpenSSL::Crypto)
        yume_apply_perf_opts(yume_h2_admission_test)
        yume_assert_exact_link_dependencies(yume_h2_admission_test
            yume_h2_admission Threads::Threads OpenSSL::Crypto)
        add_test(NAME yume_h2_admission_test COMMAND yume_h2_admission_test)
    endif()

    if(YUME_BUILD_YTP1_H2_CARRIER)
        add_executable(yume_ytp1_h2_admission_test
            providers/ytp1_h2_admission_test.cpp)
        target_link_libraries(yume_ytp1_h2_admission_test
            PRIVATE yume_ytp1_h2_admission yume_h2_admission)
        yume_apply_perf_opts(yume_ytp1_h2_admission_test)
        yume_assert_exact_link_dependencies(yume_ytp1_h2_admission_test
            yume_ytp1_h2_admission yume_h2_admission)
        add_test(NAME yume_ytp1_h2_admission_test COMMAND yume_ytp1_h2_admission_test)
        add_executable(yume_ytp1_h2_carrier_test
            providers/ytp1_h2_carrier_test.cpp)
        target_link_libraries(yume_ytp1_h2_carrier_test
            PRIVATE yume_ytp1_h2_carrier yume_ytp1_h2_admission yume_h2_admission)
        yume_apply_perf_opts(yume_ytp1_h2_carrier_test)
        yume_assert_exact_link_dependencies(
            yume_ytp1_h2_carrier_test yume_ytp1_h2_carrier
            yume_ytp1_h2_admission yume_h2_admission)
        add_test(NAME yume_ytp1_h2_carrier_test
            COMMAND yume_ytp1_h2_carrier_test)
        set_tests_properties(yume_ytp1_h2_carrier_test PROPERTIES
            LABELS "foundation;0.3;carrier-provider")

        # Compile and execute the long-lived transport-v2 H2 contract against
        # the exact shared codec sources used by the replacement adapter.
        add_executable(yume_transport_v2_h2_regression_test
            core/stealth/h2_carrier_test.cpp)
        target_link_libraries(yume_transport_v2_h2_regression_test
            PRIVATE yume_h2_carrier ${YUME_NGHTTP2_TARGET})
        target_compile_definitions(yume_transport_v2_h2_regression_test PRIVATE
            YUME_TEST_EXPECT_DEV_DIAGNOSTICS=${YUME_DEV_DIAGNOSTICS_EXPRESSION})
        if(MSVC)
            target_compile_options(yume_transport_v2_h2_regression_test
                PRIVATE /UNDEBUG)
        else()
            target_compile_options(yume_transport_v2_h2_regression_test
                PRIVATE -UNDEBUG)
        endif()
        yume_apply_perf_opts(yume_transport_v2_h2_regression_test)
        yume_assert_exact_link_dependencies(
            yume_transport_v2_h2_regression_test yume_h2_carrier ${YUME_NGHTTP2_TARGET})
        add_test(NAME yume_transport_v2_h2_regression_test
            COMMAND yume_transport_v2_h2_regression_test)
        set_tests_properties(yume_transport_v2_h2_regression_test PROPERTIES
            LABELS "foundation;0.3;carrier-provider;transport-v2-regression")
    endif()

    if(YUME_BUILD_YTP1_ASIO_TCP_BYTE_CHANNEL_PROVIDER)
        add_executable(yume_asio_tcp_byte_channel_provider_test
            providers/asio_tcp_byte_channel_provider_test.cpp)
        target_link_libraries(yume_asio_tcp_byte_channel_provider_test
            PRIVATE yume_asio_tcp_byte_channel_provider yume_asio_execution_context
                yume_system_resolver)
        target_compile_definitions(yume_asio_tcp_byte_channel_provider_test
            PRIVATE ${YUME_TEST_RESOLVER_DEFINITIONS})
        add_dependencies(yume_asio_tcp_byte_channel_provider_test
            yume-resolver yume_resolver_stall_helper)
        yume_apply_perf_opts(yume_asio_tcp_byte_channel_provider_test)
        yume_assert_exact_link_dependencies(
            yume_asio_tcp_byte_channel_provider_test
            yume_asio_tcp_byte_channel_provider yume_asio_execution_context
            yume_system_resolver)
        add_test(NAME yume_asio_tcp_byte_channel_provider_test
            COMMAND yume_asio_tcp_byte_channel_provider_test)
        set_tests_properties(
            yume_asio_tcp_byte_channel_provider_test PROPERTIES
            LABELS "foundation;0.3;byte-channel-provider")
    endif()

    add_executable(yume_ytp1_kernel_test
        ytp/tests/ytp1_kernel_test.cpp)
    target_link_libraries(yume_ytp1_kernel_test PRIVATE yume_ytp1)
    yume_apply_perf_opts(yume_ytp1_kernel_test)
    yume_assert_exact_link_dependencies(yume_ytp1_kernel_test yume_ytp1)
    add_test(NAME yume_ytp1_kernel_test COMMAND yume_ytp1_kernel_test)

    if(YUME_BUILD_YTP1_OPENSSL_PROVIDER)
        add_executable(yume_ytp1_openssl_security_test
            providers/ytp1_security_provider_test.cpp)
        target_link_libraries(yume_ytp1_openssl_security_test
            PRIVATE yume_ytp1_openssl_security OpenSSL::Crypto)
        target_compile_definitions(yume_ytp1_openssl_security_test PRIVATE
            YUME_YTP1_CRYPTO_VECTORS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/ytp/testdata/ytp1_crypto_vectors.txt")
        yume_apply_perf_opts(yume_ytp1_openssl_security_test)
        yume_assert_exact_link_dependencies(
            yume_ytp1_openssl_security_test
            yume_ytp1_openssl_security OpenSSL::Crypto)
        add_test(NAME yume_ytp1_openssl_security_test
            COMMAND yume_ytp1_openssl_security_test)
        set_tests_properties(yume_ytp1_openssl_security_test PROPERTIES
            LABELS "foundation;0.3;security-provider")
    endif()

    if(YUME_BUILD_YTP1_TLS13_PROVIDER)
        add_executable(yume_ytp1_tls13_secure_channel_test
            providers/ytp1_tls13_secure_channel_test.cpp)
        target_link_libraries(yume_ytp1_tls13_secure_channel_test
            PRIVATE yume_ytp1_tls13_secure_channel yume_tls_client_profile
                    yume_cover_profile OpenSSL::SSL OpenSSL::Crypto)
        if(MSVC)
            target_compile_options(yume_ytp1_tls13_secure_channel_test PRIVATE /UNDEBUG)
        else()
            target_compile_options(yume_ytp1_tls13_secure_channel_test PRIVATE -UNDEBUG)
        endif()
        yume_apply_perf_opts(yume_ytp1_tls13_secure_channel_test)
        yume_assert_exact_link_dependencies(
            yume_ytp1_tls13_secure_channel_test
            yume_ytp1_tls13_secure_channel yume_tls_client_profile
            yume_cover_profile OpenSSL::SSL OpenSSL::Crypto)
        add_test(NAME yume_ytp1_tls13_secure_channel_test
            COMMAND yume_ytp1_tls13_secure_channel_test)
        set_tests_properties(yume_ytp1_tls13_secure_channel_test PROPERTIES
            LABELS "foundation;0.3;secure-channel-provider")
    endif()

    if(TARGET yume_native_credentials AND NOT WIN32)
        add_executable(yume_native_credentials_test runtime/native_credentials_test.cpp)
        target_link_libraries(yume_native_credentials_test PRIVATE
            yume_native_credentials yume_ytp1_openssl_security OpenSSL::Crypto)
        yume_apply_perf_opts(yume_native_credentials_test)
        add_test(NAME yume_native_credentials_test COMMAND yume_native_credentials_test)
        set_tests_properties(yume_native_credentials_test PROPERTIES
            TIMEOUT 60 LABELS "foundation;0.3;native-runtime")
    endif()
    if(TARGET yume_egress_pacing)
        add_executable(yume_egress_limiter_test runtime/egress_limiter_test.cpp)
        target_link_libraries(yume_egress_limiter_test PRIVATE yume_egress_pacing)
        yume_apply_perf_opts(yume_egress_limiter_test)
        yume_assert_exact_link_dependencies(yume_egress_limiter_test yume_egress_pacing)
        add_test(NAME yume_egress_limiter_test COMMAND yume_egress_limiter_test)
        set_tests_properties(yume_egress_limiter_test PROPERTIES
            TIMEOUT 10 LABELS "foundation;0.3;native-runtime")
        add_executable(yume_paced_stream_test runtime/paced_stream_test.cpp)
        target_link_libraries(yume_paced_stream_test PRIVATE yume_egress_pacing Boost::system)
        yume_apply_perf_opts(yume_paced_stream_test)
        yume_assert_exact_link_dependencies(yume_paced_stream_test yume_egress_pacing Boost::system)
        add_test(NAME yume_paced_stream_test COMMAND yume_paced_stream_test)
        set_tests_properties(yume_paced_stream_test PROPERTIES
            TIMEOUT 30 LABELS "foundation;0.3;native-runtime")
    endif()
    if(TARGET yume_socks5_upstream)
        add_executable(yume_socks5_upstream_test providers/socks5_upstream_test.cpp)
        target_link_libraries(yume_socks5_upstream_test PRIVATE
            yume_socks5_upstream yume_asio_tcp_byte_channel_provider Boost::system)
        yume_apply_perf_opts(yume_socks5_upstream_test)
        yume_assert_exact_link_dependencies(yume_socks5_upstream_test
            yume_socks5_upstream yume_asio_tcp_byte_channel_provider Boost::system)
        add_test(NAME yume_socks5_upstream_test COMMAND yume_socks5_upstream_test)
        set_tests_properties(yume_socks5_upstream_test PROPERTIES
            TIMEOUT 60 LABELS "foundation;0.3;native-runtime")
    endif()
    if(TARGET yume_loopback_http_fetch)
        add_executable(yume_loopback_http_fetch_test providers/loopback_http_fetch_test.cpp)
        target_link_libraries(yume_loopback_http_fetch_test PRIVATE yume_loopback_http_fetch Boost::system)
        yume_apply_perf_opts(yume_loopback_http_fetch_test)
        yume_assert_exact_link_dependencies(yume_loopback_http_fetch_test
            yume_loopback_http_fetch Boost::system)
        add_test(NAME yume_loopback_http_fetch_test COMMAND yume_loopback_http_fetch_test)
        set_tests_properties(yume_loopback_http_fetch_test PROPERTIES
            TIMEOUT 60 LABELS "foundation;0.3;native-runtime")
    endif()
    if(TARGET yume_egress_lists)
        add_executable(yume_egress_lists_test runtime/egress_lists_test.cpp)
        target_link_libraries(yume_egress_lists_test PRIVATE yume_egress_lists)
        yume_apply_perf_opts(yume_egress_lists_test)
        yume_assert_exact_link_dependencies(yume_egress_lists_test yume_egress_lists)
        add_test(NAME yume_egress_lists_test COMMAND yume_egress_lists_test)
        set_tests_properties(yume_egress_lists_test PROPERTIES
            TIMEOUT 60 LABELS "foundation;0.3;native-runtime")
    endif()
    if(TARGET yume_native_egress_policy)
        add_executable(yume_native_egress_policy_test runtime/native_egress_policy_test.cpp)
        target_link_libraries(yume_native_egress_policy_test PRIVATE yume_native_egress_policy)
        yume_apply_perf_opts(yume_native_egress_policy_test)
        yume_assert_exact_link_dependencies(yume_native_egress_policy_test yume_native_egress_policy)
        add_test(NAME yume_native_egress_policy_test COMMAND yume_native_egress_policy_test)
        set_tests_properties(yume_native_egress_policy_test PROPERTIES
            TIMEOUT 10 LABELS "foundation;0.3;native-runtime")
    endif()
    if(TARGET yume_native_endpoint AND NOT WIN32)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        find_program(YUME_NATIVE_TEST_OPENSSL openssl
            HINTS "${OPENSSL_ROOT_DIR}/bin" REQUIRED)
        add_executable(yume_native_endpoint_test runtime/native_endpoint_test.cpp)
        target_link_libraries(yume_native_endpoint_test PRIVATE
            yume_native_endpoint yume_asio_execution_context yume_ytp1_cover_site
            yume_native_credentials yume_ytp1_h2_carrier yume_ytp1_tls13_secure_channel
            yume_system_resolver)
        target_compile_definitions(yume_native_endpoint_test PRIVATE ${YUME_TEST_RESOLVER_DEFINITIONS})
        add_dependencies(yume_native_endpoint_test yume-resolver yume_resolver_stall_helper)
        if(TARGET yume_asio_direct_route_provider)
            target_link_libraries(yume_native_endpoint_test PRIVATE
                yume_asio_direct_route_provider yume_direct_route_handler yume_native_runtime
                yume_native_egress_policy)
            target_compile_definitions(yume_native_endpoint_test PRIVATE YUME_NATIVE_TEST_ROUTES=1
                YUME_TEST_MODULE_LAUNCHER="$<TARGET_FILE:yume-module-launcher>"
                YUME_TEST_ECHO_MODULE="$<TARGET_FILE:yume-echo-module>")
            add_dependencies(yume_native_endpoint_test yume-module-launcher yume-echo-module)
        endif()
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            # Inject one OS accept error in this test process without changing
            # host limits or the production listener interface.
            target_compile_definitions(yume_native_endpoint_test PRIVATE YUME_TEST_WRAP_ACCEPT=1)
            target_link_options(yume_native_endpoint_test PRIVATE "-Wl,--wrap=accept")
        endif()
        yume_apply_perf_opts(yume_native_endpoint_test)
        add_test(NAME yume_native_endpoint_test
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/tests/run_native_endpoint_test.py"
                --binary "$<TARGET_FILE:yume_native_endpoint_test>"
                --openssl "${YUME_NATIVE_TEST_OPENSSL}")
        set_tests_properties(yume_native_endpoint_test PROPERTIES
            TIMEOUT 120 LABELS "foundation;0.3;native-runtime")
    endif()
    if(TARGET yume_native_runtime)
        add_executable(yume_native_run_loop_test runtime/native_run_loop_test.cpp)
        target_link_libraries(yume_native_run_loop_test PRIVATE yume_asio_execution_context)
        yume_apply_perf_opts(yume_native_run_loop_test)
        add_test(NAME yume_native_run_loop_test COMMAND yume_native_run_loop_test)
        set_tests_properties(yume_native_run_loop_test PROPERTIES
            TIMEOUT 10 LABELS "foundation;0.3;native-runtime")
        # Tests launch modules through this standalone launcher. yume and
        # yumed launch them by running themselves as yume-module.
        add_executable(yume-module-launcher runtime/module_launcher_main.cpp)
        target_link_libraries(yume-module-launcher PRIVATE yume_module_launcher)
        yume_apply_perf_opts(yume-module-launcher)
        add_custom_command(TARGET yume-module-launcher POST_BUILD
            COMMAND chmod 0755 "$<TARGET_FILE:yume-module-launcher>" VERBATIM)
        add_executable(yume_module_supervisor_test runtime/module_supervisor_test.cpp)
        target_link_libraries(yume_module_supervisor_test PRIVATE yume_native_runtime Boost::system)
        target_compile_definitions(yume_module_supervisor_test PRIVATE
            YUME_TEST_MODULE_LAUNCHER="$<TARGET_FILE:yume-module-launcher>"
            YUME_TEST_ECHO_MODULE="$<TARGET_FILE:yume-echo-module>")
        add_dependencies(yume_module_supervisor_test yume-module-launcher yume-echo-module)
        yume_apply_perf_opts(yume_module_supervisor_test)
        add_test(NAME yume_module_supervisor_test COMMAND yume_module_supervisor_test)
        set_tests_properties(yume_module_supervisor_test PROPERTIES
            TIMEOUT 60 LABELS "foundation;0.3;native-runtime")
        add_executable(yume_native_local_listener_test runtime/local_listener_test.cpp)
        target_link_libraries(yume_native_local_listener_test PRIVATE
            yume_native_runtime yume_asio_tcp_byte_channel_provider Boost::system)
        yume_apply_perf_opts(yume_native_local_listener_test)
        add_test(NAME yume_native_local_listener_test COMMAND yume_native_local_listener_test)
        set_tests_properties(yume_native_local_listener_test PROPERTIES
            TIMEOUT 30 LABELS "foundation;0.3;native-runtime")
        add_executable(yume_native_socks5_request_test runtime/socks5_request_test.cpp)
        target_link_libraries(yume_native_socks5_request_test PRIVATE yume_native_runtime)
        yume_apply_perf_opts(yume_native_socks5_request_test)
        add_test(NAME yume_native_socks5_request_test COMMAND yume_native_socks5_request_test)
        set_tests_properties(yume_native_socks5_request_test PROPERTIES
            TIMEOUT 10 LABELS "foundation;0.3;native-runtime")
        if(NOT WIN32 AND YUME_BUILD_NATIVE_APPLICATION)
            if(YUME_TEST_LINUX_NAMESPACES)
                if(NOT TARGET yume_linux_tun_network)
                    message(FATAL_ERROR "TUN namespace tests require the native Linux network target")
                endif()
                add_test(NAME yume_native_tun_integration
                    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tests/run_native_tun_test.py"
                        --yume "$<TARGET_FILE:yume>" --yumed "$<TARGET_FILE:yumed>"
                        --openssl "${YUME_NATIVE_TEST_OPENSSL}")
                set_tests_properties(yume_native_tun_integration PROPERTIES TIMEOUT 150 LABELS "native;packet;tun;namespace")
                option(YUME_TEST_NATIVE_STRESS
                    "Run bounded native stream stress with isolated kernel netem" OFF)
                if(YUME_TEST_NATIVE_STRESS)
                    find_program(YUME_NATIVE_TEST_TC NAMES tc HINTS /usr/sbin /sbin REQUIRED)
                    set(_yume_native_stress_options)
                    if(_yume_sanitize MATCHES "address")
                        list(APPEND _yume_native_stress_options --asan)
                    endif()
                    add_test(NAME yume_native_stress_test
                        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tests/run_native_stress_test.py"
                            --yume "$<TARGET_FILE:yume>" --yumed "$<TARGET_FILE:yumed>"
                            --openssl "${YUME_NATIVE_TEST_OPENSSL}" --tc "${YUME_NATIVE_TEST_TC}"
                            ${_yume_native_stress_options})
                    set_tests_properties(yume_native_stress_test PROPERTIES
                        TIMEOUT 330 LABELS "native;stress;namespace")
                endif()
                set(YUME_NATIVE_TEST_RESOLVED "" CACHE FILEPATH
                    "systemd-resolved executable for the isolated native DNS integration test")
                if(YUME_NATIVE_TEST_RESOLVED)
                    add_test(NAME yume_native_resolved_test
                        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tests/run_native_tun_test.py"
                            --yume "$<TARGET_FILE:yume>" --yumed "$<TARGET_FILE:yumed>"
                            --openssl "${YUME_NATIVE_TEST_OPENSSL}"
                            --resolved "${YUME_NATIVE_TEST_RESOLVED}")
                    set_tests_properties(yume_native_resolved_test PROPERTIES
                        TIMEOUT 180 LABELS "native;packet;tun;namespace;resolved")
                endif()
            endif()
            add_test(NAME yume_native_cli_test
                COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_SOURCE_DIR}/tests/check_native_cli.py"
                    --yume "$<TARGET_FILE:yume>" --yumed "$<TARGET_FILE:yumed>")
            set_tests_properties(yume_native_cli_test PROPERTIES
                TIMEOUT 30 LABELS "foundation;0.3;native-runtime")
            # Real processes: setup kit, daemon, client SOCKS5 listener and a
            # local HTTP destination behind configured egress destinations,
            # plus the echo module that yumed launches as itself.
            add_test(NAME yume_native_runtime_test
                COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_SOURCE_DIR}/tests/run_native_runtime_test.py"
                    --yumed "$<TARGET_FILE:yumed>"
                    --yume "$<TARGET_FILE:yume>"
                    --openssl "${YUME_NATIVE_TEST_OPENSSL}"
                    --module "$<TARGET_FILE:yume-echo-module>")
            set_tests_properties(yume_native_runtime_test PROPERTIES
                TIMEOUT 180 LABELS "foundation;0.3;native-runtime;integration")
            if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
                add_executable(yume_native_runtime_dns_server_test
                    runtime/native_runtime_dns_server_test.cpp)
                target_link_libraries(yume_native_runtime_dns_server_test PRIVATE yume_native_runtime)
                target_link_options(yume_native_runtime_dns_server_test PRIVATE
                    "-Wl,--wrap=getaddrinfo")
                yume_apply_perf_opts(yume_native_runtime_dns_server_test)
                add_test(NAME yume_native_runtime_dns_test
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_SOURCE_DIR}/tests/run_native_runtime_test.py"
                        --yumed "$<TARGET_FILE:yume_native_runtime_dns_server_test>"
                        --yume "$<TARGET_FILE:yume>"
                        --openssl "${YUME_NATIVE_TEST_OPENSSL}" --dns-fixture)
                set_tests_properties(yume_native_runtime_dns_test PROPERTIES
                    TIMEOUT 180 LABELS "foundation;0.3;native-runtime;integration")
            endif()
        endif()
    endif()

    if(TARGET yume_embed_ytp1)
        add_executable(yume_ytp1_backend_test facade/session/ytp1_backend_test.cpp)
        # The test compiles the private backend implementation with paused
        # execution; linking its archive too would duplicate the definitions.
        target_link_libraries(yume_ytp1_backend_test PRIVATE
            yume_native_endpoint yume_ytp1_openssl_security Threads::Threads)
        yume_apply_perf_opts(yume_ytp1_backend_test)
        add_test(NAME yume_ytp1_backend_test COMMAND yume_ytp1_backend_test
            "${CMAKE_SOURCE_DIR}/config/ytp1/yumed.json")
        set_tests_properties(yume_ytp1_backend_test PROPERTIES
            TIMEOUT 10 LABELS "foundation;0.3;native-runtime")
    endif()

    add_executable(yume_config_v1_test
        config/v1/config_test.cpp)
    target_link_libraries(yume_config_v1_test PRIVATE yume_config_v1)
    yume_apply_perf_opts(yume_config_v1_test)
    yume_assert_exact_link_dependencies(yume_config_v1_test yume_config_v1)
    add_test(NAME yume_config_v1_test COMMAND yume_config_v1_test)
    add_test(NAME yume_config_v1_client_example
        COMMAND "${CMAKE_COMMAND}"
            "-DYUME_PROGRAM=$<TARGET_FILE:yume_config_v1_test>"
            "-DYUME_ARGUMENT=--stdin-client"
            "-DYUME_INPUT=${CMAKE_SOURCE_DIR}/config/ytp1/yume.json"
            -P "${CMAKE_SOURCE_DIR}/cmake/run_with_stdin.cmake")
    add_test(NAME yume_config_v1_server_example
        COMMAND "${CMAKE_COMMAND}"
            "-DYUME_PROGRAM=$<TARGET_FILE:yume_config_v1_test>"
            "-DYUME_ARGUMENT=--stdin-server"
            "-DYUME_INPUT=${CMAKE_SOURCE_DIR}/config/ytp1/yumed.json"
            -P "${CMAKE_SOURCE_DIR}/cmake/run_with_stdin.cmake")

    if(YUME_BUILD_SHARED_ABI)
        add_executable(yume_c_abi_contract_test
            abi/yume_c_contract_test.cpp)
        target_link_libraries(yume_c_abi_contract_test PRIVATE yume_abi)
        if(YUME_BUILD_TRANSPORT_V2 AND NOT YUME_TRANSPORT_CORE_ONLY)
            target_compile_definitions(yume_c_abi_contract_test
                PRIVATE YUME_ABI_TRANSPORT_V2=1)
        endif()
        if(TARGET yume_embed_ytp1)
            target_compile_definitions(yume_c_abi_contract_test
                PRIVATE YUME_ABI_YTP1=1)
        endif()
        yume_apply_perf_opts(yume_c_abi_contract_test)
        yume_assert_exact_link_dependencies(
            yume_c_abi_contract_test yume_abi)
        add_test(NAME yume_c_abi_contract_test
            COMMAND yume_c_abi_contract_test
                "${CMAKE_SOURCE_DIR}/config/ytp1/yume.json"
                "${CMAKE_SOURCE_DIR}/config/ytp1/yumed.json")

        # The C boundary is the whole point of a C ABI: compiling the public
        # header as strict C is the only check that a C++-only declaration has
        # not leaked into it. Reuse the clean-prefix fixture source rather than
        # keeping a second copy of the same consumer.
        add_executable(yume_c_abi_consumer_c
            "${CMAKE_SOURCE_DIR}/tests/abi/install_consumer/consumer.c")
        set_target_properties(yume_c_abi_consumer_c PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF)
        target_link_libraries(yume_c_abi_consumer_c PRIVATE yume_abi)
        yume_apply_warnings(yume_c_abi_consumer_c)
        yume_assert_exact_link_dependencies(yume_c_abi_consumer_c yume_abi)
        add_test(NAME yume_c_abi_consumer_c COMMAND yume_c_abi_consumer_c)

        # Stream-id ownership regression. A rolled-back OPEN must release,
        # unregister, or close-and-retire exactly according to how far it got,
        # or a late ACK can alias a later stream on the same transport. This
        # header is dependency-free, so the check needs no runtime.
        add_executable(yume_abi_stream_open_transaction_test
            facade/session/service_open_transaction_test.cpp)
        target_include_directories(yume_abi_stream_open_transaction_test
            PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
        yume_apply_warnings(yume_abi_stream_open_transaction_test)
        add_test(NAME yume_abi_stream_open_transaction_test
            COMMAND yume_abi_stream_open_transaction_test)

        # Real schema-1 setup credentials through the public C ABI: both
        # endpoint lifecycles, peer identity, refusals, deadlines, half-close,
        # typed end of stream, stop, restart and handles that outlive their
        # endpoint. Python and OpenSSL come from the native endpoint test.
        if(TARGET yume_embed_ytp1 AND UNIX)
            add_executable(yume_abi_ytp1_stream_probe abi/ytp1_stream_probe.c)
            target_link_libraries(yume_abi_ytp1_stream_probe
                PRIVATE yume_abi Threads::Threads)
            target_include_directories(yume_abi_ytp1_stream_probe
                PRIVATE "${CMAKE_SOURCE_DIR}/include")
            yume_apply_warnings(yume_abi_ytp1_stream_probe)
            add_test(NAME yume_abi_ytp1_stream_integration
                COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_SOURCE_DIR}/tests/test_yume_abi_ytp1_stream.py"
                    --probe "$<TARGET_FILE:yume_abi_ytp1_stream_probe>"
                    --openssl "${YUME_NATIVE_TEST_OPENSSL}"
                    --resolver "$<TARGET_FILE:yume-resolver>")
            set_tests_properties(yume_abi_ytp1_stream_integration PROPERTIES
                TIMEOUT 180
                LABELS "foundation;0.3;abi;integration;native-runtime")
            if(TARGET yumed)
                add_executable(yume_abi_ytp1_packet_probe abi/ytp1_packet_probe.cpp)
                target_link_libraries(yume_abi_ytp1_packet_probe PRIVATE yume_abi Threads::Threads)
                yume_apply_warnings(yume_abi_ytp1_packet_probe)
                add_test(NAME yume_abi_ytp1_packet_integration
                    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tests/test_yume_abi_ytp1_packet.py"
                        --probe "$<TARGET_FILE:yume_abi_ytp1_packet_probe>" --yumed "$<TARGET_FILE:yumed>"
                        --openssl "${YUME_NATIVE_TEST_OPENSSL}")
                set_tests_properties(yume_abi_ytp1_packet_integration PROPERTIES TIMEOUT 300 LABELS "abi;packet;native")
                add_executable(yume_abi_ytp1_route_probe abi/ytp1_route_probe.cpp)
                target_link_libraries(yume_abi_ytp1_route_probe PRIVATE yume_abi Threads::Threads)
                yume_apply_warnings(yume_abi_ytp1_route_probe)
                add_test(NAME yume_abi_ytp1_route_integration
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_SOURCE_DIR}/tests/test_yume_abi_ytp1_route.py"
                        --probe "$<TARGET_FILE:yume_abi_ytp1_route_probe>"
                        --yumed "$<TARGET_FILE:yumed>"
                        --openssl "${YUME_NATIVE_TEST_OPENSSL}")
                set_tests_properties(yume_abi_ytp1_route_integration PROPERTIES
                    TIMEOUT 150 LABELS "foundation;0.3;abi;integration;native-runtime")
            endif()
        endif()

        if(YUME_INSTALL_EXPERIMENTAL_SDK)
            set(_yume_test_installed_native_traffic OFF)
            if(TARGET yume_embed_ytp1 AND TARGET yumed AND UNIX)
                set(_yume_test_installed_native_traffic ON)
            endif()
            add_test(NAME yume_abi_installed_consumers
                COMMAND "${CMAKE_COMMAND}"
                    "-DYUME_BUILD_DIR=${CMAKE_BINARY_DIR}"
                    "-DYUME_TEST_PREFIX=${CMAKE_BINARY_DIR}/sdk-consumers"
                    "-DYUME_BUILD_CONFIG=$<CONFIG>"
                    "-DYUME_CONSUMER_SANITIZER_FLAGS=${_yume_sanitize_flags}"
                    "-DYUME_SOURCE_DIR=${CMAKE_SOURCE_DIR}"
                    "-DYUME_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                    "-DYUME_OPENSSL_PROGRAM=${YUME_NATIVE_TEST_OPENSSL}"
                    "-DYUME_TEST_NATIVE_TRAFFIC=${_yume_test_installed_native_traffic}"
                    -P "${CMAKE_SOURCE_DIR}/cmake/check_yume_abi_install.cmake")
            set_tests_properties(yume_abi_installed_consumers PROPERTIES TIMEOUT 600 LABELS "abi;install")
        endif()

        set(_yume_abi_contract_tests
            yume_c_abi_contract_test
            yume_c_abi_consumer_c
            yume_abi_stream_open_transaction_test)
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
                    -P "${CMAKE_SOURCE_DIR}/cmake/check_yume_abi_exports.cmake")
            list(APPEND _yume_abi_contract_tests yume_abi_exports)
        endif()

        add_test(NAME yume_abi_header_matches_map
            COMMAND "${CMAKE_COMMAND}"
                "-DYUME_ABI_MAP=${CMAKE_CURRENT_SOURCE_DIR}/abi/yume.map"
                "-DYUME_ABI_HEADER=${CMAKE_SOURCE_DIR}/include/yume/yume.h"
                -P "${CMAKE_SOURCE_DIR}/cmake/check_yume_abi_header.cmake")
        add_test(NAME yume_abi_debian_symbols_match_map
            COMMAND "${CMAKE_COMMAND}"
                "-DYUME_ABI_MAP=${CMAKE_CURRENT_SOURCE_DIR}/abi/yume.map"
                "-DYUME_DEBIAN_SYMBOLS=${CMAKE_SOURCE_DIR}/debian/libyume1.symbols"
                -P "${CMAKE_SOURCE_DIR}/cmake/check_yume_abi_debian_symbols.cmake")
        list(APPEND _yume_abi_contract_tests
            yume_abi_header_matches_map
            yume_abi_debian_symbols_match_map)

        set_tests_properties(${_yume_abi_contract_tests} PROPERTIES
            LABELS "foundation;0.3;abi")
    endif()

    add_test(NAME yume_03_layering_check
        COMMAND "${CMAKE_COMMAND}"
            "-DYUME_SOURCE_DIR=${CMAKE_SOURCE_DIR}"
            -P "${CMAKE_SOURCE_DIR}/cmake/YumeLayering.cmake")
    add_test(NAME yume_03_layering_guard_test
        COMMAND "${CMAKE_COMMAND}"
            "-DYUME_LAYERING_MODULE=${CMAKE_SOURCE_DIR}/cmake/YumeLayering.cmake"
            "-DYUME_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DYUME_TEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/layering-guard-test"
            -P "${CMAKE_SOURCE_DIR}/tests/cmake/yume_03_layering_test.cmake")
    set_tests_properties(
        yume_engine_in_memory_contract_test
        yume_session_engine_test
        yume_session_bootstrap_test
        yume_direct_route_handler_test
        yume_ytp1_kernel_test
        yume_config_v1_test
        yume_config_v1_client_example
        yume_config_v1_server_example
        yume_03_layering_check
        yume_03_layering_guard_test
        PROPERTIES LABELS "foundation;0.3")
endif()

# Transport v2 retains uninstalled reference programs and unresolved capability
# owners. It is off by default; its retirement still requires capability ports.
if(YUME_BUILD_TRANSPORT_V2)


if(YUME_STATIC AND YUME_USE_SPDLOG AND NOT YUME_SPDLOG_TARGET STREQUAL "spdlog::spdlog_header_only")
    message(WARNING "Static link requested but only compiled spdlog was found; disabling spdlog.")
    set(YUME_USE_SPDLOG OFF CACHE BOOL "Disable spdlog for static builds" FORCE)
endif()

# ----------------------------------------------------------------------
# Shared protocol/security core
# ----------------------------------------------------------------------
# These protocol sources are needed by both the full yume_core and the reduced
# yume_transport_core (the mobile/ABI slice). They used to be listed in both
# targets, so every full build compiled them twice and both archives defined
# the same symbols - harmless for ordinary static resolution, but a real
# duplicate-symbol hazard on the --whole-archive shared-ABI path, where
# yume_server and yume_client_lib link *both* libraries.
#
# Transport-v2 crypto uses BaseFWX, with a separate optional liboqs edge for
# YUME's ML-KEM-768 helpers. Protected-file checks live in yume_private_files,
# shared with native YTP credential loading, with advapi32 on Windows for DACLs.
# There is no direct OpenSSL/Boost/nlohmann/spdlog link edge here. YTP/1 has
# a separate security-provider target, independent of this transport-v2 core.
add_library(yume_secure_core STATIC
    core/security/inner_crypto.cpp
    core/security/auth_v2.cpp
    core/security/ratchet.cpp
    core/security/session_ratchet.cpp
    core/protocol/protocol.cpp
    core/protocol/packet_bulk.cpp
    core/runtime/system_profile.cpp
)

target_include_directories(yume_secure_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(yume_secure_core PUBLIC yume_private_files)
yume_apply_dev_diagnostics(yume_secure_core PUBLIC)

if(TARGET basefwxcpp)
    target_link_libraries(yume_secure_core PUBLIC basefwxcpp)
    target_compile_definitions(yume_secure_core PUBLIC YUME_USE_BASEFWX=1)
else()
    target_compile_definitions(yume_secure_core PUBLIC YUME_USE_BASEFWX=0)
endif()

# YUME's own liboqs edge. inner_crypto.cpp calls OQS_KEM_new/OQS_KEM_keypair
# itself, so it links and gates on liboqs directly instead of inheriting the
# headers from basefwxcpp's PUBLIC interface and keying off BaseFWX's
# BASEFWX_HAS_OQS build macro. yume_core inherits this through its PUBLIC
# dependency on yume_secure_core, which is what version_report.cpp needs for
# OQS_VERSION_TEXT. Discovery lives in the top-level CMakeLists.
if(TARGET yume_liboqs)
    target_link_libraries(yume_secure_core PUBLIC yume_liboqs)
    target_compile_definitions(yume_secure_core PUBLIC YUME_HAS_OQS=1)
else()
    target_compile_definitions(yume_secure_core PUBLIC YUME_HAS_OQS=0)
endif()
yume_link_atomic_if_needed(yume_secure_core PUBLIC)
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
        core/stealth/http_profile.cpp
        core/security/identity.cpp
        core/runtime/atomic_file.cpp
        core/runtime/file_transaction_lock.cpp
        core/runtime/local_runtime.cpp
        core/runtime/service_stream.cpp
        core/runtime/worker_loop.cpp
        core/stealth/obfs.cpp
        core/stealth/obfs_h2.cpp
        core/stealth/obfs_signal.cpp
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
            yume_tls_client_profile
            yume_h2_carrier
            yume_bounded_files
            yume_h2_admission
            OpenSSL::SSL
            OpenSSL::Crypto
            Threads::Threads
            nlohmann_json::nlohmann_json
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

    yume_apply_perf_opts(yume_core)
    yume_apply_pch(yume_core)

endif()

add_library(yume_transport_core
    client/packet/engine.cpp
    client/transport/chrome_tls_protocol.cpp
    outbound/core.cpp
    outbound/write.cpp
    outbound/dispatch.cpp
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
yume_apply_perf_opts(yume_transport_core)
yume_apply_pch(yume_transport_core)

if(NOT YUME_TRANSPORT_CORE_ONLY)
    # ------------------------------------------------------------------
    # Shared outbound/federation transport
    # ------------------------------------------------------------------
    # Federation is a server feature, but it dials another yumed-v2-reference through the
    # same authenticated transport primitives used by the client.  Keep that
    # deliberately small common slice separate from yume_client_lib: linking
    # the full client library into yume_server used to pull CLI/runtime/share
    # code across the server boundary and also compiled outbound_proxy.cpp in
    # both archives.
    add_library(yume_outbound_transport STATIC
        outbound/stream.cpp
        outbound/tunnel.cpp
        outbound/forward.cpp
        outbound/proxy.cpp
        outbound/auth.cpp
    )
    target_include_directories(yume_outbound_transport
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(yume_outbound_transport
        PUBLIC yume_core yume_transport_core)
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

    # Filter archives own their decoder dependency; they must not reach it through
    # BaseFWX's optional compression support. The native reader replaces shell tar.
    add_library(yume_filter_archive STATIC server/filter/filter_archive.cpp)
    target_include_directories(yume_filter_archive PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        if(YUME_STATIC)
            find_library(YUME_FILTER_LZMA_STATIC NAMES liblzma.a REQUIRED)
            set(LIBLZMA_LIBRARY "${YUME_FILTER_LZMA_STATIC}")
        endif()
        find_package(LibLZMA REQUIRED)
        target_link_libraries(yume_filter_archive PRIVATE LibLZMA::LibLZMA)
        if(YUME_STATIC)
            pkg_check_modules(YUME_FILTER_TAR REQUIRED libarchive>=3.6.0)
            target_include_directories(yume_filter_archive PRIVATE ${YUME_FILTER_TAR_INCLUDE_DIRS})
            target_link_directories(yume_filter_archive PRIVATE ${YUME_FILTER_TAR_STATIC_LIBRARY_DIRS})
            target_link_libraries(yume_filter_archive PRIVATE ${YUME_FILTER_TAR_STATIC_LIBRARIES})
        else()
            find_package(LibArchive 3.6.0 REQUIRED)
            target_link_libraries(yume_filter_archive PRIVATE LibArchive::LibArchive)
        endif()
    endif()
    yume_apply_perf_opts(yume_filter_archive)

    # ------------------------------------------------------------------
    # Server library
    # ------------------------------------------------------------------
    # Extracted so both the yumed-v2-reference executable and the optional yume_facade
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
        server/runtime/cover_response.cpp
        server/runtime/manager.cpp
        server/runtime/manager_relay.cpp
        server/runtime/security_config.cpp
        server/packet/tun_egress.cpp
        server/auth/authorized_identity_store.cpp
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
        yume_outbound_transport yume_filter_archive)
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

    add_executable(yumed-v2-reference
        main_server.cpp
        server/cli/anonym.cpp
        server/cli/operator_proof_token.cpp
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
    target_link_libraries(yumed-v2-reference PRIVATE yume_server)
    yume_apply_perf_opts(yumed-v2-reference)
    if(YUME_STATIC AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_options(yumed-v2-reference PRIVATE -static)
    endif()
    if(WIN32)
        target_link_libraries(yumed-v2-reference PRIVATE ws2_32 mswsock)
        target_compile_definitions(yumed-v2-reference PRIVATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            WINVER=0x0600
            _WIN32_WINNT=0x0600
        )
    endif()

    if(YUME_BUILD_TESTING AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_executable(yume_operator_proof_token_test
            server/cli/operator_proof_token.cpp
            server/cli/operator_proof_token_test.cpp
            server/cli/curl_json_transport.cpp)
        target_include_directories(yume_operator_proof_token_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_libraries(yume_operator_proof_token_test PRIVATE yume_core)
        if(MSVC)
            target_compile_options(yume_operator_proof_token_test PRIVATE /UNDEBUG)
        else()
            target_compile_options(yume_operator_proof_token_test PRIVATE -UNDEBUG)
        endif()
        yume_apply_perf_opts(yume_operator_proof_token_test)
        add_test(NAME yume_operator_proof_token_test
            COMMAND yume_operator_proof_token_test)

        add_executable(yume_anonym_curl_transport_test
            server/cli/curl_json_transport.cpp
            server/cli/curl_json_transport_test.cpp)
        target_include_directories(yume_anonym_curl_transport_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_libraries(yume_anonym_curl_transport_test PRIVATE yume_core)
        target_compile_definitions(yume_anonym_curl_transport_test PRIVATE
            YUME_CURL_TRANSPORT_TESTING=1)
        if(MSVC)
            target_compile_options(yume_anonym_curl_transport_test PRIVATE /UNDEBUG)
        else()
            target_compile_options(yume_anonym_curl_transport_test PRIVATE -UNDEBUG)
        endif()
        # perf_opts, not warnings alone: this links yume_core, which is built
        # with LTO. Under Clang an LTO archive is bitcode and a consumer
        # without -flto cannot link it ("file format not recognized"). GCC
        # hides that by using the linker plugin automatically. The ABI targets
        # are the only deliberate exceptions, and they link non-LTO inputs.
        yume_apply_perf_opts(yume_anonym_curl_transport_test)
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

    add_executable(yume-v2-reference
        main_client.cpp
    )
    target_link_libraries(yume-v2-reference PRIVATE yume_client_lib)
    yume_apply_perf_opts(yume-v2-reference)

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
        add_dependencies(yume-v2-reference yume_chrome_tls_helper)
        target_compile_definitions(yume_client_lib PUBLIC
            YUME_HAS_CHROME_TLS_HELPER=1)

    else()
        target_compile_definitions(yume_client_lib PUBLIC
            YUME_HAS_CHROME_TLS_HELPER=0)
    endif()
    if(YUME_STATIC AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_options(yume-v2-reference PRIVATE -static)
    endif()

    set(_yume_install_targets yume-v2-reference yumed-v2-reference)

    if(YUME_BUILD_TOOLS)
        # Read-only ASCII visualization of the local yumed-v2-reference federation topology.
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
        target_link_libraries(yume-v2-reference PRIVATE ws2_32 mswsock)
        target_compile_definitions(yume-v2-reference PRIVATE
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
                "-DYUME_FEATURE_LAN_BRIDGE=ON in the yume-v2-reference/yumed-v2-reference binaries under test")
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
        yume_apply_perf_opts(yume_selftest_lib)
        # The definition and the link must live on the same target. When the
        # link was only on the `yume-v2-reference` executable, every other historical
        # consumer of yume_client_lib, including yume_facade and the retired
        # facade-backed ABI, compiled the call in client/cli/entry.cpp but had
        # nothing to resolve it against, so self-test builds failed to link with
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

    # Reference executables preserve unresolved capability tests. They have no
    # install rule and cannot become a second shipping runtime.

    # ------------------------------------------------------------------
    # Optional GUI components
    # ------------------------------------------------------------------
    # The facade library has no GUI dependency and is small enough to
    # build unconditionally; the executable is gated on YUME_BUILD_GUI.
    add_subdirectory(facade)
    if(YUME_BUILD_GUI)
        add_subdirectory(gui)
    endif()

    # Lock the first-party layering of the transport-v2 stack. Third-party
    # dependencies vary with build options, so only targets whose direct
    # dependencies are entirely first-party and option-independent are pinned
    # here. The directional source check in YumeLayering.cmake covers the rest.
    yume_assert_exact_link_dependencies(
        yume_outbound_transport yume_core yume_transport_core)
    yume_assert_exact_link_dependencies(
        yume_server yume_core yume_transport_core yume_outbound_transport
        yume_filter_archive)
    if(TARGET yume_selftest_lib)
        yume_assert_exact_link_dependencies(
            yume_client_lib yume_core yume_transport_core
            yume_outbound_transport yume_selftest_lib)
    else()
        yume_assert_exact_link_dependencies(
            yume_client_lib yume_core yume_transport_core
            yume_outbound_transport)
    endif()

    # Lock the embed/facade boundary. This directory became a GUI wrapper by
    # accident once already: a desktop need was added to the shared library
    # and nothing objected. Adding a GUI dependency to yume_embed, or letting
    # yume_facade reach past it, now fails at configure time.
    if(TARGET yume_embed)
        yume_assert_exact_link_dependencies(
            yume_embed yume_core yume_server yume_client_lib)
    endif()
    if(TARGET yume_facade)
        yume_assert_exact_link_dependencies(yume_facade yume_embed)
    endif()

    # Every archive absorbed into libyume must be PIC, hidden, and non-LTO.
    # The version script is the final export allowlist, but GCC LTO can still
    # materialize default-visible weak libstdc++ definitions after GNU ld has
    # applied it. This must cover the whole transitive chain, not just the
    # library named on the link line.
    if(YUME_BUILD_SHARED_ABI)
        foreach(_yume_absorbed IN ITEMS
                yume_embed yume_facade yume_client_lib yume_server
                yume_outbound_transport yume_filter_archive yume_selftest_lib yume_core
                yume_transport_core yume_secure_core yume_private_files
                yume_tls_client_profile yume_cover_profile yume_h2_admission)
            if(TARGET ${_yume_absorbed})
                yume_prepare_static_for_shared_abi(${_yume_absorbed})
            endif()
        endforeach()
        if(TARGET basefwxcpp)
            yume_prepare_static_for_shared_abi(basefwxcpp)
        endif()
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

add_executable(yume_profiles_test facade/config/profiles_test.cpp)
target_link_libraries(yume_profiles_test PRIVATE yume_facade Threads::Threads)
yume_apply_perf_opts(yume_profiles_test)
add_test(NAME yume_profiles_test COMMAND yume_profiles_test)

add_executable(yume_client_config_load_test
    client/cli/config/config_load_test.cpp)
target_link_libraries(yume_client_config_load_test PRIVATE yume_client_lib)
yume_apply_perf_opts(yume_client_config_load_test)
add_test(NAME yume_client_config_load_test
    COMMAND yume_client_config_load_test)

add_executable(yume_client_args_test client/cli/config/args_test.cpp)
target_link_libraries(yume_client_args_test PRIVATE yume_client_lib)
yume_apply_perf_opts(yume_client_args_test)
add_test(NAME yume_client_args_test COMMAND yume_client_args_test)

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

add_executable(yume_memory_lifetime_test core/security/memory_lifetime_test.cpp)
target_link_libraries(yume_memory_lifetime_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_memory_lifetime_test PRIVATE)
yume_apply_perf_opts(yume_memory_lifetime_test)
set(yume_memory_cases erase sign bio-growth pem-export pem-partial)
if(NOT WIN32)
    list(APPEND yume_memory_cases pem-load)
endif()
foreach(memory_case IN LISTS yume_memory_cases)
    string(REPLACE "-" "_" memory_suffix "${memory_case}")
    add_test(NAME yume_memory_${memory_suffix}_test
        COMMAND yume_memory_lifetime_test "${memory_case}")
endforeach()

add_executable(yume_dual_key_auth_test
    server/auth/dual_key_auth_test.cpp
    server/cli/key.cpp
)
target_link_libraries(yume_dual_key_auth_test PRIVATE yume_facade)
yume_apply_perf_opts(yume_dual_key_auth_test)
add_test(NAME yume_dual_key_auth_test COMMAND yume_dual_key_auth_test)

add_executable(yume_filter_reload_test server/runtime/filter_reload_test.cpp)
target_link_libraries(yume_filter_reload_test PRIVATE yume_server)
yume_apply_perf_opts(yume_filter_reload_test)
add_test(NAME yume_filter_reload_test COMMAND yume_filter_reload_test)

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

add_executable(yume_config_parity_test
    facade/config/config_parity_test.cpp
    server/cli/config_load.cpp
    server/cli/misc.cpp
)
target_link_libraries(yume_config_parity_test PRIVATE yume_embed)
yume_apply_perf_opts(yume_config_parity_test)
add_test(NAME yume_config_parity_test COMMAND yume_config_parity_test)

add_executable(yume_server_startup_admission_test
    server/runtime/security_config_test.cpp
)
target_link_libraries(yume_server_startup_admission_test PRIVATE yume_server)
yume_apply_perf_opts(yume_server_startup_admission_test)
add_test(NAME yume_server_startup_admission_test
    COMMAND yume_server_startup_admission_test)
set_tests_properties(yume_server_startup_admission_test PROPERTIES TIMEOUT 30)

add_executable(yume_cover_response_test
    server/runtime/cover_response_test.cpp
)
target_link_libraries(yume_cover_response_test PRIVATE yume_server)
yume_apply_perf_opts(yume_cover_response_test)
add_test(NAME yume_cover_response_test COMMAND yume_cover_response_test)

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

# Isolated because it replaces global operator new: these cases hold every
# allocation failing while the write scheduler marks, selects and rotates.
add_executable(yume_write_ready_ring_test
    core/runtime/write_ready_ring_test.cpp
)
target_link_libraries(yume_write_ready_ring_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_write_ready_ring_test PRIVATE)
yume_apply_perf_opts(yume_write_ready_ring_test)
add_test(NAME yume_write_ready_ring_test COMMAND yume_write_ready_ring_test)

# Isolated because it replaces global operator new to inject allocation
# failure into transport write admission.
add_executable(yume_transport_async_failure_test
    client/transport/transport_async_failure_test.cpp
)
target_link_libraries(yume_transport_async_failure_test
    PRIVATE yume_transport_core)
yume_link_atomic_if_needed(yume_transport_async_failure_test PRIVATE)
yume_apply_perf_opts(yume_transport_async_failure_test)
add_test(NAME yume_transport_async_failure_test
    COMMAND yume_transport_async_failure_test)

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

add_executable(yume_protocol_stream_test
    core/protocol/protocol_stream_test.cpp)
target_link_libraries(yume_protocol_stream_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_protocol_stream_test PRIVATE)
yume_apply_perf_opts(yume_protocol_stream_test)
add_test(NAME yume_protocol_stream_test
    COMMAND yume_protocol_stream_test)

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

    add_executable(yume_share_bundle_lifetime_test
        client/transfer/share_bundle_lifetime_test.cpp)
    target_link_libraries(yume_share_bundle_lifetime_test PRIVATE yume_client_lib)
    yume_link_atomic_if_needed(yume_share_bundle_lifetime_test PRIVATE)
    yume_apply_perf_opts(yume_share_bundle_lifetime_test)
    add_test(NAME yume_share_bundle_lifetime_test COMMAND yume_share_bundle_lifetime_test)

    add_executable(yume_share_serialization_lifetime_test
        client/transfer/share_serialization_lifetime_test.cpp)
    target_link_libraries(yume_share_serialization_lifetime_test PRIVATE yume_client_lib)
    yume_link_atomic_if_needed(yume_share_serialization_lifetime_test PRIVATE)
    yume_apply_perf_opts(yume_share_serialization_lifetime_test)
    add_test(NAME yume_share_serialization_lifetime_test
        COMMAND yume_share_serialization_lifetime_test)

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

    if(UNIX)
        add_executable(yume_server_controller_teardown_test
            server/runtime/controller_teardown_test.cpp)
        target_link_libraries(yume_server_controller_teardown_test
            PRIVATE yume_server Threads::Threads)
        yume_link_atomic_if_needed(yume_server_controller_teardown_test PRIVATE)
        yume_apply_perf_opts(yume_server_controller_teardown_test)
        foreach(_case drain stop-once stop-persistent destruct-once destruct-persistent)
            add_test(NAME yume_server_teardown_${_case}
                COMMAND yume_server_controller_teardown_test ${_case})
            set_tests_properties(yume_server_teardown_${_case} PROPERTIES TIMEOUT 15)
        endforeach()
    endif()

    add_executable(yume_server_control_survival_test
        server/session/control_survival_test.cpp)
    target_link_libraries(yume_server_control_survival_test
        PRIVATE yume_server Threads::Threads)
    yume_link_atomic_if_needed(yume_server_control_survival_test PRIVATE)
    yume_apply_perf_opts(yume_server_control_survival_test)
    add_test(NAME yume_server_control_survival_test
        COMMAND yume_server_control_survival_test)

    add_executable(yume_server_frame_budget_test
        server/session/frame_budget_test.cpp)
    target_link_libraries(yume_server_frame_budget_test PRIVATE yume_server Threads::Threads)
    yume_link_atomic_if_needed(yume_server_frame_budget_test PRIVATE)
    yume_apply_perf_opts(yume_server_frame_budget_test)
    add_test(NAME yume_server_frame_budget_test COMMAND yume_server_frame_budget_test)

    # Isolated because it replaces global operator new to inject allocation
    # failure into session write submission.
    add_executable(yume_session_async_cleanup_test
        server/session/session_async_cleanup_test.cpp)
    target_link_libraries(yume_session_async_cleanup_test
        PRIVATE yume_server Threads::Threads)
    yume_link_atomic_if_needed(yume_session_async_cleanup_test PRIVATE)
    yume_apply_perf_opts(yume_session_async_cleanup_test)
    add_test(NAME yume_session_async_cleanup_test
        COMMAND yume_session_async_cleanup_test)
    set_tests_properties(yume_session_async_cleanup_test PROPERTIES TIMEOUT 60)

    if(YUME_USE_BASEFWX)
        add_executable(yume_server_auth_publication_test
            server/session/auth_publication_test.cpp)
        target_link_libraries(yume_server_auth_publication_test
            PRIVATE yume_server Threads::Threads)
        yume_link_atomic_if_needed(yume_server_auth_publication_test PRIVATE)
        yume_apply_perf_opts(yume_server_auth_publication_test)
        add_test(NAME yume_server_auth_publication_test
            COMMAND yume_server_auth_publication_test)
        set_tests_properties(yume_server_auth_publication_test PROPERTIES TIMEOUT 30)

    endif()

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
target_link_libraries(yume_static_site_test PRIVATE yume_core)
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

add_executable(yume_worker_loop_test
    core/runtime/worker_loop_test.cpp
)
target_link_libraries(yume_worker_loop_test PRIVATE yume_core Threads::Threads)
yume_link_atomic_if_needed(yume_worker_loop_test PRIVATE)
yume_apply_perf_opts(yume_worker_loop_test)
add_test(NAME yume_worker_loop_test COMMAND yume_worker_loop_test)

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
target_link_libraries(yume_ip_filter_test PRIVATE yume_core yume_filter_archive)
yume_link_atomic_if_needed(yume_ip_filter_test PRIVATE)
yume_apply_perf_opts(yume_ip_filter_test)
add_test(NAME yume_ip_filter_test COMMAND yume_ip_filter_test)
add_executable(yume_filter_archive_test server/filter/filter_archive_test.cpp)
target_link_libraries(yume_filter_archive_test PRIVATE yume_filter_archive)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(yume_filter_archive_test PRIVATE LibLZMA::LibLZMA)
endif()
yume_apply_perf_opts(yume_filter_archive_test)
add_test(NAME yume_filter_archive_test COMMAND yume_filter_archive_test)

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
    add_executable(yume_h2_carrier_test core/stealth/h2_carrier_test.cpp)
    target_link_libraries(yume_h2_carrier_test PRIVATE yume_h2_carrier ${YUME_NGHTTP2_TARGET})
    target_compile_definitions(yume_h2_carrier_test PRIVATE
        YUME_TEST_EXPECT_DEV_DIAGNOSTICS=${YUME_DEV_DIAGNOSTICS_EXPRESSION})
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

    add_executable(yume_http_profile_test core/stealth/http_profile_test.cpp)
    target_link_libraries(yume_http_profile_test PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_http_profile_test PRIVATE)
    yume_apply_perf_opts(yume_http_profile_test)
    add_test(NAME yume_http_profile_test COMMAND yume_http_profile_test)

    add_executable(yume_h2_opening_probe core/stealth/h2_opening_probe.cpp)
    target_link_libraries(yume_h2_opening_probe PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_h2_opening_probe PRIVATE)
    yume_apply_perf_opts(yume_h2_opening_probe)

    find_package(Python3 REQUIRED COMPONENTS Interpreter)

    # The only check that the ABI actually moves bytes. It provisions a real
    # server and client and drives a named service stream in both directions,
    # so it needs the transport backend linked and a Python interpreter.
    if(YUME_BUILD_SHARED_ABI AND TARGET yume_abi AND TARGET yumed-v2-reference
       AND YUME_BUILD_TRANSPORT_V2 AND NOT YUME_TRANSPORT_CORE_ONLY)
        add_executable(yume_abi_stream_probe abi/stream_integration_probe.c)
        target_link_libraries(yume_abi_stream_probe
            PRIVATE yume_abi Threads::Threads)
        target_include_directories(yume_abi_stream_probe
            PRIVATE "${CMAKE_SOURCE_DIR}/include")
        yume_apply_warnings(yume_abi_stream_probe)
        add_test(NAME yume_abi_stream_integration
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/tests/test_yume_abi_stream.py"
                --probe "$<TARGET_FILE:yume_abi_stream_probe>"
                --yumed "$<TARGET_FILE:yumed-v2-reference>")
        set_tests_properties(yume_abi_stream_integration PROPERTIES
            TIMEOUT 180
            LABELS "0.3;abi;integration")
    endif()
    add_test(NAME yume_transport_profile_generation_check
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/generate_transport_profiles.py"
            --registry "${YUME_TRANSPORT_PROFILE_REGISTRY}"
            --check
    )
    add_test(NAME yume_socket_autotuning_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_socket_autotuning.py"
    )
    # The packet helper renders its --listen value into nftables and UFW
    # rules, so its parsing and plan invariants are a gate, not a convenience.
    add_test(NAME yume_packet_quick_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_yume_packet_quick.py"
    )
    # Provisioning coverage. These generate real kits and assert the
    # credential-store invariants, including the separation between the
    # traffic store and the admin second-factor store. They were previously
    # runnable only by hand, so a regression in setup or doctor passed CI.
    add_test(NAME yume_setup_transport_v2_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_yume_setup_transport_v2.py"
    )
    # The nDPI and direct-link scripts decide from these parsers whether a run
    # counts, so a misread report must fail here instead of passing silently.
    add_test(NAME yume_evaluation_reports_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_yume_evaluation_reports.py"
    )
    set_tests_properties(yume_setup_transport_v2_test PROPERTIES TIMEOUT 300)
    add_test(NAME yume_release_diagnostics_cost_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tests/test_release_diagnostics_cost.py"
    )
    if(UNIX AND TARGET yume-v2-reference AND TARGET yumed-v2-reference)
        add_test(NAME yume_federation_v2_integration_test
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/tests/test_yume_federation_v2.py"
                --yume "$<TARGET_FILE:yume-v2-reference>"
                --yumed "$<TARGET_FILE:yumed-v2-reference>"
        )
        set_tests_properties(yume_federation_v2_integration_test PROPERTIES
            TIMEOUT 90)
        # Three nodes in a line. Proves multi-peer link fan-out and pins the
        # single-hop boundary: the far end must stay invisible and unroutable.
        add_test(NAME yume_federation_cluster_integration_test
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/tests/test_yume_federation_cluster.py"
                --yume "$<TARGET_FILE:yume-v2-reference>"
                --yumed "$<TARGET_FILE:yumed-v2-reference>"
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
    add_test(NAME yume_diagrams_test
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/test_yume_diagrams.py"
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

    add_executable(yume_tls_verify_fetch_test
        core/stealth/tls_verify_fetch_test.cpp)
    target_link_libraries(yume_tls_verify_fetch_test PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_tls_verify_fetch_test PRIVATE)
    yume_apply_perf_opts(yume_tls_verify_fetch_test)
    add_test(NAME yume_tls_verify_fetch_test COMMAND yume_tls_verify_fetch_test)

    add_executable(yume_obfs_test core/stealth/obfs_test.cpp)
    target_link_libraries(yume_obfs_test PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_obfs_test PRIVATE)
    yume_apply_perf_opts(yume_obfs_test)
    add_test(NAME yume_obfs_test COMMAND yume_obfs_test)

    add_executable(yume_admission_replay_test core/stealth/admission_replay_test.cpp)
    target_link_libraries(yume_admission_replay_test PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_admission_replay_test PRIVATE)
    yume_apply_perf_opts(yume_admission_replay_test)
    add_test(NAME yume_admission_replay_test COMMAND yume_admission_replay_test)
endif()

endif()

endif() # YUME_BUILD_TRANSPORT_V2

if(NOT YUME_BUILD_TRANSPORT_V2)
    foreach(_transport_v2_target IN ITEMS
            yume_secure_core
            yume_core
            yume_transport_core
            yume_outbound_transport
            yume_server
            yumed-v2-reference
            yume_client_lib
            yume-v2-reference
            yume_facade
            yume-gui
            yume_chrome_tls_helper)
        if(TARGET "${_transport_v2_target}")
            message(FATAL_ERROR
                "Transport-v2 target '${_transport_v2_target}' escaped the explicit "
                "YUME_BUILD_TRANSPORT_V2 graph")
        endif()
    endforeach()
endif()

# ---------------------------------------------------------------------------
# Fuzz harnesses. Opt-in, Clang-only, never installed. Each target covers a
# parser that consumes input from outside the trust boundary. Native protocol,
# AUTH and schema-1 configuration coverage is independent of the retained
# transport-v2 parsers. They are executables rather than CTest cases because a fuzz run is
# time-bounded by the operator, not by a pass/fail assertion.
if(YUME_BUILD_FUZZERS)
    function(yume_add_fuzzer name source)
        add_executable(${name} "${CMAKE_SOURCE_DIR}/tests/fuzz/${source}")
        target_link_libraries(${name} PRIVATE ${ARGN})
        # Coverage and ASan/UBSan are inherited by libraries and harnesses.
        # Only these executables own libFuzzer's main function.
        target_link_options(${name} PRIVATE -fsanitize=fuzzer)
        yume_apply_perf_opts(${name})
    endfunction()

    yume_add_fuzzer(yume_fuzz_ytp1_protocol fuzz_ytp1_protocol.cpp yume_ytp1)
    yume_add_fuzzer(yume_fuzz_ytp1_auth fuzz_ytp1_auth.cpp yume_ytp1)
    yume_add_fuzzer(yume_fuzz_config_v1 fuzz_config_v1.cpp yume_config_v1)
    if(YUME_BUILD_TRANSPORT_V2)
        yume_add_fuzzer(yume_fuzz_h2_probe_decoder fuzz_h2_probe_decoder.cpp yume_core)
        if(TARGET yume_facade)
            yume_add_fuzzer(yume_fuzz_client_config fuzz_client_config.cpp yume_facade)
            yume_add_fuzzer(yume_fuzz_server_config fuzz_server_config.cpp yume_facade)
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
# A first-party target that links an LTO-built first-party library needs
# yume_apply_perf_opts, not yume_apply_warnings alone: under Clang the archive
# is bitcode and a consumer without -flto cannot read it. The ABI targets are
# the deliberate exception because their inputs are built without LTO.
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
