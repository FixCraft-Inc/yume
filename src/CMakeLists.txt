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

if(CMAKE_CROSSCOMPILING AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    find_library(ATOMIC_LIBRARY atomic)
endif()

function(yume_link_atomic_if_needed target scope)
    if(CMAKE_CROSSCOMPILING AND ATOMIC_LIBRARY AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_libraries(${target} ${scope} ${ATOMIC_LIBRARY})
    endif()
endfunction()

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
# explicit opt-in, and schema-1 endpoints use the native provider graph.
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
if(YUME_BUILD_NATIVE_PROVIDERS)
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

if(YUME_BUILD_NATIVE_PROVIDERS)
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
if(YUME_BUILD_NATIVE_PROVIDERS)
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
if(YUME_BUILD_NATIVE_PROVIDERS)
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
if(YUME_BUILD_NATIVE_PROVIDERS)
    add_library(yume_cover_profile STATIC
        stealth/cover_profile.cpp
        stealth/cover_profile.hpp
        stealth/tls_fingerprint.cpp
        stealth/tls_fingerprint.hpp
        stealth/transport_profiles.inc)
    target_include_directories(yume_cover_profile PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_cover_profile PRIVATE OpenSSL::Crypto)
    yume_apply_perf_opts(yume_cover_profile)
    yume_assert_exact_link_dependencies(yume_cover_profile OpenSSL::Crypto)
endif()

if(YUME_BUILD_NATIVE_PROVIDERS)
    add_library(yume_tls_client_profile STATIC
        stealth/tls_client_profile.cpp
        stealth/tls_client_profile.hpp)
    target_include_directories(yume_tls_client_profile PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_tls_client_profile
        PUBLIC yume_cover_profile PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    yume_apply_perf_opts(yume_tls_client_profile)
    yume_assert_exact_link_dependencies(yume_tls_client_profile
        yume_cover_profile OpenSSL::SSL OpenSSL::Crypto)
endif()

# Shared admission owns path/authority parsing, the HMAC primitive, and
# replay reservations. Protocol encodings remain with their separate owners.
if(YUME_BUILD_NATIVE_PROVIDERS)
    add_library(yume_h2_admission STATIC
        admission/h2_admission.cpp
        admission/h2_admission.hpp)
    target_include_directories(yume_h2_admission PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_h2_admission PRIVATE Boost::headers OpenSSL::Crypto)
    yume_apply_perf_opts(yume_h2_admission)
    yume_assert_exact_link_dependencies(yume_h2_admission Boost::headers OpenSSL::Crypto)
endif()

if(YUME_BUILD_NATIVE_PROVIDERS)
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

# One HTTP/2/WebSocket state machine for the YTP/1 carrier. It owns framing
# and receive credit, not TLS or session admission.
if(YUME_BUILD_NATIVE_PROVIDERS)
    find_package(Threads REQUIRED)
    add_library(yume_h2_carrier STATIC
        stealth/h2_carrier.cpp
        stealth/h2_carrier.hpp
        stealth/h2_wire_profile.cpp
        stealth/h2_wire_profile.hpp
        stealth/outer_carrier_observer.cpp
        stealth/outer_carrier_observer.hpp
        stealth/websocket_codec.cpp
        stealth/websocket_codec.hpp)
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

if(YUME_BUILD_NATIVE_PROVIDERS)
    add_library(yume_h2_duplex_carrier STATIC
        providers/h2_duplex_carrier.cpp
        providers/h2_duplex_carrier.hpp
        providers/control_task.hpp)
    add_library(yume::h2_duplex_carrier ALIAS yume_h2_duplex_carrier)
    target_include_directories(yume_h2_duplex_carrier
        PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_h2_duplex_carrier
        PUBLIC yume_engine yume_h2_carrier
        PRIVATE yume_ytp1_h2_admission OpenSSL::Crypto)
    yume_apply_perf_opts(yume_h2_duplex_carrier)
endif()

# The first concrete YTP/1 security-provider candidate is deliberately an
# opt-in, build-tree-only target. It uses upstream OpenSSL 3.5 primitives but
# is not part of the runnable transport-v2 graph and is not release-qualified.
if(YUME_BUILD_NATIVE_PROVIDERS)
    add_library(yume_openssl_security_provider STATIC
        providers/ytp1_crypto.cpp
        providers/ytp1_crypto.hpp
        providers/openssl_security_provider.cpp
        providers/openssl_security_provider.hpp)
    add_library(yume::openssl_security_provider ALIAS
        yume_openssl_security_provider)
    target_include_directories(yume_openssl_security_provider
        PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_openssl_security_provider
        PUBLIC yume_session_engine yume_ytp1
        PRIVATE OpenSSL::Crypto)
    yume_apply_perf_opts(yume_openssl_security_provider)
endif()

# Memory-BIO TLS wraps the engine ByteChannel contract and therefore has no
# socket dependency. Its client applies the shared browser TLS profile; it
# does not implement the HTTP front door or H2 carrier.
if(YUME_BUILD_NATIVE_PROVIDERS)
    add_library(yume_tls13_secure_channel STATIC
        providers/tls13_secure_channel.cpp
        providers/tls13_secure_channel.hpp)
    add_library(yume::tls13_secure_channel ALIAS
        yume_tls13_secure_channel)
    target_include_directories(yume_tls13_secure_channel
        PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_tls13_secure_channel
        PUBLIC yume_engine PRIVATE yume_tls_client_profile OpenSSL::SSL OpenSSL::Crypto)
    yume_apply_perf_opts(yume_tls13_secure_channel)
endif()

# Bounded, confined file reads are shared by the native cover and the share
# module. Keep their handle ownership independent of any runtime.
if(YUME_BUILD_NATIVE_PROVIDERS OR YUME_BUILD_BASEFWX_MODULES)
    add_library(yume_bounded_files STATIC
        fs/bounded_file.cpp
        fs/bounded_file.hpp)
    target_include_directories(yume_bounded_files PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    yume_prepare_static_for_shared_abi(yume_bounded_files)
    yume_apply_perf_opts(yume_bounded_files)
    yume_assert_exact_link_dependencies(yume_bounded_files)
endif()

if(YUME_BUILD_NATIVE_PROVIDERS)
    add_library(yume_cover_site STATIC
        providers/cover_site.cpp
        providers/cover_site.hpp)
    target_include_directories(yume_cover_site PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_cover_site PUBLIC yume_engine PRIVATE yume_bounded_files)
    yume_apply_perf_opts(yume_cover_site)
    yume_assert_exact_link_dependencies(yume_cover_site yume_engine yume_bounded_files)

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

    add_library(yume_h2_web_front_door STATIC
        providers/h2_web_front_door.cpp
        providers/h2_web_front_door.hpp)
    add_library(yume::h2_web_front_door ALIAS yume_h2_web_front_door)
    target_include_directories(yume_h2_web_front_door PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_h2_web_front_door PUBLIC
        yume_engine yume_asio_execution_context yume_asio_tcp_byte_channel_provider
        yume_tls13_secure_channel yume_h2_duplex_carrier
        yume_cover_site yume_h2_admission
        PRIVATE yume_ytp1_h2_admission Boost::system OpenSSL::Crypto)
    yume_apply_perf_opts(yume_h2_web_front_door)
    yume_assert_exact_link_dependencies(yume_h2_web_front_door
        yume_engine yume_asio_execution_context yume_asio_tcp_byte_channel_provider
        yume_tls13_secure_channel yume_h2_duplex_carrier
        yume_cover_site yume_h2_admission
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

add_library(yume_private_files STATIC fs/secret_file.cpp)
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

if(YUME_BUILD_NATIVE_PROVIDERS)
    add_library(yume_native_credentials STATIC
        runtime/native_credentials.cpp runtime/native_credentials.hpp)
    target_include_directories(yume_native_credentials PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(yume_native_credentials
        PUBLIC yume_config_v1 yume_engine
        PRIVATE yume_private_files yume_openssl_security_provider
            yume_tls13_secure_channel OpenSSL::Crypto)
    yume_apply_perf_opts(yume_native_credentials)
    yume_assert_exact_link_dependencies(yume_native_credentials
        yume_config_v1 yume_engine yume_private_files yume_openssl_security_provider
        yume_tls13_secure_channel OpenSSL::Crypto)

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
        PRIVATE yume_native_credentials yume_h2_web_front_door yume_openssl_security_provider
            yume_h2_duplex_carrier yume_tls13_secure_channel yume_cover_profile
            yume_direct_route_handler yume_native_egress_policy yume_egress_pacing
            yume_socks5_upstream Boost::system)
    yume_apply_perf_opts(yume_native_endpoint)
    yume_assert_exact_link_dependencies(yume_native_endpoint
        yume_config_v1 yume_session_bootstrap yume_asio_execution_context yume_asio_tcp_byte_channel_provider
        yume_native_credentials yume_h2_web_front_door yume_openssl_security_provider
        yume_h2_duplex_carrier yume_tls13_secure_channel yume_cover_profile
        yume_direct_route_handler yume_native_egress_policy yume_egress_pacing
        yume_socks5_upstream Boost::system)

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
                yume_direct_route_handler yume_openssl_security_provider yume_bounded_files ${_yume_native_network_libraries}
                Boost::system)
        yume_apply_perf_opts(yume_native_runtime)
        yume_assert_exact_link_dependencies(yume_native_runtime
            yume_config_v1 yume_session_bootstrap yume_asio_execution_context
            yume_native_endpoint yume_native_egress_policy yume_native_credentials
            yume_asio_direct_route_provider yume_asio_tcp_byte_channel_provider
            yume_system_resolver yume_system_resolver_helper
            yume_child_process yume_module_launcher
            yume_direct_route_handler yume_openssl_security_provider yume_bounded_files ${_yume_native_network_libraries}
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
    add_library(yume_embed STATIC
        abi/native_backend.cpp abi/endpoint_backend.hpp)
    target_include_directories(yume_embed PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    # The backend reports the security provider's identity and OpenSSL
    # release, so it names that provider rather than reaching it through
    # the runtime's private links.
    target_link_libraries(yume_embed PRIVATE
        yume_native_endpoint yume_openssl_security_provider Threads::Threads Boost::system)
    yume_apply_perf_opts(yume_embed)
    yume_assert_exact_link_dependencies(yume_embed
        yume_native_endpoint yume_openssl_security_provider Threads::Threads Boost::system)
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

# The 0.3 ABI is unfrozen. It reaches the native runtime only through the embed
# seam that yume_embed implements, and it installs only with the opt-in
# development SDK below.
if(YUME_BUILD_SHARED_ABI)
    # One translation unit. The shell owns handles, validation, diagnostics
    # and callback rules, and the runtime lives behind the embed seam.
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
    target_link_libraries(yume_abi PRIVATE yume_config_v1 yume_embed)
    # Every archive absorbed into libyume must be PIC, hidden and non-LTO,
    # including the whole native chain behind the schema-1 backend.
    foreach(_yume_absorbed IN ITEMS
            yume_embed yume_native_endpoint yume_native_egress_policy yume_egress_lists
            yume_native_credentials yume_socks5_upstream
            yume_egress_pacing yume_session_bootstrap yume_session_engine yume_engine yume_ytp1
            yume_asio_execution_context yume_asio_tcp_byte_channel_provider yume_system_resolver
            yume_child_process
            yume_h2_web_front_door yume_cover_site yume_h2_duplex_carrier
            yume_ytp1_h2_admission yume_h2_admission
            yume_tls13_secure_channel yume_tls_client_profile
            yume_cover_profile yume_openssl_security_provider yume_private_files)
        yume_prepare_static_for_shared_abi(${_yume_absorbed})
    endforeach()

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
if(YUME_BUILD_NATIVE_PROVIDERS)
    yume_assert_exact_link_dependencies(
        yume_openssl_security_provider
        yume_session_engine yume_ytp1 OpenSSL::Crypto)
endif()
if(YUME_BUILD_NATIVE_PROVIDERS)
    yume_assert_exact_link_dependencies(
        yume_tls13_secure_channel
        yume_engine yume_tls_client_profile OpenSSL::SSL OpenSSL::Crypto)
endif()
yume_assert_exact_link_dependencies(
    yume_config_v1 nlohmann_json::nlohmann_json)
yume_assert_exact_link_dependencies(
    yume_direct_route_handler yume_engine)
# Both network providers resolve names only through the SystemResolver helper
# process, never an in-process getaddrinfo.
if(YUME_BUILD_NATIVE_PROVIDERS)
    yume_assert_exact_link_dependencies(
        yume_asio_direct_route_provider yume_engine yume_asio_execution_context
        yume_system_resolver Boost::system)
endif()
if(YUME_BUILD_NATIVE_PROVIDERS)
    yume_assert_exact_link_dependencies(
        yume_asio_tcp_byte_channel_provider yume_engine yume_asio_execution_context
        yume_system_resolver Boost::system)
endif()
if(YUME_BUILD_NATIVE_PROVIDERS)
    yume_assert_exact_link_dependencies(
        yume_h2_duplex_carrier
        yume_engine yume_h2_carrier yume_ytp1_h2_admission OpenSSL::Crypto)
endif()
if(YUME_BUILD_SHARED_ABI)
    yume_assert_exact_link_dependencies(yume_abi yume_config_v1 yume_embed)
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
        add_executable(yume_websocket_codec_test stealth/websocket_codec_test.cpp)
        target_link_libraries(yume_websocket_codec_test PRIVATE yume_h2_carrier)
        yume_link_atomic_if_needed(yume_websocket_codec_test PRIVATE)
        yume_apply_perf_opts(yume_websocket_codec_test)
        add_test(NAME yume_websocket_codec_test COMMAND yume_websocket_codec_test)
    endif()
    if(TARGET yume_bounded_files)
        add_executable(yume_bounded_file_test fs/bounded_file_test.cpp)
        target_link_libraries(yume_bounded_file_test PRIVATE yume_bounded_files)
        yume_apply_perf_opts(yume_bounded_file_test)
        add_test(NAME yume_bounded_file_test COMMAND yume_bounded_file_test)
    endif()
    if(TARGET yume_cover_profile)
        # The active profile must match its capture manifest byte for byte.
        add_executable(yume_cover_profile_test stealth/cover_profile_test.cpp)
        target_link_libraries(yume_cover_profile_test
            PRIVATE yume_cover_profile nlohmann_json::nlohmann_json)
        target_compile_definitions(yume_cover_profile_test PRIVATE
            YUME_COVER_MANIFEST="${YUME_ACTIVE_PROFILE_MANIFEST}"
            YUME_COVER_HTTP2_PROFILE="${YUME_ACTIVE_PROFILE_HTTP2}")
        yume_apply_perf_opts(yume_cover_profile_test)
        add_test(NAME yume_cover_profile_test COMMAND yume_cover_profile_test)

        add_executable(yume_tls_fingerprint_test stealth/tls_fingerprint_test.cpp)
        target_link_libraries(yume_tls_fingerprint_test PRIVATE yume_cover_profile)
        yume_apply_perf_opts(yume_tls_fingerprint_test)
        add_test(NAME yume_tls_fingerprint_test COMMAND yume_tls_fingerprint_test)
    endif()
    add_executable(yume_secret_file_test fs/secret_file_test.cpp)
    target_link_libraries(yume_secret_file_test PRIVATE yume_private_files)
    yume_apply_perf_opts(yume_secret_file_test)
    add_test(NAME yume_secret_file_test COMMAND yume_secret_file_test)

    add_executable(yume_hex_test common/hex_test.cpp)
    target_include_directories(yume_hex_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    yume_apply_perf_opts(yume_hex_test)
    add_test(NAME yume_hex_test COMMAND yume_hex_test)

    add_executable(yume_timing_test common/timing_test.cpp)
    target_include_directories(yume_timing_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    yume_apply_dev_diagnostics(yume_timing_test PRIVATE)
    yume_apply_perf_opts(yume_timing_test)
    add_test(NAME yume_timing_test COMMAND yume_timing_test)
    foreach(_shared_test IN ITEMS yume_websocket_codec_test yume_bounded_file_test
            yume_cover_profile_test yume_tls_fingerprint_test yume_secret_file_test
            yume_hex_test yume_timing_test)
        if(TARGET ${_shared_test})
            if(MSVC)
                target_compile_options(${_shared_test} PRIVATE /UNDEBUG)
            else()
                target_compile_options(${_shared_test} PRIVATE -UNDEBUG)
            endif()
            set_tests_properties(${_shared_test} PROPERTIES LABELS "shared-component")
        endif()
    endforeach()
    if(YUME_BUILD_NATIVE_PROVIDERS)
        add_executable(yume_cover_site_test providers/cover_site_test.cpp)
        target_link_libraries(yume_cover_site_test PRIVATE yume_cover_site)
        yume_apply_perf_opts(yume_cover_site_test)
        add_test(NAME yume_cover_site_test COMMAND yume_cover_site_test)
        if(UNIX)
            add_executable(yume_h2_web_front_door_test providers/h2_web_front_door_test.cpp)
            target_link_libraries(yume_h2_web_front_door_test PRIVATE
                yume_h2_web_front_door yume_asio_execution_context yume_ytp1_h2_admission
                ${YUME_NGHTTP2_TARGET} OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
            if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
                # Inject OS bind errors in this test process without changing
                # privileges, host limits or the production provider interface.
                target_compile_definitions(yume_h2_web_front_door_test PRIVATE YUME_TEST_WRAP_BIND=1)
                target_link_options(yume_h2_web_front_door_test PRIVATE "-Wl,--wrap=bind")
            endif()
            yume_apply_perf_opts(yume_h2_web_front_door_test)
            add_test(NAME yume_h2_web_front_door_test COMMAND yume_h2_web_front_door_test)
            set_tests_properties(yume_h2_web_front_door_test PROPERTIES
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

    if(YUME_BUILD_NATIVE_PROVIDERS)
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

    if(YUME_BUILD_NATIVE_PROVIDERS)
        add_executable(yume_ytp1_h2_admission_test
            providers/ytp1_h2_admission_test.cpp)
        target_link_libraries(yume_ytp1_h2_admission_test
            PRIVATE yume_ytp1_h2_admission yume_h2_admission)
        yume_apply_perf_opts(yume_ytp1_h2_admission_test)
        yume_assert_exact_link_dependencies(yume_ytp1_h2_admission_test
            yume_ytp1_h2_admission yume_h2_admission)
        add_test(NAME yume_ytp1_h2_admission_test COMMAND yume_ytp1_h2_admission_test)
        add_executable(yume_h2_duplex_carrier_test
            providers/h2_duplex_carrier_test.cpp)
        target_link_libraries(yume_h2_duplex_carrier_test
            PRIVATE yume_h2_duplex_carrier yume_ytp1_h2_admission yume_h2_admission)
        yume_apply_perf_opts(yume_h2_duplex_carrier_test)
        yume_assert_exact_link_dependencies(
            yume_h2_duplex_carrier_test yume_h2_duplex_carrier
            yume_ytp1_h2_admission yume_h2_admission)
        add_test(NAME yume_h2_duplex_carrier_test
            COMMAND yume_h2_duplex_carrier_test)
        set_tests_properties(yume_h2_duplex_carrier_test PROPERTIES
            LABELS "foundation;0.3;carrier-provider")

        # The H2/WebSocket state machine's own contract, beside the adapter's.
        add_executable(yume_h2_carrier_test
            stealth/h2_carrier_test.cpp)
        target_link_libraries(yume_h2_carrier_test
            PRIVATE yume_h2_carrier ${YUME_NGHTTP2_TARGET})
        target_compile_definitions(yume_h2_carrier_test PRIVATE
            YUME_TEST_EXPECT_DEV_DIAGNOSTICS=${YUME_DEV_DIAGNOSTICS_EXPRESSION})
        if(MSVC)
            target_compile_options(yume_h2_carrier_test
                PRIVATE /UNDEBUG)
        else()
            target_compile_options(yume_h2_carrier_test
                PRIVATE -UNDEBUG)
        endif()
        yume_apply_perf_opts(yume_h2_carrier_test)
        yume_assert_exact_link_dependencies(
            yume_h2_carrier_test yume_h2_carrier ${YUME_NGHTTP2_TARGET})
        add_test(NAME yume_h2_carrier_test
            COMMAND yume_h2_carrier_test)
        set_tests_properties(yume_h2_carrier_test PROPERTIES
            LABELS "foundation;0.3;carrier-provider")
    endif()

    if(YUME_BUILD_NATIVE_PROVIDERS)
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

    if(YUME_BUILD_NATIVE_PROVIDERS)
        add_executable(yume_openssl_security_provider_test
            providers/openssl_security_provider_test.cpp)
        target_link_libraries(yume_openssl_security_provider_test
            PRIVATE yume_openssl_security_provider OpenSSL::Crypto)
        target_compile_definitions(yume_openssl_security_provider_test PRIVATE
            YUME_YTP1_CRYPTO_VECTORS_FILE="${CMAKE_CURRENT_SOURCE_DIR}/ytp/testdata/ytp1_crypto_vectors.txt")
        yume_apply_perf_opts(yume_openssl_security_provider_test)
        yume_assert_exact_link_dependencies(
            yume_openssl_security_provider_test
            yume_openssl_security_provider OpenSSL::Crypto)
        add_test(NAME yume_openssl_security_provider_test
            COMMAND yume_openssl_security_provider_test)
        set_tests_properties(yume_openssl_security_provider_test PROPERTIES
            LABELS "foundation;0.3;security-provider")
    endif()

    if(YUME_BUILD_NATIVE_PROVIDERS)
        add_executable(yume_tls13_secure_channel_test
            providers/tls13_secure_channel_test.cpp)
        target_link_libraries(yume_tls13_secure_channel_test
            PRIVATE yume_tls13_secure_channel yume_tls_client_profile
                    yume_cover_profile OpenSSL::SSL OpenSSL::Crypto)
        if(MSVC)
            target_compile_options(yume_tls13_secure_channel_test PRIVATE /UNDEBUG)
        else()
            target_compile_options(yume_tls13_secure_channel_test PRIVATE -UNDEBUG)
        endif()
        yume_apply_perf_opts(yume_tls13_secure_channel_test)
        yume_assert_exact_link_dependencies(
            yume_tls13_secure_channel_test
            yume_tls13_secure_channel yume_tls_client_profile
            yume_cover_profile OpenSSL::SSL OpenSSL::Crypto)
        add_test(NAME yume_tls13_secure_channel_test
            COMMAND yume_tls13_secure_channel_test)
        set_tests_properties(yume_tls13_secure_channel_test PROPERTIES
            LABELS "foundation;0.3;secure-channel-provider")
    endif()

    if(TARGET yume_native_credentials AND NOT WIN32)
        add_executable(yume_native_credentials_test runtime/native_credentials_test.cpp)
        target_link_libraries(yume_native_credentials_test PRIVATE
            yume_native_credentials yume_openssl_security_provider OpenSSL::Crypto)
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
            yume_native_endpoint yume_asio_execution_context yume_cover_site
            yume_native_credentials yume_h2_duplex_carrier yume_tls13_secure_channel
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

    if(YUME_BUILD_NATIVE_PROVIDERS)
        add_executable(yume_native_backend_test abi/native_backend_test.cpp)
        # The test compiles the private backend implementation with paused
        # execution; linking its archive too would duplicate the definitions.
        target_link_libraries(yume_native_backend_test PRIVATE
            yume_native_endpoint yume_openssl_security_provider Threads::Threads)
        yume_apply_perf_opts(yume_native_backend_test)
        add_test(NAME yume_native_backend_test COMMAND yume_native_backend_test
            "${CMAKE_SOURCE_DIR}/config/ytp1/yumed.json")
        set_tests_properties(yume_native_backend_test PROPERTIES
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
            abi/service_open_transaction_test.cpp)
        target_include_directories(yume_abi_stream_open_transaction_test
            PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
        yume_apply_warnings(yume_abi_stream_open_transaction_test)
        add_test(NAME yume_abi_stream_open_transaction_test
            COMMAND yume_abi_stream_open_transaction_test)

        # Real schema-1 setup credentials through the public C ABI: both
        # endpoint lifecycles, peer identity, refusals, deadlines, half-close,
        # typed end of stream, stop, restart and handles that outlive their
        # endpoint. Python and OpenSSL come from the native endpoint test.
        if(UNIX)
            add_executable(yume_abi_stream_probe abi/stream_probe.c)
            target_link_libraries(yume_abi_stream_probe
                PRIVATE yume_abi Threads::Threads)
            target_include_directories(yume_abi_stream_probe
                PRIVATE "${CMAKE_SOURCE_DIR}/include")
            yume_apply_warnings(yume_abi_stream_probe)
            add_test(NAME yume_abi_stream_integration
                COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_SOURCE_DIR}/tests/test_yume_abi_stream.py"
                    --probe "$<TARGET_FILE:yume_abi_stream_probe>"
                    --openssl "${YUME_NATIVE_TEST_OPENSSL}"
                    --resolver "$<TARGET_FILE:yume-resolver>")
            set_tests_properties(yume_abi_stream_integration PROPERTIES
                TIMEOUT 180
                LABELS "foundation;0.3;abi;integration;native-runtime")
            if(TARGET yumed)
                add_executable(yume_abi_packet_probe abi/packet_probe.cpp)
                target_link_libraries(yume_abi_packet_probe PRIVATE yume_abi Threads::Threads)
                yume_apply_warnings(yume_abi_packet_probe)
                add_test(NAME yume_abi_packet_integration
                    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tests/test_yume_abi_packet.py"
                        --probe "$<TARGET_FILE:yume_abi_packet_probe>" --yumed "$<TARGET_FILE:yumed>"
                        --openssl "${YUME_NATIVE_TEST_OPENSSL}")
                set_tests_properties(yume_abi_packet_integration PROPERTIES TIMEOUT 300 LABELS "abi;packet;native")
                add_executable(yume_abi_route_probe abi/route_probe.cpp)
                target_link_libraries(yume_abi_route_probe PRIVATE yume_abi Threads::Threads)
                yume_apply_warnings(yume_abi_route_probe)
                add_test(NAME yume_abi_route_integration
                    COMMAND "${Python3_EXECUTABLE}"
                        "${CMAKE_SOURCE_DIR}/tests/test_yume_abi_route.py"
                        --probe "$<TARGET_FILE:yume_abi_route_probe>"
                        --yumed "$<TARGET_FILE:yumed>"
                        --openssl "${YUME_NATIVE_TEST_OPENSSL}")
                set_tests_properties(yume_abi_route_integration PROPERTIES
                    TIMEOUT 150 LABELS "foundation;0.3;abi;integration;native-runtime")
            endif()
        endif()

        if(YUME_INSTALL_EXPERIMENTAL_SDK)
            set(_yume_test_installed_native_traffic OFF)
            if(TARGET yumed AND UNIX)
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

    # The browser profile the carriers emit: the generated table matches its
    # registry, and the committed capture matches its own evidence.
    add_test(NAME yume_transport_profile_generation_check
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/generate_transport_profiles.py"
            --registry "${YUME_TRANSPORT_PROFILE_REGISTRY}"
            --check)
    add_test(NAME yume_tls_wire_profile_check
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/yume_tls_wire.py"
            check-profile
            --profile "${YUME_ACTIVE_PROFILE_TLS_WIRE}"
            ${YUME_ACTIVE_PROFILE_TLS_CANDIDATE_ARGS})
    add_test(NAME yume_chrome151_evidence_check
        COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/scripts/yume_chrome_evidence.py"
            --fixture "${YUME_ACTIVE_PROFILE_FIXTURE}")
    if(TARGET yume_h2_carrier)
        # The HTTP/2 connection opening the carrier emits, checked against
        # the browser's.
        add_executable(yume_h2_opening_probe stealth/h2_opening_probe.cpp)
        target_link_libraries(yume_h2_opening_probe PRIVATE yume_h2_carrier)
        yume_apply_perf_opts(yume_h2_opening_probe)
        add_test(NAME yume_h2_fingerprint_check
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/scripts/yume_h2_fingerprint.py"
                --emitter "$<TARGET_FILE:yume_h2_opening_probe>"
                --check chrome)
    endif()
    if(TARGET yume_tls_client_profile)
        # Compares the ClientHello the TLS client emits against the committed
        # browser capture, rather than comparing config to config.
        add_executable(yume_tls_clienthello_dump stealth/clienthello_dump.cpp)
        target_link_libraries(yume_tls_clienthello_dump PRIVATE
            yume_tls_client_profile yume_cover_profile OpenSSL::SSL)
        yume_apply_perf_opts(yume_tls_clienthello_dump)
        add_test(NAME yume_native_tls_wire_test
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/tests/test_yume_native_tls_wire.py")
        set_tests_properties(yume_native_tls_wire_test PROPERTIES
            ENVIRONMENT "YUME_CLIENTHELLO_DUMP=$<TARGET_FILE:yume_tls_clienthello_dump>")
    endif()

    # Transport-agnostic evidence, capture and documentation tooling.
    foreach(_yume_tool_test IN ITEMS
            "yume_tls_wire_test;tests/test_yume_tls_wire.py"
            "yume_socket_autotuning_test;tests/test_socket_autotuning.py"
            "yume_evaluation_reports_test;tests/test_yume_evaluation_reports.py"
            "yume_browser_sandbox_test;scripts/test_yume_browser_sandbox.py"
            "yume_classifier_evidence_test;scripts/test_yume_classifier_evidence.py"
            "yume_classifier_gate_test;scripts/test_yume_classifier_gate.py"
            "yume_constrained_host_test;scripts/test_yume_constrained_host.py"
            "yume_capture_manifest_test;scripts/test_yume_capture_manifest.py"
            "yume_capture_binary_provenance_test;scripts/test_yume_capture_binary_provenance.py"
            "yume_capture_finalize_test;scripts/test_yume_capture_finalize.py"
            "yume_diagrams_test;scripts/test_yume_diagrams.py")
        list(GET _yume_tool_test 0 _yume_tool_test_name)
        list(GET _yume_tool_test 1 _yume_tool_test_script)
        add_test(NAME ${_yume_tool_test_name}
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/${_yume_tool_test_script}")
    endforeach()
    find_program(YUME_NODE_EXECUTABLE NAMES node nodejs)
    if(YUME_NODE_EXECUTABLE)
        add_test(NAME yume_cover_node_workload_test
            COMMAND "${YUME_NODE_EXECUTABLE}"
                "${CMAKE_SOURCE_DIR}/tools/cover-node/workload_test.mjs")
        add_test(NAME yume_chrome_navigation_test
            COMMAND "${YUME_NODE_EXECUTABLE}" --test
                "${CMAKE_SOURCE_DIR}/tools/cover-node/test_capture_chrome_navigation.mjs")
        add_test(NAME yume_cover_server_protocols_test
            COMMAND "${YUME_NODE_EXECUTABLE}" --test
                "${CMAKE_SOURCE_DIR}/tools/cover-node/test_cover_server_protocols.mjs")
    endif()
endif()

# ---------------------------------------------------------------------------
# Fuzz harnesses. Opt-in, Clang-only, never installed. Each target covers a
# parser that consumes input from outside the trust boundary: the YTP/1
# protocol, AUTH and schema-1 configuration. They are executables rather than
# CTest cases because a fuzz run is
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
set(YUME_WARNING_EXEMPT_TARGETS)

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
