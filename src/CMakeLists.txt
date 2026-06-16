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

function(yume_apply_perf_opts target)
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
        if(YUME_LTO)
            target_compile_options(${target} PRIVATE
                $<$<CONFIG:Release>:-flto>
                $<$<CONFIG:RelWithDebInfo>:-flto>
                $<$<CONFIG:MinSizeRel>:-flto>
            )
            target_link_options(${target} PRIVATE
                $<$<CONFIG:Release>:-flto>
                $<$<CONFIG:RelWithDebInfo>:-flto>
                $<$<CONFIG:MinSizeRel>:-flto>
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
        if(YUME_LTO)
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

if(YUME_STATIC AND YUME_USE_SPDLOG AND NOT YUME_SPDLOG_TARGET STREQUAL "spdlog::spdlog_header_only")
    message(WARNING "Static link requested but only compiled spdlog was found; disabling spdlog.")
    set(YUME_USE_SPDLOG OFF CACHE BOOL "Disable spdlog for static builds" FORCE)
endif()

if(NOT YUME_TRANSPORT_CORE_ONLY)
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
        core/control_protocol.cpp
        core/crypto.cpp
        core/http_profile.cpp
        core/identity.cpp
        core/inner_crypto.cpp
        core/local_runtime.cpp
        core/packet_bulk.cpp
        core/protocol.cpp
        core/obfs.cpp
        core/obfs_h2.cpp
        core/obfs_signal.cpp
        core/tls_fingerprint.cpp
        core/tls_stealth.cpp
        core/tls_metrics.cpp
        util.cpp
        ${YUME_PLATFORM_SOURCES}
    )

    target_include_directories(yume_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

    target_link_libraries(yume_core
        PUBLIC
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
        target_link_libraries(yume_core PUBLIC ws2_32 mswsock)
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
endif()

add_library(yume_transport_core
    client/transport_core.cpp
    core/inner_crypto.cpp
    core/packet_bulk.cpp
    core/protocol.cpp
)

target_include_directories(yume_transport_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(yume_transport_core
    PUBLIC
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
yume_link_atomic_if_needed(yume_transport_core PUBLIC)
yume_apply_perf_opts(yume_transport_core)

if(NOT YUME_TRANSPORT_CORE_ONLY)
    # ------------------------------------------------------------------
    # Server library
    # ------------------------------------------------------------------
    # Extracted so both the yumed executable and the optional yume_facade
    # library (consumed by yume-gui) can link a single source-of-truth
    # server implementation. The executable below contains only main().
    add_library(yume_server STATIC
        server/local_runtime.cpp
        server/federation_link.cpp
        server/federation_manager.cpp
        server/ip_filter.cpp
        server/ip_filter_mmdb.cpp
        server/manager.cpp
        server/manager_relay.cpp
        server/packet_tun_egress.cpp
        server/auth.cpp
        server/session.cpp
        server/session_control.cpp
        server/session_net.cpp
        server/session_carrier.cpp
        server/session_streams.cpp
        server/session_ext.cpp
        server/session_open.cpp
        server/session_auth.cpp
        server/runtime_controller.cpp
        client/outbound_proxy.cpp
    )
    target_include_directories(yume_server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(yume_server PUBLIC yume_core yume_transport_core)
    yume_apply_perf_opts(yume_server)
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
        server/server_anonym_cli.cpp
        server/server_cluster_cli.cpp
        server/server_key_cli.cpp
        server/server_local_cli.cpp
        server/server_misc_cli.cpp
        server/server_runtime_prep.cpp
        server/srv_help.cpp
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

    # ------------------------------------------------------------------
    # Client library
    # ------------------------------------------------------------------
    # Mirror of yume_server: every client primitive except the CLI/REPL
    # entrypoint (cli.cpp) lives here so the facade can construct a
    # client session without duplicating the transport stack. cli.cpp
    # stays inside the `yume` executable because it contains argv
    # parsing and the interactive REPL — neither relevant to the GUI.
    add_library(yume_client_lib STATIC
        client/history.cpp
        client/local_runtime.cpp
        client/relay_secret.cpp
        client/relay_runtime.cpp
        client/runtime_controller.cpp
        client/tunnel.cpp
        client/tunnel_pool.cpp
        client/socks.cpp
        client/forward.cpp
        client/outbound_proxy.cpp
        client/share_file.cpp
        client/cli.cpp
        client/cli/anonym_proof.cpp
        client/cli/attach.cpp
        client/cli/args.cpp
        client/cli/auth.cpp
        client/cli/bench.cpp
        client/cli/capabilities.cpp
        client/cli/help.cpp
        client/cli/cert.cpp
        client/cli/config.cpp
        client/cli/diagnostics.cpp
        client/cli/files.cpp
        client/cli/input.cpp
        client/cli/platform.cpp
        client/cli/pq_bootstrap.cpp
        client/cli/proxy.cpp
        client/cli/relay.cpp
        client/cli/runtime.cpp
        client/cli/server_info.cpp
        client/cli/share.cpp
        client/cli/status.cpp
    )
    target_include_directories(yume_client_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(yume_client_lib PUBLIC yume_core yume_transport_core)
    yume_apply_perf_opts(yume_client_lib)
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
        if(NOT YUME_FEATURE_LAN_BRIDGE)
            message(WARNING
                "yume-selftest can be built, but routed loopback benchmarks require "
                "-DYUME_FEATURE_LAN_BRIDGE=ON in the yume/yumed binaries under test")
        endif()
        add_executable(yume-selftest
            tools/selftest.cpp
        )
        target_link_libraries(yume-selftest PRIVATE OpenSSL::Crypto Threads::Threads)
        yume_apply_perf_opts(yume-selftest)
        add_executable(yume-basefwx-bench
            tools/basefwx_bench.cpp
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
    endif()

    install(TARGETS ${_yume_install_targets}
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    )

    # ------------------------------------------------------------------
    # Optional GUI components
    # ------------------------------------------------------------------
    # The facade library has no GUI dependency and is small enough to
    # build unconditionally; the executable is gated on YUME_BUILD_GUI.
    add_subdirectory(facade)
    if(YUME_BUILD_GUI)
        add_subdirectory(gui)
    endif()
endif()

if(YUME_BUILD_TESTING)

add_executable(yume_transport_core_test
    client/transport_core_test.cpp
)

target_link_libraries(yume_transport_core_test PRIVATE yume_transport_core)
yume_link_atomic_if_needed(yume_transport_core_test PRIVATE)
yume_apply_perf_opts(yume_transport_core_test)

add_test(NAME yume_transport_core_test COMMAND yume_transport_core_test)

add_executable(yume_packet_bulk_test core/packet_bulk_test.cpp)
target_link_libraries(yume_packet_bulk_test PRIVATE yume_transport_core)
yume_link_atomic_if_needed(yume_packet_bulk_test PRIVATE)
yume_apply_perf_opts(yume_packet_bulk_test)
add_test(NAME yume_packet_bulk_test COMMAND yume_packet_bulk_test)

add_executable(yume_ip_filter_test server/ip_filter_test.cpp server/ip_filter.cpp server/ip_filter_mmdb.cpp)
target_link_libraries(yume_ip_filter_test PRIVATE yume_core)
yume_link_atomic_if_needed(yume_ip_filter_test PRIVATE)
yume_apply_perf_opts(yume_ip_filter_test)
add_test(NAME yume_ip_filter_test COMMAND yume_ip_filter_test)

if(NOT YUME_TRANSPORT_CORE_ONLY)
    add_executable(yume_obfs_test core/obfs_test.cpp)
    target_link_libraries(yume_obfs_test PRIVATE yume_core)
    yume_link_atomic_if_needed(yume_obfs_test PRIVATE)
    yume_apply_perf_opts(yume_obfs_test)
    add_test(NAME yume_obfs_test COMMAND yume_obfs_test)
endif()
endif()
