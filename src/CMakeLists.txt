include(FetchContent)

set(_nlohmann_vendor "${CMAKE_SOURCE_DIR}/third_party/nlohmann_json")
if(EXISTS "${_nlohmann_vendor}/nlohmann/json.hpp" AND NOT TARGET nlohmann_json::nlohmann_json)
    add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
    target_include_directories(nlohmann_json::nlohmann_json INTERFACE "${_nlohmann_vendor}")
    set(nlohmann_json_FOUND TRUE)
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

find_package(ZSTD QUIET)
if(CMAKE_CROSSCOMPILING)
    find_library(ATOMIC_LIBRARY atomic)
    if(NOT ATOMIC_LIBRARY)
        set(ATOMIC_LIBRARY atomic)
    endif()
endif()

if(YUME_USE_SPDLOG)
    find_package(spdlog QUIET)
    if(NOT spdlog_FOUND)
        message(STATUS "spdlog not found, fetching...")
        FetchContent_Declare(
            spdlog
            GIT_REPOSITORY https://github.com/gabime/spdlog.git
            GIT_TAG v1.14.1
        )
        FetchContent_MakeAvailable(spdlog)
    endif()
endif()

if(YUME_STATIC AND YUME_USE_SPDLOG)
    message(WARNING "Static link requested; disabling spdlog to avoid linking shared libspdlog.")
    set(YUME_USE_SPDLOG OFF CACHE BOOL "Disable spdlog for static builds" FORCE)
endif()

add_library(yume_core
    core/crypto.cpp
    core/inner_crypto.cpp
    core/protocol.cpp
    core/obfs.cpp
    util.cpp
)

target_include_directories(yume_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(yume_core
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::system
        Threads::Threads
        nlohmann_json::nlohmann_json
)
if(TARGET Boost::headers)
    target_link_libraries(yume_core PUBLIC Boost::headers)
elseif(TARGET Boost::boost)
    target_link_libraries(yume_core PUBLIC Boost::boost)
elseif(Boost_INCLUDE_DIR)
    target_include_directories(yume_core PUBLIC ${Boost_INCLUDE_DIR})
endif()
if(WIN32)
    target_link_libraries(yume_core PUBLIC ws2_32 mswsock)
endif()
if(CMAKE_CROSSCOMPILING AND ATOMIC_LIBRARY)
    target_link_libraries(yume_core PUBLIC ${ATOMIC_LIBRARY})
endif()

if(ZSTD_FOUND)
    target_link_libraries(yume_core PUBLIC ZSTD::ZSTD)
elseif(ZSTD_LIBRARY)
    target_link_libraries(yume_core PUBLIC ${ZSTD_LIBRARY})
    if(ZSTD_INCLUDE_DIR)
        target_include_directories(yume_core PUBLIC ${ZSTD_INCLUDE_DIR})
    endif()
elseif(YUME_STATIC)
    message(WARNING "ZSTD not found; static OpenSSL builds may fail to link")
endif()

if(YUME_USE_SPDLOG)
    target_link_libraries(yume_core PUBLIC spdlog::spdlog)
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

if(CMAKE_CROSSCOMPILING)
    get_target_property(_yume_includes yume_core INCLUDE_DIRECTORIES)
    if(_yume_includes)
        list(REMOVE_ITEM _yume_includes "/usr/include" "/usr/include/")
        set_target_properties(yume_core PROPERTIES INCLUDE_DIRECTORIES "${_yume_includes}")
    endif()
endif()

add_executable(yumed
    main_server.cpp
    server/manager.cpp
    server/auth.cpp
    server/session.cpp
)

target_link_libraries(yumed PRIVATE yume_core)
if(YUME_STATIC AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(yumed PRIVATE -static)
endif()

add_executable(yume
    main_client.cpp
    client/cli.cpp
    client/tunnel.cpp
    client/socks.cpp
    client/forward.cpp
)

target_link_libraries(yume PRIVATE yume_core)
if(YUME_STATIC AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(yume PRIVATE -static)
endif()
