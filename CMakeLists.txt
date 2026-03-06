cmake_minimum_required(VERSION 3.20)
project(YUME LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

option(YUME_USE_BASEFWX "Enable BaseFWX inner crypto support" ON)
option(YUME_USE_SPDLOG "Enable spdlog logging backend" ON)
option(YUME_MINIMAL "Build for minimal systems (disable heavy deps/features)" OFF)
option(YUME_STATIC "Attempt static build (requires static deps)" OFF)
option(YUME_NATIVE_OPT "Enable native CPU tuning for yume builds" ON)
option(YUME_LTO "Enable link-time optimization for yume builds" ON)
option(YUME_FAST_MATH "Enable fast-math (unsafe for crypto)" OFF)

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

if(YUME_STATIC)
    set(BUILD_SHARED_LIBS OFF)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(Boost_USE_STATIC_LIBS ON)
else()
    set(OPENSSL_USE_STATIC_LIBS FALSE)
    set(Boost_USE_STATIC_LIBS OFF)
endif()

if(CMAKE_CROSSCOMPILING)
    set(YUME_NATIVE_OPT OFF CACHE BOOL "Enable native CPU tuning for yume builds" FORCE)
    set(YUME_LTO OFF CACHE BOOL "Enable link-time optimization for yume builds" FORCE)
endif()

find_package(OpenSSL REQUIRED)
find_package(Boost CONFIG QUIET COMPONENTS system)
if(NOT Boost_FOUND)
    find_package(Boost REQUIRED COMPONENTS system)
endif()
find_package(Threads REQUIRED)

if(YUME_MINIMAL)
    set(YUME_USE_BASEFWX ON CACHE BOOL "Enable BaseFWX for minimal builds" FORCE)
    set(YUME_USE_SPDLOG OFF CACHE BOOL "Disable spdlog for minimal builds" FORCE)
endif()

if(YUME_USE_BASEFWX)
    if(NOT CMAKE_CROSSCOMPILING)
        set(BASEFWX_NATIVE_OPT ${YUME_NATIVE_OPT} CACHE BOOL "Enable -march/-mtune native optimizations" FORCE)
    endif()
    if(CMAKE_CROSSCOMPILING)
        set(BASEFWX_NATIVE_OPT OFF CACHE BOOL "Disable native tuning for cross builds" FORCE)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/basefwx/cpp/CMakeLists.txt")
        set(BASEFWX_BUILD_CLI OFF CACHE BOOL "Disable BaseFWX CLI build" FORCE)
        add_subdirectory(basefwx/cpp EXCLUDE_FROM_ALL)
        if(TARGET basefwxcpp)
            if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
                target_compile_options(basefwxcpp PRIVATE -Wno-deprecated-declarations)
            elseif(MSVC)
                target_compile_options(basefwxcpp PRIVATE /wd4996)
            endif()
        endif()
    else()
        message(FATAL_ERROR "BaseFWX sources not found at basefwx/cpp")
    endif()
endif()

add_subdirectory(src)
