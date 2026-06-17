cmake_minimum_required(VERSION 3.20)
project(YUME LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()
# CMP0091: MSVC runtime library selection via CMAKE_MSVC_RUNTIME_LIBRARY
# and the equivalent per-target property. Required for YUME_GUI_PORTABLE
# to switch the GUI to /MT(d) without affecting other targets.
if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()

option(YUME_USE_BASEFWX "Enable BaseFWX inner crypto support" ON)
option(YUME_USE_SYSTEM_BASEFWX "Prefer a system-installed BaseFWX (find_package basefwx CONFIG) over the bundled tree" OFF)
option(YUME_USE_SPDLOG "Enable spdlog logging backend" ON)
option(YUME_USE_BUNDLED_NLOHMANN "Allow bundled nlohmann_json fallback" ON)
option(YUME_MINIMAL "Build for minimal systems (disable heavy deps/features)" OFF)
option(YUME_STATIC "Attempt static build (requires static deps)" OFF)
option(YUME_NATIVE_OPT "Enable host-specific -march/-mtune=native CPU tuning; disables portable binaries" OFF)
option(YUME_LTO "Enable link-time optimization for yume builds" ON)
option(YUME_FAST_MATH "Enable fast-math (unsafe for crypto)" OFF)
option(YUME_TRANSPORT_CORE_ONLY "Build only the shared transport core target" OFF)
option(YUME_DEB_SHLIBDEPS "Use dpkg-shlibdeps when building Debian packages" ON)
option(YUME_BUILD_SELFTEST "Build optional localhost benchmark self-test tool for desktop developers" OFF)
option(YUME_BUILD_TESTING "Build optional YUME unit test executables" OFF)
option(YUME_BUILD_TOOLS "Build optional helper tools such as yume-net-map" OFF)
option(YUME_BUILD_SHARED_ABI "Build and install the stable libyume C ABI shared library" OFF)

set(BUILD_TESTING ${YUME_BUILD_TESTING} CACHE BOOL "Build YUME unit tests" FORCE)
include(CTest)

if(YUME_BUILD_SELFTEST AND NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
        "Build type for optimized self-test benchmark builds" FORCE)
    message(STATUS "YUME_BUILD_SELFTEST=ON: defaulting CMAKE_BUILD_TYPE to RelWithDebInfo for meaningful benchmark results")
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

# Portable static GUI: link libgcc/libstdc++ statically on g++/clang, and
# the static MSVC runtime on Windows so the binary runs without a
# matching redistributable. Does NOT, on its own, make every transitive
# dep static — that still needs the underlying packages (OpenSSL, Boost,
# liboqs) to be present in static form on the host (use the vcpkg
# x64-windows-static triplet, or build static OpenSSL on Linux).
option(YUME_GUI_PORTABLE "Statically link the C/C++ runtime into yume-gui" OFF)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/src/core/version.hpp" _yume_version_line
    REGEX "constexpr const char kVersion\\[\\]")
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
if(YUME_TRANSPORT_CORE_ONLY AND YUME_BUILD_SHARED_ABI)
    message(FATAL_ERROR "YUME_BUILD_SHARED_ABI requires the full YUME core; disable YUME_TRANSPORT_CORE_ONLY")
endif()

if(YUME_STATIC)
    set(BUILD_SHARED_LIBS OFF)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(Boost_USE_STATIC_LIBS ON)
    add_compile_definitions(YUME_STATIC_BUILD=1)
else()
    set(OPENSSL_USE_STATIC_LIBS FALSE)
    set(Boost_USE_STATIC_LIBS OFF)
endif()

if(CMAKE_CROSSCOMPILING)
    set(YUME_NATIVE_OPT OFF CACHE BOOL "Enable host-specific -march/-mtune=native CPU tuning; disables portable binaries" FORCE)
    set(YUME_LTO OFF CACHE BOOL "Enable link-time optimization for yume builds" FORCE)
endif()

if(YUME_NATIVE_OPT)
    message(STATUS "YUME native CPU tuning: ON (host-specific binary; do not copy across different CPUs)")
else()
    message(STATUS "YUME native CPU tuning: OFF (portable CPU baseline)")
endif()

if(NOT YUME_TRANSPORT_CORE_ONLY)
    find_package(OpenSSL REQUIRED)
    find_package(Boost CONFIG QUIET COMPONENTS system)
    if(NOT Boost_FOUND)
        find_package(Boost REQUIRED COMPONENTS system)
    endif()
    find_package(Threads REQUIRED)
endif()

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

    set(_yume_basefwx_via_system OFF)
    if(YUME_USE_SYSTEM_BASEFWX)
        find_package(basefwx CONFIG QUIET)
        if(basefwx_FOUND)
            if(NOT TARGET basefwxcpp)
                add_library(basefwxcpp ALIAS basefwx::basefwxcpp)
            endif()
            set(_yume_basefwx_via_system ON)
            message(STATUS "Using system BaseFWX ${basefwx_VERSION}")
        elseif(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/basefwx/cpp/CMakeLists.txt")
            message(FATAL_ERROR
                "YUME_USE_SYSTEM_BASEFWX=ON but find_package(basefwx CONFIG) failed "
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

if(NOT YUME_TRANSPORT_CORE_ONLY)
    set(YUME_DOC_INSTALL_DIR "${CMAKE_INSTALL_DATAROOTDIR}/doc/yume")

    install(FILES
        README.md
        docs/ABI.md
        docs/EXPLAINED.md
        docs/OPERATIONS.md
        docs/PACKAGING.md
        docs/PERFORMANCE.md
        docs/PERMISSIONS.md
        docs/QUICKSTART.md
        docs/STEALTH.md
        docs/release/CHANGELOG.md
        docs/release/RELEASE-NOTES-1.0.md
        DESTINATION "${YUME_DOC_INSTALL_DIR}"
    )

    install(DIRECTORY config/
        DESTINATION "${YUME_DOC_INSTALL_DIR}/examples"
        FILES_MATCHING PATTERN "*.json"
    )

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/debian/copyright")
        install(FILES debian/copyright
            DESTINATION "${YUME_DOC_INSTALL_DIR}"
            RENAME copyright
        )
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog")
        install(FILES debian/changelog
            DESTINATION "${YUME_DOC_INSTALL_DIR}"
            RENAME changelog.Debian
        )
    endif()

    install(FILES docs/man/yume.1
        DESTINATION "${CMAKE_INSTALL_MANDIR}/man1"
    )
    install(FILES docs/man/yumed.8
        DESTINATION "${CMAKE_INSTALL_MANDIR}/man8"
    )
    if(YUME_BUILD_GUI)
        install(FILES docs/man/yume-gui.1
            DESTINATION "${CMAKE_INSTALL_MANDIR}/man1"
        )
    endif()

    set(CPACK_PACKAGE_NAME "yume")
    set(CPACK_PACKAGE_VENDOR "FixCraft")
    set(CPACK_PACKAGE_CONTACT "https://github.com/F1xGOD/yume/issues")
    set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/F1xGOD/yume")
    set(CPACK_PACKAGE_VERSION "${YUME_PACKAGE_VERSION}")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Post-quantum stealth transport client and server")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "yume")
    if(UNIX AND NOT APPLE)
        set(CPACK_GENERATOR "TGZ;DEB")
        set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
        set(CPACK_DEBIAN_PACKAGE_SECTION "net")
        set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
        set(CPACK_DEBIAN_PACKAGE_MAINTAINER "FixCraft")
        set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ${YUME_DEB_SHLIBDEPS})
        set(CPACK_DEBIAN_PACKAGE_DESCRIPTION
"YUME is a TLS 1.3 stealth transport with optional HTTP/2 masking,
BaseFWX-backed inner crypto, live key hopping, SOCKS, forwarding,
relay, and server daemon modes.")
    else()
        set(CPACK_GENERATOR "TGZ")
    endif()
    include(CPack)
endif()
