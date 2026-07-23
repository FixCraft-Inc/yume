if(NOT DEFINED YUME_BUILD_TYPE_MODULE)
    message(FATAL_ERROR "YUME_BUILD_TYPE_MODULE is required")
endif()

include("${YUME_BUILD_TYPE_MODULE}")

macro(reset_build_type)
    unset(CMAKE_BUILD_TYPE CACHE)
    unset(CMAKE_BUILD_TYPE)
    unset(CMAKE_CONFIGURATION_TYPES)
    set(YUME_BUILD_SELFTEST OFF)
endmacro()

reset_build_type()
yume_configure_default_build_type()
if(NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    message(FATAL_ERROR
        "single-config builds must default to Release; got '${CMAKE_BUILD_TYPE}'")
endif()

reset_build_type()
set(YUME_BUILD_SELFTEST ON)
yume_configure_default_build_type()
if(NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    message(FATAL_ERROR
        "self-test builds must default to RelWithDebInfo; got '${CMAKE_BUILD_TYPE}'")
endif()

reset_build_type()
set(CMAKE_BUILD_TYPE Debug)
yume_configure_default_build_type()
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(FATAL_ERROR
        "explicit build types must be preserved; got '${CMAKE_BUILD_TYPE}'")
endif()

reset_build_type()
set(CMAKE_CONFIGURATION_TYPES Debug Release)
yume_configure_default_build_type()
if(DEFINED CMAKE_BUILD_TYPE AND NOT CMAKE_BUILD_TYPE STREQUAL "")
    message(FATAL_ERROR
        "multi-config builds must not set CMAKE_BUILD_TYPE; got '${CMAKE_BUILD_TYPE}'")
endif()
