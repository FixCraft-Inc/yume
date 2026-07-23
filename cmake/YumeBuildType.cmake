function(yume_configure_default_build_type)
    if(CMAKE_CONFIGURATION_TYPES)
        return()
    endif()
    if(DEFINED CMAKE_BUILD_TYPE AND NOT CMAKE_BUILD_TYPE STREQUAL "")
        return()
    endif()

    if(YUME_BUILD_SELFTEST)
        set(_yume_default_build_type RelWithDebInfo)
    else()
        set(_yume_default_build_type Release)
    endif()
    set(CMAKE_BUILD_TYPE "${_yume_default_build_type}" CACHE STRING
        "Build type for single-config YUME builds" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release RelWithDebInfo MinSizeRel)
    message(STATUS
        "CMAKE_BUILD_TYPE was not set; defaulting to ${CMAKE_BUILD_TYPE}")
endfunction()
