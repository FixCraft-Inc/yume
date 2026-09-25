function(yume_configure_default_build_type)
    if(CMAKE_CONFIGURATION_TYPES)
        return()
    endif()
    if(DEFINED CMAKE_BUILD_TYPE AND NOT CMAKE_BUILD_TYPE STREQUAL "")
        return()
    endif()

    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Build type for single-config YUME builds" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release RelWithDebInfo MinSizeRel)
    message(STATUS
        "CMAKE_BUILD_TYPE was not set; defaulting to ${CMAKE_BUILD_TYPE}")
endfunction()
