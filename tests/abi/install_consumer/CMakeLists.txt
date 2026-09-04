# Clean-prefix build fixture for installed YUME C and C++ consumers.

cmake_minimum_required(VERSION 3.20)
project(yume_installed_abi_consumers LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(yume 0.3 CONFIG REQUIRED)
if(NOT TARGET yume::yume)
    message(FATAL_ERROR "installed yume package did not define yume::yume")
endif()

add_executable(yume_installed_consumer_c consumer.c)
target_link_libraries(yume_installed_consumer_c PRIVATE yume::yume)

add_executable(yume_installed_consumer_cpp consumer.cpp)
target_link_libraries(yume_installed_consumer_cpp PRIVATE yume::yume)

foreach(_target IN ITEMS
        yume_installed_consumer_c
        yume_installed_consumer_cpp)
    if(MSVC)
        target_compile_options(${_target} PRIVATE /W4 /WX)
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" OR
           CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${_target} PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    endif()
endforeach()

include(CTest)
if(BUILD_TESTING)
    add_test(NAME yume_installed_consumer_c
        COMMAND yume_installed_consumer_c)
    add_test(NAME yume_installed_consumer_cpp
        COMMAND yume_installed_consumer_cpp)
endif()
