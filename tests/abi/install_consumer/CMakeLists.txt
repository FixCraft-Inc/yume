# Clean-prefix build fixture for installed YUME C and C++ consumers.

cmake_minimum_required(VERSION 3.20)
project(yume_installed_abi_consumers LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(yume CONFIG REQUIRED)
if(NOT TARGET yume::yume)
    message(FATAL_ERROR "installed yume package did not define yume::yume")
endif()

foreach(_required IN ITEMS YUME_EXPECTED_PREFIX YUME_EXPECTED_LIBRARY)
    if(NOT DEFINED ${_required} OR NOT EXISTS "${${_required}}")
        message(FATAL_ERROR "installed consumer requires ${_required}")
    endif()
endforeach()
file(REAL_PATH "${YUME_EXPECTED_PREFIX}" _expected_prefix)
file(REAL_PATH "${YUME_EXPECTED_LIBRARY}" _expected_library)
function(yume_assert_staged_path _path)
    if(NOT EXISTS "${_path}")
        message(FATAL_ERROR "installed target refers to a missing path: ${_path}")
    endif()
    file(REAL_PATH "${_path}" _resolved)
    string(FIND "${_resolved}" "${_expected_prefix}/" _position)
    if(NOT _position EQUAL 0)
        message(FATAL_ERROR "installed target escaped the staged prefix: ${_path}")
    endif()
endfunction()
yume_assert_staged_path("${_expected_library}")
if(NOT DEFINED yume_RESOLVER_PROGRAM)
    message(FATAL_ERROR "installed yume package does not name its resolver helper")
endif()
yume_assert_staged_path("${yume_RESOLVER_PROGRAM}")
get_target_property(_include_directories yume::yume INTERFACE_INCLUDE_DIRECTORIES)
foreach(_directory IN LISTS _include_directories)
    yume_assert_staged_path("${_directory}")
endforeach()
get_target_property(_configurations yume::yume IMPORTED_CONFIGURATIONS)
set(_imported_locations)
foreach(_configuration IN LISTS _configurations)
    get_target_property(_location yume::yume "IMPORTED_LOCATION_${_configuration}")
    if(_location)
        yume_assert_staged_path("${_location}")
        file(REAL_PATH "${_location}" _resolved)
        if(NOT _resolved STREQUAL _expected_library)
            message(FATAL_ERROR "installed target selects an unexpected runtime library")
        endif()
        list(APPEND _imported_locations "${_location}")
    endif()
endforeach()
if(NOT _imported_locations)
    message(FATAL_ERROR "installed target has no runtime import location")
endif()

add_executable(yume_installed_consumer_c consumer.c)
target_link_libraries(yume_installed_consumer_c PRIVATE yume::yume)

add_executable(yume_installed_consumer_cpp consumer.cpp)
target_link_libraries(yume_installed_consumer_cpp PRIVATE yume::yume)

set(_consumer_targets yume_installed_consumer_c yume_installed_consumer_cpp)
if(UNIX)
    add_executable(yume_installed_loader_probe loader_probe.cpp)
    target_link_libraries(yume_installed_loader_probe PRIVATE yume::yume ${CMAKE_DL_LIBS})
    list(APPEND _consumer_targets yume_installed_loader_probe)
endif()

if(YUME_TEST_NATIVE_TRAFFIC)
    foreach(_required IN ITEMS YUME_SOURCE_DIR YUME_PYTHON_EXECUTABLE
                               YUME_OPENSSL_EXECUTABLE YUME_INSTALLED_DAEMON)
        if(NOT DEFINED ${_required} OR NOT EXISTS "${${_required}}")
            message(FATAL_ERROR "installed native traffic requires ${_required}")
        endif()
    endforeach()
    if(NOT UNIX)
        message(FATAL_ERROR "native installed traffic fixtures require UNIX")
    endif()
    yume_assert_staged_path("${YUME_INSTALLED_DAEMON}")
    find_package(Threads REQUIRED)
    # The existing probes include only yume/yume.h. Its include path and the
    # library come exclusively from the installed imported target.
    foreach(_kind IN ITEMS stream route packet)
        if(_kind STREQUAL "stream")
            set(_extension c)
        else()
            set(_extension cpp)
        endif()
        add_executable(yume_installed_${_kind}_probe
            "${YUME_SOURCE_DIR}/src/abi/ytp1_${_kind}_probe.${_extension}")
        target_link_libraries(yume_installed_${_kind}_probe PRIVATE yume::yume Threads::Threads)
        list(APPEND _consumer_targets yume_installed_${_kind}_probe)
    endforeach()
endif()

foreach(_target IN LISTS _consumer_targets)
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
    set(_direct_tests yume_installed_consumer_c yume_installed_consumer_cpp)
    if(UNIX)
        add_test(NAME yume_installed_loader_probe
            COMMAND yume_installed_loader_probe "${_expected_library}")
        set_tests_properties(yume_installed_loader_probe PROPERTIES
            FIXTURES_SETUP yume_staged_library TIMEOUT 15)
        set_tests_properties(yume_installed_consumer_c yume_installed_consumer_cpp
            PROPERTIES FIXTURES_REQUIRED yume_staged_library)
        list(APPEND _direct_tests yume_installed_loader_probe)
    endif()
    set_tests_properties(${_direct_tests} PROPERTIES TIMEOUT 15)
    if(DEFINED YUME_CHILD_ASAN_OPTIONS)
        set_tests_properties(${_direct_tests} PROPERTIES
            ENVIRONMENT "ASAN_OPTIONS=${YUME_CHILD_ASAN_OPTIONS}")
    endif()
    if(YUME_TEST_NATIVE_TRAFFIC)
        add_test(NAME yume_installed_named_streams
            COMMAND "${YUME_PYTHON_EXECUTABLE}"
                "${YUME_SOURCE_DIR}/tests/test_yume_abi_stream.py"
                --probe "$<TARGET_FILE:yume_installed_stream_probe>"
                --openssl "${YUME_OPENSSL_EXECUTABLE}")
        add_test(NAME yume_installed_tcp_routes
            COMMAND "${YUME_PYTHON_EXECUTABLE}"
                "${YUME_SOURCE_DIR}/tests/test_yume_abi_route.py"
                --probe "$<TARGET_FILE:yume_installed_route_probe>"
                --yumed "${YUME_INSTALLED_DAEMON}"
                --openssl "${YUME_OPENSSL_EXECUTABLE}")
        add_test(NAME yume_installed_named_packets_and_udp
            COMMAND "${YUME_PYTHON_EXECUTABLE}"
                "${YUME_SOURCE_DIR}/tests/test_yume_abi_packet.py"
                --probe "$<TARGET_FILE:yume_installed_packet_probe>"
                --yumed "${YUME_INSTALLED_DAEMON}"
                --openssl "${YUME_OPENSSL_EXECUTABLE}")
        set_tests_properties(yume_installed_named_streams PROPERTIES TIMEOUT 180)
        set_tests_properties(yume_installed_tcp_routes PROPERTIES TIMEOUT 150)
        set_tests_properties(yume_installed_named_packets_and_udp PROPERTIES TIMEOUT 300)
        set_tests_properties(yume_installed_named_streams yume_installed_tcp_routes
                            yume_installed_named_packets_and_udp PROPERTIES
            FIXTURES_REQUIRED yume_staged_library RUN_SERIAL TRUE LABELS "abi;install;native")
    endif()
endif()
