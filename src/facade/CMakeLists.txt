# ------------------------------------------------------------------------
# yume_facade - thin GUI-friendly wrapper around yume_core/server/client.
#
# Built unconditionally (no GUI dependencies). Exposes lifecycle, config,
# key and log primitives that desktop apps need without dragging in the
# REPL-oriented CLI surface.
# ------------------------------------------------------------------------

add_library(yume_facade STATIC
    logging/log_sink.cpp
    config/config_io.cpp
    config/client_config_io.cpp
    config/server_config_io.cpp
    security/secure_materials.cpp
    config/profiles.cpp
    keys/keys.cpp
    metrics/traffic_meter.cpp
    session/inproc_client.cpp
    session/client_session.cpp
    session/server_session.cpp
)

target_include_directories(yume_facade PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

target_link_libraries(yume_facade
    PUBLIC
        yume_core
        yume_server
        yume_client_lib
)

if(YUME_BUILD_SHARED_ABI)
    set_target_properties(yume_facade PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

if(YUME_USE_SPDLOG)
    target_compile_definitions(yume_facade PUBLIC YUME_FACADE_HAVE_SPDLOG=1)
else()
    target_compile_definitions(yume_facade PUBLIC YUME_FACADE_HAVE_SPDLOG=0)
endif()

yume_apply_perf_opts(yume_facade)
