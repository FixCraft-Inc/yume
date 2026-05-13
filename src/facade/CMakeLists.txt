# ------------------------------------------------------------------------
# yume_facade - thin GUI-friendly wrapper around yume_core/server/client.
#
# Built unconditionally (no GUI dependencies). Exposes lifecycle, config,
# key and log primitives that desktop apps need without dragging in the
# REPL-oriented CLI surface.
# ------------------------------------------------------------------------

add_library(yume_facade STATIC
    log_sink.cpp
    config_io.cpp
    secure_materials.cpp
    keys.cpp
    traffic_meter.cpp
    client_session.cpp
    server_session.cpp
)

target_include_directories(yume_facade PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

target_link_libraries(yume_facade
    PUBLIC
        yume_core
        yume_server
        yume_client_lib
)

if(YUME_USE_SPDLOG)
    target_compile_definitions(yume_facade PUBLIC YUME_FACADE_HAVE_SPDLOG=1)
else()
    target_compile_definitions(yume_facade PUBLIC YUME_FACADE_HAVE_SPDLOG=0)
endif()

yume_apply_perf_opts(yume_facade)
