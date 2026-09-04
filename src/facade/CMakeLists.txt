# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
# ------------------------------------------------------------------------
# Two libraries, because two very different consumers live here.
#
# yume_embed is what an *embedder* needs: configuration marshalling, the
# in-process client runtime, and the diagnostic log ring. The C ABI links
# this and nothing else from here.
#
# yume_facade adds what a *desktop application* needs on top: observable
# session objects, a traffic-rate meter for the dashboard graph, GUI profile
# switching, key management, and CA-material import. Only yume-gui consumes
# those, and the ABI must not carry them.
#
# Keeping them separate is what stops the GUI's needs from silently widening
# the embedding surface, which is how this directory grew in the first place.
# ------------------------------------------------------------------------

add_library(yume_embed STATIC
    logging/log_sink.cpp
    config/config_io.cpp
    config/client_config_io.cpp
    config/server_config_io.cpp
    session/inproc_client.cpp
    session/transport_v2_backend.cpp
)

target_include_directories(yume_embed PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

target_link_libraries(yume_embed
    PUBLIC
        yume_core
        yume_server
        yume_client_lib
)

if(YUME_USE_SPDLOG)
    target_compile_definitions(yume_embed PUBLIC YUME_FACADE_HAVE_SPDLOG=1)
else()
    target_compile_definitions(yume_embed PUBLIC YUME_FACADE_HAVE_SPDLOG=0)
endif()

yume_apply_perf_opts(yume_embed)

add_library(yume_facade STATIC
    config/gui_preferences.cpp
    security/secure_materials.cpp
    config/profiles.cpp
    keys/keys.cpp
    metrics/traffic_meter.cpp
    session/client_session.cpp
    session/server_session.cpp
)

target_include_directories(yume_facade PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)

# PUBLIC so an existing consumer that expects the whole facade surface, such
# as the GUI, keeps compiling unchanged.
target_link_libraries(yume_facade PUBLIC yume_embed)

yume_apply_perf_opts(yume_facade)

if(YUME_ABI_CLIENT_ONLY)
    add_library(yume_client_facade STATIC
        logging/log_sink.cpp
        config/config_io.cpp
        config/client_config_io.cpp
        session/inproc_client.cpp
    )
    target_include_directories(yume_client_facade PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
    target_link_libraries(yume_client_facade PUBLIC yume_core yume_client_lib)
    if(YUME_USE_SPDLOG)
        target_compile_definitions(yume_client_facade PUBLIC YUME_FACADE_HAVE_SPDLOG=1)
    else()
        target_compile_definitions(yume_client_facade PUBLIC YUME_FACADE_HAVE_SPDLOG=0)
    endif()
    yume_apply_perf_opts(yume_client_facade)
endif()
