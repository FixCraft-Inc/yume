# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

# The desktop GUI, yume-gui, built only with YUME_BUILD_GUI=ON. It talks to
# each yume through that yume's control socket and runs the yume program for
# kit import and starts, so it links no YUME library and no YUME library
# links Qt. It uses only Qt 6.4 interfaces, the Qt of Ubuntu 24.04.
find_package(Qt6 6.4 REQUIRED COMPONENTS Core Gui Network Qml Quick QuickControls2 Widgets)

set(CMAKE_AUTOMOC ON)

# The backend, the QML pages and the assets. The pages are plain resources
# rather than a compiled QML module, so one layout serves Qt 6.4 to 6.8, and
# the capture test fails on any QML warning a page raises when it loads.
add_library(yume_gui_core STATIC
    app_state.cpp app_state.hpp
    capture.cpp capture.hpp
    control_client.cpp control_client.hpp
    headless.cpp headless.hpp
    kit_store.cpp kit_store.hpp
    mark.cpp mark.hpp
    message_model.cpp message_model.hpp
    offline_network.cpp offline_network.hpp
    presets.cpp presets.hpp
    tray.cpp tray.hpp
    tunnel.cpp tunnel.hpp
    yume_gui_help_text.hpp)
target_include_directories(yume_gui_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..")
# Widgets is for the tray icon alone, which Qt offers only there.
target_link_libraries(yume_gui_core PUBLIC Qt6::Core Qt6::Gui Qt6::Network Qt6::Qml Qt6::Quick Qt6::Widgets)
yume_apply_perf_opts(yume_gui_core)

set(_yume_gui_qml
    qml/qmldir
    qml/Labels.js
    qml/Theme.qml
    qml/Main.qml
    qml/Sidebar.qml
    qml/OverviewPage.qml
    qml/ConnectPage.qml
    qml/LogsPage.qml
    qml/PosturePage.qml
    qml/RouteReviewDialog.qml
    qml/AppButton.qml
    qml/AppTextField.qml
    qml/Card.qml
    qml/CopyRow.qml
    qml/FactRow.qml
    qml/Icon.qml
    qml/LevelMeter.qml
    qml/Logo.qml
    qml/Metric.qml
    qml/NavButton.qml
    qml/Sparkline.qml
    qml/StatePill.qml)
qt_add_resources(yume_gui_core yume_gui_qml PREFIX /yume/qml BASE qml FILES ${_yume_gui_qml}
    OUTPUT_TARGETS _yume_gui_resource_targets)
qt_add_resources(yume_gui_core yume_gui_assets PREFIX /yume BASE assets
    FILES assets/icon.svg assets/fonts/Jost-Regular.ttf
    OUTPUT_TARGETS _yume_gui_asset_targets)
# The presets table is embedded unchanged, so the GUI names presets from the
# same file yume-setup and yume-doctor use.
set(_yume_gui_presets "${PROJECT_SOURCE_DIR}/config/tuning_presets.json")
set_source_files_properties("${_yume_gui_presets}" PROPERTIES QT_RESOURCE_ALIAS tuning_presets.json)
qt_add_resources(yume_gui_core yume_gui_data PREFIX /yume FILES "${_yume_gui_presets}"
    OUTPUT_TARGETS _yume_gui_data_targets)
# A static library's resources compile into object libraries of their own,
# which get the project's warnings like any other first-party code.
foreach(_target IN LISTS _yume_gui_resource_targets _yume_gui_asset_targets _yume_gui_data_targets)
    yume_apply_warnings(${_target})
endforeach()
# The GUI links Qt and no YUME library.
yume_assert_exact_link_dependencies(yume_gui_core
    Qt6::Core Qt6::Gui Qt6::Network Qt6::Qml Qt6::Quick Qt6::Widgets)

add_executable(yume-gui main.cpp)
target_link_libraries(yume-gui PRIVATE yume_gui_core Qt6::QuickControls2)
yume_apply_perf_opts(yume-gui)

install(TARGETS yume-gui RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT yume_gui)
install(FILES packaging/yume-gui.desktop
    DESTINATION "${CMAKE_INSTALL_DATADIR}/applications" COMPONENT yume_gui)
install(FILES assets/icon.svg
    DESTINATION "${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps"
    RENAME yume-gui.svg COMPONENT yume_gui)
install(FILES "${PROJECT_SOURCE_DIR}/docs/man/yume-gui.1"
    DESTINATION "${CMAKE_INSTALL_MANDIR}/man1" COMPONENT yume_gui)

if(YUME_BUILD_TESTING)
    find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    # Keyboard access, focus order, right-to-left mirroring and the route
    # consent dialog, driven through the real pages with a fake yume.
    add_executable(yume_gui_ui_test ui_test.cpp)
    target_link_libraries(yume_gui_ui_test PRIVATE yume_gui_core Qt6::QuickControls2 Qt6::Test)
    target_compile_definitions(yume_gui_ui_test PRIVATE
        YUME_GUI_FAKE_YUME="${PROJECT_SOURCE_DIR}/tests/gui/fake_yume.py")
    yume_apply_perf_opts(yume_gui_ui_test)
    add_test(NAME yume_gui_ui_test COMMAND yume_gui_ui_test)
    add_test(NAME yume_gui_ui_rtl_test COMMAND yume_gui_ui_test --rtl)
    set_tests_properties(yume_gui_ui_test yume_gui_ui_rtl_test PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        TIMEOUT 120 LABELS "gui")

    # The headless lifecycle, kit import, capture of every page and the
    # command line, against a fake yume that speaks control protocol 1.
    add_test(NAME yume_gui_test
        COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/gui/test_yume_gui.py"
            --gui "$<TARGET_FILE:yume-gui>"
            --fake-yume "${PROJECT_SOURCE_DIR}/tests/gui/fake_yume.py")
    set_tests_properties(yume_gui_test PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        TIMEOUT 300 LABELS "gui")

    # The same lifecycle against a real yumed and yume: connect, stop,
    # reconnect and stop with each leg's report inspected, the tunnel
    # outliving a killed GUI, and a kit imported through the GUI.
    if(TARGET yume AND TARGET yumed AND TARGET yume-setup)
        add_test(NAME yume_gui_live_test
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/gui/run_gui_live_test.py"
                --gui "$<TARGET_FILE:yume-gui>"
                --yume "$<TARGET_FILE:yume>"
                --yumed "$<TARGET_FILE:yumed>"
                --setup "$<TARGET_FILE:yume-setup>"
                --openssl "${YUME_NATIVE_TEST_OPENSSL}")
        set_tests_properties(yume_gui_live_test PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 300 LABELS "gui;integration")
    endif()
endif()
