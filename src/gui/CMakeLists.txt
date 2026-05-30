# ------------------------------------------------------------------------
# yume-gui - optional Dear ImGui-based desktop application.
#
# Pulled in only when YUME_BUILD_GUI=ON. All dependencies (ImGui, GLFW,
# ImPlot) are either supplied via system packages (find_package) or
# pinned-tag FetchContent fallbacks. Pinning the tags keeps reproducibility.
# ------------------------------------------------------------------------

include(FetchContent)
find_package(OpenGL REQUIRED)

# NOTE on macOS Objective-C++: we deliberately do NOT enable_language(OBJCXX).
# Enabling it as a separate language made CMake add a stray `-isystem
# /usr/include` to OBJCXX compiles (it strips that host dir for CXX as an
# implicit dir, but not for the separately-detected OBJCXX language). Under an
# osxcross cross-build that host /usr/include then won libc++'s
# `#include_next <string.h>` and broke compilation with glibc errors. Instead
# the lone .mm is compiled through the CXX toolchain with `-x objective-c++`
# (see the file_dialog_macos.mm source-file properties below), which reuses the
# clean CXX include set. clang — native or osxcross — compiles Objective-C++
# fine this way.

# Freetype is wanted on every platform - it produces dramatically
# better text rasterization than ImGui's built-in stb_truetype, and
# it provides synthetic bold/oblique for our embedded Jost font (we
# ship the Regular weight only). On Windows it comes through vcpkg;
# the earlier "skip on Windows" guard was a heavy-handed workaround
# for find_package leaking /usr/include during cross-builds. With
# CMAKE_FIND_ROOT_PATH + MODE_*=ONLY now set by ezbuild's WINDOWS_CROSS
# path, find_package is constrained to the mingw sysroot + vcpkg
# prefix, so it picks the right Freetype without dragging host paths in.
find_package(Freetype QUIET)
# Fontconfig is Linux/X11-only — Windows and macOS don't ship it. We
# use it on Linux to find URW Gothic / Inter / etc. so the GUI uses
# the user's preferred system font with its original sizes instead of
# the bundled Jost fallback. macOS (incl. the osxcross cross-build) and
# Windows fall back to the bundled Jost font. NOTE: APPLE must be excluded
# explicitly — otherwise a Darwin cross-build run on a Linux host lets
# pkg-config pick up the HOST's fontconfig.pc and then fails compiling
# <fontconfig/fontconfig.h>, which isn't in the macOS SDK.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT APPLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(FONTCONFIG QUIET fontconfig)
    endif()
endif()

set(YUME_IMGUI_TAG  "v1.91.5"  CACHE STRING "Dear ImGui git tag")
set(YUME_GLFW_TAG   "3.4"      CACHE STRING "GLFW git tag")
set(YUME_IMPLOT_TAG "v0.16"    CACHE STRING "ImPlot git tag")

# ---- GLFW ---------------------------------------------------------------
# 3.4 is the floor: that's the version where glfwInitHintString +
# GLFW_WAYLAND_APP_ID / GLFW_X11_CLASS_NAME landed, which we need to make
# the window's app id resolvable for icon lookup.
find_package(glfw3 3.4 QUIET)
if(NOT glfw3_FOUND)
    message(STATUS "[yume-gui] glfw3 >= 3.4 not found via find_package; fetching ${YUME_GLFW_TAG}")
    set(GLFW_BUILD_DOCS     OFF CACHE INTERNAL "")
    set(GLFW_BUILD_TESTS    OFF CACHE INTERNAL "")
    set(GLFW_BUILD_EXAMPLES OFF CACHE INTERNAL "")
    set(GLFW_INSTALL        OFF CACHE INTERNAL "")
    # GLFW's Wayland backend needs three things at configure time:
    #   - wayland-scanner (binary, Debian: libwayland-bin)
    #   - libwayland-client headers (Debian: libwayland-dev)
    #   - the wayland-protocols data package (Debian: wayland-protocols),
    #     exposed to CMake via the wayland-protocols.pc pkg-config file.
    # Any one missing causes a baffling failure deep inside FetchContent.
    # Detect them here; if any are absent, build GLFW with X11 only.
    # Xwayland keeps things working on GNOME/KDE/Sway sessions.
    if(UNIX AND NOT APPLE)
        find_program(YUME_WAYLAND_SCANNER wayland-scanner)
        set(YUME_WAYLAND_PROTOCOLS_FOUND OFF)
        if(PkgConfig_FOUND)
            pkg_check_modules(YUME_WAYLAND_PROTOCOLS_PC QUIET wayland-protocols)
            if(YUME_WAYLAND_PROTOCOLS_PC_FOUND)
                set(YUME_WAYLAND_PROTOCOLS_FOUND ON)
            endif()
        endif()
        if(NOT YUME_WAYLAND_SCANNER OR NOT YUME_WAYLAND_PROTOCOLS_FOUND)
            set(_missing "")
            if(NOT YUME_WAYLAND_SCANNER)
                set(_missing "${_missing} wayland-scanner (libwayland-bin)")
            endif()
            if(NOT YUME_WAYLAND_PROTOCOLS_FOUND)
                set(_missing "${_missing} wayland-protocols")
            endif()
            message(WARNING
                "[yume-gui] missing for native Wayland:${_missing}. "
                "Building GLFW with the X11 backend only; the app will run "
                "under Xwayland on Wayland sessions. Install the listed "
                "packages and reconfigure to enable native Wayland.")
            set(GLFW_BUILD_WAYLAND OFF CACHE INTERNAL "")
            set(GLFW_BUILD_X11     ON  CACHE INTERNAL "")
        endif()
    endif()
    FetchContent_Declare(glfw
        GIT_REPOSITORY https://github.com/glfw/glfw.git
        GIT_TAG        ${YUME_GLFW_TAG})
    FetchContent_MakeAvailable(glfw)
endif()

# ---- Dear ImGui ---------------------------------------------------------
# ImGui does not ship a CMakeLists.txt; we always build it ourselves.
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        ${YUME_IMGUI_TAG})
FetchContent_MakeAvailable(imgui)

add_library(yume_imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
)
if(TARGET Freetype::Freetype)
    target_sources(yume_imgui PRIVATE
        ${imgui_SOURCE_DIR}/misc/freetype/imgui_freetype.cpp)
    target_link_libraries(yume_imgui PUBLIC Freetype::Freetype)
    target_compile_definitions(yume_imgui PUBLIC IMGUI_ENABLE_FREETYPE=1)
endif()
target_include_directories(yume_imgui PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends)
target_link_libraries(yume_imgui PUBLIC glfw)

# ---- ImPlot -------------------------------------------------------------
FetchContent_Declare(implot
    GIT_REPOSITORY https://github.com/epezent/implot.git
    GIT_TAG        ${YUME_IMPLOT_TAG})
FetchContent_MakeAvailable(implot)

add_library(yume_implot STATIC
    ${implot_SOURCE_DIR}/implot.cpp
    ${implot_SOURCE_DIR}/implot_items.cpp
)
target_include_directories(yume_implot PUBLIC ${implot_SOURCE_DIR})
target_link_libraries(yume_implot PUBLIC yume_imgui)

# ---- Tray support (Linux dep optional) ----------------------------------
option(YUME_GUI_TRAY "Build the system tray integration" ON)
set(YUME_GUI_TRAY_AVAILABLE OFF)
if(YUME_GUI_TRAY)
    if(WIN32 OR APPLE)
        set(YUME_GUI_TRAY_AVAILABLE ON)
    else()
        if(PkgConfig_FOUND)
            pkg_check_modules(APPINDICATOR QUIET ayatana-appindicator3-0.1)
            if(NOT APPINDICATOR_FOUND)
                pkg_check_modules(APPINDICATOR QUIET appindicator3-0.1)
            endif()
            if(APPINDICATOR_FOUND)
                set(YUME_GUI_TRAY_AVAILABLE ON)
            else()
                message(STATUS "[yume-gui] libappindicator dev pkg missing; tray disabled")
            endif()
        else()
            message(STATUS "[yume-gui] pkg-config missing; tray disabled")
        endif()
    endif()
endif()

# ---- App icon: embed assets/icon.svg as a byte array -------------------
# We bake the SVG into the binary so the icon is self-contained on every
# launch (no runtime file dependency); the rasteriser produces RGBA pixel
# buffers at multiple sizes for glfwSetWindowIcon on X11/Win/Cocoa, and
# the same SVG is installed into ~/.local/share/icons/.../yume-gui.svg on
# first run so Wayland compositors can match it to the .desktop entry.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/assets/icon.svg"
     YUME_ICON_SVG_HEX HEX)
string(REGEX REPLACE "(..)" "0x\\1," YUME_ICON_SVG_BYTES_RAW
       "${YUME_ICON_SVG_HEX}")
# trim trailing comma
string(REGEX REPLACE ",$" "" YUME_ICON_SVG_BYTES "${YUME_ICON_SVG_BYTES_RAW}")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/platform/app_icon_data.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/app_icon_data.hpp"
    @ONLY)

# ---- Embed Jost as the GUI's bundled UI font ----------------------------
# Linux originally used URW Gothic via fontconfig, which we liked, but URW
# base35 is AGPL-3 with a PostScript-only font exception — embedding it in
# a C++ binary would force AGPL on yume-gui. Jost is a SIL OFL Futura
# clone that looks ~95% like URW Gothic, ships freely in any binary, and
# is small (~90 KB). We bake it into yume-gui via the bin2c helper and
# use it as the primary UI typeface on every OS so the GUI renders
# identically on Linux, Windows, and macOS.
set(YUME_FONT_JOST_INPUT
    "${CMAKE_CURRENT_SOURCE_DIR}/assets/fonts/Jost-Regular.ttf")
set(YUME_FONT_JOST_OUTPUT
    "${CMAKE_CURRENT_BINARY_DIR}/generated/embedded_jost_regular.cpp")
add_custom_command(
    OUTPUT "${YUME_FONT_JOST_OUTPUT}"
    COMMAND ${CMAKE_COMMAND}
        "-DINPUT_FILE=${YUME_FONT_JOST_INPUT}"
        "-DOUTPUT_FILE=${YUME_FONT_JOST_OUTPUT}"
        "-DVAR_NAME=jost_regular_ttf"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/bin2c_impl.cmake"
    DEPENDS "${YUME_FONT_JOST_INPUT}"
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/bin2c_impl.cmake"
    COMMENT "Embedding Jost-Regular.ttf into the binary"
    VERBATIM)

# ---- yume-gui executable ------------------------------------------------
set(YUME_GUI_SOURCES
    main.cpp
    app.cpp
    platform/app_icon.cpp
    platform/file_dialog.cpp
    platform/tray.cpp
    platform/window.cpp
    theme/material3.cpp
    ui/design.cpp
    pages/dashboard.cpp
    pages/connect.cpp
    pages/security.cpp
    pages/server.cpp
    pages/directory.cpp
    pages/chat.cpp
    pages/keys.cpp
    pages/logs.cpp
    pages/settings.cpp
    pages/tools.cpp
    pages/credits.cpp
    geo/country_lookup.cpp
    "${YUME_FONT_JOST_OUTPUT}"
)
# file_dialog.cpp guards itself out on Apple; the native AppKit pickers come
# from the Objective-C++ .mm instead. (Both can sit in the list safely — the
# .cpp is empty on Apple, the .mm is empty everywhere else by virtue of not
# being added.)
if(APPLE)
    list(APPEND YUME_GUI_SOURCES platform/file_dialog_macos.mm)
    # Compile the .mm through the CXX toolchain (clean include set) as
    # Objective-C++, rather than as a separate OBJCXX language — see the note
    # near find_package(OpenGL). -x objective-c++ tells clang to treat the .mm
    # as ObjC++; -ObjC++ runtime + AppKit framework come from the link step.
    set_source_files_properties(platform/file_dialog_macos.mm PROPERTIES
        LANGUAGE CXX
        COMPILE_OPTIONS "-x;objective-c++")
endif()
# tray.cpp is always compiled — internally it gates the libayatana-
# appindicator code path on YUME_GUI_TRAY=1 and falls back to a stub when
# the dev pkg isn't present, so the Tray class is always available to
# the App without needing source-level conditionals.

add_executable(yume-gui ${YUME_GUI_SOURCES})

target_include_directories(yume-gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nanosvg
    ${CMAKE_CURRENT_BINARY_DIR}/generated)

target_link_libraries(yume-gui PRIVATE
    yume_facade
    yume_imgui
    yume_implot
    OpenGL::GL
)

if(TARGET Freetype::Freetype)
    target_compile_definitions(yume-gui PRIVATE YUME_GUI_FREETYPE=1)
else()
    target_compile_definitions(yume-gui PRIVATE YUME_GUI_FREETYPE=0)
endif()
if(FONTCONFIG_FOUND)
    target_compile_definitions(yume-gui PRIVATE YUME_GUI_FONTCONFIG=1)
    target_include_directories(yume-gui PRIVATE ${FONTCONFIG_INCLUDE_DIRS})
    target_link_libraries(yume-gui PRIVATE ${FONTCONFIG_LIBRARIES})
    target_compile_options(yume-gui PRIVATE ${FONTCONFIG_CFLAGS_OTHER})
else()
    target_compile_definitions(yume-gui PRIVATE YUME_GUI_FONTCONFIG=0)
endif()

if(YUME_GUI_TRAY_AVAILABLE)
    target_compile_definitions(yume-gui PRIVATE YUME_GUI_TRAY=1)
    if(UNIX AND NOT APPLE)
        target_include_directories(yume-gui PRIVATE ${APPINDICATOR_INCLUDE_DIRS})
        target_link_libraries(yume-gui PRIVATE ${APPINDICATOR_LIBRARIES})
        target_compile_options(yume-gui PRIVATE ${APPINDICATOR_CFLAGS_OTHER})
    endif()
else()
    target_compile_definitions(yume-gui PRIVATE YUME_GUI_TRAY=0)
endif()

if(WIN32)
    # ws2_32/mswsock: ASIO/transport. shell32: Shell_NotifyIcon. user32:
    # window class + popup menu. gdi32: DIB section / icon bitmap.
    # comdlg32: GetOpenFileNameW for the file picker.
    # dwmapi: DwmSetWindowAttribute for dark mode title bar.
    target_link_libraries(yume-gui PRIVATE
        ws2_32 mswsock shell32 user32 gdi32 comdlg32 ole32 dwmapi)
    target_compile_definitions(yume-gui PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    if(MSVC)
        target_compile_definitions(yume-gui PRIVATE
            WINVER=0x0601 _WIN32_WINNT=0x0601)
    else()
        # MinGW's gcc spec already injects -DWINVER / -D_WIN32_WINNT
        # via the toolchain's defaults. Re-adding them through
        # target_compile_definitions triggers "WINVER redefined"
        # warnings on every TU. Undefine first, then pin the floor
        # we actually need (Win7 for Shell_NotifyIcon's NOTIFYICONDATAW
        # flags we use).
        target_compile_options(yume-gui PRIVATE
            -UWINVER -DWINVER=0x0601
            -U_WIN32_WINNT -D_WIN32_WINNT=0x0601
        )
    endif()
    # No console window in release builds.
    set_target_properties(yume-gui PROPERTIES WIN32_EXECUTABLE ON)
endif()
if(APPLE)
    target_link_libraries(yume-gui PRIVATE
        "-framework Cocoa" "-framework IOKit" "-framework CoreVideo")

    # Ship as a proper Yume.app bundle (Contents/MacOS/Yume + a CMake-generated
    # Info.plist + Resources/). This works for BOTH a native macOS build and an
    # osxcross cross-build — CMake only lays out the directory tree and writes
    # the plist; no macOS-only tooling is required (code-signing, which would
    # need a Mac, is intentionally not done here).
    set_target_properties(yume-gui PROPERTIES
        MACOSX_BUNDLE TRUE
        OUTPUT_NAME "Yume"
        MACOSX_BUNDLE_BUNDLE_NAME "Yume"
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.fixcraft.yume.gui"
        MACOSX_BUNDLE_BUNDLE_VERSION "1.0"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0"
        MACOSX_BUNDLE_COPYRIGHT "Copyright (C) FixCraft Inc.")

    # Bake the country-by-IP DB into Contents/Resources/geoip so the lookup
    # resolves it via the ../Resources/geoip candidate added in
    # geo/country_lookup.cpp. Files with MACOSX_PACKAGE_LOCATION are copied
    # into the bundle, not compiled.
    file(GLOB YUME_GUI_GEOIP_FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/assets/geoip/*.db"
        "${CMAKE_CURRENT_SOURCE_DIR}/assets/geoip/*.tsv")
    if(YUME_GUI_GEOIP_FILES)
        set_source_files_properties(${YUME_GUI_GEOIP_FILES} PROPERTIES
            MACOSX_PACKAGE_LOCATION "Resources/geoip")
        target_sources(yume-gui PRIVATE ${YUME_GUI_GEOIP_FILES})
    endif()
endif()

yume_apply_perf_opts(yume-gui)

if(YUME_GUI_PORTABLE)
    if(MSVC)
        # Static C runtime: /MT and /MTd. Setting the policy CMP0091 lets
        # CMAKE_MSVC_RUNTIME_LIBRARY apply per-target.
        set_property(TARGET yume-gui PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT APPLE)
        # Static libgcc/libstdc++ so the binary doesn't drag a runtime
        # symlink with it. On MinGW this also avoids libstdc++-6.dll /
        # libgcc_s_seh-1.dll alongside the .exe. Skipped on Apple: macOS clang
        # uses libc++ (always system-provided) and rejects -static-libstdc++,
        # so a "static" macOS build means static third-party libs + the system
        # libc++/frameworks — which is the most static a Mach-O app can be.
        target_link_options(yume-gui PRIVATE
            -static-libgcc -static-libstdc++)
        if(WIN32)
            # MinGW: also pin winpthread statically so the .exe runs on a
            # bare Windows install.
            target_link_options(yume-gui PRIVATE -static)
        endif()
    endif()
endif()

install(TARGETS yume-gui
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    BUNDLE DESTINATION "${CMAKE_INSTALL_BINDIR}")

# Country-by-IP DB. Installed next to the desktop entry so the lookup
# code can find it via the prefix-relative candidate paths it walks at
# runtime. Optional because nothing else hard-fails without it.
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/assets/geoip/"
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/yume-gui/geoip"
    FILES_MATCHING PATTERN "*.db" PATTERN "*.tsv")

if(UNIX AND NOT APPLE)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/packaging/yume-gui.desktop"
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/applications"
        OPTIONAL)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/packaging/yume-gui.png"
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/icons/hicolor/512x512/apps"
        OPTIONAL)
endif()
