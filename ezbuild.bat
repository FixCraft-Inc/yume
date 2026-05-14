@echo off
REM ============================================================================
REM ezbuild.bat - Windows equivalent of ezbuild.sh.
REM
REM Builds Yume (CLI + daemon + optional GUI) using CMake + the native
REM Visual Studio toolchain. Dependencies are pulled from vcpkg.
REM
REM Usage:
REM   ezbuild.bat                  Build CLI/daemon only (Release).
REM   ezbuild.bat --gui            Also build yume-gui.exe.
REM   ezbuild.bat --portable       Static C runtime + static libs (one exe).
REM   ezbuild.bat --debug          Build the Debug configuration.
REM   ezbuild.bat --clean          Remove the build directory and exit.
REM   ezbuild.bat --no-pull        Skip the auto-pull step.
REM
REM Environment overrides:
REM   VCPKG_ROOT  Path to vcpkg checkout (auto-detected if vcpkg is on PATH).
REM   GENERATOR   CMake generator (default: Visual Studio 17 2022).
REM   ARCH        Target arch (default: x64).
REM ============================================================================

setlocal enabledelayedexpansion

set "BUILD_GUI=0"
set "PORTABLE=0"
set "CLEAN_ONLY=0"
set "SKIP_PULL=0"
set "BUILD_TYPE=Release"
set "BUILD_DIR=build-win"

:parse
if "%~1"=="" goto args_done
if /I "%~1"=="--gui"      ( set "BUILD_GUI=1" & shift & goto parse )
if /I "%~1"=="--with-gui" ( set "BUILD_GUI=1" & shift & goto parse )
if /I "%~1"=="--portable" ( set "PORTABLE=1" & shift & goto parse )
if /I "%~1"=="--static"   ( set "PORTABLE=1" & shift & goto parse )
if /I "%~1"=="--clean"    ( set "CLEAN_ONLY=1" & shift & goto parse )
if /I "%~1"=="--no-pull"  ( set "SKIP_PULL=1" & shift & goto parse )
if /I "%~1"=="--debug"    ( set "BUILD_TYPE=Debug" & shift & goto parse )
if /I "%~1"=="--release"  ( set "BUILD_TYPE=Release" & shift & goto parse )
if /I "%~1"=="-h"         ( goto usage )
if /I "%~1"=="--help"     ( goto usage )
echo [warn] Unknown option: %~1
shift
goto parse
:args_done

if "%CLEAN_ONLY%"=="1" (
    if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
    echo [ok] Cleaned %BUILD_DIR%.
    exit /b 0
)

echo [info] YUME ezbuild (Windows) starting...

REM ---------- Auto-pull (best-effort, optional) -------------------------------
if "%SKIP_PULL%"=="0" (
    where git >nul 2>&1
    if not errorlevel 1 (
        git rev-parse --is-inside-work-tree >nul 2>&1
        if not errorlevel 1 (
            for /f "delims=" %%a in ('git status --porcelain 2^>nul') do (
                set "DIRTY=1"
            )
            if defined DIRTY (
                echo [warn] Working tree dirty, skipping repo sync.
            ) else (
                git fetch --quiet >nul 2>&1
                for /f "delims=" %%a in ('git rev-parse "@{upstream}" 2^>nul') do set "UPSTREAM_SHA=%%a"
                for /f "delims=" %%a in ('git rev-parse @ 2^>nul') do set "LOCAL_SHA=%%a"
                if defined UPSTREAM_SHA if not "!UPSTREAM_SHA!"=="!LOCAL_SHA!" (
                    echo [step] Pulling new commits from upstream...
                    git merge --ff-only --quiet "@{upstream}"
                )
            )
        )
    )
)

REM ---------- vcpkg discovery -------------------------------------------------
REM 1. Honour an explicit VCPKG_ROOT (already-set or passed in via env).
REM 2. Read %LOCALAPPDATA%\vcpkg\vcpkg.path.txt - this file is what
REM    `vcpkg integrate install` writes, and its single line is the
REM    absolute path to the vcpkg root. Most reliable signal.
REM 3. `where vcpkg` (works only when vcpkg is on PATH).
REM 4. Probe common install locations.
if defined VCPKG_ROOT (
    if not exist "%VCPKG_ROOT%\vcpkg.exe" set "VCPKG_ROOT="
)
if "%VCPKG_ROOT%"=="" (
    if exist "%LOCALAPPDATA%\vcpkg\vcpkg.path.txt" (
        for /f "usebackq delims=" %%a in ("%LOCALAPPDATA%\vcpkg\vcpkg.path.txt") do (
            if exist "%%a\vcpkg.exe" set "VCPKG_ROOT=%%a"
        )
    )
)
if "%VCPKG_ROOT%"=="" (
    for /f "delims=" %%a in ('where vcpkg 2^>nul') do (
        if exist "%%~dpavcpkg.exe" (
            set "_vcpkg_dir=%%~dpa"
            REM Strip trailing backslash.
            if defined _vcpkg_dir set "VCPKG_ROOT=!_vcpkg_dir:~0,-1!"
        )
    )
)
REM Common install locations. Order roughly matches how often each
REM appears in the wild on Windows dev boxes.
for %%P in (
    "%USERPROFILE%\vcpkg"
    "%USERPROFILE%\source\vcpkg"
    "%USERPROFILE%\source\repos\vcpkg"
    "%USERPROFILE%\.vcpkg-root"
    "C:\vcpkg"
    "C:\src\vcpkg"
    "C:\dev\vcpkg"
    "C:\tools\vcpkg"
    "D:\vcpkg"
    "D:\src\vcpkg"
) do (
    if "!VCPKG_ROOT!"=="" (
        if exist "%%~P\vcpkg.exe" set "VCPKG_ROOT=%%~P"
    )
)
if defined VCPKG_ROOT (
    echo [info] vcpkg found at !VCPKG_ROOT!
) else (
    echo [warn] vcpkg not detected. Tried %%LOCALAPPDATA%%\vcpkg\vcpkg.path.txt,
    echo        where, and the usual install locations. If you have vcpkg
    echo        somewhere else, run ezbuild.bat with VCPKG_ROOT set:
    echo            set VCPKG_ROOT=C:\src\vcpkg
    echo            ezbuild.bat --gui
)

REM ---------- Triplet selection ----------------------------------------------
if "%ARCH%"=="" set "ARCH=x64"
if "%PORTABLE%"=="1" (
    set "TRIPLET=%ARCH%-windows-static"
) else (
    set "TRIPLET=%ARCH%-windows"
)

REM ---------- Install required deps via vcpkg if available -------------------
if defined VCPKG_ROOT (
    if exist "%VCPKG_ROOT%\vcpkg.exe" (
        echo [step] Ensuring vcpkg dependencies are present ^(%TRIPLET%^)...
        set "VCPKG_PKGS=openssl boost-asio boost-system nlohmann-json spdlog zstd liboqs"
        if "%BUILD_GUI%"=="1" (
            set "VCPKG_PKGS=!VCPKG_PKGS! glfw3 freetype"
        )
        for %%P in (!VCPKG_PKGS!) do (
            "%VCPKG_ROOT%\vcpkg.exe" install %%P:%TRIPLET% >nul
            if errorlevel 1 (
                echo [warn] vcpkg install %%P failed; configure may complain.
            )
        )
    ) else (
        echo [warn] VCPKG_ROOT set to %VCPKG_ROOT% but vcpkg.exe not found there.
    )
) else (
    echo [warn] vcpkg not detected. Install it from https://vcpkg.io and re-run,
    echo        or set VCPKG_ROOT to your existing checkout.
)

REM ---------- Vendor liboqs fallback -----------------------------------------
REM If vcpkg is missing or its liboqs install fell over, look in
REM vendor\windows-x86_64\lib for a pre-staged MSVC-format liboqs.lib.
REM (The .dll.a shipped for the MinGW cross route is a gcc archive
REM that the MSVC linker cannot consume; it gets ignored here.)
set "VENDOR_WIN=%CD%\vendor\windows-x86_64"
set "VENDOR_OQS_INCLUDE="
set "VENDOR_OQS_LIBRARY="
if exist "%VENDOR_WIN%\include\oqs\oqs.h" (
    if exist "%VENDOR_WIN%\lib\liboqs.lib" (
        set "VENDOR_OQS_INCLUDE=%VENDOR_WIN%\include"
        set "VENDOR_OQS_LIBRARY=%VENDOR_WIN%\lib\liboqs.lib"
    ) else if exist "%VENDOR_WIN%\lib\oqs.lib" (
        set "VENDOR_OQS_INCLUDE=%VENDOR_WIN%\include"
        set "VENDOR_OQS_LIBRARY=%VENDOR_WIN%\lib\oqs.lib"
    ) else if exist "%VENDOR_WIN%\lib\liboqs.dll.a" (
        echo [warn] vendor\windows-x86_64\lib\liboqs.dll.a is a MinGW import
        echo        library and cannot be linked by MSVC. Either build with
        echo        ezbuild.sh + YUME_WINDOWS_CROSS=1 (MinGW cross), or drop
        echo        a real liboqs.lib next to it.
    )
)
if defined VENDOR_OQS_LIBRARY (
    echo [info] Using vendored liboqs at %VENDOR_OQS_LIBRARY%.
)

REM ---------- Generator -------------------------------------------------------
if "%GENERATOR%"=="" set "GENERATOR=Visual Studio 17 2022"

REM ---------- Configure -------------------------------------------------------
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

set "CMAKE_ARGS=-G ""%GENERATOR%"" -A %ARCH%"
set "CMAKE_ARGS=%CMAKE_ARGS% -DCMAKE_BUILD_TYPE=%BUILD_TYPE%"
if defined VCPKG_ROOT (
    set "CMAKE_ARGS=%CMAKE_ARGS% -DCMAKE_TOOLCHAIN_FILE=""%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"""
    set "CMAKE_ARGS=%CMAKE_ARGS% -DVCPKG_TARGET_TRIPLET=%TRIPLET%"
)
if defined VENDOR_OQS_LIBRARY (
    set "CMAKE_ARGS=%CMAKE_ARGS% -DOQS_INCLUDE_DIR=""%VENDOR_OQS_INCLUDE%"""
    set "CMAKE_ARGS=%CMAKE_ARGS% -DOQS_LIBRARY=""%VENDOR_OQS_LIBRARY%"""
    set "CMAKE_ARGS=%CMAKE_ARGS% -DOQS_INCLUDE_DIRS=""%VENDOR_OQS_INCLUDE%"""
    set "CMAKE_ARGS=%CMAKE_ARGS% -DOQS_LIBRARIES=""%VENDOR_OQS_LIBRARY%"""
    set "CMAKE_ARGS=%CMAKE_ARGS% -DOQS_FOUND=TRUE"
    set "CMAKE_ARGS=%CMAKE_ARGS% -DBASEFWX_REQUIRE_OQS=ON"
)
if "%BUILD_GUI%"=="1" (
    set "CMAKE_ARGS=%CMAKE_ARGS% -DYUME_BUILD_GUI=ON"
)
if "%PORTABLE%"=="1" (
    set "CMAKE_ARGS=%CMAKE_ARGS% -DYUME_GUI_PORTABLE=ON"
)

echo [step] Configuring with: %CMAKE_ARGS%
cmake -S . -B "%BUILD_DIR%" %CMAKE_ARGS%
if errorlevel 1 (
    echo [error] CMake configure failed.
    exit /b 1
)

REM ---------- Build -----------------------------------------------------------
echo [step] Building (%BUILD_TYPE%)...
cmake --build "%BUILD_DIR%" --config %BUILD_TYPE% -j
if errorlevel 1 (
    echo [error] Build failed.
    exit /b 1
)

echo [ok] Build complete.
echo      Binaries under %BUILD_DIR%\bin\%BUILD_TYPE%\
exit /b 0

:usage
echo Usage: ezbuild.bat [--gui] [--portable] [--debug] [--clean] [--no-pull]
echo.
echo   --gui         Also build yume-gui.exe (Dear ImGui frontend).
echo   --portable    Static C runtime + static-triplet vcpkg.
echo                 Pair with --gui for a single-file portable .exe.
echo   --debug       Build Debug configuration (default: Release).
echo   --clean       Remove the build directory and exit.
echo   --no-pull     Skip the git fast-forward step.
echo.
echo Environment:
echo   VCPKG_ROOT    Path to vcpkg checkout (auto-detected if on PATH).
echo   GENERATOR     CMake generator override (default: "Visual Studio 17 2022").
echo   ARCH          Target arch (default: x64).
exit /b 0
