@echo off
REM ============================================================================
REM bundle-windows.bat - Windows companion to scripts/bundle-windows.sh.
REM
REM Reads each yume*.exe's PE import table, recursively follows every
REM non-system DLL it needs, and packs the lot into yume-windows.zip.
REM Output runs on a plain Windows machine with nothing preinstalled.
REM
REM Implementation: delegates to the bash script via MSYS2, because the
REM dependency walk uses objdump output and is much simpler in shell.
REM MSYS2 is already a requirement for `ezbuild.bat --mingw`, so anyone
REM doing a MinGW build on Windows already has it.
REM
REM Usage:
REM     bundle-windows.bat
REM     bundle-windows.bat build-other-dir
REM     set YUME_BUNDLE_OUT=yume-1.1-win64 && bundle-windows.bat
REM ============================================================================

setlocal enabledelayedexpansion

REM Locate MSYS2.
set "MSYS2_ROOT="
if exist "C:\msys64\usr\bin\bash.exe"            set "MSYS2_ROOT=C:\msys64"
if "!MSYS2_ROOT!"=="" if exist "C:\msys2\usr\bin\bash.exe"            set "MSYS2_ROOT=C:\msys2"
if "!MSYS2_ROOT!"=="" if exist "%USERPROFILE%\msys64\usr\bin\bash.exe" set "MSYS2_ROOT=%USERPROFILE%\msys64"

if "!MSYS2_ROOT!"=="" (
    echo [error] MSYS2 not detected at C:\msys64, C:\msys2, or %%USERPROFILE%%\msys64.
    echo         Install it with:
    echo             winget install MSYS2.MSYS2
    echo         then re-run this script.
    exit /b 1
)

REM Forward any arg as the build dir, plus carry the env var through.
set "MSYSTEM=MINGW64"
set "CHERE_INVOKING=1"

if "%~1"=="" (
    "!MSYS2_ROOT!\usr\bin\bash.exe" -lc "./scripts/bundle-windows.sh"
) else (
    "!MSYS2_ROOT!\usr\bin\bash.exe" -lc "./scripts/bundle-windows.sh '%~1'"
)
exit /b !ERRORLEVEL!
