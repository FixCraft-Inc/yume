#!/usr/bin/env bash
# bundle-windows.sh - take the yume*.exe binaries from a Linux cross-
# build and pack them with every DLL they actually depend on into a
# single zip. The dependency walk is iterative (a DLL can pull more
# DLLs), so the output runs on a plain Windows machine with nothing
# pre-installed.
#
# Usage:
#   scripts/bundle-windows.sh                       # uses build/
#   scripts/bundle-windows.sh build-portable        # custom build dir
#   YUME_BUNDLE_OUT=yume-1.0-win64 scripts/bundle-windows.sh
#
# The dependency walk reads objdump's import table, so anything the
# linker decided was required ships. System DLLs (kernel32, user32,
# advapi32, etc.) ship with Windows itself - they're filtered out.

set -euo pipefail

BUILD_DIR="${1:-build}"
OUT_NAME="${YUME_BUNDLE_OUT:-yume-windows}"
WORK_DIR="${PWD}/${OUT_NAME}"
ZIP_PATH="${PWD}/${OUT_NAME}.zip"

if [[ ! -d "${BUILD_DIR}/bin" ]]; then
    echo "[error] ${BUILD_DIR}/bin does not exist."
    echo "        Run the cross-build first:"
    echo "            YUME_WINDOWS_CROSS=1 ./ezbuild.sh --gui"
    exit 1
fi

# Pick whichever yume*.exe files were built. Don't fail if some are
# absent - users who only build the CLI shouldn't need the GUI.
mapfile -t EXES < <(find "${BUILD_DIR}/bin" -maxdepth 1 -name "yume*.exe" -type f)
if [[ ${#EXES[@]} -eq 0 ]]; then
    echo "[error] no yume*.exe files found in ${BUILD_DIR}/bin."
    exit 1
fi
echo "[info] bundling ${#EXES[@]} executable(s):"
printf '         %s\n' "${EXES[@]}"

# Candidate locations for DLLs the .exe imports. Add more if your
# vcpkg or mingw lives elsewhere.
SEARCH_DIRS=(
    "${HOME}/vcpkg/installed/x64-mingw-dynamic/bin"
    "${HOME}/vcpkg/installed/x64-mingw-dynamic/debug/bin"
    "${PWD}/vendor/windows-x86_64/bin"
    "/usr/lib/gcc/x86_64-w64-mingw32/14-posix"
    "/usr/lib/gcc/x86_64-w64-mingw32/14-win32"
    "/usr/x86_64-w64-mingw32/lib"
    "/usr/x86_64-w64-mingw32/bin"
)

# Known system DLLs that ship with Windows - skip them.
SYSTEM_DLLS=(
    kernel32.dll user32.dll gdi32.dll advapi32.dll shell32.dll
    ole32.dll oleaut32.dll comdlg32.dll comctl32.dll
    ws2_32.dll mswsock.dll wsock32.dll iphlpapi.dll
    msvcrt.dll ucrtbase.dll bcrypt.dll crypt32.dll
    shlwapi.dll secur32.dll dbghelp.dll psapi.dll
    netapi32.dll userenv.dll version.dll winmm.dll
    setupapi.dll cfgmgr32.dll dwmapi.dll uxtheme.dll
    opengl32.dll glu32.dll dwrite.dll d3d9.dll d3d11.dll
    ntdll.dll rpcrt4.dll imm32.dll oleacc.dll
    api-ms-win-*.dll ext-ms-*.dll  # OS forwarders
)
is_system_dll() {
    local name_lower="${1,,}"
    for sys in "${SYSTEM_DLLS[@]}"; do
        case "$name_lower" in ${sys,,}) return 0 ;; esac
    done
    return 1
}

find_dll() {
    local name="$1"
    for dir in "${SEARCH_DIRS[@]}"; do
        if [[ -f "${dir}/${name}" ]]; then
            echo "${dir}/${name}"
            return 0
        fi
        # Case-insensitive match on the same dir in case mingw uses a
        # different casing than the .exe's import table.
        local hit
        hit="$(find "${dir}" -maxdepth 1 -iname "${name}" -type f 2>/dev/null | head -n 1)"
        if [[ -n "${hit}" ]]; then
            echo "${hit}"
            return 0
        fi
    done
    return 1
}

list_imports() {
    # Names of DLLs imported by the given PE file. objdump uses
    # whatever target tool exists; mingw-objdump or plain objdump
    # both work on PE.
    local file="$1"
    local tool
    if command -v x86_64-w64-mingw32-objdump >/dev/null 2>&1; then
        tool=x86_64-w64-mingw32-objdump
    else
        tool=objdump
    fi
    "$tool" -p "$file" 2>/dev/null \
        | awk '/DLL Name/ {print $3}'
}

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"

# Iterative walk: start with the exes, queue every non-system DLL
# they import, recurse into each DLL we add until nothing new appears.
declare -A SEEN=()
QUEUE=("${EXES[@]}")
while [[ ${#QUEUE[@]} -gt 0 ]]; do
    item="${QUEUE[0]}"
    QUEUE=("${QUEUE[@]:1}")
    name="$(basename "$item")"
    if [[ -n "${SEEN[${name,,}]:-}" ]]; then continue; fi
    SEEN[${name,,}]=1
    cp -L "$item" "${WORK_DIR}/$name"
    echo "  + $name"
    while IFS= read -r dep; do
        [[ -z "$dep" ]] && continue
        if is_system_dll "$dep"; then continue; fi
        if [[ -n "${SEEN[${dep,,}]:-}" ]]; then continue; fi
        if hit="$(find_dll "$dep")"; then
            QUEUE+=("$hit")
        else
            echo "  ? $dep  (not found - the .exe may fail to start)"
            SEEN[${dep,,}]=1
        fi
    done < <(list_imports "$item")
done

rm -f "${ZIP_PATH}"
( cd "$(dirname "${WORK_DIR}")" && zip -q -r "${ZIP_PATH}" "$(basename "${WORK_DIR}")" )

echo
echo "[ok] bundle ready: ${ZIP_PATH}"
ls -lh "${ZIP_PATH}"
echo "     contents in ${WORK_DIR}/"
ls -lh "${WORK_DIR}/" | awk 'NR>1 {printf "       %s  %s\n", $5, $NF}'
