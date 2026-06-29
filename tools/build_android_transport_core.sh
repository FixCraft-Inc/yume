#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_OUT_DIR="${ROOT_DIR}/build/android-transport-core"
DEFAULT_API=28
DEFAULT_ABIS=("armeabi-v7a" "arm64-v8a" "x86" "x86_64")

usage() {
    cat <<'EOF'
Usage: build_android_transport_core.sh --ndk <path> [options]

Options:
  --ndk <path>       Android NDK root
  --cmake <path>     CMake binary to use (default: cmake from PATH)
  --api <level>      Android API level (default: 28)
  --abi <name>       Build only one ABI; may be provided multiple times
  --out <path>       Output directory (default: build/android-transport-core)
  --without-basefwx  Build a smoke-test core without native BaseFWX support

The script builds the shared yume_transport_core static library in
YUME_TRANSPORT_CORE_ONLY mode and copies each ABI archive to:
  <out>/<abi>/libyume_transport_core.a
EOF
}

NDK_DIR=""
CMAKE_BIN="cmake"
API_LEVEL="${DEFAULT_API}"
OUT_DIR="${DEFAULT_OUT_DIR}"
USE_BASEFWX="ON"
ABIS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ndk)
            NDK_DIR="${2:-}"
            shift 2
            ;;
        --cmake)
            CMAKE_BIN="${2:-}"
            shift 2
            ;;
        --api)
            API_LEVEL="${2:-}"
            shift 2
            ;;
        --abi)
            ABIS+=("${2:-}")
            shift 2
            ;;
        --out)
            OUT_DIR="${2:-}"
            shift 2
            ;;
        --without-basefwx)
            USE_BASEFWX="OFF"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -z "${NDK_DIR}" ]]; then
    echo "--ndk is required" >&2
    usage >&2
    exit 1
fi

if [[ ! -d "${NDK_DIR}" ]]; then
    echo "NDK directory does not exist: ${NDK_DIR}" >&2
    exit 1
fi

TOOLCHAIN_FILE="${NDK_DIR}/build/cmake/android.toolchain.cmake"
if [[ ! -f "${TOOLCHAIN_FILE}" ]]; then
    echo "NDK toolchain file not found: ${TOOLCHAIN_FILE}" >&2
    exit 1
fi

if [[ ${#ABIS[@]} -eq 0 ]]; then
    ABIS=("${DEFAULT_ABIS[@]}")
fi

mkdir -p "${OUT_DIR}"

for ABI in "${ABIS[@]}"; do
    BUILD_DIR="${OUT_DIR}/.build/${ABI}"
    ABI_OUT_DIR="${OUT_DIR}/${ABI}"

    echo "==> Building yume_transport_core for ${ABI}"
    "${CMAKE_BIN}" \
        -S "${ROOT_DIR}" \
        -B "${BUILD_DIR}" \
        -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}" \
        -DANDROID_ABI="${ABI}" \
        -DANDROID_PLATFORM="android-${API_LEVEL}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DYUME_TRANSPORT_CORE_ONLY=ON \
        -DYUME_USE_SPDLOG=OFF \
        -DYUME_USE_BASEFWX="${USE_BASEFWX}"

    "${CMAKE_BIN}" --build "${BUILD_DIR}" --target yume_transport_core -j"$(nproc)"

    mkdir -p "${ABI_OUT_DIR}"
    cp "${BUILD_DIR}/src/libyume_transport_core.a" "${ABI_OUT_DIR}/libyume_transport_core.a"
done
