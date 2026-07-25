#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED_BASELINE="8f6eb6748614618d4b7e8e4ba36ff92a8d8d7d96"
DEFAULT_OUT_DIR="${ROOT_DIR}/build/android-shared-abi"
DEFAULT_API=28
DEFAULT_ABIS=("armeabi-v7a" "arm64-v8a" "x86" "x86_64")

usage() {
    cat <<'EOF'
Usage: build_android_shared_abi.sh --ndk PATH --vcpkg PATH [options]

Options:
  --ndk PATH              Pinned Android NDK root
  --vcpkg PATH            vcpkg checkout root
  --api LEVEL             Android API level (default: 28)
  --abi NAME              Build one ABI; repeat for more ABIs
  --out PATH              Output root (default: build/android-shared-abi)
  --expected-baseline SHA Required signed ancestor (default: 8f6eb67...)
  --expected-commit SHA   Compatibility alias for --expected-baseline
  --jobs COUNT            Parallel build jobs

The output for each ABI is <out>/<abi>/libyume.so plus the public header at
<out>/include/yume/yume.h. Native dependencies are statically linked into the
single shared ABI library; libc++_shared.so remains supplied by the Android app.
EOF
}

NDK_DIR=""
VCPKG_DIR=""
OUT_DIR="${DEFAULT_OUT_DIR}"
API_LEVEL="${DEFAULT_API}"
DETECTED_JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '2')"
# Android C++ translation units are memory-heavy. A conservative default keeps
# release builds responsive on ordinary developer machines; CI and larger
# builders can opt in to more parallelism with --jobs.
if (( DETECTED_JOBS > 4 )); then
    JOBS=4
else
    JOBS="${DETECTED_JOBS}"
fi
ABIS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ndk) NDK_DIR="${2:-}"; shift 2 ;;
        --vcpkg) VCPKG_DIR="${2:-}"; shift 2 ;;
        --api) API_LEVEL="${2:-}"; shift 2 ;;
        --abi) ABIS+=("${2:-}"); shift 2 ;;
        --out) OUT_DIR="${2:-}"; shift 2 ;;
        --expected-baseline|--expected-commit) EXPECTED_BASELINE="${2:-}"; shift 2 ;;
        --jobs) JOBS="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ "$(id -u)" -eq 0 ]]; then
    printf 'Refusing to build Android artifacts as root.\n' >&2
    exit 1
fi
if [[ ! -f "${NDK_DIR}/build/cmake/android.toolchain.cmake" ]]; then
    printf 'Android NDK toolchain not found under: %s\n' "${NDK_DIR}" >&2
    exit 1
fi
if [[ ! -f "${VCPKG_DIR}/scripts/buildsystems/vcpkg.cmake" ]]; then
    printf 'vcpkg toolchain not found under: %s\n' "${VCPKG_DIR}" >&2
    exit 1
fi
if [[ ! "${JOBS}" =~ ^[1-9][0-9]*$ ]]; then
    printf 'Parallel build jobs must be a positive integer: %s\n' "${JOBS}" >&2
    exit 1
fi
if ! git -C "${ROOT_DIR}" cat-file -e "${EXPECTED_BASELINE}^{commit}" 2>/dev/null; then
    printf 'Required YUME baseline commit is unavailable: %s\n' "${EXPECTED_BASELINE}" >&2
    exit 1
fi
if ! git -C "${ROOT_DIR}" merge-base --is-ancestor "${EXPECTED_BASELINE}" HEAD; then
    printf 'YUME HEAD is not based on required signed baseline %s\n' "${EXPECTED_BASELINE}" >&2
    exit 1
fi
git -C "${ROOT_DIR}" verify-commit "${EXPECTED_BASELINE}" >/dev/null

if [[ ${#ABIS[@]} -eq 0 ]]; then
    ABIS=("${DEFAULT_ABIS[@]}")
fi

triplet_for_abi() {
    case "$1" in
        armeabi-v7a) printf 'arm-neon-android' ;;
        arm64-v8a) printf 'arm64-android' ;;
        x86) printf 'x86-android' ;;
        x86_64) printf 'x64-android' ;;
        *) printf 'Unsupported Android ABI: %s\n' "$1" >&2; return 1 ;;
    esac
}

mkdir -p "${OUT_DIR}/include/yume"
cp "${ROOT_DIR}/include/yume/yume.h" "${OUT_DIR}/include/yume/yume.h"

for ABI in "${ABIS[@]}"; do
    TRIPLET="$(triplet_for_abi "${ABI}")"
    BUILD_DIR="${OUT_DIR}/.build/${ABI}"
    ABI_DIR="${OUT_DIR}/${ABI}"
    printf '==> Building shared YUME ABI for %s (%s)\n' "${ABI}" "${TRIPLET}"
    # vcpkg's Android triplets start a separate compiler-detection CMake
    # process using scripts/toolchains/android.cmake. That subprocess does not
    # inherit VCPKG_CHAINLOAD_TOOLCHAIN_FILE and locates the NDK through
    # ANDROID_NDK_HOME instead. Pin both environment spellings to the same NDK
    # Gradle selected so detection and the actual build cannot diverge.
    if ! env \
        ANDROID_NDK_HOME="${NDK_DIR}" \
        ANDROID_NDK_ROOT="${NDK_DIR}" \
        cmake \
            -S "${ROOT_DIR}" \
            -B "${BUILD_DIR}" \
            -DCMAKE_TOOLCHAIN_FILE="${VCPKG_DIR}/scripts/buildsystems/vcpkg.cmake" \
            -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE="${NDK_DIR}/build/cmake/android.toolchain.cmake" \
            -DVCPKG_TARGET_TRIPLET="${TRIPLET}" \
            -DVCPKG_MANIFEST_DIR="${ROOT_DIR}" \
            -DANDROID_ABI="${ABI}" \
            -DANDROID_PLATFORM="android-${API_LEVEL}" \
            -DANDROID_STL=c++_shared \
            -DCMAKE_BUILD_TYPE=Release \
            -DYUME_BUILD_SHARED_ABI=ON \
            -DYUME_ABI_CLIENT_ONLY=ON \
            -DYUME_BUILD_GUI=OFF \
            -DYUME_BUILD_SELFTEST=OFF \
            -DYUME_BUILD_TESTING=OFF \
            -DYUME_BUILD_TOOLS=OFF \
            -DYUME_USE_SPDLOG=OFF \
            -DYUME_USE_BASEFWX=ON; then
        manifest_log="${BUILD_DIR}/vcpkg-manifest-install.log"
        if [[ -f "${manifest_log}" ]]; then
            printf '\nLast vcpkg configure output (%s):\n' "${manifest_log}" >&2
            tail -n 120 "${manifest_log}" >&2
        fi
        exit 1
    fi
    build_log="${BUILD_DIR}/yume-abi-build.log"
    # Keep the complete native output even when Gradle suppresses child-process
    # diagnostics. pipefail preserves cmake's exit status through tee.
    if ! cmake --build "${BUILD_DIR}" --target yume_abi --parallel "${JOBS}" \
        2>&1 | tee "${build_log}"; then
        printf '\nNative build failed. Last output (%s):\n' "${build_log}" >&2
        tail -n 160 "${build_log}" >&2
        exit 1
    fi
    mkdir -p "${ABI_DIR}"
    cmake -E copy "${BUILD_DIR}/src/libyume.so" "${ABI_DIR}/libyume.so"
done
