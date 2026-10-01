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
  --unverified-source     Build a tree without Git metadata, such as a
                          synchronized qualification copy. Nothing then ties
                          the output to a signed commit, so never release it.
  --jobs COUNT            Parallel build jobs

The output for each ABI is <out>/<abi>/libyume.so plus the public header at
<out>/include/yume/yume.h. Native dependencies are statically linked into the
single shared ABI library, and libc++_shared.so remains supplied by the Android
app.

The native TLS provider needs the pinned OpenSSL with YUME's patch series,
which vcpkg does not build. This script builds it for each ABI from the
source scripts/ensure-openssl.sh pins and verifies, with zlib, zstd and
Brotli from the ABI's vcpkg triplet, and keeps it under
<out>/.openssl/<abi>/ by version and patch series.
EOF
}

NDK_DIR=""
VCPKG_DIR=""
OUT_DIR="${DEFAULT_OUT_DIR}"
API_LEVEL="${DEFAULT_API}"
VERIFY_SOURCE=1
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
        --unverified-source) VERIFY_SOURCE=0; shift ;;
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
if [[ ! "${API_LEVEL}" =~ ^[1-9][0-9]*$ ]]; then
    printf 'Android API level must be a positive integer: %s\n' "${API_LEVEL}" >&2
    exit 1
fi
if (( VERIFY_SOURCE )); then
    if ! git -C "${ROOT_DIR}" cat-file -e "${EXPECTED_BASELINE}^{commit}" 2>/dev/null; then
        printf 'Required YUME baseline commit is unavailable: %s\n' "${EXPECTED_BASELINE}" >&2
        exit 1
    fi
    if ! git -C "${ROOT_DIR}" merge-base --is-ancestor "${EXPECTED_BASELINE}" HEAD; then
        printf 'YUME HEAD is not based on required signed baseline %s\n' "${EXPECTED_BASELINE}" >&2
        exit 1
    fi
    git -C "${ROOT_DIR}" verify-commit "${EXPECTED_BASELINE}" >/dev/null
else
    printf 'warning: building an unverified source tree. Do not release this output.\n' >&2
fi

# The pinned OpenSSL source, its checksum and the patch series have one owner.
# shellcheck source=scripts/ensure-openssl.sh
source "${ROOT_DIR}/scripts/ensure-openssl.sh"
OPENSSL_PATCH_DIR="${ROOT_DIR}/patches/openssl"
OPENSSL_SERIES="$(yume_openssl_series_tag "${OPENSSL_PATCH_DIR}")"
if [[ "${OPENSSL_SERIES}" == "stock" ]]; then
    printf 'The OpenSSL patch series is missing or empty: %s\n' "${OPENSSL_PATCH_DIR}" >&2
    exit 1
fi
NDK_HOST_BIN="${NDK_DIR}/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [[ ! -x "${NDK_HOST_BIN}/clang" ]]; then
    printf 'NDK compiler not found under: %s\n' "${NDK_HOST_BIN}" >&2
    exit 1
fi

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

openssl_target_for_abi() {
    case "$1" in
        armeabi-v7a) printf 'android-arm' ;;
        arm64-v8a) printf 'android-arm64' ;;
        x86) printf 'android-x86' ;;
        x86_64) printf 'android-x86_64' ;;
        *) printf 'Unsupported Android ABI: %s\n' "$1" >&2; return 1 ;;
    esac
}

# Fetches the pinned OpenSSL archive once and checks it against its pin.
openssl_archive() {
    local archive_dir="${OUT_DIR}/.openssl/downloads"
    local archive="${archive_dir}/openssl-${YUME_OPENSSL_SOURCE_VERSION}.tar.gz"
    local url="https://github.com/openssl/openssl/releases/download/openssl-${YUME_OPENSSL_SOURCE_VERSION}/openssl-${YUME_OPENSSL_SOURCE_VERSION}.tar.gz"
    mkdir -p "${archive_dir}"
    if [[ ! -f "${archive}" ]]; then
        printf '==> Downloading OpenSSL %s\n' "${YUME_OPENSSL_SOURCE_VERSION}" >&2
        yume_openssl_download "${archive}" "${url}" || return 1
    fi
    if [[ "$(yume_openssl_hash_file "${archive}")" != "${YUME_OPENSSL_SOURCE_SHA256}" ]]; then
        rm -f -- "${archive}"
        printf 'OpenSSL source checksum mismatch; the archive was removed.\n' >&2
        return 1
    fi
    printf '%s' "${archive}"
}

# Builds static, position-independent libssl and libcrypto for one ABI into
# prefix, with the compression libraries of the ABI's vcpkg installation.
# A finished prefix is reused: its name carries the version and patch series,
# and its marker the API level and NDK it was built with.
build_openssl() {
    local abi="$1"
    local installed="$2"
    local prefix="$3"
    local identity="api=${API_LEVEL} ndk=$(sed -n 's/^Pkg.Revision *= *//p' "${NDK_DIR}/source.properties")"
    local marker="${prefix}/.yume-android-build"
    local target=""
    local archive=""
    local work_dir=""
    local log=""
    if [[ -f "${marker}" && "$(cat "${marker}")" == "${identity}" &&
          -f "${prefix}/lib/libssl.a" && -f "${prefix}/lib/libcrypto.a" ]]; then
        return 0
    fi
    target="$(openssl_target_for_abi "${abi}")"
    archive="$(openssl_archive)"
    for header in zlib.h zstd.h brotli/encode.h; do
        if [[ ! -f "${installed}/include/${header}" ]]; then
            printf 'vcpkg did not install %s for %s\n' "${header}" "${abi}" >&2
            return 1
        fi
    done
    work_dir="$(mktemp -d "${TMPDIR:-/tmp}/yume-openssl-android-XXXXXX")"
    log="${OUT_DIR}/.openssl/${abi}/build.log"
    mkdir -p "$(dirname "${log}")"
    printf '==> Building OpenSSL %s (%s) for %s\n' \
        "${YUME_OPENSSL_SOURCE_VERSION}" "${OPENSSL_SERIES}" "${abi}"
    # Brotli is required: Chrome offers only that certificate compression,
    # so a build without it would show in the ClientHello.
    if ! (
        set -e
        tar -xzf "${archive}" -C "${work_dir}" --strip-components=1
        yume_openssl_apply_patches "${work_dir}" "${OPENSSL_PATCH_DIR}"
        rm -rf -- "${prefix}"
        cd "${work_dir}"
        export ANDROID_NDK_ROOT="${NDK_DIR}"
        export PATH="${NDK_HOST_BIN}:${PATH}"
        ./Configure "${target}" "-D__ANDROID_API__=${API_LEVEL}" -fPIC \
            --prefix="${prefix}" --openssldir="${prefix}/ssl" --libdir=lib \
            no-shared no-tests no-apps no-docs \
            zlib enable-zstd enable-brotli \
            --with-zlib-include="${installed}/include" \
            --with-zlib-lib="${installed}/lib" \
            --with-zstd-include="${installed}/include" \
            --with-zstd-lib="${installed}/lib" \
            --with-brotli-include="${installed}/include" \
            --with-brotli-lib="${installed}/lib"
        make -j"${JOBS}" build_libs
        make install_dev
    ) >"${log}" 2>&1; then
        rm -rf -- "${work_dir}" "${prefix}"
        printf '\nOpenSSL build failed for %s. Last output (%s):\n' "${abi}" "${log}" >&2
        tail -n 80 "${log}" >&2
        return 1
    fi
    rm -rf -- "${work_dir}"
    printf '%s' "${identity}" > "${marker}"
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
    #
    # The triplet's packages are installed first, where the configure step
    # below expects them, because the OpenSSL build needs their headers and
    # archives before CMake can look for OpenSSL.
    INSTALLED_DIR="${BUILD_DIR}/vcpkg_installed/${TRIPLET}"
    OPENSSL_PREFIX="${OUT_DIR}/.openssl/${ABI}/openssl-${YUME_OPENSSL_SOURCE_VERSION}-${OPENSSL_SERIES}"
    mkdir -p "${BUILD_DIR}"
    if ! env \
        ANDROID_NDK_HOME="${NDK_DIR}" \
        ANDROID_NDK_ROOT="${NDK_DIR}" \
        "${VCPKG_DIR}/vcpkg" install \
            --triplet "${TRIPLET}" \
            --x-manifest-root="${ROOT_DIR}" \
            --x-install-root="${BUILD_DIR}/vcpkg_installed" \
            >"${BUILD_DIR}/vcpkg-install.log" 2>&1; then
        printf '\nvcpkg install failed for %s. Last output (%s):\n' \
            "${ABI}" "${BUILD_DIR}/vcpkg-install.log" >&2
        tail -n 80 "${BUILD_DIR}/vcpkg-install.log" >&2
        exit 1
    fi
    build_openssl "${ABI}" "${INSTALLED_DIR}" "${OPENSSL_PREFIX}"
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
            -DYUME_BUILD_NATIVE_APPLICATION=OFF \
            -DYUME_STATIC_OPENSSL=ON \
            -DOpenSSL_DIR="${OPENSSL_PREFIX}/lib/cmake/OpenSSL" \
            -DCMAKE_FIND_ROOT_PATH="${OPENSSL_PREFIX}" \
            `# The static OpenSSL names zlib, zstd and Brotli by -l alone.` \
            -DCMAKE_SHARED_LINKER_FLAGS="-L${INSTALLED_DIR}/lib" \
            -DCMAKE_EXE_LINKER_FLAGS="-L${INSTALLED_DIR}/lib" \
            -DYUME_BUILD_TESTING=OFF; then
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
