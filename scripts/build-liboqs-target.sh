#!/usr/bin/env bash
# Build liboqs for a specific target (host or cross-arch) and install it
# to a target-appropriate prefix so yume's CMake build can find it.
#
# Usage:
#   LIBOQS_TARGET=host       ./scripts/build-liboqs-target.sh   # /usr/local
#   LIBOQS_TARGET=armv7      ./scripts/build-liboqs-target.sh   # /usr/arm-linux-gnueabihf
#   LIBOQS_TARGET=armv8      ./scripts/build-liboqs-target.sh   # /usr/aarch64-linux-gnu
#   LIBOQS_TARGET=i386       ./scripts/build-liboqs-target.sh   # vendor/busybox-x86
#
# Always builds a static archive (`liboqs.a`). yume's release pipeline
# static-links liboqs into every binary anyway because the binary then
# has no run-time dependency on a system liboqs.so — important on
# embedded targets that may not have one.
#
# Honored env:
#   LIBOQS_TARGET       host | armv7 | armv8 | i386            (required)
#   LIBOQS_VERSION      upstream tag, default 0.11.0
#   LIBOQS_BUILD_DIR    scratch dir, default $TMPDIR/liboqs-$target-build
#   LIBOQS_PREFIX_OVERRIDE  override the default install prefix
#   LIBOQS_FORCE        rebuild even if .a + header already present at prefix

set -euo pipefail

LIBOQS_TARGET="${LIBOQS_TARGET:?LIBOQS_TARGET must be set (host|armv7|armv8|i386)}"
LIBOQS_VERSION="${LIBOQS_VERSION:-0.11.0}"
LIBOQS_FORCE="${LIBOQS_FORCE:-0}"

case "${LIBOQS_TARGET}" in
    host)
        prefix_default="/usr/local"
        toolchain_file=""
        ;;
    armv7)
        prefix_default="/usr/arm-linux-gnueabihf"
        cross_prefix="arm-linux-gnueabihf"
        cmake_processor="arm"
        ;;
    armv8)
        prefix_default="/usr/aarch64-linux-gnu"
        cross_prefix="aarch64-linux-gnu"
        cmake_processor="aarch64"
        ;;
    i386)
        # busybox-x86 is the only consumer; ezbuild looks under
        # ${PWD}/vendor/busybox-x86 so we install there.
        prefix_default="$(pwd)/vendor/busybox-x86"
        cross_prefix="i686-linux-gnu"
        cmake_processor="x86"
        ;;
    *)
        echo "Unsupported LIBOQS_TARGET: ${LIBOQS_TARGET}" >&2
        exit 2
        ;;
esac

LIBOQS_PREFIX="${LIBOQS_PREFIX_OVERRIDE:-${prefix_default}}"
LIBOQS_BUILD_DIR="${LIBOQS_BUILD_DIR:-${TMPDIR:-/tmp}/liboqs-${LIBOQS_TARGET}-build}"

echo "=== liboqs build (target=${LIBOQS_TARGET}, prefix=${LIBOQS_PREFIX}) ==="

# Idempotency: skip if a static lib + header already exist at the prefix
# (or its lib64 sibling) and LIBOQS_FORCE is not set.
if [[ "${LIBOQS_FORCE}" != "1" ]]; then
    have_header=0
    if [[ -f "${LIBOQS_PREFIX}/include/oqs/oqs.h" ]]; then have_header=1; fi
    have_static=0
    for libdir in "${LIBOQS_PREFIX}/lib" "${LIBOQS_PREFIX}/lib64"; do
        if [[ -f "${libdir}/liboqs.a" ]]; then have_static=1; break; fi
    done
    if (( have_header && have_static )); then
        echo "✓ Reusing existing static liboqs at ${LIBOQS_PREFIX}"
        exit 0
    fi
fi

mkdir -p "${LIBOQS_BUILD_DIR}"
src_dir="${LIBOQS_BUILD_DIR}/src"
build_dir="${LIBOQS_BUILD_DIR}/build"

if [[ ! -d "${src_dir}/CMakeLists.txt" && ! -f "${src_dir}/CMakeLists.txt" ]]; then
    echo "Fetching liboqs ${LIBOQS_VERSION} source..."
    rm -rf "${src_dir}"
    mkdir -p "${src_dir}"
    tarball="${LIBOQS_BUILD_DIR}/liboqs.tar.gz"
    wget -q "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" -O "${tarball}"
    tar -xzf "${tarball}" --strip-components=1 -C "${src_dir}"
fi

cmake_args=(
    -S "${src_dir}"
    -B "${build_dir}"
    -G Ninja
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_INSTALL_PREFIX="${LIBOQS_PREFIX}"
    -DBUILD_SHARED_LIBS=OFF        # always static .a
    -DOQS_BUILD_ONLY_LIB=ON
    -DOQS_DIST_BUILD=ON
    -DOQS_USE_OPENSSL=ON
    -DCMAKE_INSTALL_LIBDIR=lib
)

if [[ -n "${toolchain_file:-}" ]]; then
    cmake_args+=( "-DCMAKE_TOOLCHAIN_FILE=${toolchain_file}" )
fi

# For cross targets, write a tiny toolchain file inline and pass it to
# CMake. We don't ship a separate file per arch because the GCC cross
# triplets are all installable from apt with a stable naming scheme.
if [[ "${LIBOQS_TARGET}" != "host" ]]; then
    tc="${LIBOQS_BUILD_DIR}/toolchain.cmake"
    cat > "${tc}" <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ${cmake_processor})
set(CMAKE_C_COMPILER ${cross_prefix}-gcc)
set(CMAKE_CXX_COMPILER ${cross_prefix}-g++)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
EOF
    cmake_args+=( "-DCMAKE_TOOLCHAIN_FILE=${tc}" )
fi

echo "Configuring liboqs for ${LIBOQS_TARGET}..."
cmake "${cmake_args[@]}"

echo "Building liboqs (parallel)..."
cmake --build "${build_dir}" --parallel "$(nproc)"

echo "Installing liboqs to ${LIBOQS_PREFIX}..."
sudo_cmd=()
if [[ ! -w "${LIBOQS_PREFIX}" && ! -w "$(dirname "${LIBOQS_PREFIX}")" ]]; then
    if command -v sudo >/dev/null 2>&1; then
        sudo_cmd=(sudo)
    fi
fi
"${sudo_cmd[@]}" cmake --install "${build_dir}"

# Verify
if [[ ! -f "${LIBOQS_PREFIX}/include/oqs/oqs.h" ]]; then
    echo "✗ Header not installed at ${LIBOQS_PREFIX}/include/oqs/oqs.h" >&2
    exit 1
fi
if [[ ! -f "${LIBOQS_PREFIX}/lib/liboqs.a" && ! -f "${LIBOQS_PREFIX}/lib64/liboqs.a" ]]; then
    echo "✗ Static lib not installed under ${LIBOQS_PREFIX}/lib{,64}/liboqs.a" >&2
    exit 1
fi
echo "✓ liboqs ${LIBOQS_VERSION} installed at ${LIBOQS_PREFIX} (target=${LIBOQS_TARGET})"
