#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
# Build libargon2 for a specific target (host or cross-arch) and install
# the static archive + header into the appropriate prefix so yume's
# CMake build can find it on link.
#
# Mirrors scripts/build-liboqs-target.sh — same target labels, same
# install layout — but uses libargon2's plain Makefile (no CMake) so
# cross-builds are just CC=<triplet>-gcc, no toolchain file.
#
# Usage:
#   LIBARGON2_TARGET=host           ./scripts/build-libargon2-target.sh  # /usr/local
#   LIBARGON2_TARGET=armv7          ./scripts/build-libargon2-target.sh  # /usr/arm-linux-gnueabihf
#   LIBARGON2_TARGET=armv8          ./scripts/build-libargon2-target.sh  # /usr/aarch64-linux-gnu
#   LIBARGON2_TARGET=i386           ./scripts/build-libargon2-target.sh  # vendor/busybox-x86
#   LIBARGON2_TARGET=openwrt-mips   ./scripts/build-libargon2-target.sh  # $OPENWRT_SDK/.../target-mips_*/usr
#
# We always build the static .a. The dynamic .so isn't needed for any
# release artifact (basefwx + yume link argon2 statically into the
# final binary).
#
# Honored env:
#   LIBARGON2_TARGET    host | armv7 | armv8 | i386 | openwrt-mips   (required)
#   LIBARGON2_VERSION   upstream tag, default 20190702 (matches Debian/Ubuntu's libargon2-dev)
#   LIBARGON2_FORCE     rebuild even if .a + header already at prefix
#   OPENWRT_SDK         path to the OpenWRT SDK extraction (needed only for openwrt-mips)

set -euo pipefail

LIBARGON2_TARGET="${LIBARGON2_TARGET:?LIBARGON2_TARGET must be set (host|armv7|armv8|i386|openwrt-mips)}"
LIBARGON2_VERSION="${LIBARGON2_VERSION:-20190702}"
LIBARGON2_FORCE="${LIBARGON2_FORCE:-0}"

case "${LIBARGON2_TARGET}" in
    host)
        prefix_default="/usr/local"
        cross_cc=""
        cross_ar=""
        is_openwrt=0
        ;;
    armv7)
        prefix_default="/usr/arm-linux-gnueabihf"
        cross_cc="arm-linux-gnueabihf-gcc"
        cross_ar="arm-linux-gnueabihf-ar"
        is_openwrt=0
        ;;
    armv8)
        prefix_default="/usr/aarch64-linux-gnu"
        cross_cc="aarch64-linux-gnu-gcc"
        cross_ar="aarch64-linux-gnu-ar"
        is_openwrt=0
        ;;
    i386)
        prefix_default="$(pwd)/vendor/busybox-x86"
        cross_cc="i686-linux-gnu-gcc"
        cross_ar="i686-linux-gnu-ar"
        is_openwrt=0
        ;;
    openwrt-mips)
        # Same SDK-discovery logic as build-liboqs-target.sh's
        # openwrt-mips case. Honor $OPENWRT_SDK if set; otherwise
        # autodetect under $HOME.
        if [[ -z "${OPENWRT_SDK:-}" ]]; then
            OPENWRT_SDK="$(find "${HOME}" -maxdepth 1 -type d \
                -name "openwrt-sdk-*-musl.Linux-x86_64" 2>/dev/null | head -1)"
        fi
        if [[ -z "${OPENWRT_SDK}" || ! -d "${OPENWRT_SDK}" ]]; then
            echo "OpenWRT SDK not found. Set OPENWRT_SDK or stage one at ~/openwrt-sdk-*-musl.Linux-x86_64" >&2
            exit 2
        fi
        openwrt_tc_dir="$(find "${OPENWRT_SDK}/staging_dir" -maxdepth 1 \
            -type d -name "toolchain-mips_*musl*" 2>/dev/null | head -1)"
        openwrt_target_dir="$(find "${OPENWRT_SDK}/staging_dir" -maxdepth 1 \
            -type d -name "target-mips_*musl*" 2>/dev/null | head -1)"
        if [[ -z "${openwrt_tc_dir}" || -z "${openwrt_target_dir}" ]]; then
            echo "OpenWRT MIPS toolchain or sysroot missing under ${OPENWRT_SDK}/staging_dir" >&2
            exit 2
        fi
        prefix_default="${openwrt_target_dir}/usr"
        cross_cc="${openwrt_tc_dir}/bin/mips-openwrt-linux-musl-gcc"
        cross_ar="${openwrt_tc_dir}/bin/mips-openwrt-linux-musl-ar"
        is_openwrt=1
        ;;
    *)
        echo "Unsupported LIBARGON2_TARGET: ${LIBARGON2_TARGET}" >&2
        exit 2
        ;;
esac

LIBARGON2_PREFIX="${LIBARGON2_PREFIX_OVERRIDE:-${prefix_default}}"
LIBARGON2_BUILD_DIR="${LIBARGON2_BUILD_DIR:-${TMPDIR:-/tmp}/libargon2-${LIBARGON2_TARGET}-build}"

echo "=== libargon2 build (target=${LIBARGON2_TARGET}, prefix=${LIBARGON2_PREFIX}) ==="

# Idempotency: skip if static + header already present.
if [[ "${LIBARGON2_FORCE}" != "1" ]]; then
    have_header=0
    if [[ -f "${LIBARGON2_PREFIX}/include/argon2.h" ]]; then have_header=1; fi
    have_static=0
    for libdir in "${LIBARGON2_PREFIX}/lib" "${LIBARGON2_PREFIX}/lib64"; do
        if [[ -f "${libdir}/libargon2.a" ]]; then have_static=1; break; fi
    done
    if (( have_header && have_static )); then
        echo "✓ Reusing existing static libargon2 at ${LIBARGON2_PREFIX}"
        exit 0
    fi
fi

mkdir -p "${LIBARGON2_BUILD_DIR}"
src_dir="${LIBARGON2_BUILD_DIR}/src"

if [[ ! -f "${src_dir}/Makefile" ]]; then
    # Cache the source tarball outside the per-target build dir so all
    # cross targets reuse a single download (see build-liboqs-target.sh
    # for the same pattern + rationale).
    cache_dir="${LIBARGON2_SRC_CACHE_DIR:-${TMPDIR:-/tmp}/libargon2-src-cache}"
    mkdir -p "${cache_dir}"
    tarball="${cache_dir}/libargon2-${LIBARGON2_VERSION}.tar.gz"
    if [[ ! -s "${tarball}" ]]; then
        echo "Fetching libargon2 ${LIBARGON2_VERSION} source..."
        wget --tries=5 --waitretry=10 --retry-connrefused \
            "https://github.com/P-H-C/phc-winner-argon2/archive/refs/tags/${LIBARGON2_VERSION}.tar.gz" \
            -O "${tarball}.part"
        mv -f "${tarball}.part" "${tarball}"
    else
        echo "Reusing cached libargon2 ${LIBARGON2_VERSION} tarball at ${tarball}"
    fi
    rm -rf "${src_dir}"
    mkdir -p "${src_dir}"
    tar -xzf "${tarball}" --strip-components=1 -C "${src_dir}"
fi

# argon2's Makefile builds libargon2.so + libargon2.a + the argon2 CLI.
# We only need libargon2.a; OPTTARGET=generic disables -march=native
# which would inject host-x86_64 instructions into the cross output.
make_args=(
    -C "${src_dir}"
    OPTTARGET=generic
    LIBRARY_REL=lib
)
if [[ -n "${cross_cc}" ]]; then
    make_args+=( "CC=${cross_cc}" )
fi
if [[ -n "${cross_ar}" ]]; then
    make_args+=( "AR=${cross_ar}" )
fi

echo "Building libargon2.a for ${LIBARGON2_TARGET}..."
# Build just the static library target so we don't waste cycles on the
# .so or the CLI binary (which would also fail to link cross because
# argon2's Makefile is host-shaped for those).
make "${make_args[@]}" -j"$(nproc)" libargon2.a

# Install. argon2's Makefile install target tries to compile docs etc.
# and assumes a host install; do it manually so we control the layout.
sudo_cmd=()
if [[ ! -w "${LIBARGON2_PREFIX}" && ! -w "$(dirname "${LIBARGON2_PREFIX}")" ]]; then
    if command -v sudo >/dev/null 2>&1; then
        sudo_cmd=(sudo)
    fi
fi
"${sudo_cmd[@]}" mkdir -p "${LIBARGON2_PREFIX}/include" "${LIBARGON2_PREFIX}/lib"
"${sudo_cmd[@]}" cp -f "${src_dir}/include/argon2.h" "${LIBARGON2_PREFIX}/include/argon2.h"
"${sudo_cmd[@]}" cp -f "${src_dir}/libargon2.a"        "${LIBARGON2_PREFIX}/lib/libargon2.a"

# Verify
if [[ ! -f "${LIBARGON2_PREFIX}/include/argon2.h" ]]; then
    echo "✗ Header not installed at ${LIBARGON2_PREFIX}/include/argon2.h" >&2
    exit 1
fi
if [[ ! -f "${LIBARGON2_PREFIX}/lib/libargon2.a" ]]; then
    echo "✗ Static lib not installed at ${LIBARGON2_PREFIX}/lib/libargon2.a" >&2
    exit 1
fi
echo "✓ libargon2 ${LIBARGON2_VERSION} installed at ${LIBARGON2_PREFIX} (target=${LIBARGON2_TARGET})"
