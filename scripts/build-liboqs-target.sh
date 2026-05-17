#!/usr/bin/env bash
# Build liboqs for a specific target (host or cross-arch) and install it
# to a target-appropriate prefix so yume's CMake build can find it.
#
# Usage:
#   LIBOQS_TARGET=host           ./scripts/build-liboqs-target.sh  # /usr/local
#   LIBOQS_TARGET=armv7          ./scripts/build-liboqs-target.sh  # /usr/arm-linux-gnueabihf
#   LIBOQS_TARGET=armv8          ./scripts/build-liboqs-target.sh  # /usr/aarch64-linux-gnu
#   LIBOQS_TARGET=i386           ./scripts/build-liboqs-target.sh  # vendor/busybox-x86
#   LIBOQS_TARGET=openwrt-mips   ./scripts/build-liboqs-target.sh  # $OPENWRT_SDK/staging_dir/target-mips_*/usr
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
        # x86_64 is in liboqs's supported-arch whitelist.
        permit_unsupported_arch=0
        # Host build uses system OpenSSL for its AES-NI / SHA-NI
        # backends. Cross builds disable it (see below).
        use_openssl=1
        ;;
    armv7)
        prefix_default="/usr/arm-linux-gnueabihf"
        cross_prefix="arm-linux-gnueabihf"
        cmake_processor="arm"
        # liboqs 0.11.x doesn't ship hand-tuned assembly for 32-bit
        # ARM; the configure step refuses to proceed unless we set
        # OQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON. That flag does not
        # disable any cryptographic invariants — it just allows the
        # portable-C fallbacks (which exist for every primitive) to
        # be compiled instead of arch-specific intrinsics.
        permit_unsupported_arch=1
        use_openssl=0
        ;;
    armv8)
        prefix_default="/usr/aarch64-linux-gnu"
        cross_prefix="aarch64-linux-gnu"
        cmake_processor="aarch64"
        # aarch64 IS in liboqs's whitelist (with NEON intrinsics).
        permit_unsupported_arch=0
        use_openssl=0
        ;;
    i386)
        # busybox-x86 is the only consumer; ezbuild looks under
        # ${PWD}/vendor/busybox-x86 so we install there.
        prefix_default="$(pwd)/vendor/busybox-x86"
        cross_prefix="i686-linux-gnu"
        cmake_processor="x86"
        # 32-bit x86 is also not in the whitelist — same rationale
        # as armv7. Portable C fallbacks compile cleanly under i686.
        permit_unsupported_arch=1
        use_openssl=0
        ;;
    openwrt-mips)
        # OpenWRT MIPS build via the SDK toolchain. We expect either
        # OPENWRT_SDK (the workflow sets this after `Download OpenWRT
        # SDK`) or a SDK already pre-staged under $HOME/openwrt-sdk-*.
        # Installing into the SDK's target-*/usr means ezbuild's
        # OPENWRT_USR auto-detection finds the .a immediately without
        # any vendor-dir gymnastics.
        if [[ -z "${OPENWRT_SDK:-}" ]]; then
            # Look for an existing local SDK extraction.
            OPENWRT_SDK="$(find "${HOME}" -maxdepth 1 -type d \
                -name "openwrt-sdk-*-musl.Linux-x86_64" 2>/dev/null | head -1)"
        fi
        if [[ -z "${OPENWRT_SDK}" || ! -d "${OPENWRT_SDK}" ]]; then
            echo "OpenWRT SDK not found. Set OPENWRT_SDK or stage one at ~/openwrt-sdk-*-musl.Linux-x86_64" >&2
            exit 2
        fi
        # SDK naming for ath79-nand 24.10.0:
        #   staging_dir/toolchain-mips_24kc_gcc-13.3.0_musl/
        #   staging_dir/target-mips_24kc_musl/
        openwrt_tc_dir="$(find "${OPENWRT_SDK}/staging_dir" -maxdepth 1 \
            -type d -name "toolchain-mips_*musl*" 2>/dev/null | head -1)"
        openwrt_target_dir="$(find "${OPENWRT_SDK}/staging_dir" -maxdepth 1 \
            -type d -name "target-mips_*musl*" 2>/dev/null | head -1)"
        if [[ -z "${openwrt_tc_dir}" || -z "${openwrt_target_dir}" ]]; then
            echo "OpenWRT MIPS toolchain or sysroot missing under ${OPENWRT_SDK}/staging_dir" >&2
            exit 2
        fi
        prefix_default="${openwrt_target_dir}/usr"
        cmake_processor="mips"
        # MIPS is not in liboqs's whitelist; portable C fallbacks
        # compile fine. liboqs has no MIPS-specific intrinsics anyway.
        permit_unsupported_arch=1
        # Don't link against the SDK's host OpenSSL. Sysroot may have a
        # musl-mips libopenssl but its arch/ABI matching is fragile;
        # portable C inside liboqs is the safe choice and matches what
        # we do for the other cross targets.
        use_openssl=0
        is_openwrt=1
        ;;
    *)
        echo "Unsupported LIBOQS_TARGET: ${LIBOQS_TARGET}" >&2
        exit 2
        ;;
esac

# Why use_openssl=0 for cross builds:
#
# When we cross-compile liboqs with -DOQS_USE_OPENSSL=ON, its CMake
# config picks up the HOST (amd64) OpenSSL headers from /usr/include/
# even though we're targeting another arch. The compile then fails:
#
#   /usr/include/openssl/macros.h:14: fatal error: openssl/opensslconf.h:
#   No such file or directory
#
# because `opensslconf.h` is arch-specific and lives under
# /usr/include/<triplet>/openssl/ in Debian/Ubuntu multiarch layout —
# but the version that exists at build time is the HOST triplet, not
# the target.
#
# We could instead install libssl-dev:<target> via dpkg --add-architecture
# and rebuild liboqs against the cross-arch OpenSSL. But:
#   - That requires multiarch setup before this script runs.
#   - The static liboqs.a we ship doesn't NEED OpenSSL — every PQ
#     primitive has a portable-C fallback inside liboqs itself; OpenSSL
#     is purely an optional hardware-accelerated backend for the
#     SHA-2 / SHA-3 / AES helpers that the PQ algorithms call.
#   - yume / yumed link against their own cross-arch OpenSSL anyway for
#     TLS; liboqs's internal helpers are separate.
#
# So for cross targets we ship liboqs.a built with portable C only —
# slightly slower SHA/AES inside liboqs but no real overall impact
# (PQ KEM is a few-microsecond operation; the SHA inside it isn't a
# hot loop). For the host build we keep OpenSSL on because the runner
# definitely has matching headers and the AES-NI / SHA-NI paths are
# free wins on amd64.

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

if [[ ! -f "${src_dir}/CMakeLists.txt" ]]; then
    # Cache the source tarball outside the per-target build dir so all
    # cross targets reuse a single download. Without this, the workflow
    # re-fetches the same tarball 4-5 times and a single transient
    # GitHub 5xx/rate-limit kills the entire matrix (we saw exit 8 from
    # wget on the armv8 leg even though armv7 had just succeeded).
    cache_dir="${LIBOQS_SRC_CACHE_DIR:-${TMPDIR:-/tmp}/liboqs-src-cache}"
    mkdir -p "${cache_dir}"
    tarball="${cache_dir}/liboqs-${LIBOQS_VERSION}.tar.gz"
    if [[ ! -s "${tarball}" ]]; then
        echo "Fetching liboqs ${LIBOQS_VERSION} source..."
        # --tries / --waitretry / --retry-connrefused make wget survive
        # transient errors; drop -q so HTTP failure reasons are visible
        # in the workflow log.
        wget --tries=5 --waitretry=10 --retry-connrefused \
            "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" \
            -O "${tarball}.part"
        mv -f "${tarball}.part" "${tarball}"
    else
        echo "Reusing cached liboqs ${LIBOQS_VERSION} tarball at ${tarball}"
    fi
    rm -rf "${src_dir}"
    mkdir -p "${src_dir}"
    tar -xzf "${tarball}" --strip-components=1 -C "${src_dir}"
fi

_use_openssl_flag="ON"
if [[ "${use_openssl:-1}" -eq 0 ]]; then
    _use_openssl_flag="OFF"
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
    -DOQS_USE_OPENSSL="${_use_openssl_flag}"
    -DCMAKE_INSTALL_LIBDIR=lib
)

if [[ "${permit_unsupported_arch:-0}" -eq 1 ]]; then
    cmake_args+=( -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON )
fi

if [[ -n "${toolchain_file:-}" ]]; then
    cmake_args+=( "-DCMAKE_TOOLCHAIN_FILE=${toolchain_file}" )
fi

# For cross targets, write a tiny toolchain file inline and pass it to
# CMake. The apt-installable GCC cross triplets (armv7/armv8/i386) use
# the prefix naming convention `${cross_prefix}-gcc`. The OpenWRT path
# uses the SDK's bundled musl toolchain at a fully-qualified path and
# additionally pins CMAKE_SYSROOT to the SDK's target dir so library
# / header lookups stay inside the sysroot.
if [[ "${is_openwrt:-0}" -eq 1 ]]; then
    tc="${LIBOQS_BUILD_DIR}/toolchain.cmake"
    cat > "${tc}" <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ${cmake_processor})
set(CMAKE_C_COMPILER ${openwrt_tc_dir}/bin/mips-openwrt-linux-musl-gcc)
set(CMAKE_CXX_COMPILER ${openwrt_tc_dir}/bin/mips-openwrt-linux-musl-g++)
set(CMAKE_SYSROOT ${openwrt_target_dir})
set(CMAKE_FIND_ROOT_PATH ${openwrt_target_dir};${openwrt_tc_dir})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
EOF
    cmake_args+=( "-DCMAKE_TOOLCHAIN_FILE=${tc}" )
elif [[ "${LIBOQS_TARGET}" != "host" ]]; then
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
