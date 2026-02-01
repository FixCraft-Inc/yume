#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="/home/user/bins"
OPENWRT_SDK=""
OPENWRT_SDK_VERSION="24.10.0"
OPENWRT_SDK_TARGET="ath79-nand"
OPENWRT_SDK_NAME="openwrt-sdk-${OPENWRT_SDK_VERSION}-${OPENWRT_SDK_TARGET}_gcc-13.3.0_musl.Linux-x86_64"
OPENWRT_SDK_URL="https://downloads.openwrt.org/releases/${OPENWRT_SDK_VERSION}/targets/ath79/nand/${OPENWRT_SDK_NAME}.tar.zst"
SYSROOT=""
TOOLCHAIN_BIN=""
TOOLCHAIN_ROOT=""
OQS_SRC="/home/user/liboqs"
OQS_BUILD_MIPS="/tmp/liboqs-mips-build"
OQS_BUILD_HOST="/tmp/liboqs-host-build"
ARGON2_SRC="/home/user/argon2"
VENDOR_BUILDER="./scripts/build_vendor_libs.sh"
VENDOR_ARCHIVE="./yume-vendor-prebuilt.tar.xz"
VENDOR_DIR="./vendor"

# Cross toolchains/sysroots for additional targets (set these before running).
X86_BUSYBOX_SYSROOT=""
X86_BUSYBOX_TOOLCHAIN_PREFIX=""

ARMV7_LINUX_SYSROOT=""
ARMV7_LINUX_TOOLCHAIN_PREFIX=""
ARMV7_BUSYBOX_SYSROOT=""
ARMV7_BUSYBOX_TOOLCHAIN_PREFIX=""

ARMV8_LINUX_SYSROOT=""
ARMV8_LINUX_TOOLCHAIN_PREFIX=""
ARMV8_BUSYBOX_SYSROOT=""
ARMV8_BUSYBOX_TOOLCHAIN_PREFIX=""
USE_DOCKER_FALLBACK=1

mkdir -p "${BIN_DIR}"/{x86/{linux,busybox},mips/openwrt,armv7/{linux,busybox},armv8/{linux,busybox}}
rm -f "${BIN_DIR}/x86/linux/"* "${BIN_DIR}/x86/busybox/"* \
      "${BIN_DIR}/mips/openwrt/"* \
      "${BIN_DIR}/armv7/linux/"* "${BIN_DIR}/armv7/busybox/"* \
      "${BIN_DIR}/armv8/linux/"* "${BIN_DIR}/armv8/busybox/"* 2>/dev/null || true
rm -rf build basefwx/cpp/build

build_liboqs_mips() {
  if [ ! -d "${OQS_SRC}" ]; then
    echo "liboqs source not found at ${OQS_SRC}" >&2
    exit 1
  fi
  if [ ! -d "${SYSROOT}/usr" ]; then
    echo "OpenWRT sysroot not found at ${SYSROOT}" >&2
    exit 1
  fi
  export STAGING_DIR="${OPENWRT_SDK}/staging_dir"
  rm -rf "${OQS_BUILD_MIPS}"
  mkdir -p "${OQS_BUILD_MIPS}"
  cmake -S "${OQS_SRC}" -B "${OQS_BUILD_MIPS}" \
    -DCMAKE_SYSTEM_NAME=Linux \
    -DCMAKE_SYSTEM_PROCESSOR=mips \
    -DCMAKE_C_COMPILER="${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-gcc" \
    -DCMAKE_CXX_COMPILER="${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-g++" \
    -DCMAKE_AR="${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-ar" \
    -DCMAKE_RANLIB="${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-ranlib" \
    -DCMAKE_STRIP="${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-strip" \
    -DCMAKE_SYSROOT="${SYSROOT}" \
    -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${TOOLCHAIN_ROOT}" \
    -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER \
    -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
    -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
    -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY \
    -DCMAKE_INSTALL_PREFIX="${SYSROOT}/usr" \
    -DCMAKE_PREFIX_PATH="${SYSROOT}/usr" \
    -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_BUILD_TESTS=OFF \
    -DOQS_BUILD_BENCHMARKS=OFF \
    -DOQS_BUILD_DEMOS=OFF \
    -DOQS_BUILD_EXAMPLES=OFF \
    -DOQS_USE_OPENSSL=OFF \
    -DOQS_BUILD_SHARED_LIBS=OFF \
    -DOQS_BUILD_STATIC_LIBS=ON \
    -DOQS_INSTALL_SHARED=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTING=OFF
  cmake --build "${OQS_BUILD_MIPS}" -j
  cmake --install "${OQS_BUILD_MIPS}"
}

build_liboqs_host() {
  if [ ! -d "${OQS_SRC}" ]; then
    echo "liboqs source not found at ${OQS_SRC}" >&2
    exit 1
  fi
  rm -rf "${OQS_BUILD_HOST}"
  mkdir -p "${OQS_BUILD_HOST}"
  cmake -S "${OQS_SRC}" -B "${OQS_BUILD_HOST}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_BUILD_TESTS=OFF \
    -DOQS_BUILD_BENCHMARKS=OFF \
    -DOQS_BUILD_DEMOS=OFF \
    -DOQS_BUILD_EXAMPLES=OFF \
    -DOQS_USE_OPENSSL=ON \
    -DOQS_BUILD_SHARED_LIBS=OFF \
    -DOQS_BUILD_STATIC_LIBS=ON \
    -DOQS_INSTALL_SHARED=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_TESTING=OFF
  cmake --build "${OQS_BUILD_HOST}" -j
  cmake --install "${OQS_BUILD_HOST}"
}

ensure_argon2_src() {
  if [ -d "${ARGON2_SRC}" ]; then
    return 0
  fi
  echo "Cloning argon2 sources to ${ARGON2_SRC}..."
  git clone --depth 1 https://github.com/P-H-C/phc-winner-argon2.git "${ARGON2_SRC}"
}

build_argon2_mips() {
  ensure_argon2_src
  echo "Building argon2 for MIPS..."
  make -C "${ARGON2_SRC}" clean || true
  local argon2_inc="${ARGON2_SRC}/include"
  make -C "${ARGON2_SRC}" \
    CC="${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-gcc" \
    AR="${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-ar" \
    RANLIB="${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-ranlib" \
    OPTTARGET=generic \
    LIBRARY_REL=lib \
    PKGCONFIG_REL=lib \
    BINARY_REL=bin \
    INCLUDE_REL=include \
    CFLAGS="--sysroot=${SYSROOT} -I${SYSROOT}/usr/include -I${argon2_inc}"
  make -C "${ARGON2_SRC}" install \
    DESTDIR="${SYSROOT}" \
    PREFIX=/usr \
    LIBRARY_REL=lib \
    PKGCONFIG_REL=lib \
    BINARY_REL=bin \
    INCLUDE_REL=include \
    CC="${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-gcc" \
    AR="${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-ar" \
    RANLIB="${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-ranlib" \
    OPTTARGET=generic \
    CFLAGS="--sysroot=${SYSROOT} -I${SYSROOT}/usr/include -I${argon2_inc}"
}

build_argon2_host() {
  ensure_argon2_src
  echo "Building argon2 for host..."
  make -C "${ARGON2_SRC}" clean || true
  make -C "${ARGON2_SRC}"
  make -C "${ARGON2_SRC}" install PREFIX=/usr
}

require_var() {
  local name="$1"
  local value="${!name:-}"
  if [[ -z "${value}" ]]; then
    echo "Missing required config: ${name}" >&2
    exit 1
  fi
}

fetch_url() {
  local url="$1"
  local out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -L --fail -o "${out}" "${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "${out}" "${url}"
  else
    echo "Missing downloader (curl or wget) for ${url}" >&2
    exit 1
  fi
}

ensure_openwrt_sdk() {
  local base_dir="${HOME}/toolchain-openwrt-sdk-${OPENWRT_SDK_VERSION}-${OPENWRT_SDK_TARGET}"
  local sdk_dir="${base_dir}/${OPENWRT_SDK_NAME}"
  if [[ -n "${OPENWRT_SDK}" && -d "${OPENWRT_SDK}" ]]; then
    return 0
  fi
  if [[ -d "${sdk_dir}" ]]; then
    OPENWRT_SDK="${sdk_dir}"
  else
    mkdir -p "${base_dir}"
    local archive="/tmp/${OPENWRT_SDK_NAME}.tar.zst"
    fetch_url "${OPENWRT_SDK_URL}" "${archive}"
    if command -v zstd >/dev/null 2>&1; then
      tar -I zstd -xf "${archive}" -C "${base_dir}"
    elif command -v unzstd >/dev/null 2>&1; then
      unzstd -c "${archive}" | tar -xf - -C "${base_dir}"
    else
      echo "Missing zstd or unzstd for ${archive}" >&2
      exit 1
    fi
    if [[ ! -d "${sdk_dir}" ]]; then
      echo "OpenWRT SDK extraction failed; expected ${sdk_dir}" >&2
      exit 1
    fi
    OPENWRT_SDK="${sdk_dir}"
  fi
  SYSROOT="${OPENWRT_SDK}/staging_dir/target-mips_24kc_musl"
  TOOLCHAIN_BIN="${OPENWRT_SDK}/staging_dir/toolchain-mips_24kc_gcc-13.3.0_musl/bin"
  TOOLCHAIN_ROOT="${OPENWRT_SDK}/staging_dir/toolchain-mips_24kc_gcc-13.3.0_musl"
  if [[ ! -d "${SYSROOT}/usr" ]]; then
    echo "OpenWRT sysroot not found at ${SYSROOT}" >&2
    exit 1
  fi
}

ensure_dockcross() {
  local image="$1"
  local script_path="$2"
  if [[ -x "${script_path}" ]]; then
    return 0
  fi
  docker run --rm "${image}" > "${script_path}"
  chmod +x "${script_path}"
}

vendor_cleanup() {
  if [[ "${VENDOR_TEMP_CREATED:-0}" -eq 1 ]]; then
    rm -rf "${VENDOR_DIR}"
  fi
}

vendor_restore_if_missing() {
  if [[ ! -d "${VENDOR_DIR}" ]]; then
    if [[ -f "${VENDOR_ARCHIVE}" ]]; then
      tar -xJf "${VENDOR_ARCHIVE}"
      VENDOR_TEMP_CREATED=1
    fi
  fi
}

docker_build_target() {
  local label="$1"
  local cmake_arch="$2"
  local image="$3"
  local outdir="$4"
  local busybox_flag="${5:-0}"
  local script_path="/tmp/dockcross-${label}"
  ensure_dockcross "${image}" "${script_path}"
  DOCKER_ARGS="-v ${BIN_DIR}:/bins" "${script_path}" bash -lc "
    set -euo pipefail
    cd /work
    SYSROOT=\"\$(\${CROSS_TRIPLE}-gcc -print-sysroot)\"
    if [[ ${busybox_flag} -eq 1 ]]; then
      ./scripts/build_vendor_libs.sh --target \"busybox-${label}\" --toolchain-prefix \"\${CROSS_TRIPLE}\" --sysroot \"\${SYSROOT}\"
    else
      ./scripts/build_vendor_libs.sh --target \"${label}\" --toolchain-prefix \"\${CROSS_TRIPLE}\" --sysroot \"\${SYSROOT}\"
    fi
    cat > /tmp/yume-toolchain.cmake <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ${cmake_arch})
set(CMAKE_C_COMPILER \${CROSS_TRIPLE}-gcc)
set(CMAKE_CXX_COMPILER \${CROSS_TRIPLE}-g++)
set(CMAKE_AR \${CROSS_TRIPLE}-ar)
set(CMAKE_RANLIB \${CROSS_TRIPLE}-ranlib)
set(CMAKE_STRIP \${CROSS_TRIPLE}-strip)
set(CMAKE_SYSROOT \${SYSROOT})
set(CMAKE_FIND_ROOT_PATH \${SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
EOF
    if [[ ${busybox_flag} -eq 1 ]]; then
      YUME_TOOLCHAIN_FILE=/tmp/yume-toolchain.cmake ./ezbuild.sh --busybox --arch \"${label}\"
    else
      YUME_TOOLCHAIN_FILE=/tmp/yume-toolchain.cmake ./ezbuild.sh --arch \"${label}\"
    fi
    cp -f build/bin/yume \"${outdir}/yume\"
    cp -f build/bin/yumed \"${outdir}/yumed\"
    \${CROSS_TRIPLE}-strip --strip-unneeded \"${outdir}/yume\" \"${outdir}/yumed\"
  "
}

make_toolchain_file() {
  local out="$1"
  local prefix="$2"
  local sysroot="$3"
  local arch="$4"
  cat > "${out}" <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ${arch})
set(CMAKE_C_COMPILER ${prefix}-gcc)
set(CMAKE_CXX_COMPILER ${prefix}-g++)
set(CMAKE_AR ${prefix}-ar)
set(CMAKE_RANLIB ${prefix}-ranlib)
set(CMAKE_STRIP ${prefix}-strip)
set(CMAKE_SYSROOT ${sysroot})
set(CMAKE_FIND_ROOT_PATH ${sysroot})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
EOF
}

build_busybox_target() {
  local label="$1"
  local cmake_arch="$2"
  local prefix="$3"
  local sysroot="$4"
  local outdir="$5"
  local toolchain_file="/tmp/yume-toolchain-busybox-${label}.cmake"
  make_toolchain_file "${toolchain_file}" "${prefix}" "${sysroot}" "${cmake_arch}"
  if [[ -x "${VENDOR_BUILDER}" ]]; then
    "${VENDOR_BUILDER}" --target "busybox-${label}" --toolchain-prefix "${prefix}" --sysroot "${sysroot}"
  fi
  YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
  cp -f build/bin/yume "${outdir}/yume"
  cp -f build/bin/yumed "${outdir}/yumed"
  "${prefix}-strip" --strip-unneeded "${outdir}/yume" "${outdir}/yumed"
}

build_linux_target() {
  local label="$1"
  local cmake_arch="$2"
  local prefix="$3"
  local sysroot="$4"
  local outdir="$5"
  local toolchain_file="/tmp/yume-toolchain-linux-${label}.cmake"
  make_toolchain_file "${toolchain_file}" "${prefix}" "${sysroot}" "${cmake_arch}"
  if [[ -x "${VENDOR_BUILDER}" ]]; then
    "${VENDOR_BUILDER}" --target "${label}" --toolchain-prefix "${prefix}" --sysroot "${sysroot}"
  fi
  YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
  cp -f build/bin/yume "${outdir}/yume"
  cp -f build/bin/yumed "${outdir}/yumed"
  "${prefix}-strip" --strip-unneeded "${outdir}/yume" "${outdir}/yumed"
}

vendor_restore_if_missing
ensure_openwrt_sdk
build_liboqs_mips

build_argon2_mips
if [[ -x "${VENDOR_BUILDER}" ]]; then
  "${VENDOR_BUILDER}" --target openwrt-mips --openwrt-sdk "${OPENWRT_SDK}"
fi
YUME_CLEAN_BAD_OQS=1 YUME_OQS_STATIC=1 ./ezbuild.sh --openwrt --openwrt-sdk "${OPENWRT_SDK}" --arch mips
cp -f build/bin/yume "${BIN_DIR}/mips/openwrt/yume"
cp -f build/bin/yumed "${BIN_DIR}/mips/openwrt/yumed"
"${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-strip" --strip-unneeded "${BIN_DIR}/mips/openwrt/yume" "${BIN_DIR}/mips/openwrt/yumed"

rm -rf build basefwx/cpp/build
build_liboqs_host
build_argon2_host
if [[ -x "${VENDOR_BUILDER}" ]]; then
  "${VENDOR_BUILDER}" --target host
fi
YUME_OQS_STATIC=1 ./ezbuild.sh
cp -f build/bin/yume "${BIN_DIR}/x86/linux/yume"
cp -f build/bin/yumed "${BIN_DIR}/x86/linux/yumed"
strip "${BIN_DIR}/x86/linux/yume" "${BIN_DIR}/x86/linux/yumed"

# Busybox x86
rm -rf build basefwx/cpp/build
if [[ -n "${X86_BUSYBOX_SYSROOT}" && -n "${X86_BUSYBOX_TOOLCHAIN_PREFIX}" ]]; then
build_busybox_target "x86" "i686" "${X86_BUSYBOX_TOOLCHAIN_PREFIX}" "${X86_BUSYBOX_SYSROOT}" "${BIN_DIR}/x86/busybox"
elif [[ ${USE_DOCKER_FALLBACK} -eq 1 ]]; then
  docker_build_target "x86" "i686" "dockcross/linux-x86" "${BIN_DIR}/x86/busybox" 1
else
  require_var X86_BUSYBOX_SYSROOT
  require_var X86_BUSYBOX_TOOLCHAIN_PREFIX
fi

# ARMv7
rm -rf build basefwx/cpp/build
if [[ -n "${ARMV7_LINUX_SYSROOT}" && -n "${ARMV7_LINUX_TOOLCHAIN_PREFIX}" ]]; then
build_linux_target "armv7" "armv7" "${ARMV7_LINUX_TOOLCHAIN_PREFIX}" "${ARMV7_LINUX_SYSROOT}" "${BIN_DIR}/armv7/linux"
elif [[ ${USE_DOCKER_FALLBACK} -eq 1 ]]; then
  docker_build_target "armv7" "armv7" "dockcross/linux-armv7" "${BIN_DIR}/armv7/linux" 0
else
  require_var ARMV7_LINUX_SYSROOT
  require_var ARMV7_LINUX_TOOLCHAIN_PREFIX
fi

rm -rf build basefwx/cpp/build
if [[ -n "${ARMV7_BUSYBOX_SYSROOT}" && -n "${ARMV7_BUSYBOX_TOOLCHAIN_PREFIX}" ]]; then
build_busybox_target "armv7" "armv7" "${ARMV7_BUSYBOX_TOOLCHAIN_PREFIX}" "${ARMV7_BUSYBOX_SYSROOT}" "${BIN_DIR}/armv7/busybox"
elif [[ ${USE_DOCKER_FALLBACK} -eq 1 ]]; then
  docker_build_target "armv7" "armv7" "dockcross/linux-armv7" "${BIN_DIR}/armv7/busybox" 1
else
  require_var ARMV7_BUSYBOX_SYSROOT
  require_var ARMV7_BUSYBOX_TOOLCHAIN_PREFIX
fi

# ARMv8 (aarch64)
rm -rf build basefwx/cpp/build
if [[ -n "${ARMV8_LINUX_SYSROOT}" && -n "${ARMV8_LINUX_TOOLCHAIN_PREFIX}" ]]; then
build_linux_target "armv8" "aarch64" "${ARMV8_LINUX_TOOLCHAIN_PREFIX}" "${ARMV8_LINUX_SYSROOT}" "${BIN_DIR}/armv8/linux"
elif [[ ${USE_DOCKER_FALLBACK} -eq 1 ]]; then
  docker_build_target "armv8" "aarch64" "dockcross/linux-arm64" "${BIN_DIR}/armv8/linux" 0
else
  require_var ARMV8_LINUX_SYSROOT
  require_var ARMV8_LINUX_TOOLCHAIN_PREFIX
fi

rm -rf build basefwx/cpp/build
if [[ -n "${ARMV8_BUSYBOX_SYSROOT}" && -n "${ARMV8_BUSYBOX_TOOLCHAIN_PREFIX}" ]]; then
build_busybox_target "armv8" "aarch64" "${ARMV8_BUSYBOX_TOOLCHAIN_PREFIX}" "${ARMV8_BUSYBOX_SYSROOT}" "${BIN_DIR}/armv8/busybox"

vendor_cleanup
elif [[ ${USE_DOCKER_FALLBACK} -eq 1 ]]; then
  docker_build_target "armv8" "aarch64" "dockcross/linux-arm64" "${BIN_DIR}/armv8/busybox" 1
else
  require_var ARMV8_BUSYBOX_SYSROOT
  require_var ARMV8_BUSYBOX_TOOLCHAIN_PREFIX
fi
