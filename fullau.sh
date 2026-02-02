#!/usr/bin/env bash
set -euo pipefail
if [[ "${YUME_VERBOSE:-0}" == "1" ]]; then
  export PS4='+${BASH_SOURCE}:${LINENO}: '
  set -x
fi

BIN_DIR="/home/f1xgod/bins"
OPENWRT_SDK="/home/f1xgod/openwrt-sdk-24.10.0-ath79-nand_gcc-13.3.0_musl.Linux-x86_64"
OPENWRT_SDK_VERSION="24.10.0"
OPENWRT_SDK_TARGET="ath79-nand"
OPENWRT_SDK_NAME="openwrt-sdk-${OPENWRT_SDK_VERSION}-${OPENWRT_SDK_TARGET}_gcc-13.3.0_musl.Linux-x86_64"
OPENWRT_SDK_URL="https://downloads.openwrt.org/releases/${OPENWRT_SDK_VERSION}/targets/ath79/nand/${OPENWRT_SDK_NAME}.tar.zst"
OPENWRT_SDK_PREFERRED="${HOME}/openwrt-sdk-${OPENWRT_SDK_VERSION}-${OPENWRT_SDK_TARGET}_gcc-13.3.0_musl.Linux-x86_64"
OPENWRT_SDK_USER_PREFERRED="${OPENWRT_SDK_PREFERRED}"
OPENWRT_SDK_CACHE_DIR="${HOME}/.cache/yume"
SYSROOT=""
TOOLCHAIN_BIN=""
TOOLCHAIN_STRIP=""
TOOLCHAIN_ROOT=""
OQS_SRC="/home/f1xgod/liboqs"
OQS_BUILD_MIPS="/tmp/liboqs-mips-build"
OQS_BUILD_HOST="/tmp/liboqs-host-build"
ARGON2_SRC="/home/f1xgod/argon2"
VENDOR_BUILDER="./scripts/build_vendor_libs.sh"
VENDOR_ARCHIVE="./yume-vendor-prebuilt.tar.xz"
VENDOR_DIR="./vendor"
export YUME_VENDOR_ONLY=1
OPENWRT_SDK_TEMP=0
OPENWRT_SDK_TEMP_DIR=""

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
USE_DOCKER_FALLBACK=0
AUTO_DETECT_TOOLCHAINS=1

resolve_real_home() {
  local home="${HOME}"
  if [[ -n "${SUDO_USER:-}" ]]; then
    local sudo_home
    sudo_home="$(getent passwd "${SUDO_USER}" 2>/dev/null | cut -d: -f6 || true)"
    if [[ -n "${sudo_home}" ]]; then
      home="${sudo_home}"
    fi
  fi
  echo "${home}"
}

REAL_HOME="$(resolve_real_home)"
OPENWRT_SDK_PREFERRED="${REAL_HOME}/openwrt-sdk-${OPENWRT_SDK_VERSION}-${OPENWRT_SDK_TARGET}_gcc-13.3.0_musl.Linux-x86_64"
OPENWRT_SDK_USER_PREFERRED="${OPENWRT_SDK_PREFERRED}"
OPENWRT_SDK_CACHE_DIR="${REAL_HOME}/.cache/yume"

mkdir -p "${BIN_DIR}"/{x86/{linux,busybox},mips/openwrt,armv7/{linux,busybox},armv8/{linux,busybox}}
rm -f "${BIN_DIR}/x86/linux/"* "${BIN_DIR}/x86/busybox/"* \
      "${BIN_DIR}/mips/openwrt/"* \
      "${BIN_DIR}/armv7/linux/"* "${BIN_DIR}/armv7/busybox/"* \
      "${BIN_DIR}/armv8/linux/"* "${BIN_DIR}/armv8/busybox/"* 2>/dev/null || true
rm -rf build basefwx/cpp/build

ensure_argon2_src() {
  if [ -d "${ARGON2_SRC}" ]; then
    return 0
  fi
  echo "Cloning argon2 sources to ${ARGON2_SRC}..."
  git clone --depth 1 https://github.com/P-H-C/phc-winner-argon2.git "${ARGON2_SRC}"
}

require_var() {
  local name="$1"
  local value="${!name:-}"
  if [[ -z "${value}" ]]; then
    echo "Missing required config: ${name}" >&2
    exit 1
  fi
}

auto_detect_toolchain() {
  local triplet="$1"
  local gcc_path
  gcc_path="$(command -v "${triplet}-gcc" 2>/dev/null || true)"
  if [[ -z "${gcc_path}" && -x "/usr/bin/${triplet}-gcc" ]]; then
    gcc_path="/usr/bin/${triplet}-gcc"
  fi
  if [[ -z "${gcc_path}" ]]; then
    return 1
  fi
  local prefix="${gcc_path%-gcc}"
  local sysroot
  sysroot="$("${gcc_path}" -print-sysroot 2>/dev/null || true)"
  if [[ -z "${sysroot}" || "${sysroot}" == "/" ]]; then
    if [[ -d "/usr/${triplet}" ]]; then
      sysroot="/usr/${triplet}"
    fi
  fi
  if [[ "${triplet}" == "i686-linux-gnu" ]]; then
    if [[ -d "/usr/i386-linux-gnu" && -f "/usr/i386-linux-gnu/lib/libc.so.6" ]]; then
      sysroot="/usr/i386-linux-gnu"
    fi
  fi
  if [[ -z "${sysroot}" ]]; then
    return 1
  fi
  echo "${prefix}|${sysroot}"
  return 0
}

auto_detect_toolchains() {
  if [[ ${AUTO_DETECT_TOOLCHAINS} -ne 1 ]]; then
    return 0
  fi
  local res=""
  if [[ -z "${X86_BUSYBOX_TOOLCHAIN_PREFIX}" || -z "${X86_BUSYBOX_SYSROOT}" ]]; then
    res="$(auto_detect_toolchain "i686-linux-gnu" || true)"
    if [[ -n "${res}" ]]; then
      X86_BUSYBOX_TOOLCHAIN_PREFIX="${res%%|*}"
      X86_BUSYBOX_SYSROOT="${res##*|}"
    fi
  fi
  if [[ -x "/usr/bin/i686-linux-gnu-gcc" ]]; then
    X86_BUSYBOX_TOOLCHAIN_PREFIX="/usr/bin/i686-linux-gnu"
    if [[ -f "/lib/i386-linux-gnu/libc.so.6" || -f "/usr/lib/i386-linux-gnu/libc.so.6" ]]; then
      X86_BUSYBOX_SYSROOT="/"
    elif [[ -d "/usr/i386-linux-gnu" ]]; then
      X86_BUSYBOX_SYSROOT="/usr/i386-linux-gnu"
    fi
  fi
  if [[ -z "${X86_BUSYBOX_TOOLCHAIN_PREFIX}" && -x "/usr/bin/i686-linux-gnu-gcc" ]]; then
    X86_BUSYBOX_TOOLCHAIN_PREFIX="/usr/bin/i686-linux-gnu"
  fi
  if [[ -z "${ARMV7_LINUX_TOOLCHAIN_PREFIX}" || -z "${ARMV7_LINUX_SYSROOT}" ]]; then
    res="$(auto_detect_toolchain "arm-linux-gnueabihf" || true)"
    if [[ -n "${res}" ]]; then
      ARMV7_LINUX_TOOLCHAIN_PREFIX="${res%%|*}"
      ARMV7_LINUX_SYSROOT="${res##*|}"
    fi
  fi
  if [[ -f "/lib/arm-linux-gnueabihf/libc.so.6" || -f "/usr/lib/arm-linux-gnueabihf/libc.so.6" ]]; then
    ARMV7_LINUX_SYSROOT="/"
  fi
  if [[ -z "${ARMV7_BUSYBOX_TOOLCHAIN_PREFIX}" || -z "${ARMV7_BUSYBOX_SYSROOT}" ]]; then
    if [[ -n "${ARMV7_LINUX_TOOLCHAIN_PREFIX}" && -n "${ARMV7_LINUX_SYSROOT}" ]]; then
      ARMV7_BUSYBOX_TOOLCHAIN_PREFIX="${ARMV7_LINUX_TOOLCHAIN_PREFIX}"
      ARMV7_BUSYBOX_SYSROOT="${ARMV7_LINUX_SYSROOT}"
    fi
  fi
  if [[ -z "${ARMV8_LINUX_TOOLCHAIN_PREFIX}" || -z "${ARMV8_LINUX_SYSROOT}" ]]; then
    res="$(auto_detect_toolchain "aarch64-linux-gnu" || true)"
    if [[ -n "${res}" ]]; then
      ARMV8_LINUX_TOOLCHAIN_PREFIX="${res%%|*}"
      ARMV8_LINUX_SYSROOT="${res##*|}"
    fi
  fi
  if [[ -f "/lib/aarch64-linux-gnu/libc.so.6" || -f "/usr/lib/aarch64-linux-gnu/libc.so.6" ]]; then
    ARMV8_LINUX_SYSROOT="/"
  fi
  if [[ -z "${ARMV8_BUSYBOX_TOOLCHAIN_PREFIX}" || -z "${ARMV8_BUSYBOX_SYSROOT}" ]]; then
    if [[ -n "${ARMV8_LINUX_TOOLCHAIN_PREFIX}" && -n "${ARMV8_LINUX_SYSROOT}" ]]; then
      ARMV8_BUSYBOX_TOOLCHAIN_PREFIX="${ARMV8_LINUX_TOOLCHAIN_PREFIX}"
      ARMV8_BUSYBOX_SYSROOT="${ARMV8_LINUX_SYSROOT}"
    fi
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

resolve_openwrt_sdk_root() {
  local candidate="$1"
  if [[ -d "${candidate}/staging_dir" ]]; then
    echo "${candidate}"
    return 0
  fi
  local nested
  nested="$(find "${candidate}" -maxdepth 2 -type d -name "${OPENWRT_SDK_NAME}" 2>/dev/null | head -n 1)"
  if [[ -n "${nested}" && -d "${nested}/staging_dir" ]]; then
    echo "${nested}"
    return 0
  fi
  return 1
}

ensure_openwrt_sdk() {
  local base_dir
  base_dir="$(dirname "${OPENWRT_SDK_PREFERRED}")"
  local sdk_dir="${OPENWRT_SDK_PREFERRED}"
  local candidate=""
  if [[ -n "${OPENWRT_SDK}" ]]; then
    candidate="${OPENWRT_SDK}"
  fi
  if [[ -z "${OPENWRT_SDK}" && -d "${OPENWRT_SDK_USER_PREFERRED}" ]]; then
    candidate="${OPENWRT_SDK_USER_PREFERRED}"
  fi
  if [[ -z "${candidate}" && -d "${OPENWRT_SDK_PREFERRED}" ]]; then
    candidate="${OPENWRT_SDK_PREFERRED}"
  fi
  if [[ -z "${candidate}" && -d "${sdk_dir}" ]]; then
    candidate="${sdk_dir}"
  fi
  if [[ -n "${candidate}" ]]; then
    OPENWRT_SDK="$(resolve_openwrt_sdk_root "${candidate}" || true)"
  fi
  if [[ -z "${OPENWRT_SDK}" ]]; then
    local temp_dir="${sdk_dir}"
    mkdir -p "${base_dir}"
    local archive="${OPENWRT_SDK_CACHE_DIR}/${OPENWRT_SDK_NAME}.tar.zst"
    mkdir -p "${OPENWRT_SDK_CACHE_DIR}"
    if [[ ! -s "${archive}" ]]; then
      fetch_url "${OPENWRT_SDK_URL}" "${archive}"
    fi
    if command -v zstd >/dev/null 2>&1; then
      tar -I zstd -xf "${archive}" -C "${base_dir}"
    elif command -v unzstd >/dev/null 2>&1; then
      unzstd -c "${archive}" | tar -xf - -C "${base_dir}"
    else
      echo "Missing zstd or unzstd for ${archive}" >&2
      exit 1
    fi
    if [[ ! -d "${temp_dir}" ]]; then
      echo "OpenWRT SDK extraction failed; expected ${temp_dir}" >&2
      exit 1
    fi
    OPENWRT_SDK="$(resolve_openwrt_sdk_root "${temp_dir}" || true)"
    if [[ -z "${OPENWRT_SDK}" ]]; then
      echo "OpenWRT SDK not resolved from ${temp_dir}" >&2
      exit 1
    fi
  fi
  echo "Using OpenWRT SDK: ${OPENWRT_SDK}"
  SYSROOT="${OPENWRT_SDK}/staging_dir/target-mips_24kc_musl"
  TOOLCHAIN_BIN="${OPENWRT_SDK}/staging_dir/toolchain-mips_24kc_gcc-13.3.0_musl/bin"
  TOOLCHAIN_ROOT="${OPENWRT_SDK}/staging_dir/toolchain-mips_24kc_gcc-13.3.0_musl"
  OPENWRT_USR="${SYSROOT}/usr"
  if [[ ! -d "${SYSROOT}/usr" ]]; then
    echo "OpenWRT sysroot not found at ${SYSROOT}" >&2
    exit 1
  fi
  if [[ ! -x "${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-gcc" ]]; then
    echo "OpenWRT toolchain not found at ${TOOLCHAIN_BIN}" >&2
    exit 1
  fi
  if [[ ! -x "${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-strip" ]]; then
    local alt_strip
    alt_strip="$(find "${TOOLCHAIN_BIN}" -maxdepth 1 -type f -name '*-strip' | head -n 1)"
    if [[ -n "${alt_strip}" ]]; then
      TOOLCHAIN_STRIP="${alt_strip}"
    elif command -v mipsel-linux-gnu-strip >/dev/null 2>&1; then
      TOOLCHAIN_STRIP="$(command -v mipsel-linux-gnu-strip)"
    else
      echo "OpenWRT strip not found at ${TOOLCHAIN_BIN}" >&2
      exit 1
    fi
  else
    TOOLCHAIN_STRIP="${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-strip"
  fi
}

cleanup_temp_assets() {
  vendor_cleanup
}

openwrt_find_package_makefile() {
  local pkg="$1"
  find "${OPENWRT_SDK}/package" "${OPENWRT_SDK}/feeds" -path "*/${pkg}/Makefile" 2>/dev/null | head -n 1
}

openwrt_build_package() {
  local pkg="$1"
  local makefile
  makefile="$(openwrt_find_package_makefile "${pkg}")"
  if [[ -z "${makefile}" && -x "${OPENWRT_SDK}/scripts/feeds" ]]; then
    (cd "${OPENWRT_SDK}" && ./scripts/feeds update packages >/dev/null)
    (cd "${OPENWRT_SDK}" && ./scripts/feeds install -a -p packages >/dev/null)
    makefile="$(openwrt_find_package_makefile "${pkg}")"
  fi
  if [[ -z "${makefile}" ]]; then
    echo "OpenWRT package ${pkg} not found in SDK" >&2
    exit 1
  fi
  local rel="${makefile#${OPENWRT_SDK}/}"
  rel="${rel%/Makefile}"
  make -C "${OPENWRT_SDK}" "${rel}/compile" V=s
}

ensure_openwrt_sysroot_libs() {
  local usr="${OPENWRT_USR}"
  if [[ -z "${usr}" || ! -d "${usr}" ]]; then
    return 1
  fi
  local has_crypto=0
  compgen -G "${usr}/lib/libcrypto.so."* >/dev/null 2>&1 && has_crypto=1
  if [[ ! -f "${usr}/lib/libcrypto.so" && ${has_crypto} -eq 0 ]]; then
    openwrt_build_package "openssl"
  fi
  local has_ssl=0
  compgen -G "${usr}/lib/libssl.so."* >/dev/null 2>&1 && has_ssl=1
  if [[ ! -f "${usr}/lib/libssl.so" && ${has_ssl} -eq 0 ]]; then
    openwrt_build_package "openssl"
  fi
  local has_zlib=0
  compgen -G "${usr}/lib/libz.so."* >/dev/null 2>&1 && has_zlib=1
  if [[ ! -f "${usr}/lib/libz.so" && ${has_zlib} -eq 0 ]]; then
    openwrt_build_package "zlib"
  fi
  local has_boost_system=0
  compgen -G "${usr}/lib/libboost_system.so."* >/dev/null 2>&1 && has_boost_system=1
  if [[ ! -f "${usr}/lib/libboost_system.so" && ${has_boost_system} -eq 0 ]]; then
    openwrt_build_package "boost"
  fi
  local has_boost_thread=0
  compgen -G "${usr}/lib/libboost_thread.so."* >/dev/null 2>&1 && has_boost_thread=1
  if [[ ! -f "${usr}/lib/libboost_thread.so" && ${has_boost_thread} -eq 0 ]]; then
    openwrt_build_package "boost"
  fi
  return 0
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
  DOCKCROSS_ARGS="-v ${BIN_DIR}:/bins" "${script_path}" bash -lc "
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

ensure_i386_deps() {
  if ! command -v dpkg >/dev/null 2>&1; then
    return 0
  fi
  if ! dpkg --print-foreign-architectures | grep -qx i386; then
    dpkg --add-architecture i386
    apt-get update || true
  fi
  apt-get install -y libc6-dev-i386 zlib1g-dev:i386 libssl-dev:i386 libboost-dev:i386 libboost-system-dev:i386 || true
}

ensure_armhf_deps() {
  if ! command -v dpkg >/dev/null 2>&1; then
    return 0
  fi
  if ! dpkg --print-foreign-architectures | grep -qx armhf; then
    dpkg --add-architecture armhf
    apt-get update || true
  fi
  apt-get install -y libc6-dev:armhf libstdc++-14-dev:armhf zlib1g-dev:armhf libssl-dev:armhf libboost-dev:armhf libboost-system-dev:armhf || true
}

ensure_arm64_deps() {
  if ! command -v dpkg >/dev/null 2>&1; then
    return 0
  fi
  if ! dpkg --print-foreign-architectures | grep -qx arm64; then
    dpkg --add-architecture arm64
    apt-get update || true
  fi
  apt-get install -y libc6-dev:arm64 libstdc++-14-dev:arm64 zlib1g-dev:arm64 libssl-dev:arm64 libboost-dev:arm64 libboost-system-dev:arm64 || true
}

resolve_boost_dir() {
  local arch_lib="$1"
  local cfg
  cfg="$(find "/usr/lib/${arch_lib}/cmake" -maxdepth 3 -name 'BoostConfig.cmake' -o -name 'boost-config.cmake' 2>/dev/null | head -n 1)"
  if [[ -n "${cfg}" ]]; then
    echo "$(dirname "${cfg}")"
  fi
}

build_busybox_target() {
  local label="$1"
  local cmake_arch="$2"
  local prefix="$3"
  local sysroot="$4"
  local outdir="$5"
  local toolchain_file="/tmp/yume-toolchain-busybox-${label}.cmake"
  if [[ -z "${prefix}" || -z "${sysroot}" ]]; then
    echo "Missing toolchain for ${label} busybox; set *_{BUSYBOX}_TOOLCHAIN_PREFIX and *_{BUSYBOX}_SYSROOT" >&2
    exit 1
  fi
  local boost_dir_env=""
  if [[ "${label}" == "x86" ]]; then
    ensure_i386_deps
    if [[ -f "/lib/i386-linux-gnu/libc.so.6" || -f "/usr/lib/i386-linux-gnu/libc.so.6" ]]; then
      sysroot="/"
    fi
    local boost_cfg
    boost_cfg="$(find /usr/lib/i386-linux-gnu/cmake -maxdepth 3 -name 'BoostConfig.cmake' -o -name 'boost-config.cmake' 2>/dev/null | head -n 1)"
    if [[ -z "${boost_cfg}" ]]; then
      echo "i386 BoostConfig.cmake not found. Install: dpkg --add-architecture i386; apt-get update; apt-get install -y libboost-dev:i386 libboost-system-dev:i386" >&2
      exit 1
    fi
    if [[ ! -f "/usr/lib/i386-linux-gnu/libz.so" ]]; then
      echo "i386 zlib dev not found. Install: apt-get install -y zlib1g-dev:i386" >&2
      exit 1
    fi
    if [[ ! -f "/usr/lib/i386-linux-gnu/libssl.so" || ! -f "/usr/lib/i386-linux-gnu/libcrypto.so" ]]; then
      echo "i386 OpenSSL dev not found. Install: apt-get install -y libssl-dev:i386" >&2
      exit 1
    fi
    boost_dir_env="Boost_DIR=$(dirname "${boost_cfg}")"
  elif [[ "${label}" == "armv7" ]]; then
    ensure_armhf_deps
    if [[ -f "/lib/arm-linux-gnueabihf/libc.so.6" || -f "/usr/lib/arm-linux-gnueabihf/libc.so.6" ]]; then
      sysroot="/"
    fi
    boost_dir_env="Boost_DIR=$(resolve_boost_dir arm-linux-gnueabihf)"
  elif [[ "${label}" == "armv8" ]]; then
    ensure_arm64_deps
    if [[ -f "/lib/aarch64-linux-gnu/libc.so.6" || -f "/usr/lib/aarch64-linux-gnu/libc.so.6" ]]; then
      sysroot="/"
    fi
    boost_dir_env="Boost_DIR=$(resolve_boost_dir aarch64-linux-gnu)"
  fi
  make_toolchain_file "${toolchain_file}" "${prefix}" "${sysroot}" "${cmake_arch}"
  if [[ "${label}" == "x86" ]]; then
    cat >> "${toolchain_file}" <<EOF
set(CMAKE_LIBRARY_ARCHITECTURE i386-linux-gnu)
EOF
  elif [[ "${label}" == "armv7" ]]; then
    cat >> "${toolchain_file}" <<EOF
set(CMAKE_LIBRARY_ARCHITECTURE arm-linux-gnueabihf)
EOF
  elif [[ "${label}" == "armv8" ]]; then
    cat >> "${toolchain_file}" <<EOF
set(CMAKE_LIBRARY_ARCHITECTURE aarch64-linux-gnu)
EOF
  fi
  require_vendor_dir "${VENDOR_DIR}/busybox-${label}"
  if [[ "${label}" == "x86" ]]; then
    local zlib_lib="/usr/lib/i386-linux-gnu/libz.so"
    local ssl_lib="/usr/lib/i386-linux-gnu/libssl.so"
    local crypto_lib="/usr/lib/i386-linux-gnu/libcrypto.so"
    local extra_args="-DZLIB_LIBRARY=${zlib_lib} -DZLIB_INCLUDE_DIR=/usr/include -DOPENSSL_SSL_LIBRARY=${ssl_lib} -DOPENSSL_CRYPTO_LIBRARY=${crypto_lib} -DOPENSSL_INCLUDE_DIR=/usr/include"
    if [[ -n "${boost_dir_env}" ]]; then
      extra_args="${extra_args} -D${boost_dir_env}"
      env ${boost_dir_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
    else
      env YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
    fi
  elif [[ "${label}" == "armv7" ]]; then
    local zlib_lib="/usr/lib/arm-linux-gnueabihf/libz.so"
    local ssl_lib="/usr/lib/arm-linux-gnueabihf/libssl.so"
    local crypto_lib="/usr/lib/arm-linux-gnueabihf/libcrypto.so"
    local extra_args="-DZLIB_LIBRARY=${zlib_lib} -DZLIB_INCLUDE_DIR=/usr/include -DOPENSSL_SSL_LIBRARY=${ssl_lib} -DOPENSSL_CRYPTO_LIBRARY=${crypto_lib} -DOPENSSL_INCLUDE_DIR=/usr/include"
    if [[ -n "${boost_dir_env}" ]]; then
      extra_args="${extra_args} -D${boost_dir_env}"
      env ${boost_dir_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
    else
      env YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
    fi
  elif [[ "${label}" == "armv8" ]]; then
    local zlib_lib="/usr/lib/aarch64-linux-gnu/libz.so"
    local ssl_lib="/usr/lib/aarch64-linux-gnu/libssl.so"
    local crypto_lib="/usr/lib/aarch64-linux-gnu/libcrypto.so"
    local extra_args="-DZLIB_LIBRARY=${zlib_lib} -DZLIB_INCLUDE_DIR=/usr/include -DOPENSSL_SSL_LIBRARY=${ssl_lib} -DOPENSSL_CRYPTO_LIBRARY=${crypto_lib} -DOPENSSL_INCLUDE_DIR=/usr/include"
    if [[ -n "${boost_dir_env}" ]]; then
      extra_args="${extra_args} -D${boost_dir_env}"
      env ${boost_dir_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
    else
      env YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
    fi
  elif [[ -n "${boost_dir_env}" ]]; then
    env ${boost_dir_env} YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
  else
    YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
  fi
  cp -f build/bin/yume "${outdir}/yume"
  cp -f build/bin/yumed "${outdir}/yumed"
  "${prefix}-strip" --strip-unneeded "${outdir}/yume" "${outdir}/yumed"
}

require_vendor_dir() {
  local dir="$1"
  if [[ ! -d "${dir}" ]]; then
    echo "Missing vendor directory: ${dir}. Build vendor libs first." >&2
    exit 1
  fi
}

build_linux_target() {
  local label="$1"
  local cmake_arch="$2"
  local prefix="$3"
  local sysroot="$4"
  local outdir="$5"
  local toolchain_file="/tmp/yume-toolchain-linux-${label}.cmake"
  if [[ -z "${prefix}" || -z "${sysroot}" ]]; then
    echo "Missing toolchain for ${label} linux; set *_{LINUX}_TOOLCHAIN_PREFIX and *_{LINUX}_SYSROOT" >&2
    exit 1
  fi
  local boost_dir_env=""
  if [[ "${label}" == "armv7" ]]; then
    ensure_armhf_deps
    if [[ -f "/lib/arm-linux-gnueabihf/libc.so.6" || -f "/usr/lib/arm-linux-gnueabihf/libc.so.6" ]]; then
      sysroot="/"
    fi
    boost_dir_env="Boost_DIR=$(resolve_boost_dir arm-linux-gnueabihf)"
  elif [[ "${label}" == "armv8" ]]; then
    ensure_arm64_deps
    if [[ -f "/lib/aarch64-linux-gnu/libc.so.6" || -f "/usr/lib/aarch64-linux-gnu/libc.so.6" ]]; then
      sysroot="/"
    fi
    boost_dir_env="Boost_DIR=$(resolve_boost_dir aarch64-linux-gnu)"
  fi
  make_toolchain_file "${toolchain_file}" "${prefix}" "${sysroot}" "${cmake_arch}"
  if [[ "${label}" == "armv7" ]]; then
    cat >> "${toolchain_file}" <<EOF
set(CMAKE_LIBRARY_ARCHITECTURE arm-linux-gnueabihf)
EOF
  elif [[ "${label}" == "armv8" ]]; then
    cat >> "${toolchain_file}" <<EOF
set(CMAKE_LIBRARY_ARCHITECTURE aarch64-linux-gnu)
EOF
  fi
  require_vendor_dir "${VENDOR_DIR}/${label}"
  if [[ "${label}" == "armv7" ]]; then
    local zlib_lib="/usr/lib/arm-linux-gnueabihf/libz.so"
    local ssl_lib="/usr/lib/arm-linux-gnueabihf/libssl.so"
    local crypto_lib="/usr/lib/arm-linux-gnueabihf/libcrypto.so"
    local extra_args="-DZLIB_LIBRARY=${zlib_lib} -DZLIB_INCLUDE_DIR=/usr/include -DOPENSSL_SSL_LIBRARY=${ssl_lib} -DOPENSSL_CRYPTO_LIBRARY=${crypto_lib} -DOPENSSL_INCLUDE_DIR=/usr/include"
    if [[ -n "${boost_dir_env}" ]]; then
      extra_args="${extra_args} -D${boost_dir_env}"
      env ${boost_dir_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
    else
      env YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
    fi
  elif [[ "${label}" == "armv8" ]]; then
    local zlib_lib="/usr/lib/aarch64-linux-gnu/libz.so"
    local ssl_lib="/usr/lib/aarch64-linux-gnu/libssl.so"
    local crypto_lib="/usr/lib/aarch64-linux-gnu/libcrypto.so"
    local extra_args="-DZLIB_LIBRARY=${zlib_lib} -DZLIB_INCLUDE_DIR=/usr/include -DOPENSSL_SSL_LIBRARY=${ssl_lib} -DOPENSSL_CRYPTO_LIBRARY=${crypto_lib} -DOPENSSL_INCLUDE_DIR=/usr/include"
    if [[ -n "${boost_dir_env}" ]]; then
      extra_args="${extra_args} -D${boost_dir_env}"
      env ${boost_dir_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
    else
      env YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
    fi
  elif [[ -n "${boost_dir_env}" ]]; then
    env ${boost_dir_env} YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
  else
    YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
  fi
  cp -f build/bin/yume "${outdir}/yume"
  cp -f build/bin/yumed "${outdir}/yumed"
  "${prefix}-strip" --strip-unneeded "${outdir}/yume" "${outdir}/yumed"
}

vendor_restore_if_missing
trap cleanup_temp_assets EXIT
auto_detect_toolchains
ensure_openwrt_sdk
ensure_openwrt_sysroot_libs
require_vendor_dir "${VENDOR_DIR}/openwrt-mips"
YUME_CLEAN_BAD_OQS=1 YUME_OQS_STATIC=1 ./ezbuild.sh --openwrt --openwrt-sdk "${OPENWRT_SDK}" --arch mips
cp -f build/bin/yume "${BIN_DIR}/mips/openwrt/yume"
cp -f build/bin/yumed "${BIN_DIR}/mips/openwrt/yumed"
if [[ -z "${TOOLCHAIN_STRIP}" ]]; then
  if command -v mipsel-linux-gnu-strip >/dev/null 2>&1; then
    TOOLCHAIN_STRIP="$(command -v mipsel-linux-gnu-strip)"
  else
    echo "OpenWRT strip tool not resolved; check toolchain in ${TOOLCHAIN_BIN}" >&2
    exit 1
  fi
fi
"${TOOLCHAIN_STRIP}" --strip-unneeded "${BIN_DIR}/mips/openwrt/yume" "${BIN_DIR}/mips/openwrt/yumed"

rm -rf build basefwx/cpp/build
require_vendor_dir "${VENDOR_DIR}/linux-x86_64"
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
elif [[ ${USE_DOCKER_FALLBACK} -eq 1 ]]; then
  docker_build_target "armv8" "aarch64" "dockcross/linux-arm64" "${BIN_DIR}/armv8/busybox" 1
else
  require_var ARMV8_BUSYBOX_SYSROOT
  require_var ARMV8_BUSYBOX_TOOLCHAIN_PREFIX
fi
