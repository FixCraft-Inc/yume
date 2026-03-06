#!/usr/bin/env bash
set -euo pipefail
if [[ "${YUME_VERBOSE:-0}" == "1" ]]; then
  export PS4='+${BASH_SOURCE}:${LINENO}: '
  set -x
fi

BIN_DIR=""
BIN_DYNAMIC=""
BIN_STATIC=""
BIN_STABLE=""
# OPENWRT_SDK can be set externally; if empty, script will use OPENWRT_SDK_PREFERRED or download
OPENWRT_SDK="${OPENWRT_SDK:-}"
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
OQS_SRC="${OQS_SRC:-${HOME}/liboqs}"
OQS_BUILD_MIPS="/tmp/liboqs-mips-build"
OQS_BUILD_HOST="/tmp/liboqs-host-build"
ARGON2_SRC="${ARGON2_SRC:-${HOME}/argon2}"
VENDOR_BUILDER="./scripts/build_vendor_libs.sh"
VENDOR_ARCHIVE="./yume-vendor-prebuilt.tar.xz"
VENDOR_DIR="./vendor"
export YUME_VENDOR_ONLY=1
OPENWRT_SDK_TEMP=0
OPENWRT_SDK_TEMP_DIR=""

# Cross toolchains/sysroots for additional targets (set these before running).
X86_BUSYBOX_SYSROOT="${X86_BUSYBOX_SYSROOT:-}"
X86_BUSYBOX_TOOLCHAIN_PREFIX="${X86_BUSYBOX_TOOLCHAIN_PREFIX:-}"

ARMV7_LINUX_SYSROOT="${ARMV7_LINUX_SYSROOT:-}"
ARMV7_LINUX_TOOLCHAIN_PREFIX="${ARMV7_LINUX_TOOLCHAIN_PREFIX:-}"
ARMV7_BUSYBOX_SYSROOT="${ARMV7_BUSYBOX_SYSROOT:-}"
ARMV7_BUSYBOX_TOOLCHAIN_PREFIX="${ARMV7_BUSYBOX_TOOLCHAIN_PREFIX:-}"

ARMV8_LINUX_SYSROOT="${ARMV8_LINUX_SYSROOT:-}"
ARMV8_LINUX_TOOLCHAIN_PREFIX="${ARMV8_LINUX_TOOLCHAIN_PREFIX:-}"
ARMV8_BUSYBOX_SYSROOT="${ARMV8_BUSYBOX_SYSROOT:-}"
ARMV8_BUSYBOX_TOOLCHAIN_PREFIX="${ARMV8_BUSYBOX_TOOLCHAIN_PREFIX:-}"
USE_DOCKER_FALLBACK="${USE_DOCKER_FALLBACK:-0}"
AUTO_DETECT_TOOLCHAINS="${AUTO_DETECT_TOOLCHAINS:-1}"
OPENWRT_FEEDS_READY=0
OPENWRT_FAST_MODE="${YUME_OPENWRT_FAST:-0}"
OPENWRT_TARGET_READY=1

# Helper function to normalize cross-build flags (0 or 1)
normalize_cross_flag() {
  local flag_value="$1"
  if [[ -z "${flag_value}" || "${flag_value}" != "0" && "${flag_value}" != "1" ]]; then
    echo "0|1"  # value|auto_detect
  else
    echo "${flag_value}|0"
  fi
}

IFS='|' read -r WINDOWS_CROSS WINDOWS_CROSS_AUTO <<< "$(normalize_cross_flag "${YUME_WINDOWS_CROSS:-}")"
WINDOWS_TOOLCHAIN_PREFIX="${YUME_WINDOWS_TOOLCHAIN_PREFIX:-x86_64-w64-mingw32}"
WINDOWS_TRIPLET="${YUME_WINDOWS_TRIPLET:-x64-mingw-dynamic}"
WINDOWS_VCPKG_PACKAGES="${YUME_WINDOWS_VCPKG_PACKAGES:-openssl boost-cmake boost-headers boost-system boost-asio zlib zstd liblzma nlohmann-json argon2 liboqs}"

IFS='|' read -r MACOS_CROSS MACOS_CROSS_AUTO <<< "$(normalize_cross_flag "${YUME_MACOS_CROSS:-}")"
MACOS_TOOLCHAIN_PREFIX="${YUME_MACOS_TOOLCHAIN_PREFIX:-}"
MACOS_TRIPLET="${YUME_MACOS_TRIPLET:-x64-osx}"
MACOS_VCPKG_PACKAGES="${YUME_MACOS_VCPKG_PACKAGES:-openssl boost-cmake boost-headers boost-system zlib zstd liblzma fmt spdlog argon2 liboqs}"
MACOS_SDK="${YUME_MACOS_SDK:-${OSXCROSS_SDK:-}}"
MACOS_DEPLOYMENT_TARGET="${YUME_MACOS_DEPLOYMENT_TARGET:-10.15}"
APT_UPDATED_FLAG="${APT_UPDATED_FLAG:-/tmp/yume-apt-updated}"

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

apt_update_once() {
  local force_update="${1:-0}"
  if ! command -v apt-get >/dev/null 2>&1; then
    return 0
  fi
  if [[ "${force_update}" != "1" && -f "${APT_UPDATED_FLAG}" ]]; then
    return 0
  fi
  apt-get update || true
  touch "${APT_UPDATED_FLAG}" || true
}

apt_install() {
  apt_update_once
  apt-get install -y "$@" || true
}
detect_vcpkg_root() {
  if [[ -n "${VCPKG_ROOT:-}" && -x "${VCPKG_ROOT}/vcpkg" ]]; then
    echo "${VCPKG_ROOT}"
    return 0
  fi
  local bin
  bin="$(command -v vcpkg 2>/dev/null || true)"
  if [[ -n "${bin}" ]]; then
    local root
    root="$(cd "$(dirname "${bin}")" && pwd)"
    if [[ -f "${root}/scripts/buildsystems/vcpkg.cmake" ]]; then
      echo "${root}"
      return 0
    fi
  fi
  local candidate
  for candidate in "${REAL_HOME}/vcpkg" "${REAL_HOME}/.vcpkg"; do
    if [[ -x "${candidate}/vcpkg" && -f "${candidate}/scripts/buildsystems/vcpkg.cmake" ]]; then
      echo "${candidate}"
      return 0
    fi
  done
  return 1
}
if [[ -z "${VCPKG_ROOT:-}" ]]; then
  VCPKG_ROOT="$(detect_vcpkg_root || true)"
fi

ensure_vcpkg() {
  if [[ -n "${VCPKG_ROOT:-}" && -x "${VCPKG_ROOT}/vcpkg" ]]; then
    return 0
  fi
  if ! target_enabled windows-x86_64 && ! target_enabled macos-x86_64 && ! target_enabled macos-arm64; then
    return 0
  fi
  VCPKG_ROOT="${REAL_HOME}/vcpkg"
  if [[ -x "${VCPKG_ROOT}/vcpkg" ]]; then
    return 0
  fi
  echo "Cloning vcpkg into ${VCPKG_ROOT}..."
  git clone --depth 1 https://github.com/microsoft/vcpkg.git "${VCPKG_ROOT}"
  "${VCPKG_ROOT}/bootstrap-vcpkg.sh" -disableMetrics
}

patch_vcpkg_boost_ports() {
  local vcpkg_root="$1"
  local boost_install="${vcpkg_root}/ports/vcpkg-boost/boost-install.cmake"
  local include_line=""
  local include_block=""
  if [[ -z "${vcpkg_root}" || ! -f "${boost_install}" ]]; then
    return 0
  fi
  include_line="include(\"${boost_install}\")"
  include_block="# yume-boost-install-patch
if(NOT COMMAND vcpkg_cmake_configure)
  include(\"${vcpkg_root}/ports/vcpkg-cmake/vcpkg_cmake_configure.cmake\")
endif()
if(NOT COMMAND vcpkg_cmake_install)
  include(\"${vcpkg_root}/ports/vcpkg-cmake/vcpkg_cmake_install.cmake\")
endif()
if(NOT COMMAND vcpkg_cmake_config_fixup)
  include(\"${vcpkg_root}/ports/vcpkg-cmake-config/vcpkg_cmake_config_fixup.cmake\")
endif()
"
  if ! grep -q "yume-boost-install-patch" "${boost_install}"; then
    local tmp
    tmp="$(mktemp)"
    {
      IFS= read -r first_line || true
      if [[ -n "${first_line}" ]]; then
        echo "${first_line}"
      fi
      printf "%s" "${include_block}"
      cat
    } < "${boost_install}" > "${tmp}"
    mv "${tmp}" "${boost_install}"
  fi
  local vcpkg_cmake="${vcpkg_root}/ports/vcpkg-cmake/vcpkg_cmake_configure.cmake"
  if [[ -f "${vcpkg_cmake}" ]] && ! grep -q "yume-disable-parallel-configure" "${vcpkg_cmake}"; then
    local tmp
    tmp="$(mktemp)"
    awk '
      {
        print
        if (!inserted) {
          if (index($0, "cmake_parse_arguments(PARSE_ARGV") > 0) {
            in_parse = 1
          } else if (in_parse && $0 ~ /^\\s*\\)\\s*$/) {
            print "    # yume-disable-parallel-configure"
            print "    if(DEFINED ENV{VCPKG_DISABLE_PARALLEL_CONFIGURE} AND NOT \"\\$ENV{VCPKG_DISABLE_PARALLEL_CONFIGURE}\" STREQUAL \"0\")"
            print "        set(arg_DISABLE_PARALLEL_CONFIGURE ON)"
            print "    endif()"
            inserted = 1
            in_parse = 0
          }
        }
      }
    ' "${vcpkg_cmake}" > "${tmp}"
    mv "${tmp}" "${vcpkg_cmake}"
  fi
  local portfile
  for portfile in "${vcpkg_root}"/ports/boost-*/portfile.cmake; do
    [[ -f "${portfile}" ]] || continue
    if grep -q "boost_configure_and_install" "${portfile}" && ! grep -q "boost-install.cmake" "${portfile}"; then
      local tmp
      tmp="$(mktemp)"
      {
        echo "# Patched by yume build scripts"
        echo "${include_line}"
        cat "${portfile}"
      } > "${tmp}"
      mv "${tmp}" "${portfile}"
    fi
  done
}
detect_osxcross_root() {
  if [[ -n "${OSXCROSS_ROOT:-}" && -d "${OSXCROSS_ROOT}" ]]; then
    echo "${OSXCROSS_ROOT}"
    return 0
  fi
  local candidate
  for candidate in "${REAL_HOME}/osxcross" "/opt/osxcross"; do
    if [[ -d "${candidate}" && -d "${candidate}/tarballs" ]]; then
      echo "${candidate}"
      return 0
    fi
  done
  return 1
}
if [[ -z "${OSXCROSS_ROOT:-}" ]]; then
  OSXCROSS_ROOT="$(detect_osxcross_root || true)"
fi

ensure_macos_sdk_tarball() {
  local sdk_src="${REAL_HOME}/macos-sdk"
  local tarballs="${OSXCROSS_ROOT}/tarballs"
  mkdir -p "${tarballs}"
  if ls "${tarballs}/MacOSX"*.sdk.tar.* >/dev/null 2>&1; then
    return 0
  fi
  if [[ -d "${sdk_src}" ]]; then
    local sdk_dir
    sdk_dir="$(ls -d "${sdk_src}/MacOSX"*.sdk 2>/dev/null | sort -V | tail -n 1 || true)"
    if [[ -n "${sdk_dir}" ]]; then
      local sdk_name
      sdk_name="$(basename "${sdk_dir}")"
      tar -cJf "${tarballs}/${sdk_name}.tar.xz" -C "${sdk_src}" "${sdk_name}"
      return 0
    fi
    local sdk_tar
    sdk_tar="$(ls "${sdk_src}/MacOSX"*.sdk.tar.* 2>/dev/null | sort -V | tail -n 1 || true)"
    if [[ -n "${sdk_tar}" ]]; then
      cp -f "${sdk_tar}" "${tarballs}/"
      return 0
    fi
  fi
  echo "macOS SDK not found in ${sdk_src}; place MacOSX*.sdk or MacOSX*.sdk.tar.xz there." >&2
  return 1
}

ensure_osxcross() {
  if ! target_enabled macos-x86_64 && ! target_enabled macos-arm64; then
    return 0
  fi
  if [[ -n "${OSXCROSS_ROOT:-}" && -d "${OSXCROSS_ROOT}" ]]; then
    :
  else
    OSXCROSS_ROOT="${REAL_HOME}/osxcross"
    if [[ ! -d "${OSXCROSS_ROOT}" ]]; then
      echo "Cloning osxcross into ${OSXCROSS_ROOT}..."
      git clone --depth 1 https://github.com/tpoechtrager/osxcross.git "${OSXCROSS_ROOT}"
    fi
  fi
  if ! ensure_macos_sdk_tarball; then
    echo "osxcross requires a macOS SDK tarball; see README for details." >&2
    exit 1
  fi
  if [[ ! -d "${OSXCROSS_ROOT}/target/bin" ]]; then
    (cd "${OSXCROSS_ROOT}" && UNATTENDED=1 ./build.sh)
  fi
}
if [[ -z "${MACOS_SDK}" && -n "${OSXCROSS_ROOT:-}" ]]; then
  mac_sdk_auto="$(ls -d "${OSXCROSS_ROOT}/target/SDK/MacOSX"*.sdk 2>/dev/null | sort -V | tail -n 1 || true)"
  if [[ -n "${mac_sdk_auto}" ]]; then
    MACOS_SDK="${mac_sdk_auto}"
  fi
fi
OPENWRT_SDK_PREFERRED="${REAL_HOME}/openwrt-sdk-${OPENWRT_SDK_VERSION}-${OPENWRT_SDK_TARGET}_gcc-13.3.0_musl.Linux-x86_64"
OPENWRT_SDK_USER_PREFERRED="${OPENWRT_SDK_PREFERRED}"
OPENWRT_SDK_CACHE_DIR="${REAL_HOME}/.cache/yume"
BIN_DIR="${REAL_HOME}/bins"
BIN_DYNAMIC="${BIN_DIR}/dynamic"
BIN_STABLE="${BIN_DIR}/stable"
BIN_STATIC="${BIN_STABLE}"
HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"
case "${HOST_ARCH}" in
  x86_64|amd64) HOST_ARCH="x86_64" ;;
  i386|i686) HOST_ARCH="x86" ;;
  aarch64|arm64) HOST_ARCH="arm64" ;;
esac
TARGETS_RAW="${YUME_TARGETS:-all}"
TARGETS_RAW="${TARGETS_RAW// /}"

target_enabled() {
  local target="$1"
  if [[ "${TARGETS_RAW}" == "all" || -z "${TARGETS_RAW}" ]]; then
    return 0
  fi
  local list=",${TARGETS_RAW// /,},"
  case "${target}" in
    openwrt-mips)
      [[ "${list}" == *",openwrt,"* || "${list}" == *",openwrt-mips,"* ]]
      ;;
    linux-x86_64)
      [[ "${list}" == *",linux,"* || "${list}" == *",linux-x86_64,"* || "${list}" == *",host-linux,"* ]]
      ;;
    windows-x86_64)
      [[ "${list}" == *",windows,"* || "${list}" == *",windows-x86_64,"* ]]
      ;;
    macos-x86_64)
      [[ "${list}" == *",macos,"* || "${list}" == *",macos-x86_64,"* || "${list}" == *",macos-x64,"* ]]
      ;;
    macos-arm64)
      [[ "${list}" == *",macos,"* || "${list}" == *",macos-arm64,"* ]]
      ;;
    busybox-x86)
      [[ "${list}" == *",busybox,"* || "${list}" == *",busybox-x86,"* ]]
      ;;
    armv7-linux)
      [[ "${list}" == *",armv7,"* || "${list}" == *",armv7-linux,"* ]]
      ;;
    armv7-busybox)
      [[ "${list}" == *",armv7,"* || "${list}" == *",armv7-busybox,"* ]]
      ;;
    armv8-linux)
      [[ "${list}" == *",armv8,"* || "${list}" == *",armv8-linux,"* || "${list}" == *",aarch64,"* ]]
      ;;
    armv8-busybox)
      [[ "${list}" == *",armv8,"* || "${list}" == *",armv8-busybox,"* || "${list}" == *",aarch64,"* ]]
      ;;
    *)
      return 1
      ;;
  esac
}

CLEAN_BINS="${YUME_CLEAN_BINS:-1}"
if [[ "${CLEAN_BINS}" == "1" && -d "${BIN_DIR}" ]]; then
  if [[ "${BIN_DIR}" == "${REAL_HOME}/bins" ]]; then
    rm -rf "${BIN_DIR}"
  else
    echo "Refusing to delete unexpected BIN_DIR: ${BIN_DIR}" >&2
    exit 1
  fi
fi
mkdir -p "${BIN_DIR}"
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

variant_cmake_args() {
  local variant="$1"
  if [[ "${variant}" == "static" ]]; then
    echo "-DYUME_STATIC=ON"
  else
    echo "-DYUME_STATIC=OFF"
  fi
}

is_truthy() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

static_libs_ok() {
  local label="$1"
  shift
  local missing=()
  local lib
  for lib in "$@"; do
    if [[ ! -f "${lib}" ]]; then
      missing+=("${lib}")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Skipping static ${label}; missing: ${missing[*]}" >&2
    return 1
  fi
  return 0
}

binary_is_static() {
  local bin="$1"
  if [[ ! -f "${bin}" ]]; then
    return 1
  fi
  if command -v readelf >/dev/null 2>&1; then
    if readelf -l "${bin}" 2>/dev/null | rg -q "INTERP"; then
      return 1
    fi
    return 0
  fi
  if command -v file >/dev/null 2>&1; then
    file "${bin}" 2>/dev/null | rg -qi "statically linked"
    return $?
  fi
  return 0
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
    res="$(auto_detect_toolchain "aarch64-linux-musl" || true)"
    if [[ -n "${res}" ]]; then
      ARMV8_BUSYBOX_TOOLCHAIN_PREFIX="${res%%|*}"
      ARMV8_BUSYBOX_SYSROOT="${res##*|}"
    elif [[ -n "${ARMV8_LINUX_TOOLCHAIN_PREFIX}" && -n "${ARMV8_LINUX_SYSROOT}" ]]; then
      ARMV8_BUSYBOX_TOOLCHAIN_PREFIX="${ARMV8_LINUX_TOOLCHAIN_PREFIX}"
      ARMV8_BUSYBOX_SYSROOT="${ARMV8_LINUX_SYSROOT}"
    fi
  fi
}

resolve_macos_toolchain() {
  local bin_dir=""
  if [[ -n "${OSXCROSS_ROOT:-}" && -d "${OSXCROSS_ROOT}/target/bin" ]]; then
    bin_dir="${OSXCROSS_ROOT}/target/bin"
  fi
  local cxx=""
  local desired_arch="x86_64"
  if [[ "${MACOS_TRIPLET}" == arm64* || "${MACOS_TRIPLET}" == *arm64* ]]; then
    desired_arch="arm64"
  fi
  if [[ -n "${MACOS_TOOLCHAIN_PREFIX}" ]]; then
    cxx="$(command -v "${MACOS_TOOLCHAIN_PREFIX}-clang++" 2>/dev/null || true)"
  fi
  if [[ -z "${cxx}" && -n "${bin_dir}" ]]; then
    if [[ "${desired_arch}" == "x86_64" && -x "${bin_dir}/o64-clang++" ]]; then
      cxx="${bin_dir}/o64-clang++"
    elif [[ "${desired_arch}" == "arm64" && -x "${bin_dir}/oa64-clang++" ]]; then
      cxx="${bin_dir}/oa64-clang++"
    fi
  fi
  if [[ -z "${cxx}" && -n "${bin_dir}" ]]; then
    if [[ "${desired_arch}" == "arm64" ]]; then
      cxx="$(ls "${bin_dir}"/arm64-apple-darwin*-clang++ "${bin_dir}"/aarch64-apple-darwin*-clang++ 2>/dev/null | head -n 1 || true)"
    else
      cxx="$(ls "${bin_dir}"/x86_64-apple-darwin*-clang++ "${bin_dir}"/x86_64h-apple-darwin*-clang++ 2>/dev/null | head -n 1 || true)"
    fi
  fi
  if [[ -z "${cxx}" ]]; then
    if [[ "${desired_arch}" == "x86_64" ]]; then
      cxx="$(command -v o64-clang++ 2>/dev/null || true)"
    else
      cxx="$(command -v oa64-clang++ 2>/dev/null || true)"
    fi
  fi
  if [[ -z "${cxx}" ]]; then
    return 1
  fi
  local cc="${cxx/clang++/clang}"
  if [[ ! -x "${cc}" ]]; then
    local alt="${cxx%++}"
    if [[ -x "${alt}" ]]; then
      cc="${alt}"
    else
      return 1
    fi
  fi
  local arch="x86_64"
  case "${cxx}" in
    *oa64*|*aarch64*|*arm64*|*armv8*) arch="arm64" ;;
  esac
  local sdk=""
  if [[ -n "${MACOS_SDK}" ]]; then
    if [[ -d "${MACOS_SDK}" ]]; then
      sdk="${MACOS_SDK}"
    elif [[ -n "${OSXCROSS_ROOT:-}" && -d "${OSXCROSS_ROOT}/target/SDK/${MACOS_SDK}" ]]; then
      sdk="${OSXCROSS_ROOT}/target/SDK/${MACOS_SDK}"
    fi
  fi
  if [[ -z "${sdk}" && -n "${OSXCROSS_ROOT:-}" ]]; then
    sdk="$(ls -d "${OSXCROSS_ROOT}/target/SDK/MacOSX"*.sdk 2>/dev/null | sort -V | tail -n 1 || true)"
  fi
  if [[ -z "${sdk}" ]]; then
    return 2
  fi
  echo "${cc}|${cxx}|${sdk}|${arch}"
}

maybe_enable_windows_cross() {
  if [[ "${WINDOWS_CROSS_AUTO}" -ne 1 ]]; then
    return 0
  fi
  if ! target_enabled windows-x86_64; then
    return 0
  fi
  if resolve_windows_mingw_compilers "${WINDOWS_TOOLCHAIN_PREFIX}" >/dev/null 2>&1 && \
     [[ -n "${VCPKG_ROOT:-}" && -x "${VCPKG_ROOT}/vcpkg" && -f "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" ]]; then
    WINDOWS_CROSS=1
  fi
}

maybe_enable_macos_cross() {
  if [[ "${MACOS_CROSS_AUTO}" -ne 1 ]]; then
    return 0
  fi
  if ! target_enabled macos-x86_64 && ! target_enabled macos-arm64; then
    return 0
  fi
  if resolve_macos_toolchain >/dev/null 2>&1 && \
     [[ -n "${VCPKG_ROOT:-}" && -x "${VCPKG_ROOT}/vcpkg" && -f "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" ]]; then
    MACOS_CROSS=1
  fi
}

list_macos_sdks() {
  local out=""
  local sdk_dir
  if [[ -n "${OSXCROSS_ROOT:-}" && -d "${OSXCROSS_ROOT}/target/SDK" ]]; then
    for sdk_dir in "${OSXCROSS_ROOT}/target/SDK"/MacOSX*.sdk; do
      [ -d "${sdk_dir}" ] || continue
      out+=$(basename "${sdk_dir}")" "
    done
  fi
  if [[ -z "${out}" && -d "${REAL_HOME}/macos-sdk" ]]; then
    for sdk_dir in "${REAL_HOME}/macos-sdk"/MacOSX*.sdk; do
      [ -d "${sdk_dir}" ] || continue
      out+=$(basename "${sdk_dir}")" "
    done
  fi
  if [[ -z "${out}" ]]; then
    echo "none"
  else
    echo "${out}"
  fi
}

print_build_plan() {
  echo "Building for:"
  if [[ "${HOST_OS}" == "Linux" ]]; then
    if target_enabled linux-x86_64; then
      echo "  - linux x86_64 (dynamic, stable)"
    fi
    if target_enabled openwrt-mips; then
      echo "  - openwrt mips (dynamic)"
    fi
    if target_enabled busybox-x86; then
      echo "  - busybox x86 (dynamic, stable)"
    fi
    if target_enabled armv7-linux || target_enabled armv7-busybox; then
      echo "  - armv7 linux/busybox (dynamic, stable)"
    fi
    if target_enabled armv8-linux || target_enabled armv8-busybox; then
      echo "  - armv8 linux/busybox (dynamic, stable)"
    fi
  elif [[ "${HOST_OS}" == "Darwin" ]]; then
    echo "  - macos ${HOST_ARCH} (dynamic)"
  elif [[ "${HOST_OS}" == MINGW* || "${HOST_OS}" == MSYS* || "${HOST_OS}" == CYGWIN* ]]; then
    echo "  - windows ${HOST_ARCH} (dynamic)"
  fi
  if [[ "${WINDOWS_CROSS}" -eq 1 ]] && target_enabled windows-x86_64; then
    echo "  - windows x86_64 (mingw, ${WINDOWS_TRIPLET}, dynamic)"
  fi
  if [[ "${MACOS_CROSS}" -eq 1 ]] && ( target_enabled macos-x86_64 || target_enabled macos-arm64 ); then
    echo "  - macos $(macos_triplet_arch) (${MACOS_TRIPLET}, dynamic, stable)"
  fi
  echo "Detected SDKs/libs:"
  echo "  - vcpkg: ${VCPKG_ROOT:-not found}"
  echo "  - osxcross: ${OSXCROSS_ROOT:-not found}"
  echo "  - macOS SDKs: $(list_macos_sdks)"
  if [[ -n "${MACOS_SDK}" ]]; then
    echo "  - macOS SDK selected: ${MACOS_SDK}"
  fi
  if [[ -n "${OPENWRT_SDK}" && -d "${OPENWRT_SDK}/staging_dir" ]]; then
    echo "  - openwrt SDK: ${OPENWRT_SDK}"
  elif [[ -d "${OPENWRT_SDK_PREFERRED}/staging_dir" ]]; then
    echo "  - openwrt SDK: ${OPENWRT_SDK_PREFERRED}"
  else
    echo "  - openwrt SDK: (will fetch) ${OPENWRT_SDK_PREFERRED}"
  fi
  if [[ "${WINDOWS_CROSS}" -ne 1 && "${WINDOWS_CROSS_AUTO}" -eq 1 ]]; then
    if ! resolve_windows_mingw_compilers "${WINDOWS_TOOLCHAIN_PREFIX}" >/dev/null 2>&1; then
      echo "  - windows toolchain: missing MinGW compiler pair for ${WINDOWS_TOOLCHAIN_PREFIX}"
    else
      local tool_info
      tool_info="$(resolve_windows_mingw_compilers "${WINDOWS_TOOLCHAIN_PREFIX}" || true)"
      echo "  - windows toolchain: ${tool_info##*|}"
    fi
  fi
}
fetch_url() {
  local url="$1"
  local out="$2"
  if command -v curl >/dev/null 2>&1; then
    if [[ -f "${out}" ]]; then
      curl -L --fail --continue-at - -o "${out}" "${url}"
    else
      curl -L --fail -o "${out}" "${url}"
    fi
  elif command -v wget >/dev/null 2>&1; then
    if [[ -f "${out}" ]]; then
      wget -c -O "${out}" "${url}"
    else
      wget -O "${out}" "${url}"
    fi
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
  local makefile=""
  if [[ -f "${OPENWRT_SDK}/package/feeds/base/${pkg}/Makefile" ]]; then
    echo "${OPENWRT_SDK}/package/feeds/base/${pkg}/Makefile"
    return
  fi
  if [[ -f "${OPENWRT_SDK}/package/feeds/packages/${pkg}/Makefile" ]]; then
    echo "${OPENWRT_SDK}/package/feeds/packages/${pkg}/Makefile"
    return
  fi
  makefile="$(find "${OPENWRT_SDK}/package/feeds" -path "*/${pkg}/Makefile" 2>/dev/null | head -n 1 || true)"
  if [[ -z "${makefile}" ]]; then
    makefile="$(find "${OPENWRT_SDK}/package" -path "*/${pkg}/Makefile" 2>/dev/null | head -n 1 || true)"
  fi
  echo "${makefile}"
}

ensure_openwrt_host_deps() {
  if command -v apt-get >/dev/null 2>&1; then
    apt_install gawk unzip
  fi
  if command -v update-alternatives >/dev/null 2>&1 && command -v gawk >/dev/null 2>&1; then
    update-alternatives --set awk /usr/bin/gawk >/dev/null 2>&1 || true
  fi
  if ! command -v gawk >/dev/null 2>&1; then
    echo "OpenWRT SDK requires GNU awk (gawk); please install it." >&2
    exit 1
  fi
  if ! command -v unzip >/dev/null 2>&1; then
    echo "OpenWRT SDK requires unzip; please install it." >&2
    exit 1
  fi
}

ensure_host_deps() {
  if ! command -v apt-get >/dev/null 2>&1; then
    return 0
  fi
  apt_install \
    build-essential \
    cmake \
    git \
    pkg-config \
    curl \
    wget \
    ca-certificates \
    unzip \
    zip \
    xz-utils \
    zstd \
    python3 \
    perl
  if target_enabled windows-x86_64; then
    apt_install mingw-w64 gcc-mingw-w64-x86-64-posix g++-mingw-w64-x86-64-posix
  fi
  if target_enabled macos-x86_64 || target_enabled macos-arm64; then
    apt_install clang lld llvm
  fi
}

openwrt_write_minimal_feeds() {
  local default_conf="${OPENWRT_SDK}/feeds.conf.default"
  local feeds_conf="${OPENWRT_SDK}/feeds.conf"
  if [[ ! -f "${default_conf}" ]]; then
    return 0
  fi
  awk '
    $2 == "base" {
      gsub(/^src-git-full/, "src-git", $1)
      print
      next
    }
    $2 == "packages" { print; next }
  ' "${default_conf}" > "${feeds_conf}"
}

openwrt_sync_feeds() {
  if [[ "${OPENWRT_FEEDS_READY}" -eq 1 ]]; then
    return 0
  fi
  if [[ ! -x "${OPENWRT_SDK}/scripts/feeds" ]]; then
    return 1
  fi
  openwrt_write_minimal_feeds
  local attempt=0
  local max_attempts=3
  local log="${OPENWRT_SDK}/.feeds-update.log"
  while [[ ${attempt} -lt ${max_attempts} ]]; do
    attempt=$((attempt + 1))
    if (cd "${OPENWRT_SDK}" && GIT_HTTP_VERSION=HTTP/1.1 GIT_TERMINAL_PROMPT=0 ./scripts/feeds update base packages >"${log}" 2>&1); then
      if [[ "${YUME_VERBOSE:-0}" == "1" ]]; then
        cat "${log}"
      fi
      OPENWRT_FEEDS_READY=1
      return 0
    fi
    cat "${log}" >&2
    rm -rf "${OPENWRT_SDK}/feeds/base" "${OPENWRT_SDK}/feeds/packages"
    sleep 2
  done
  echo "OpenWRT feeds update failed (base/packages). Check network and retry." >&2
  exit 1
}

ensure_openwrt_config() {
  local cfg="${OPENWRT_SDK}/.config"
  local min_cfg="/tmp/yume-openwrt-min.config"
  local target_base="${OPENWRT_SDK_TARGET%%-*}"
  local target_sub="${OPENWRT_SDK_TARGET//-/_}"
  if [[ -f "${cfg}" ]]; then
    rg '^CONFIG_TARGET_' "${cfg}" | rg -v '^CONFIG_TARGET_DEVICE_' | rg -v '^CONFIG_TARGET_ALL_PROFILES' > "${min_cfg}" || true
  else
    : > "${min_cfg}"
  fi
  if ! rg -q '^CONFIG_TARGET_' "${min_cfg}" 2>/dev/null; then
    {
      echo "CONFIG_TARGET_${target_base}=y"
      echo "CONFIG_TARGET_${target_sub}=y"
    } >> "${min_cfg}"
  fi
  rm -f "${cfg}" "${cfg}.old"
  (cd "${OPENWRT_SDK}" && KCONFIG_ALLCONFIG="${min_cfg}" make defconfig)
  rm -f "${min_cfg}"
}

openwrt_find_feed_for_pkg() {
  local pkg="$1"
  local path=""
  path="$(find "${OPENWRT_SDK}/feeds" -path "*/${pkg}/Makefile" 2>/dev/null | head -n 1 || true)"
  if [[ -z "${path}" ]]; then
    return 1
  fi
  local rel="${path#${OPENWRT_SDK}/feeds/}"
  echo "${rel%%/*}"
}

openwrt_install_feed_pkg() {
  local feed="$1"
  local pkg="$2"
  if [[ -z "${feed}" ]]; then
    return 1
  fi
  if [[ -f "${OPENWRT_SDK}/package/feeds/${feed}/${pkg}/Makefile" ]]; then
    return 0
  fi
  local log="${OPENWRT_SDK}/.feeds-install-${feed}-${pkg}.log"
  if ! (cd "${OPENWRT_SDK}" && ./scripts/feeds install -p "${feed}" "${pkg}" >"${log}" 2>&1); then
    cat "${log}" >&2
    return 1
  fi
  if [[ "${YUME_VERBOSE:-0}" == "1" ]]; then
    cat "${log}"
  fi
  if [[ ! -f "${OPENWRT_SDK}/package/feeds/${feed}/${pkg}/Makefile" ]]; then
    echo "OpenWRT feed install did not stage ${pkg} into package/feeds/${feed}" >&2
    return 1
  fi
}

openwrt_build_package() {
  local pkg="$1"
  local makefile
  makefile="$(openwrt_find_package_makefile "${pkg}")"
  if [[ -z "${makefile}" ]]; then
    ensure_openwrt_host_deps
    openwrt_sync_feeds
    local feed=""
    feed="$(openwrt_find_feed_for_pkg "${pkg}" || true)"
    if [[ -n "${feed}" ]]; then
      openwrt_install_feed_pkg "${feed}" "${pkg}"
    fi
    makefile="$(openwrt_find_package_makefile "${pkg}")"
  fi
  if [[ -z "${makefile}" ]]; then
    echo "OpenWRT package ${pkg} not found in SDK" >&2
    exit 1
  fi
  ensure_openwrt_config
  local rel=""
  rel="${makefile#${OPENWRT_SDK}/}"
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
  local has_ssl=0
  compgen -G "${usr}/lib/libssl.so."* >/dev/null 2>&1 && has_ssl=1
  if [[ (! -f "${usr}/lib/libcrypto.so" && ${has_crypto} -eq 0) || (! -f "${usr}/lib/libssl.so" && ${has_ssl} -eq 0) ]]; then
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
  return 0
}

openwrt_sysroot_ready() {
  local usr="${OPENWRT_USR:-}"
  if [[ -z "${usr}" || ! -d "${usr}" ]]; then
    return 1
  fi
  if [[ ! -d "${usr}/include/openssl" ]]; then
    return 1
  fi
  if ! compgen -G "${usr}/lib/libcrypto.so."* >/dev/null 2>&1 && [[ ! -f "${usr}/lib/libcrypto.so" && ! -f "${usr}/lib/libcrypto.a" ]]; then
    return 1
  fi
  if ! compgen -G "${usr}/lib/libssl.so."* >/dev/null 2>&1 && [[ ! -f "${usr}/lib/libssl.so" && ! -f "${usr}/lib/libssl.a" ]]; then
    return 1
  fi
  if ! compgen -G "${usr}/lib/libz.so."* >/dev/null 2>&1 && [[ ! -f "${usr}/lib/libz.so" && ! -f "${usr}/lib/libz.a" ]]; then
    return 1
  fi
  local boost_cfg=""
  boost_cfg="$(find "${usr}/lib/cmake" -maxdepth 2 -type f -name 'BoostConfig.cmake' 2>/dev/null | head -n 1 || true)"
  if [[ -z "${boost_cfg}" ]]; then
    return 1
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
  local variant="${6:-dynamic}"
  local script_path="/tmp/dockcross-${label}"
  local variant_args
  variant_args="$(variant_cmake_args "${variant}")"
  local outdir_container="${outdir}"
  if [[ "${outdir}" == "${BIN_DIR}"* ]]; then
    outdir_container="/bins/${outdir#${BIN_DIR}/}"
  fi
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
    mkdir -p \"${outdir_container}\"
    if [[ ${busybox_flag} -eq 1 ]]; then
      YUME_WINDOWS_CROSS=0 YUME_MACOS_CROSS=0 YUME_CMAKE_ARGS=\"${variant_args}\" YUME_TOOLCHAIN_FILE=/tmp/yume-toolchain.cmake ./ezbuild.sh --busybox --arch \"${label}\"
    else
      YUME_WINDOWS_CROSS=0 YUME_MACOS_CROSS=0 YUME_CMAKE_ARGS=\"${variant_args}\" YUME_TOOLCHAIN_FILE=/tmp/yume-toolchain.cmake ./ezbuild.sh --arch \"${label}\"
    fi
    cp -f build/bin/yume \"${outdir_container}/yume\"
    cp -f build/bin/yumed \"${outdir_container}/yumed\"
    \${CROSS_TRIPLE}-strip --strip-unneeded \"${outdir_container}/yume\" \"${outdir_container}/yumed\"
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
    rm -f "${APT_UPDATED_FLAG}" || true
    apt_update_once 1
  fi
  apt_install libc6-dev-i386 zlib1g-dev:i386 libssl-dev:i386 libboost-dev:i386 libboost-system-dev:i386
}

ensure_armhf_deps() {
  if ! command -v dpkg >/dev/null 2>&1; then
    return 0
  fi
  if ! dpkg --print-foreign-architectures | grep -qx armhf; then
    dpkg --add-architecture armhf
    rm -f "${APT_UPDATED_FLAG}" || true
    apt_update_once 1
  fi
  local gcc_major=""
  gcc_major="$(g++ -dumpversion 2>/dev/null | awk -F. '{print $1}' || true)"
  if [[ -z "${gcc_major}" || ! "${gcc_major}" =~ ^[0-9]+$ ]]; then
    gcc_major="$(gcc -dumpversion 2>/dev/null | awk -F. '{print $1}' || true)"
  fi
  local stdcpp_pkg="libstdc++-${gcc_major}-dev:armhf"
  if [[ -z "${gcc_major}" || ! "${gcc_major}" =~ ^[0-9]+$ ]] || ! apt-cache show "${stdcpp_pkg}" >/dev/null 2>&1; then
    stdcpp_pkg=""
  fi
  if [[ -n "${stdcpp_pkg}" ]]; then
    apt_install libc6-dev:armhf "${stdcpp_pkg}" zlib1g-dev:armhf libssl-dev:armhf libboost-dev:armhf libboost-system-dev:armhf
  else
    apt_install libc6-dev:armhf zlib1g-dev:armhf libssl-dev:armhf libboost-dev:armhf libboost-system-dev:armhf
  fi
}

ensure_arm64_deps() {
  if ! command -v dpkg >/dev/null 2>&1; then
    return 0
  fi
  if ! dpkg --print-foreign-architectures | grep -qx arm64; then
    dpkg --add-architecture arm64
    rm -f "${APT_UPDATED_FLAG}" || true
    apt_update_once 1
  fi
  local gcc_major=""
  gcc_major="$(g++ -dumpversion 2>/dev/null | awk -F. '{print $1}' || true)"
  if [[ -z "${gcc_major}" || ! "${gcc_major}" =~ ^[0-9]+$ ]]; then
    gcc_major="$(gcc -dumpversion 2>/dev/null | awk -F. '{print $1}' || true)"
  fi
  local stdcpp_pkg="libstdc++-${gcc_major}-dev:arm64"
  if [[ -z "${gcc_major}" || ! "${gcc_major}" =~ ^[0-9]+$ ]] || ! apt-cache show "${stdcpp_pkg}" >/dev/null 2>&1; then
    stdcpp_pkg=""
  fi
  if [[ -n "${stdcpp_pkg}" ]]; then
    apt_install libc6-dev:arm64 "${stdcpp_pkg}" zlib1g-dev:arm64 libssl-dev:arm64 libboost-dev:arm64 libboost-system-dev:arm64
  else
    apt_install libc6-dev:arm64 zlib1g-dev:arm64 libssl-dev:arm64 libboost-dev:arm64 libboost-system-dev:arm64
  fi
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
  local variant="${6:-dynamic}"
  local toolchain_file="/tmp/yume-toolchain-busybox-${label}.cmake"
  if [[ -z "${prefix}" || -z "${sysroot}" ]]; then
    echo "Missing toolchain for ${label} busybox; set *_{BUSYBOX}_TOOLCHAIN_PREFIX and *_{BUSYBOX}_SYSROOT" >&2
    exit 1
  fi
  local boost_dir_env=""
  local variant_args
  variant_args="$(variant_cmake_args "${variant}")"
  local cross_env="YUME_WINDOWS_CROSS=0 YUME_MACOS_CROSS=0"
  local lib_ext="so"
  if [[ "${variant}" == "static" ]]; then
    lib_ext="a"
  fi
  local use_musl=0
  if [[ "${prefix}" == *"linux-musl"* || "${sysroot}" == *"musl"* ]]; then
    use_musl=1
  fi
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
    boost_dir_env="Boost_DIR=$(dirname "${boost_cfg}")"
  elif [[ "${label}" == "armv7" ]]; then
    ensure_armhf_deps
    if [[ -f "/lib/arm-linux-gnueabihf/libc.so.6" || -f "/usr/lib/arm-linux-gnueabihf/libc.so.6" ]]; then
      sysroot="/"
    fi
    boost_dir_env="Boost_DIR=$(resolve_boost_dir arm-linux-gnueabihf)"
  elif [[ "${label}" == "armv8" ]]; then
    ensure_arm64_deps
    if (( use_musl == 0 )); then
      if [[ -f "/lib/aarch64-linux-gnu/libc.so.6" || -f "/usr/lib/aarch64-linux-gnu/libc.so.6" ]]; then
        sysroot="/"
      fi
      boost_dir_env="Boost_DIR=$(resolve_boost_dir aarch64-linux-gnu)"
    fi
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
    if (( use_musl == 1 )); then
      cat >> "${toolchain_file}" <<EOF
set(CMAKE_LIBRARY_ARCHITECTURE aarch64-linux-musl)
EOF
    else
      cat >> "${toolchain_file}" <<EOF
set(CMAKE_LIBRARY_ARCHITECTURE aarch64-linux-gnu)
EOF
    fi
  fi
  require_vendor_dir "${VENDOR_DIR}/busybox-${label}"
  if [[ "${label}" == "x86" ]]; then
    if [[ "${variant}" == "static" ]]; then
      if ! static_libs_ok "${label} busybox" \
        "/usr/lib/i386-linux-gnu/libz.a" \
        "/usr/lib/i386-linux-gnu/liblzma.a" \
        "/usr/lib/i386-linux-gnu/libzstd.a" \
        "/usr/lib/i386-linux-gnu/libssl.a" \
        "/usr/lib/i386-linux-gnu/libcrypto.a" \
        "/usr/lib/i386-linux-gnu/libboost_system.a"; then
        return 0
      fi
    else
      if [[ ! -f "/usr/lib/i386-linux-gnu/libz.so" ]]; then
        echo "i386 zlib dev not found. Install: apt-get install -y zlib1g-dev:i386" >&2
        exit 1
      fi
      if [[ ! -f "/usr/lib/i386-linux-gnu/libssl.so" || ! -f "/usr/lib/i386-linux-gnu/libcrypto.so" ]]; then
        echo "i386 OpenSSL dev not found. Install: apt-get install -y libssl-dev:i386" >&2
        exit 1
      fi
    fi
    local zlib_lib="/usr/lib/i386-linux-gnu/libz.${lib_ext}"
    local lzma_lib="/usr/lib/i386-linux-gnu/liblzma.${lib_ext}"
    local zstd_lib="/usr/lib/i386-linux-gnu/libzstd.${lib_ext}"
    local ssl_lib="/usr/lib/i386-linux-gnu/libssl.${lib_ext}"
    local crypto_lib="/usr/lib/i386-linux-gnu/libcrypto.${lib_ext}"
    local extra_args="-DZLIB_LIBRARY=${zlib_lib} -DZLIB_INCLUDE_DIR=/usr/include -DOPENSSL_SSL_LIBRARY=${ssl_lib} -DOPENSSL_CRYPTO_LIBRARY=${crypto_lib} -DOPENSSL_INCLUDE_DIR=/usr/include ${variant_args}"
    if [[ -f "${zstd_lib}" ]]; then
      extra_args="${extra_args} -DZSTD_LIBRARY=${zstd_lib} -DZSTD_INCLUDE_DIR=/usr/include"
    fi
    if [[ -n "${boost_dir_env}" ]]; then
      extra_args="${extra_args} -D${boost_dir_env}"
      env ${boost_dir_env} ${cross_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
    else
      env ${cross_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
    fi
  elif [[ "${label}" == "armv7" ]]; then
    if [[ "${variant}" == "static" ]]; then
      if ! static_libs_ok "${label} busybox" \
        "/usr/lib/arm-linux-gnueabihf/libz.a" \
        "/usr/lib/arm-linux-gnueabihf/liblzma.a" \
        "/usr/lib/arm-linux-gnueabihf/libzstd.a" \
        "/usr/lib/arm-linux-gnueabihf/libssl.a" \
        "/usr/lib/arm-linux-gnueabihf/libcrypto.a" \
        "/usr/lib/arm-linux-gnueabihf/libboost_system.a"; then
        return 0
      fi
    fi
    local zlib_lib="/usr/lib/arm-linux-gnueabihf/libz.${lib_ext}"
    local lzma_lib="/usr/lib/arm-linux-gnueabihf/liblzma.${lib_ext}"
    local zstd_lib="/usr/lib/arm-linux-gnueabihf/libzstd.${lib_ext}"
    local ssl_lib="/usr/lib/arm-linux-gnueabihf/libssl.${lib_ext}"
    local crypto_lib="/usr/lib/arm-linux-gnueabihf/libcrypto.${lib_ext}"
    local extra_args="-DZLIB_LIBRARY=${zlib_lib} -DZLIB_INCLUDE_DIR=/usr/include -DOPENSSL_SSL_LIBRARY=${ssl_lib} -DOPENSSL_CRYPTO_LIBRARY=${crypto_lib} -DOPENSSL_INCLUDE_DIR=/usr/include ${variant_args}"
    if [[ -f "${zstd_lib}" ]]; then
      extra_args="${extra_args} -DZSTD_LIBRARY=${zstd_lib} -DZSTD_INCLUDE_DIR=/usr/include"
    fi
    if [[ -n "${boost_dir_env}" ]]; then
      extra_args="${extra_args} -D${boost_dir_env}"
      env ${boost_dir_env} ${cross_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
    else
      env ${cross_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
    fi
  elif [[ "${label}" == "armv8" ]]; then
    if [[ "${variant}" == "static" ]]; then
      local inc_dir="/usr/include"
      local lib_dir="/usr/lib/aarch64-linux-gnu"
      if (( use_musl == 1 )); then
        if [[ -d "${sysroot}/usr/lib" ]]; then
          lib_dir="${sysroot}/usr/lib"
        elif [[ -d "${sysroot}/lib" ]]; then
          lib_dir="${sysroot}/lib"
        fi
        if [[ -d "${sysroot}/usr/include" ]]; then
          inc_dir="${sysroot}/usr/include"
        elif [[ -d "${sysroot}/include" ]]; then
          inc_dir="${sysroot}/include"
        fi
      fi
      if ! static_libs_ok "${label} busybox" \
        "${lib_dir}/libz.a" \
        "${lib_dir}/liblzma.a" \
        "${lib_dir}/libzstd.a" \
        "${lib_dir}/libssl.a" \
        "${lib_dir}/libcrypto.a" \
        "${lib_dir}/libboost_system.a"; then
        return 0
      fi
    fi
    local inc_dir="/usr/include"
    local lib_dir="/usr/lib/aarch64-linux-gnu"
    if (( use_musl == 1 )); then
      if [[ -d "${sysroot}/usr/lib" ]]; then
        lib_dir="${sysroot}/usr/lib"
      elif [[ -d "${sysroot}/lib" ]]; then
        lib_dir="${sysroot}/lib"
      fi
      if [[ -d "${sysroot}/usr/include" ]]; then
        inc_dir="${sysroot}/usr/include"
      elif [[ -d "${sysroot}/include" ]]; then
        inc_dir="${sysroot}/include"
      fi
    fi
    local zlib_lib="${lib_dir}/libz.${lib_ext}"
    local lzma_lib="${lib_dir}/liblzma.${lib_ext}"
    local zstd_lib="${lib_dir}/libzstd.${lib_ext}"
    local ssl_lib="${lib_dir}/libssl.${lib_ext}"
    local crypto_lib="${lib_dir}/libcrypto.${lib_ext}"
    local extra_args="-DZLIB_LIBRARY=${zlib_lib} -DZLIB_INCLUDE_DIR=${inc_dir} -DOPENSSL_SSL_LIBRARY=${ssl_lib} -DOPENSSL_CRYPTO_LIBRARY=${crypto_lib} -DOPENSSL_INCLUDE_DIR=${inc_dir} ${variant_args}"
    if [[ -f "${zstd_lib}" ]]; then
      extra_args="${extra_args} -DZSTD_LIBRARY=${zstd_lib} -DZSTD_INCLUDE_DIR=${inc_dir}"
    fi
    if [[ -n "${boost_dir_env}" ]]; then
      extra_args="${extra_args} -D${boost_dir_env}"
      env ${boost_dir_env} ${cross_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
    else
      env ${cross_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
    fi
  elif [[ -n "${boost_dir_env}" ]]; then
    env ${boost_dir_env} ${cross_env} YUME_CMAKE_ARGS="${variant_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
  else
    YUME_WINDOWS_CROSS=0 YUME_MACOS_CROSS=0 YUME_CMAKE_ARGS="${variant_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --busybox --arch "${label}"
  fi
  copy_build_outputs "${outdir}" "" || return 1
  "${prefix}-strip" --strip-unneeded "${outdir}/yume" "${outdir}/yumed"
  if [[ "${variant}" == "static" ]]; then
    if ! binary_is_static "${outdir}/yume" || ! binary_is_static "${outdir}/yumed"; then
      echo "Busybox static build produced dynamic binaries. Install static deps or use a musl toolchain for ${label}." >&2
      exit 1
    fi
  fi
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
  local variant="${6:-dynamic}"
  local toolchain_file="/tmp/yume-toolchain-linux-${label}.cmake"
  if [[ -z "${prefix}" || -z "${sysroot}" ]]; then
    echo "Missing toolchain for ${label} linux; set *_{LINUX}_TOOLCHAIN_PREFIX and *_{LINUX}_SYSROOT" >&2
    exit 1
  fi
  local boost_dir_env=""
  local variant_args
  variant_args="$(variant_cmake_args "${variant}")"
  local cross_env="YUME_WINDOWS_CROSS=0 YUME_MACOS_CROSS=0"
  local lib_ext="so"
  if [[ "${variant}" == "static" ]]; then
    lib_ext="a"
  fi
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
    if [[ "${variant}" == "static" ]]; then
      if ! static_libs_ok "${label} linux" \
        "/usr/lib/arm-linux-gnueabihf/libz.a" \
        "/usr/lib/arm-linux-gnueabihf/liblzma.a" \
        "/usr/lib/arm-linux-gnueabihf/libzstd.a" \
        "/usr/lib/arm-linux-gnueabihf/libssl.a" \
        "/usr/lib/arm-linux-gnueabihf/libcrypto.a" \
        "/usr/lib/arm-linux-gnueabihf/libboost_system.a"; then
        return 0
      fi
    fi
    local zlib_lib="/usr/lib/arm-linux-gnueabihf/libz.${lib_ext}"
    local lzma_lib="/usr/lib/arm-linux-gnueabihf/liblzma.${lib_ext}"
    local zstd_lib="/usr/lib/arm-linux-gnueabihf/libzstd.${lib_ext}"
    local ssl_lib="/usr/lib/arm-linux-gnueabihf/libssl.${lib_ext}"
    local crypto_lib="/usr/lib/arm-linux-gnueabihf/libcrypto.${lib_ext}"
    local extra_args="-DZLIB_LIBRARY=${zlib_lib} -DZLIB_INCLUDE_DIR=/usr/include -DOPENSSL_SSL_LIBRARY=${ssl_lib} -DOPENSSL_CRYPTO_LIBRARY=${crypto_lib} -DOPENSSL_INCLUDE_DIR=/usr/include ${variant_args}"
    if [[ -f "${zstd_lib}" ]]; then
      extra_args="${extra_args} -DZSTD_LIBRARY=${zstd_lib} -DZSTD_INCLUDE_DIR=/usr/include"
    fi
    if [[ -n "${boost_dir_env}" ]]; then
      extra_args="${extra_args} -D${boost_dir_env}"
      env ${boost_dir_env} ${cross_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
    else
      env ${cross_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
    fi
  elif [[ "${label}" == "armv8" ]]; then
    if [[ "${variant}" == "static" ]]; then
      if ! static_libs_ok "${label} linux" \
        "/usr/lib/aarch64-linux-gnu/libz.a" \
        "/usr/lib/aarch64-linux-gnu/liblzma.a" \
        "/usr/lib/aarch64-linux-gnu/libzstd.a" \
        "/usr/lib/aarch64-linux-gnu/libssl.a" \
        "/usr/lib/aarch64-linux-gnu/libcrypto.a" \
        "/usr/lib/aarch64-linux-gnu/libboost_system.a"; then
        return 0
      fi
    fi
    local zlib_lib="/usr/lib/aarch64-linux-gnu/libz.${lib_ext}"
    local lzma_lib="/usr/lib/aarch64-linux-gnu/liblzma.${lib_ext}"
    local zstd_lib="/usr/lib/aarch64-linux-gnu/libzstd.${lib_ext}"
    local ssl_lib="/usr/lib/aarch64-linux-gnu/libssl.${lib_ext}"
    local crypto_lib="/usr/lib/aarch64-linux-gnu/libcrypto.${lib_ext}"
    local extra_args="-DZLIB_LIBRARY=${zlib_lib} -DZLIB_INCLUDE_DIR=/usr/include -DOPENSSL_SSL_LIBRARY=${ssl_lib} -DOPENSSL_CRYPTO_LIBRARY=${crypto_lib} -DOPENSSL_INCLUDE_DIR=/usr/include ${variant_args}"
    if [[ -f "${zstd_lib}" ]]; then
      extra_args="${extra_args} -DZSTD_LIBRARY=${zstd_lib} -DZSTD_INCLUDE_DIR=/usr/include"
    fi
    if [[ -n "${boost_dir_env}" ]]; then
      extra_args="${extra_args} -D${boost_dir_env}"
      env ${boost_dir_env} ${cross_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
    else
      env ${cross_env} YUME_CMAKE_ARGS="${extra_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
    fi
  elif [[ -n "${boost_dir_env}" ]]; then
    env ${boost_dir_env} ${cross_env} YUME_CMAKE_ARGS="${variant_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
  else
    YUME_WINDOWS_CROSS=0 YUME_MACOS_CROSS=0 YUME_CMAKE_ARGS="${variant_args}" YUME_TOOLCHAIN_FILE="${toolchain_file}" ./ezbuild.sh --arch "${label}"
  fi
  copy_build_outputs "${outdir}" "" || return 1
  "${prefix}-strip" --strip-unneeded "${outdir}/yume" "${outdir}/yumed"
}

clean_build_dirs() {
  rm -rf build basefwx/cpp/build
}

build_host_linux_target() {
  local variant="$1"
  local outdir="$2"
  local variant_args
  variant_args="$(variant_cmake_args "${variant}")"
  local lib_ext="so"
  if [[ "${variant}" == "static" ]]; then
    lib_ext="a"
  fi
  if [[ "${variant}" == "static" ]]; then
    if ! static_libs_ok "x86_64 linux" \
      "/usr/lib/x86_64-linux-gnu/libz.a" \
      "/usr/lib/x86_64-linux-gnu/liblzma.a" \
      "/usr/lib/x86_64-linux-gnu/libzstd.a" \
      "/usr/lib/x86_64-linux-gnu/libssl.a" \
      "/usr/lib/x86_64-linux-gnu/libcrypto.a" \
      "/usr/lib/x86_64-linux-gnu/libboost_system.a"; then
      return 0
    fi
  fi
  require_vendor_dir "${VENDOR_DIR}/linux-x86_64"
  local zlib_lib="/usr/lib/x86_64-linux-gnu/libz.${lib_ext}"
  local lzma_lib="/usr/lib/x86_64-linux-gnu/liblzma.${lib_ext}"
  local zstd_lib="/usr/lib/x86_64-linux-gnu/libzstd.${lib_ext}"
  local ssl_lib="/usr/lib/x86_64-linux-gnu/libssl.${lib_ext}"
  local crypto_lib="/usr/lib/x86_64-linux-gnu/libcrypto.${lib_ext}"
  local extra_args="${variant_args} -DZLIB_LIBRARY=${zlib_lib} -DZLIB_INCLUDE_DIR=/usr/include"
  if [[ -f "${ssl_lib}" && -f "${crypto_lib}" ]]; then
    extra_args="${extra_args} -DOPENSSL_SSL_LIBRARY=${ssl_lib} -DOPENSSL_CRYPTO_LIBRARY=${crypto_lib} -DOPENSSL_INCLUDE_DIR=/usr/include"
  fi
  if [[ -f "${zstd_lib}" ]]; then
    extra_args="${extra_args} -DZSTD_LIBRARY=${zstd_lib} -DZSTD_INCLUDE_DIR=/usr/include"
  fi
  YUME_WINDOWS_CROSS=0 YUME_MACOS_CROSS=0 YUME_OQS_STATIC=1 YUME_CMAKE_ARGS="${extra_args}" ./ezbuild.sh
  copy_build_outputs "${outdir}" "" || return 1
  strip "${outdir}/yume" "${outdir}/yumed"
}

build_host_native_target() {
  local variant="$1"
  local outdir="$2"
  local exe_suffix="$3"
  local variant_args
  variant_args="$(variant_cmake_args "${variant}")"
  YUME_WINDOWS_CROSS=0 YUME_MACOS_CROSS=0 YUME_CMAKE_ARGS="${variant_args}" ./ezbuild.sh
  local yume_src="build/bin/yume${exe_suffix}"
  local yumed_src="build/bin/yumed${exe_suffix}"
  if [[ ! -f "${yume_src}" || ! -f "${yumed_src}" ]]; then
    echo "Host build outputs missing: ${yume_src} ${yumed_src}" >&2
    return 1
  fi
  mkdir -p "${outdir}"
  cp -f "${yume_src}" "${outdir}/yume${exe_suffix}"
  cp -f "${yumed_src}" "${outdir}/yumed${exe_suffix}"
  if command -v strip >/dev/null 2>&1; then
    strip "${outdir}/yume${exe_suffix}" "${outdir}/yumed${exe_suffix}" >/dev/null 2>&1 || true
  fi
}

copy_build_outputs() {
  local outdir="$1"
  local exe_suffix="${2:-}"
  local yume_src="build/bin/yume${exe_suffix}"
  local yumed_src="build/bin/yumed${exe_suffix}"

  if [[ -z "${exe_suffix}" && -f build/bin/yume.exe ]]; then
    echo "Build produced Windows executables (.exe); check toolchain/targets before copying Linux outputs." >&2
    return 1
  fi
  if [[ -n "${exe_suffix}" && -f build/bin/yume && ! -f "${yume_src}" ]]; then
    echo "Build produced non-Windows outputs; expected ${yume_src}." >&2
    return 1
  fi
  if [[ ! -f "${yume_src}" || ! -f "${yumed_src}" ]]; then
    echo "Build outputs missing: ${yume_src} ${yumed_src}" >&2
    return 1
  fi
  mkdir -p "${outdir}"
  cp -f "${yume_src}" "${outdir}/yume${exe_suffix}"
  cp -f "${yumed_src}" "${outdir}/yumed${exe_suffix}"
}

resolve_windows_mingw_compilers() {
  local tool_prefix="$1"
  local cc=""
  local cxx=""
  local rc=""
  if command -v "${tool_prefix}-g++-posix" >/dev/null 2>&1 && \
     command -v "${tool_prefix}-gcc-posix" >/dev/null 2>&1; then
    cxx="${tool_prefix}-g++-posix"
    cc="${tool_prefix}-gcc-posix"
  elif command -v "${tool_prefix}-g++" >/dev/null 2>&1 && \
       command -v "${tool_prefix}-gcc" >/dev/null 2>&1; then
    cxx="${tool_prefix}-g++"
    cc="${tool_prefix}-gcc"
  else
    return 1
  fi
  if command -v "${tool_prefix}-windres" >/dev/null 2>&1; then
    rc="${tool_prefix}-windres"
  else
    return 1
  fi
  echo "${cc}|${cxx}|${rc}"
}

copy_mingw_runtime_dlls() {
  local outdir="$1"
  local gcc_bin="${2:-x86_64-w64-mingw32-g++}"
  local tool_prefix="${3:-x86_64-w64-mingw32}"
  local gcc_triplet="${tool_prefix##*/}"
  local thread_model=""
  if command -v "${gcc_bin}" >/dev/null 2>&1; then
    thread_model="$("${gcc_bin}" -v 2>&1 | awk -F': ' '/Thread model/ {print $2}')"
  fi
  local search_dirs=()
  if [[ "${thread_model}" == "posix" ]]; then
    search_dirs=(/usr/lib/gcc/${gcc_triplet}/*-posix /usr/lib/gcc/${gcc_triplet}/*-win32)
  elif [[ "${thread_model}" == "win32" ]]; then
    search_dirs=(/usr/lib/gcc/${gcc_triplet}/*-win32 /usr/lib/gcc/${gcc_triplet}/*-posix)
  else
    search_dirs=(/usr/lib/gcc/${gcc_triplet}/*)
  fi

  local dlls=(libgcc_s_seh-1.dll libstdc++-6.dll)
  for dll in "${dlls[@]}"; do
    local found=""
    for dir in "${search_dirs[@]}"; do
      for path in "${dir}"/"${dll}"; do
        if [[ -f "${path}" ]]; then
          found="${path}"
          break
        fi
      done
      [[ -n "${found}" ]] && break
    done
    if [[ -n "${found}" ]]; then
      cp -f "${found}" "${outdir}/" || true
    else
      echo "Warning: ${dll} not found in ${search_dirs[*]}" >&2
    fi
  done

  local winpthread="/usr/${gcc_triplet}/lib/libwinpthread-1.dll"
  if [[ -f "${winpthread}" ]]; then
    cp -f "${winpthread}" "${outdir}/" || true
  else
    echo "Warning: libwinpthread-1.dll not found at ${winpthread}" >&2
  fi
}

write_windows_install_cmd() {
  local outdir="$1"
  cat > "${outdir}/install.cmd" <<'EOF'
@echo off
setlocal enabledelayedexpansion

net session >nul 2>&1
if not %errorlevel%==0 (
  echo Please run this as Administrator.
  pause
  exit /b 1
)

set "SRC=%~dp0"
set "DEST=%ProgramFiles%\Yume\bin"

if not exist "%DEST%" mkdir "%DEST%"

for %%F in ("%SRC%yume.exe" "%SRC%yumed.exe") do (
  if exist "%%~fF" copy /Y "%%~fF" "%DEST%\" >nul
)

for %%D in ("%SRC%*.dll") do (
  copy /Y "%%~fD" "%DEST%\" >nul
)

for /f "usebackq delims=" %%P in (`powershell -NoProfile -Command "[Environment]::GetEnvironmentVariable('Path','Machine')"`) do set "PATHM=%%P"
echo %PATHM% | find /I "%DEST%" >nul
if errorlevel 1 (
  powershell -NoProfile -Command "[Environment]::SetEnvironmentVariable('Path', ($env:Path + ';%DEST%'), 'Machine')"
)

echo Installed to: %DEST%
echo If a terminal is already open, restart it to pick up PATH changes.
pause
EOF
}

build_windows_cross_target() {
  local variant="$1"
  local outdir="$2"
  local tool_prefix="${WINDOWS_TOOLCHAIN_PREFIX}"
  local triplet="${WINDOWS_TRIPLET}"
  local tool_info=""
  local tool_cc=""
  local tool_cxx=""
  local tool_rc=""
  local vcpkg_root="${VCPKG_ROOT:-}"
  local vcpkg_bin=""
  local toolchain_file="/tmp/yume-mingw-toolchain.cmake"
  local sysroot=""
  local vcpkg_prefix=""
  local oqs_lib=""
  local oqs_include=""
  local shim_bin="/tmp/yume-windows-shim"
  local powershell_stub="${shim_bin}/powershell.exe"
  local vcpkg_build_type="${YUME_WINDOWS_VCPKG_BUILD_TYPE:-release}"
  local overlay_triplets_dir=""
  local upstream_triplet_file=""

  if [[ "${WINDOWS_CROSS}" -ne 1 ]]; then
    return 0
  fi
  tool_info="$(resolve_windows_mingw_compilers "${tool_prefix}" || true)"
  if [[ -z "${tool_info}" ]]; then
    echo "Skipping windows cross build; missing MinGW POSIX/standard compiler pair for ${tool_prefix}" >&2
    return 0
  fi
  IFS='|' read -r tool_cc tool_cxx tool_rc <<< "${tool_info}"
  echo "✨ Windows cross compiler: ${tool_cxx}"
  if [[ -z "${vcpkg_root}" ]]; then
    echo "Skipping windows cross build; set VCPKG_ROOT to your vcpkg clone" >&2
    return 0
  fi
  vcpkg_bin="${vcpkg_root}/vcpkg"
  if [[ ! -x "${vcpkg_bin}" ]]; then
    echo "Skipping windows cross build; vcpkg not found at ${vcpkg_bin}" >&2
    return 0
  fi
  if [[ ! -f "${vcpkg_root}/scripts/buildsystems/vcpkg.cmake" ]]; then
    echo "Skipping windows cross build; vcpkg toolchain file missing" >&2
    return 0
  fi

  if [[ -f "${vcpkg_root}/triplets/community/${triplet}.cmake" ]]; then
    upstream_triplet_file="${vcpkg_root}/triplets/community/${triplet}.cmake"
  elif [[ -f "${vcpkg_root}/triplets/${triplet}.cmake" ]]; then
    upstream_triplet_file="${vcpkg_root}/triplets/${triplet}.cmake"
  fi

  patch_vcpkg_boost_ports "${vcpkg_root}"

  vcpkg_prefix="${vcpkg_root}/installed/${triplet}"
  oqs_include="${vcpkg_prefix}/include"
  if [[ -f "${vcpkg_prefix}/lib/liboqs.dll.a" ]]; then
    oqs_lib="${vcpkg_prefix}/lib/liboqs.dll.a"
  elif [[ -f "${vcpkg_prefix}/lib/liboqs.a" ]]; then
    oqs_lib="${vcpkg_prefix}/lib/liboqs.a"
  fi

  sysroot="$("${tool_cc}" -print-sysroot 2>/dev/null || true)"
  if [[ -z "${sysroot}" || "${sysroot}" == "/" ]]; then
    if [[ -d "/usr/${tool_prefix}" ]]; then
      sysroot="/usr/${tool_prefix}"
    fi
  fi

  mkdir -p "${shim_bin}"
  if [[ ! -x "${powershell_stub}" ]]; then
    cat > "${powershell_stub}" <<'EOS'
#!/usr/bin/env bash
exit 0
EOS
    chmod +x "${powershell_stub}"
  fi

  local vcpkg_triplet_args=(--triplet "${triplet}")
  if [[ "${vcpkg_build_type}" == "release" && -n "${upstream_triplet_file}" ]]; then
    overlay_triplets_dir="/tmp/yume-vcpkg-triplets-windows"
    mkdir -p "${overlay_triplets_dir}"
    cat > "${overlay_triplets_dir}/${triplet}.cmake" <<EOF
include("${upstream_triplet_file}")
set(VCPKG_BUILD_TYPE release)
EOF
    vcpkg_triplet_args+=(--overlay-triplets "${overlay_triplets_dir}")
  fi

  local windows_vcpkg_packages="${WINDOWS_VCPKG_PACKAGES//,/ }"
  if [[ " ${windows_vcpkg_packages} " != *" boost-headers "* ]]; then
    windows_vcpkg_packages="${windows_vcpkg_packages} boost-headers"
  fi
  if [[ " ${windows_vcpkg_packages} " != *" boost-system "* ]]; then
    windows_vcpkg_packages="${windows_vcpkg_packages} boost-system"
  fi
  if [[ " ${windows_vcpkg_packages} " != *" boost-asio "* ]]; then
    windows_vcpkg_packages="${windows_vcpkg_packages} boost-asio"
  fi

  CC="${tool_cc}" CXX="${tool_cxx}" PATH="${shim_bin}:${PATH}" VCPKG_POWERSHELL_PATH="${powershell_stub}" \
    "${vcpkg_bin}" install "${vcpkg_triplet_args[@]}" ${windows_vcpkg_packages}

  if [[ ! -f "${vcpkg_prefix}/include/boost/asio.hpp" ]]; then
    echo "Windows vcpkg Boost.Asio headers missing after install; retrying explicit boost-asio/boost-headers."
    CC="${tool_cc}" CXX="${tool_cxx}" PATH="${shim_bin}:${PATH}" VCPKG_POWERSHELL_PATH="${powershell_stub}" \
      "${vcpkg_bin}" install "${vcpkg_triplet_args[@]}" boost-headers boost-system boost-asio
  fi
  if [[ ! -f "${vcpkg_prefix}/include/boost/asio.hpp" ]]; then
    echo "Windows cross build cannot continue: boost/asio.hpp not found in ${vcpkg_prefix}/include." >&2
    echo "Set YUME_WINDOWS_VCPKG_PACKAGES to include boost-headers boost-system boost-asio." >&2
    return 1
  fi

  cat > "${toolchain_file}" <<EOF
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER ${tool_cc})
set(CMAKE_CXX_COMPILER ${tool_cxx})
set(CMAKE_RC_COMPILER ${tool_rc})
EOF
  if [[ -n "${sysroot}" && -d "${sysroot}" ]]; then
    cat >> "${toolchain_file}" <<EOF
set(CMAKE_SYSROOT ${sysroot})
set(CMAKE_FIND_ROOT_PATH ${sysroot} ${vcpkg_prefix})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF
  else
    cat >> "${toolchain_file}" <<EOF
set(CMAKE_FIND_ROOT_PATH ${vcpkg_prefix})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF
  fi

  local variant_args
  variant_args="$(variant_cmake_args "${variant}")"
  local extra_oqs_args=""
  if [[ -n "${oqs_lib}" && -d "${oqs_include}" ]]; then
    extra_oqs_args="-DOQS_INCLUDE_DIR=${oqs_include} -DOQS_LIBRARY=${oqs_lib}"
  fi

  local extra_vcpkg_toolchain_args=""
  if [[ -n "${overlay_triplets_dir}" ]]; then
    extra_vcpkg_toolchain_args="-DVCPKG_OVERLAY_TRIPLETS=${overlay_triplets_dir}"
  fi

  PATH="${shim_bin}:${PATH}" VCPKG_POWERSHELL_PATH="${powershell_stub}" \
    YUME_WINDOWS_CROSS=1 YUME_MACOS_CROSS=0 YUME_SKIP_DEPS=1 YUME_CMAKE_ARGS="${variant_args} -DYUME_USE_SPDLOG=OFF -DBASEFWX_USE_VENDOR_DEPS=OFF -DOPENSSL_ROOT_DIR=${vcpkg_prefix} ${extra_oqs_args} -DCMAKE_TOOLCHAIN_FILE=${vcpkg_root}/scripts/buildsystems/vcpkg.cmake -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=${toolchain_file} -DVCPKG_TARGET_TRIPLET=${triplet} ${extra_vcpkg_toolchain_args} -DVCPKG_APPLOCAL_DEPS=OFF -DCMAKE_SYSTEM_NAME=Windows" \
    ./ezbuild.sh

  if [[ ! -f build/bin/yume.exe || ! -f build/bin/yumed.exe ]]; then
    echo "Windows build outputs missing in build/bin" >&2
    return 1
  fi
  mkdir -p "${outdir}"
  cp -f build/bin/yume.exe "${outdir}/yume.exe"
  cp -f build/bin/yumed.exe "${outdir}/yumed.exe"
  if [[ "${triplet}" == *"dynamic"* ]]; then
    cp -f "${vcpkg_root}/installed/${triplet}/bin/"*.dll "${outdir}/" 2>/dev/null || true
    cp -f "${vcpkg_root}/installed/${triplet}/debug/bin/"*.dll "${outdir}/" 2>/dev/null || true
    copy_mingw_runtime_dlls "${outdir}" "${tool_cxx}" "${tool_prefix}"
  fi
  write_windows_install_cmd "${outdir}"
}

build_macos_cross_target() {
  local variant="$1"
  local outdir="$2"
  local lib_linkage="static"
  if [[ "${variant}" == "dynamic" ]]; then
    lib_linkage="dynamic"
  fi
  local triplet="${MACOS_TRIPLET}"
  local vcpkg_root="${VCPKG_ROOT:-}"
  local toolchain_file="/tmp/yume-osxcross-toolchain.cmake"
  local toolchain_info=""
  local oqs_lib=""
  local oqs_include=""

  if [[ "${MACOS_CROSS}" -ne 1 ]]; then
    return 0
  fi
  if [[ -z "${vcpkg_root}" ]]; then
    echo "Skipping macos cross build; set VCPKG_ROOT to your vcpkg clone" >&2
    return 0
  fi
  if [[ ! -x "${vcpkg_root}/vcpkg" ]]; then
    echo "Skipping macos cross build; vcpkg not found at ${vcpkg_root}/vcpkg" >&2
    return 0
  fi
  if [[ ! -f "${vcpkg_root}/scripts/buildsystems/vcpkg.cmake" ]]; then
    echo "Skipping macos cross build; vcpkg toolchain file missing" >&2
    return 0
  fi

  patch_vcpkg_boost_ports "${vcpkg_root}"

  toolchain_info="$(resolve_macos_toolchain || true)"
  if [[ -z "${toolchain_info}" ]]; then
    echo "Skipping macos cross build; osxcross toolchain not found (set OSXCROSS_ROOT or YUME_MACOS_TOOLCHAIN_PREFIX)" >&2
    return 0
  fi

  local cc=""
  local cxx=""
  local sdk=""
  local arch=""
  local bin_dir=""
  local tool_prefix=""
  local install_name_tool_path=""
  local ld_path=""
  local overlay_triplets_dir="/tmp/yume-vcpkg-triplets"
  local shim_bin="/tmp/yume-osxcross-bin"
  local triplet_arch="x64"
  local vcpkg_prefix=""
  IFS='|' read -r cc cxx sdk arch <<< "${toolchain_info}"
  if [[ -z "${cc}" || -z "${cxx}" || -z "${sdk}" ]]; then
    echo "Skipping macos cross build; missing osxcross compiler or SDK (set OSXCROSS_ROOT/YUME_MACOS_SDK)" >&2
    return 0
  fi
  if [[ "${arch}" == "arm64" ]]; then
    triplet_arch="arm64"
  fi
  if [[ "${triplet_arch}" == "x64" && "${arch}" != "x86_64" ]]; then
    echo "Skipping macos cross build; toolchain arch ${arch} does not match ${triplet}." >&2
    return 0
  fi
  if [[ "${triplet_arch}" == "arm64" && "${arch}" != "arm64" ]]; then
    echo "Skipping macos cross build; toolchain arch ${arch} does not match ${triplet}." >&2
    return 0
  fi

  bin_dir="$(dirname "${cc}")"
  tool_prefix="${cc##*/}"
  tool_prefix="${tool_prefix%-clang}"
  tool_prefix="${tool_prefix%-cc}"
  tool_prefix="${tool_prefix%-gcc}"
  if [[ -n "${bin_dir}" && -n "${tool_prefix}" && -x "${bin_dir}/${tool_prefix}-install_name_tool" ]]; then
    install_name_tool_path="${bin_dir}/${tool_prefix}-install_name_tool"
  fi
  if [[ -z "${install_name_tool_path}" && -n "${bin_dir}" ]]; then
    install_name_tool_path="$(ls "${bin_dir}"/*-install_name_tool 2>/dev/null | head -n 1 || true)"
  fi
  if [[ -n "${install_name_tool_path}" && -n "${bin_dir}" ]]; then
    local prefix_fallback="${install_name_tool_path##*/}"
    prefix_fallback="${prefix_fallback%-install_name_tool}"
    if [[ -n "${prefix_fallback}" ]]; then
      if [[ ! -x "${bin_dir}/${tool_prefix}-ar" && -x "${bin_dir}/${prefix_fallback}-ar" ]]; then
        tool_prefix="${prefix_fallback}"
      elif [[ ! -x "${bin_dir}/${tool_prefix}-ranlib" && -x "${bin_dir}/${prefix_fallback}-ranlib" ]]; then
        tool_prefix="${prefix_fallback}"
      fi
    fi
  fi
  if [[ -n "${bin_dir}" && -n "${tool_prefix}" ]]; then
    mkdir -p "${shim_bin}"
    if [[ -x "${bin_dir}/${tool_prefix}-install_name_tool" ]]; then
      ln -sf "${bin_dir}/${tool_prefix}-install_name_tool" "${shim_bin}/install_name_tool"
    fi
    if [[ -x "${bin_dir}/${tool_prefix}-otool" ]]; then
      ln -sf "${bin_dir}/${tool_prefix}-otool" "${shim_bin}/otool"
    fi
    if [[ -x "${bin_dir}/${tool_prefix}-lipo" ]]; then
      ln -sf "${bin_dir}/${tool_prefix}-lipo" "${shim_bin}/lipo"
    fi
    if [[ -x "${bin_dir}/${tool_prefix}-strip" ]]; then
      ln -sf "${bin_dir}/${tool_prefix}-strip" "${shim_bin}/strip"
    fi
    if [[ -x "${bin_dir}/${tool_prefix}-ld" ]]; then
      ld_path="${bin_dir}/${tool_prefix}-ld"
    elif [[ -n "${bin_dir}" ]]; then
      if [[ "${arch}" == "arm64" ]]; then
        ld_path="$(ls "${bin_dir}"/arm64-apple-darwin*-ld "${bin_dir}"/aarch64-apple-darwin*-ld 2>/dev/null | head -n 1 || true)"
      else
        ld_path="$(ls "${bin_dir}"/x86_64-apple-darwin*-ld "${bin_dir}"/x86_64h-apple-darwin*-ld 2>/dev/null | head -n 1 || true)"
      fi
    fi
  if [[ -n "${ld_path}" ]]; then
    ln -sf "${ld_path}" "${shim_bin}/ld"
    ln -sf "${ld_path}" "${shim_bin}/ld64"
  fi
  fi

  mkdir -p "${overlay_triplets_dir}"
  cat > "${overlay_triplets_dir}/${triplet}.cmake" <<EOF
set(VCPKG_TARGET_ARCHITECTURE ${triplet_arch})
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE ${lib_linkage})
set(VCPKG_CMAKE_SYSTEM_NAME Darwin)
set(VCPKG_OSX_ARCHITECTURES ${arch})
set(VCPKG_OSX_DEPLOYMENT_TARGET ${MACOS_DEPLOYMENT_TARGET})
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${toolchain_file}")
EOF

  vcpkg_prefix="${vcpkg_root}/installed/${triplet}"
  oqs_include="${vcpkg_prefix}/include"
  if [[ -f "${vcpkg_root}/installed/${triplet}/lib/liboqs.a" ]]; then
    oqs_lib="${vcpkg_root}/installed/${triplet}/lib/liboqs.a"
  elif [[ -f "${vcpkg_root}/installed/${triplet}/lib/liboqs.dylib" ]]; then
    oqs_lib="${vcpkg_root}/installed/${triplet}/lib/liboqs.dylib"
  fi

  cat > "${toolchain_file}" <<EOF
set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_SYSTEM_PROCESSOR ${arch})
set(CMAKE_C_COMPILER ${cc})
set(CMAKE_CXX_COMPILER ${cxx})
set(CMAKE_OSX_SYSROOT ${sdk})
set(CMAKE_OSX_ARCHITECTURES ${arch})
EOF
  if [[ -n "${ld_path}" ]]; then
    cat >> "${toolchain_file}" <<EOF
set(CMAKE_LINKER ${ld_path})
EOF
  fi
  if [[ -n "${install_name_tool_path}" ]]; then
    cat >> "${toolchain_file}" <<EOF
set(CMAKE_INSTALL_NAME_TOOL ${install_name_tool_path})
set(CMAKE_RANLIB ${bin_dir}/${tool_prefix}-ranlib)
set(CMAKE_AR ${bin_dir}/${tool_prefix}-ar)
set(CMAKE_LIPO ${bin_dir}/${tool_prefix}-lipo)
set(CMAKE_STRIP ${bin_dir}/${tool_prefix}-strip)
EOF
  fi
  if [[ -n "${MACOS_DEPLOYMENT_TARGET}" ]]; then
    echo "set(CMAKE_OSX_DEPLOYMENT_TARGET ${MACOS_DEPLOYMENT_TARGET} CACHE STRING \"\" FORCE)" >> "${toolchain_file}"
  fi
  cat >> "${toolchain_file}" <<EOF
set(CMAKE_PREFIX_PATH ${vcpkg_prefix})
set(OPENSSL_ROOT_DIR ${vcpkg_prefix})
set(CMAKE_FIND_ROOT_PATH ${sdk} ${vcpkg_prefix})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
EOF

  if [[ -d "${vcpkg_prefix}" && ! -f "${vcpkg_prefix}/lib/pkgconfig/liblzma.pc" ]]; then
    echo "macOS vcpkg liblzma pkgconfig missing; forcing reinstall."
    PATH="${shim_bin}:${bin_dir}:${PATH}" \
      "${vcpkg_root}/vcpkg" remove --recurse --triplet "${triplet}" liblzma >/dev/null 2>&1 || true
  fi
  if [[ -d "${vcpkg_prefix}" && ! -f "${vcpkg_prefix}/lib/pkgconfig/spdlog.pc" ]]; then
    echo "macOS vcpkg spdlog pkgconfig missing; forcing reinstall."
    PATH="${shim_bin}:${bin_dir}:${PATH}" \
      "${vcpkg_root}/vcpkg" remove --recurse --triplet "${triplet}" spdlog >/dev/null 2>&1 || true
  fi
  if [[ -d "${vcpkg_prefix}" && ! -f "${vcpkg_prefix}/lib/pkgconfig/zlib.pc" ]]; then
    echo "macOS vcpkg zlib pkgconfig missing; forcing reinstall."
    PATH="${shim_bin}:${bin_dir}:${PATH}" \
      "${vcpkg_root}/vcpkg" remove --recurse --triplet "${triplet}" zlib >/dev/null 2>&1 || true
  fi
  if [[ -d "${vcpkg_prefix}" && ! -f "${vcpkg_prefix}/lib/pkgconfig/libzstd.pc" ]]; then
    echo "macOS vcpkg zstd pkgconfig missing; forcing reinstall."
    PATH="${shim_bin}:${bin_dir}:${PATH}" \
      "${vcpkg_root}/vcpkg" remove --recurse --triplet "${triplet}" zstd >/dev/null 2>&1 || true
  fi
  if [[ -d "${vcpkg_prefix}" && ! -f "${vcpkg_prefix}/share/boost/cmake-build/BoostRoot.cmake" ]]; then
    echo "macOS vcpkg boost-cmake missing; forcing reinstall."
    PATH="${shim_bin}:${bin_dir}:${PATH}" \
      "${vcpkg_root}/vcpkg" remove --recurse --triplet "${triplet}" boost-cmake boost-headers >/dev/null 2>&1 || true
  fi
  if [[ -d "${vcpkg_prefix}" && ! -f "${vcpkg_prefix}/include/boost/version.hpp" ]]; then
    echo "macOS vcpkg boost headers missing; forcing reinstall."
    PATH="${shim_bin}:${bin_dir}:${PATH}" \
      "${vcpkg_root}/vcpkg" remove --recurse --triplet "${triplet}" \
      boost-headers boost-system >/dev/null 2>&1 || true
  fi

  PATH="${shim_bin}:${bin_dir}:${PATH}" \
    MACOSX_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}" \
    VCPKG_DISABLE_PARALLEL_CONFIGURE=1 \
    OPENSSL_ROOT_DIR="${vcpkg_prefix}" \
    VCPKG_CHAINLOAD_TOOLCHAIN_FILE="${toolchain_file}" \
    VCPKG_OVERLAY_TRIPLETS="${overlay_triplets_dir}" \
    "${vcpkg_root}/vcpkg" install --triplet "${triplet}" --overlay-triplets="${overlay_triplets_dir}" ${MACOS_VCPKG_PACKAGES}

  local variant_args
  variant_args="$(variant_cmake_args "${variant}")"
  local extra_oqs_args=""
  if [[ -n "${oqs_lib}" && -d "${oqs_include}" ]]; then
    extra_oqs_args="-DOQS_INCLUDE_DIR=${oqs_include} -DOQS_LIBRARY=${oqs_lib}"
  fi

  PATH="${shim_bin}:${bin_dir}:${PATH}" \
    MACOSX_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}" \
    YUME_WINDOWS_CROSS=0 YUME_MACOS_CROSS=1 YUME_SKIP_DEPS=1 YUME_CMAKE_ARGS="${variant_args} -DBASEFWX_USE_VENDOR_DEPS=OFF ${extra_oqs_args} -DCMAKE_TOOLCHAIN_FILE=${vcpkg_root}/scripts/buildsystems/vcpkg.cmake -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=${toolchain_file} -DVCPKG_TARGET_TRIPLET=${triplet} -DVCPKG_OVERLAY_TRIPLETS=${overlay_triplets_dir} -DCMAKE_SYSTEM_NAME=Darwin -DCMAKE_OSX_DEPLOYMENT_TARGET=${MACOS_DEPLOYMENT_TARGET}" \
    ./ezbuild.sh

  copy_build_outputs "${outdir}" "" || return 1
}

macos_triplet_arch() {
  case "${MACOS_TRIPLET}" in
    arm64*|*arm64*) echo "arm64" ;;
    *) echo "x86_64" ;;
  esac
}

build_openwrt_target() {
  local variant="$1"
  local outdir="$2"
  if [[ "${variant}" == "static" ]]; then
    echo "Skipping static mips/openwrt build; ezbuild forces dynamic for OpenWRT." >&2
    return 0
  fi
  require_vendor_dir "${VENDOR_DIR}/openwrt-mips"
  YUME_WINDOWS_CROSS=0 YUME_MACOS_CROSS=0 YUME_CLEAN_BAD_OQS=1 YUME_OQS_STATIC=1 ./ezbuild.sh --openwrt --openwrt-sdk "${OPENWRT_SDK}" --arch mips
  copy_build_outputs "${outdir}" "" || return 1
  if [[ -z "${TOOLCHAIN_STRIP}" ]]; then
    if command -v mipsel-linux-gnu-strip >/dev/null 2>&1; then
      TOOLCHAIN_STRIP="$(command -v mipsel-linux-gnu-strip)"
    else
      echo "OpenWRT strip tool not resolved; check toolchain in ${TOOLCHAIN_BIN}" >&2
      exit 1
    fi
  fi
  "${TOOLCHAIN_STRIP}" --strip-unneeded "${outdir}/yume" "${outdir}/yumed"
}

if [[ "${HOST_OS}" != "Linux" ]]; then
  clean_build_dirs
  case "${HOST_OS}" in
    Darwin)
      build_host_native_target "dynamic" "${BIN_DYNAMIC}/macos/${HOST_ARCH}" ""
      ;;
    MINGW*|MSYS*|CYGWIN*)
      build_host_native_target "dynamic" "${BIN_DYNAMIC}/windows/${HOST_ARCH}" ".exe"
      ;;
    *)
      echo "Unsupported host OS for fullau: ${HOST_OS}" >&2
      exit 1
      ;;
  esac
  exit 0
fi

vendor_restore_if_missing
trap cleanup_temp_assets EXIT
auto_detect_toolchains
ensure_vcpkg
ensure_osxcross
maybe_enable_windows_cross
maybe_enable_macos_cross
if target_enabled windows-x86_64 && [[ "${WINDOWS_CROSS}" -ne 1 ]]; then
  echo "Windows target requested but toolchain/vcpkg not ready; set VCPKG_ROOT and install MinGW compiler pair for ${WINDOWS_TOOLCHAIN_PREFIX}." >&2
  exit 1
fi
if ( target_enabled macos-x86_64 || target_enabled macos-arm64 ) && [[ "${MACOS_CROSS}" -ne 1 ]]; then
  echo "macOS target requested but osxcross/toolchain not ready; set OSXCROSS_ROOT and macOS SDK." >&2
  exit 1
fi
print_build_plan
ensure_host_deps
if target_enabled openwrt-mips; then
  ensure_openwrt_sdk
  if is_truthy "${OPENWRT_FAST_MODE}"; then
    if openwrt_sysroot_ready; then
      echo "OpenWRT fast mode: using pre-staged SDK libs."
    else
      echo "OpenWRT fast mode: SDK libs not staged; skipping openwrt-mips target to keep release fast."
      OPENWRT_TARGET_READY=0
    fi
  else
    ensure_openwrt_sysroot_libs
  fi
fi

if target_enabled openwrt-mips && [[ "${OPENWRT_TARGET_READY}" -eq 1 ]]; then
  clean_build_dirs
  build_openwrt_target "dynamic" "${BIN_DYNAMIC}/mips/openwrt"
  clean_build_dirs
  build_openwrt_target "static" "${BIN_STATIC}/mips/openwrt"
fi

if target_enabled linux-x86_64; then
  clean_build_dirs
  build_host_linux_target "dynamic" "${BIN_DYNAMIC}/x86/linux"
  clean_build_dirs
  build_host_linux_target "static" "${BIN_STATIC}/x86/linux"
fi

# Windows cross build (optional; requires mingw-w64 + vcpkg)
if [[ "${WINDOWS_CROSS}" -eq 1 ]] && target_enabled windows-x86_64; then
  clean_build_dirs
  YUME_WINDOWS_CROSS=1 build_windows_cross_target "dynamic" "${BIN_DYNAMIC}/windows/x86_64"
fi

# macOS cross build (optional; requires osxcross + vcpkg)
if [[ "${MACOS_CROSS}" -eq 1 ]] && ( target_enabled macos-x86_64 || target_enabled macos-arm64 ); then
  clean_build_dirs
  mac_arch="$(macos_triplet_arch)"
  YUME_MACOS_CROSS=1 build_macos_cross_target "dynamic" "${BIN_DYNAMIC}/macos/${mac_arch}"
  clean_build_dirs
  YUME_MACOS_CROSS=1 build_macos_cross_target "static" "${BIN_STATIC}/macos/${mac_arch}"
fi

# Busybox x86
if target_enabled busybox-x86; then
  clean_build_dirs
  if [[ -n "${X86_BUSYBOX_SYSROOT}" && -n "${X86_BUSYBOX_TOOLCHAIN_PREFIX}" ]]; then
    build_busybox_target "x86" "i686" "${X86_BUSYBOX_TOOLCHAIN_PREFIX}" "${X86_BUSYBOX_SYSROOT}" "${BIN_DYNAMIC}/x86/busybox" "dynamic"
    clean_build_dirs
    build_busybox_target "x86" "i686" "${X86_BUSYBOX_TOOLCHAIN_PREFIX}" "${X86_BUSYBOX_SYSROOT}" "${BIN_STATIC}/x86/busybox" "static"
  elif [[ ${USE_DOCKER_FALLBACK} -eq 1 ]]; then
    docker_build_target "x86" "i686" "dockcross/linux-x86" "${BIN_DYNAMIC}/x86/busybox" 1 "dynamic"
    docker_build_target "x86" "i686" "dockcross/linux-x86" "${BIN_STATIC}/x86/busybox" 1 "static"
  else
    require_var X86_BUSYBOX_SYSROOT
    require_var X86_BUSYBOX_TOOLCHAIN_PREFIX
  fi
fi

# ARMv7
if target_enabled armv7-linux; then
  clean_build_dirs
  if [[ -n "${ARMV7_LINUX_SYSROOT}" && -n "${ARMV7_LINUX_TOOLCHAIN_PREFIX}" ]]; then
    build_linux_target "armv7" "armv7" "${ARMV7_LINUX_TOOLCHAIN_PREFIX}" "${ARMV7_LINUX_SYSROOT}" "${BIN_DYNAMIC}/armv7/linux" "dynamic"
    clean_build_dirs
    build_linux_target "armv7" "armv7" "${ARMV7_LINUX_TOOLCHAIN_PREFIX}" "${ARMV7_LINUX_SYSROOT}" "${BIN_STATIC}/armv7/linux" "static"
  elif [[ ${USE_DOCKER_FALLBACK} -eq 1 ]]; then
    docker_build_target "armv7" "armv7" "dockcross/linux-armv7" "${BIN_DYNAMIC}/armv7/linux" 0 "dynamic"
    docker_build_target "armv7" "armv7" "dockcross/linux-armv7" "${BIN_STATIC}/armv7/linux" 0 "static"
  else
    require_var ARMV7_LINUX_SYSROOT
    require_var ARMV7_LINUX_TOOLCHAIN_PREFIX
  fi
fi

if target_enabled armv7-busybox; then
  clean_build_dirs
  if [[ -n "${ARMV7_BUSYBOX_SYSROOT}" && -n "${ARMV7_BUSYBOX_TOOLCHAIN_PREFIX}" ]]; then
    build_busybox_target "armv7" "armv7" "${ARMV7_BUSYBOX_TOOLCHAIN_PREFIX}" "${ARMV7_BUSYBOX_SYSROOT}" "${BIN_DYNAMIC}/armv7/busybox" "dynamic"
    clean_build_dirs
    build_busybox_target "armv7" "armv7" "${ARMV7_BUSYBOX_TOOLCHAIN_PREFIX}" "${ARMV7_BUSYBOX_SYSROOT}" "${BIN_STATIC}/armv7/busybox" "static"
  elif [[ ${USE_DOCKER_FALLBACK} -eq 1 ]]; then
    docker_build_target "armv7" "armv7" "dockcross/linux-armv7" "${BIN_DYNAMIC}/armv7/busybox" 1 "dynamic"
    docker_build_target "armv7" "armv7" "dockcross/linux-armv7" "${BIN_STATIC}/armv7/busybox" 1 "static"
  else
    require_var ARMV7_BUSYBOX_SYSROOT
    require_var ARMV7_BUSYBOX_TOOLCHAIN_PREFIX
  fi
fi

# ARMv8 (aarch64)
if target_enabled armv8-linux; then
  clean_build_dirs
  if [[ -n "${ARMV8_LINUX_SYSROOT}" && -n "${ARMV8_LINUX_TOOLCHAIN_PREFIX}" ]]; then
    build_linux_target "armv8" "aarch64" "${ARMV8_LINUX_TOOLCHAIN_PREFIX}" "${ARMV8_LINUX_SYSROOT}" "${BIN_DYNAMIC}/armv8/linux" "dynamic"
    clean_build_dirs
    build_linux_target "armv8" "aarch64" "${ARMV8_LINUX_TOOLCHAIN_PREFIX}" "${ARMV8_LINUX_SYSROOT}" "${BIN_STATIC}/armv8/linux" "static"
  elif [[ ${USE_DOCKER_FALLBACK} -eq 1 ]]; then
    docker_build_target "armv8" "aarch64" "dockcross/linux-arm64" "${BIN_DYNAMIC}/armv8/linux" 0 "dynamic"
    docker_build_target "armv8" "aarch64" "dockcross/linux-arm64" "${BIN_STATIC}/armv8/linux" 0 "static"
  else
    require_var ARMV8_LINUX_SYSROOT
    require_var ARMV8_LINUX_TOOLCHAIN_PREFIX
  fi
fi

if target_enabled armv8-busybox; then
  clean_build_dirs
  if [[ -n "${ARMV8_BUSYBOX_SYSROOT}" && -n "${ARMV8_BUSYBOX_TOOLCHAIN_PREFIX}" ]]; then
    build_busybox_target "armv8" "aarch64" "${ARMV8_BUSYBOX_TOOLCHAIN_PREFIX}" "${ARMV8_BUSYBOX_SYSROOT}" "${BIN_DYNAMIC}/armv8/busybox" "dynamic"
    clean_build_dirs
    build_busybox_target "armv8" "aarch64" "${ARMV8_BUSYBOX_TOOLCHAIN_PREFIX}" "${ARMV8_BUSYBOX_SYSROOT}" "${BIN_STATIC}/armv8/busybox" "static"
  elif [[ ${USE_DOCKER_FALLBACK} -eq 1 ]]; then
    docker_build_target "armv8" "aarch64" "dockcross/linux-arm64" "${BIN_DYNAMIC}/armv8/busybox" 1 "dynamic"
    docker_build_target "armv8" "aarch64" "dockcross/linux-arm64" "${BIN_STATIC}/armv8/busybox" 1 "static"
  else
    require_var ARMV8_BUSYBOX_SYSROOT
    require_var ARMV8_BUSYBOX_TOOLCHAIN_PREFIX
  fi
fi
