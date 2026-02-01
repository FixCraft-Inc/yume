#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="/home/f1xgod/bins"
OPENWRT_SDK="/home/f1xgod/openwrt-sdk-24.10.0-ath79-nand_gcc-13.3.0_musl.Linux-x86_64"
SYSROOT="${OPENWRT_SDK}/staging_dir/target-mips_24kc_musl"
TOOLCHAIN_BIN="${OPENWRT_SDK}/staging_dir/toolchain-mips_24kc_gcc-13.3.0_musl/bin"
OQS_SRC="/home/f1xgod/liboqs"
OQS_BUILD_MIPS="/tmp/liboqs-mips-build"
OQS_BUILD_HOST="/tmp/liboqs-host-build"

mkdir -p "${BIN_DIR}"
rm -f "${BIN_DIR}"/*
rm -rf build basefwx/cpp/build

build_liboqs_mips() {
  if [ ! -d "${OQS_SRC}" ]; then
    echo "liboqs source not found at ${OQS_SRC}" >&2
    exit 1
  fi
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
    -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
    -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER \
    -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
    -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
    -DCMAKE_INSTALL_PREFIX="${SYSROOT}/usr" \
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

build_liboqs_mips

YUME_CLEAN_BAD_OQS=1 YUME_OQS_STATIC=1 ./ezbuild.sh --openwrt --openwrt-sdk "${OPENWRT_SDK}" --arch mips
cp -f build/bin/yume "${BIN_DIR}/yume_mips"
cp -f build/bin/yumed "${BIN_DIR}/yumed_mips"
"${TOOLCHAIN_BIN}/mips-openwrt-linux-musl-strip" --strip-unneeded "${BIN_DIR}/yume_mips" "${BIN_DIR}/yumed_mips"

rm -rf build basefwx/cpp/build
build_liboqs_host
YUME_OQS_STATIC=1 ./ezbuild.sh
cp -f build/bin/* "${BIN_DIR}/"
strip "${BIN_DIR}/yume" "${BIN_DIR}/yumed"
upx -9 "${BIN_DIR}"/*
