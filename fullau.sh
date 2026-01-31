#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="/home/user/bins"
OPENWRT_SDK="/home/user/openwrt-sdk-24.10.0-ath79-nand_gcc-13.3.0_musl.Linux-x86_64"

mkdir -p "${BIN_DIR}"
rm -f "${BIN_DIR}"/*
rm -rf build basefwx/cpp/build

YUME_CLEAN_BAD_OQS=1 YUME_OQS_STATIC=1 ./ezbuild.sh --openwrt --openwrt-sdk "${OPENWRT_SDK}" --arch mips
cp -f build/bin/yume "${BIN_DIR}/yume_mips"
cp -f build/bin/yumed "${BIN_DIR}/yumed_mips"
mips-linux-gnu-strip --strip-unneeded "${BIN_DIR}/yume_mips" "${BIN_DIR}/yumed_mips"

rm -rf build basefwx/cpp/build
YUME_OQS_STATIC=1 ./ezbuild.sh
cp -f build/bin/* "${BIN_DIR}/"
strip "${BIN_DIR}/yume" "${BIN_DIR}/yumed"
upx -9 "${BIN_DIR}"/*
