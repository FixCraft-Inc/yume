#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

# Ensure that the host has the nghttp2 API level required by YUME 2.0.
# This file is intentionally sourceable: ezbuild needs PKG_CONFIG_PATH to
# remain set after a cached/source-built fallback is selected.

YUME_NGHTTP2_MIN_VERSION="${YUME_NGHTTP2_MIN_VERSION:-1.64.0}"
YUME_NGHTTP2_SOURCE_VERSION="1.69.0"
YUME_NGHTTP2_SOURCE_SHA256="c866b7477cbb7512ab6863a685027adbb1bb8da8fc3bab7429ed43d3281d5aa9"

yume_nghttp2_log() {
    if declare -F info >/dev/null 2>&1; then
        info "$*"
    else
        printf '[info] %s\n' "$*"
    fi
}

yume_nghttp2_warn() {
    if declare -F warn >/dev/null 2>&1; then
        warn "$*"
    else
        printf '[warn] %s\n' "$*" >&2
    fi
}

yume_nghttp2_error() {
    if declare -F error >/dev/null 2>&1; then
        error "$*"
    else
        printf '[error] %s\n' "$*" >&2
    fi
}

yume_nghttp2_detect() {
    command -v pkg-config >/dev/null 2>&1 \
        && pkg-config --exists "libnghttp2 >= ${YUME_NGHTTP2_MIN_VERSION}"
}

yume_nghttp2_hash_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${path}" | awk '{print $1}'
        return 0
    fi
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${path}" | awk '{print $1}'
        return 0
    fi
    return 1
}

yume_nghttp2_pkgconfig_dir() {
    local prefix="$1"
    [[ -d "${prefix}" ]] || return 1
    find "${prefix}" -type f -name libnghttp2.pc -print -quit 2>/dev/null \
        | sed 's#/libnghttp2\.pc$##'
}

yume_nghttp2_activate_prefix() {
    local prefix="$1"
    local pc_dir=""
    pc_dir="$(yume_nghttp2_pkgconfig_dir "${prefix}")"
    if [[ -z "${pc_dir}" ]]; then
        return 1
    fi
    case ":${PKG_CONFIG_PATH:-}:" in
        *":${pc_dir}:"*) ;;
        *) export PKG_CONFIG_PATH="${pc_dir}${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}" ;;
    esac
    return 0
}

yume_nghttp2_download() {
    local output="$1"
    local url="$2"
    local tmp_output=""

    tmp_output="$(mktemp "${output}.tmp.XXXXXX")"
    if command -v curl >/dev/null 2>&1; then
        if ! curl --fail --location --proto '=https' --tlsv1.2 \
            --retry 3 --output "${tmp_output}" "${url}"; then
            rm -f -- "${tmp_output}"
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget --https-only --tries=3 --output-document="${tmp_output}" "${url}"; then
            rm -f -- "${tmp_output}"
            return 1
        fi
    else
        rm -f -- "${tmp_output}"
        yume_nghttp2_error "curl or wget is required to fetch the nghttp2 fallback."
        return 1
    fi
    mv -- "${tmp_output}" "${output}"
}

yume_nghttp2_build_fallback() (
    set -euo pipefail

    local cache_root="$1"
    local prefix="$2"
    local version="${YUME_NGHTTP2_SOURCE_VERSION}"
    local archive_dir="${cache_root}/downloads"
    local archive="${archive_dir}/nghttp2-${version}.tar.gz"
    local source_url="https://github.com/nghttp2/nghttp2/releases/download/v${version}/nghttp2-${version}.tar.gz"
    local work_dir=""
    local actual_hash=""
    local jobs="4"

    if [[ -n "${YUME_NGHTTP2_BUILD_JOBS:-}" ]]; then
        if [[ ! "${YUME_NGHTTP2_BUILD_JOBS}" =~ ^[1-9][0-9]*$ ]]; then
            yume_nghttp2_error "YUME_NGHTTP2_BUILD_JOBS must be a positive integer."
            return 1
        fi
        jobs="${YUME_NGHTTP2_BUILD_JOBS}"
    elif command -v nproc >/dev/null 2>&1; then
        jobs="$(nproc)"
    elif command -v sysctl >/dev/null 2>&1; then
        jobs="$(sysctl -n hw.ncpu 2>/dev/null || printf '4')"
    fi

    mkdir -p "${archive_dir}" "${cache_root}/locks"
    if command -v flock >/dev/null 2>&1; then
        exec 8>"${cache_root}/locks/nghttp2-${version}.lock"
        if ! flock -w 30 8; then
            yume_nghttp2_error "Timed out waiting for another nghttp2 bootstrap process."
            return 1
        fi
    fi

    # Another process may have completed the prefix while this one waited.
    if yume_nghttp2_activate_prefix "${prefix}" && yume_nghttp2_detect; then
        return 0
    fi

    if [[ ! -f "${archive}" ]]; then
        yume_nghttp2_log "Downloading pinned nghttp2 ${version} source archive..."
        yume_nghttp2_download "${archive}" "${source_url}"
    fi
    actual_hash="$(yume_nghttp2_hash_file "${archive}" || true)"
    if [[ -z "${actual_hash}" ]]; then
        yume_nghttp2_error "sha256sum or shasum is required to verify the nghttp2 source archive."
        return 1
    fi
    if [[ "${actual_hash}" != "${YUME_NGHTTP2_SOURCE_SHA256}" ]]; then
        rm -f -- "${archive}"
        yume_nghttp2_error "nghttp2 source checksum mismatch; the cached archive was removed."
        return 1
    fi

    work_dir="$(mktemp -d "${TMPDIR:-/tmp}/yume-nghttp2-${version}-XXXXXX")"
    trap 'rm -rf -- "${work_dir}"' EXIT
    tar -xzf "${archive}" -C "${work_dir}" --strip-components=1

    # The prefix is fixed beneath YUME_CACHE_ROOT. Refuse to remove anything
    # if that invariant changes, even if a caller supplies hostile variables.
    case "${prefix}" in
        "${cache_root}"/nghttp2-*) rm -rf -- "${prefix}" ;;
        *)
            yume_nghttp2_error "Refusing unsafe nghttp2 install prefix: ${prefix}"
            return 1
            ;;
    esac

    yume_nghttp2_log "Building nghttp2 ${version} (lib-only fallback)..."
    cmake -S "${work_dir}" -B "${work_dir}/build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="${prefix}" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DENABLE_LIB_ONLY=ON \
        -DENABLE_DOC=OFF \
        -DENABLE_FAILMALLOC=OFF \
        -DWITH_LIBXML2=OFF \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_STATIC_LIBS=ON \
        -DBUILD_TESTING=OFF
    cmake --build "${work_dir}/build" --parallel "${jobs}"
    cmake --install "${work_dir}/build"
)

yume_nghttp2_ensure() {
    local cache_root="${YUME_CACHE_ROOT:-${HOME}/.cache/yume}"
    local prefix="${cache_root}/nghttp2-${YUME_NGHTTP2_SOURCE_VERSION}"
    local found_version=""
    local pc_dir=""

    if yume_nghttp2_detect; then
        found_version="$(pkg-config --modversion libnghttp2)"
        yume_nghttp2_log "libnghttp2 ${found_version} detected (required >= ${YUME_NGHTTP2_MIN_VERSION})."
        return 0
    fi

    # Prefer an already verified cache before considering a network build.
    if yume_nghttp2_activate_prefix "${prefix}" && yume_nghttp2_detect; then
        found_version="$(pkg-config --modversion libnghttp2)"
        yume_nghttp2_log "Using cached libnghttp2 ${found_version} from ${prefix}."
    else
        found_version="$(pkg-config --modversion libnghttp2 2>/dev/null || true)"
        if [[ -n "${found_version}" ]]; then
            yume_nghttp2_warn "libnghttp2 ${found_version} is below the required ${YUME_NGHTTP2_MIN_VERSION}."
        else
            yume_nghttp2_warn "libnghttp2 development files were not detected by pkg-config."
        fi
        if [[ "${YUME_SKIP_DEPS:-0}" == "1" || -n "${YUME_VENDOR_ONLY:-}" ]]; then
            yume_nghttp2_error "Install libnghttp2 >= ${YUME_NGHTTP2_MIN_VERSION} or allow ezbuild to create its pinned user-cache fallback."
            return 1
        fi
        if ! command -v cmake >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
            yume_nghttp2_error "cmake and tar are required to build the nghttp2 fallback."
            return 1
        fi
        if ! yume_nghttp2_build_fallback "${cache_root}" "${prefix}"; then
            return 1
        fi
        if ! yume_nghttp2_activate_prefix "${prefix}" || ! yume_nghttp2_detect; then
            yume_nghttp2_error "The nghttp2 fallback completed but pkg-config cannot resolve libnghttp2 >= ${YUME_NGHTTP2_MIN_VERSION}."
            return 1
        fi
        found_version="$(pkg-config --modversion libnghttp2)"
        yume_nghttp2_log "Using source-built libnghttp2 ${found_version} from ${prefix}."
    fi

    # Standalone CI invocation cannot export into its parent shell. Persist the
    # resolved pkg-config path for subsequent GitHub Actions steps when asked.
    pc_dir="$(yume_nghttp2_pkgconfig_dir "${prefix}")"
    if [[ -n "${GITHUB_ENV:-}" && -n "${pc_dir}" ]]; then
        printf 'PKG_CONFIG_PATH=%s\n' "${PKG_CONFIG_PATH}" >> "${GITHUB_ENV}"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -euo pipefail
    yume_nghttp2_ensure
fi
