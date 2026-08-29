#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

# Ensure that the host OpenSSL can provide the ML-DSA-87 primitive required by
# YUME's composite identity. This file is intentionally sourceable: ezbuild and
# the release workflow need the resolved prefix to remain active afterwards.

YUME_OPENSSL_MIN_VERSION="${YUME_OPENSSL_MIN_VERSION:-3.5.0}"
YUME_OPENSSL_SOURCE_VERSION="3.5.7"
YUME_OPENSSL_SOURCE_COMMIT="8cf17aaeb4599f8af87fefd810b5b5fee90fe69e"
YUME_OPENSSL_SOURCE_SHA256="a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8"

yume_openssl_log() {
    if declare -F info >/dev/null 2>&1; then
        info "$*"
    else
        printf '[info] %s\n' "$*"
    fi
}

yume_openssl_warn() {
    if declare -F warn >/dev/null 2>&1; then
        warn "$*"
    else
        printf '[warn] %s\n' "$*" >&2
    fi
}

yume_openssl_error() {
    if declare -F error >/dev/null 2>&1; then
        error "$*"
    else
        printf '[error] %s\n' "$*" >&2
    fi
}

yume_openssl_detect() {
    command -v pkg-config >/dev/null 2>&1 \
        && pkg-config --exists "openssl >= ${YUME_OPENSSL_MIN_VERSION}" \
        && command -v openssl >/dev/null 2>&1 \
        && openssl list -signature-algorithms 2>/dev/null \
            | grep -Fq 'ML-DSA-87'
}

yume_openssl_hash_file() {
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

yume_openssl_prepend() {
    local current="$1"
    local value="$2"
    case ":${current}:" in
        *":${value}:"*) printf '%s' "${current}" ;;
        *) printf '%s' "${value}${current:+:${current}}" ;;
    esac
}

yume_openssl_activate_prefix() {
    local prefix="$1"
    local lib_dir="${prefix}/lib"
    local pkgconfig_dir="${lib_dir}/pkgconfig"
    if [[ ! -x "${prefix}/bin/openssl" ||
          ! -f "${prefix}/include/openssl/ssl.h" ||
          ! -f "${prefix}/ssl/openssl.cnf" ||
          ! -d "${pkgconfig_dir}" ]]; then
        return 1
    fi

    export OPENSSL_ROOT_DIR="${prefix}"
    export OPENSSL_MODULES="${lib_dir}/ossl-modules"
    export PATH="$(yume_openssl_prepend "${PATH:-}" "${prefix}/bin")"
    export LD_LIBRARY_PATH="$(yume_openssl_prepend "${LD_LIBRARY_PATH:-}" "${lib_dir}")"
    export PKG_CONFIG_PATH="$(yume_openssl_prepend "${PKG_CONFIG_PATH:-}" "${pkgconfig_dir}")"
    export CMAKE_PREFIX_PATH="$(yume_openssl_prepend "${CMAKE_PREFIX_PATH:-}" "${prefix}")"
    return 0
}

yume_openssl_download() {
    local output="$1"
    local url="$2"
    local tmp_output=""

    tmp_output="$(mktemp "${output}.tmp.XXXXXX")"
    if command -v curl >/dev/null 2>&1; then
        if ! curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
            --output "${tmp_output}" "${url}"; then
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
        yume_openssl_error "curl or wget is required to fetch the OpenSSL fallback."
        return 1
    fi
    mv -- "${tmp_output}" "${output}"
}

# Apply patches/openssl/series to an extracted OpenSSL source tree.
#
# Every patch in the series must be additive and
# default-off, so the resulting library is byte-identical to stock unless a
# caller opts in -- BaseFWX and the rest of the tree link this same build.
#
# A rejected hunk fails the build. Continuing unpatched would silently produce
# a library missing the ClientHello properties the parity backend needs, and
# that failure would only surface later as a wire-gate mismatch.
# OpenSSL can only offer a certificate-compression algorithm it was compiled
# with, so brotli is a Configure-time decision, not a runtime one. Chrome offers
# brotli alone; a build without it can only advertise zlib/zstd, which is a
# visible ClientHello difference. The patched backend is the default, so a
# non-stock series fails closed when Brotli is unavailable; a deliberately
# stock diagnostic build may still warn.
yume_openssl_brotli_available() {
    local probe=""
    for probe in /usr/include/brotli/encode.h /usr/local/include/brotli/encode.h; do
        [[ -f "${probe}" ]] && return 0
    done
    if command -v pkg-config >/dev/null 2>&1 \
        && pkg-config --exists libbrotlienc libbrotlidec; then
        return 0
    fi
    return 1
}

# Short identity for the current patch series, folded into the install prefix.
#
# Without this, a cached prefix built from a DIFFERENT series would be reused
# silently -- the cache key would say "openssl-3.5.7" whether the tree was
# stock or carried YUME's ClientHello changes. Editing a patch would then appear
# to do nothing until someone cleared the cache by hand. Hashing the series
# means a changed patch set is simply a different prefix.
yume_openssl_series_tag() {
    local series_dir="$1"
    local series_file="${series_dir}/series"
    local entry=""
    local digest=""
    local manifest=""

    [[ -f "${series_file}" ]] || { printf 'stock'; return 0; }

    manifest="$(yume_openssl_hash_file "${series_file}" || true)"
    while IFS= read -r entry || [[ -n "${entry}" ]]; do
        entry="${entry%%#*}"
        entry="${entry#"${entry%%[![:space:]]*}"}"
        entry="${entry%"${entry##*[![:space:]]}"}"
        [[ -z "${entry}" ]] && continue
        if [[ -f "${series_dir}/${entry}" ]]; then
            manifest+=" $(yume_openssl_hash_file "${series_dir}/${entry}" || true)"
        else
            manifest+=" missing:${entry}"
        fi
    done < "${series_file}"

    # An empty series is the stock tree, so name it that way rather than
    # burning a hash on "no patches applied".
    if [[ "${manifest}" != *" "* ]]; then
        printf 'stock'
        return 0
    fi
    digest="$(printf '%s' "${manifest}" | (sha256sum 2>/dev/null || shasum -a 256) | awk '{print $1}')"
    printf 'p%s' "${digest:0:12}"
}

yume_openssl_apply_patches() {
    local source_dir="$1"
    local series_dir="$2"
    local series_file="${series_dir}/series"
    local entry=""
    local applied=0

    if [[ ! -f "${series_file}" ]]; then
        yume_openssl_log "No OpenSSL patch series at ${series_file}; building stock."
        return 0
    fi
    if ! command -v patch >/dev/null 2>&1; then
        yume_openssl_error "patch(1) is required to apply the OpenSSL patch series."
        return 1
    fi

    while IFS= read -r entry || [[ -n "${entry}" ]]; do
        entry="${entry%%#*}"
        entry="${entry#"${entry%%[![:space:]]*}"}"
        entry="${entry%"${entry##*[![:space:]]}"}"
        [[ -z "${entry}" ]] && continue
        case "${entry}" in
            /*|*..*)
                yume_openssl_error "Refusing unsafe patch path in series: ${entry}"
                return 1
                ;;
        esac
        if [[ ! -f "${series_dir}/${entry}" ]]; then
            yume_openssl_error "Patch listed in series is missing: ${entry}"
            return 1
        fi
        yume_openssl_log "Applying OpenSSL patch ${entry}..."
        if ! patch -p1 --batch --forward --directory="${source_dir}" \
                 --input="${series_dir}/${entry}"; then
            yume_openssl_error "OpenSSL patch failed to apply cleanly: ${entry}"
            return 1
        fi
        applied=$((applied + 1))
    done < "${series_file}"

    if (( applied == 0 )); then
        yume_openssl_log "OpenSSL patch series is empty; building stock source."
    else
        yume_openssl_log "Applied ${applied} OpenSSL patch(es)."
    fi
    return 0
}

yume_openssl_build_fallback() (
    set -euo pipefail

    local cache_root="$1"
    local prefix="$2"
    local patch_dir="$3"
    local version="${YUME_OPENSSL_SOURCE_VERSION}"
    local archive_dir="${cache_root}/downloads"
    local archive="${archive_dir}/openssl-${version}.tar.gz"
    local source_url="https://github.com/openssl/openssl/releases/download/openssl-${version}/openssl-${version}.tar.gz"
    local work_dir=""
    local actual_hash=""
    local jobs="${YUME_OPENSSL_BUILD_JOBS:-2}"

    # The prefix is deleted and rebuilt below, so it must be exactly the path
    # this function derives -- never a caller-supplied directory. The series tag
    # is part of that identity: openssl-<version>-<stock|pNNNNNNNNNNNN>.
    if [[ "${cache_root}" != /* || "${cache_root}" == "/" ||
          "${prefix}" != "${cache_root}/openssl-${version}-"* ||
          "${prefix}" == *"/.."* ]]; then
        yume_openssl_error "Refusing unsafe OpenSSL cache or install prefix."
        return 1
    fi
    mkdir -p "${archive_dir}" "${cache_root}/locks"
    if command -v flock >/dev/null 2>&1; then
        exec 8>"${cache_root}/locks/openssl-${version}.lock"
        if ! flock -w 30 8; then
            yume_openssl_error "Timed out waiting for another OpenSSL bootstrap process."
            return 1
        fi
    fi

    if yume_openssl_activate_prefix "${prefix}" && yume_openssl_detect; then
        return 0
    fi

    if [[ ! -f "${archive}" ]]; then
        yume_openssl_log "Downloading pinned OpenSSL ${version} source archive..."
        yume_openssl_download "${archive}" "${source_url}"
    fi
    actual_hash="$(yume_openssl_hash_file "${archive}" || true)"
    if [[ -z "${actual_hash}" ]]; then
        yume_openssl_error "sha256sum or shasum is required to verify the OpenSSL source archive."
        return 1
    fi
    if [[ "${actual_hash}" != "${YUME_OPENSSL_SOURCE_SHA256}" ]]; then
        rm -f -- "${archive}"
        yume_openssl_error "OpenSSL source checksum mismatch; the cached archive was removed."
        return 1
    fi

    work_dir="$(mktemp -d "${TMPDIR:-/tmp}/yume-openssl-${version}-XXXXXX")"
    trap 'rm -rf -- "${work_dir}"' EXIT
    tar -xzf "${archive}" -C "${work_dir}" --strip-components=1

    # Patch the verified source before configuring it. Order matters: the
    # checksum above covers the pristine upstream archive, and the series is
    # what turns it into YUME's build.
    if ! yume_openssl_apply_patches "${work_dir}" "${patch_dir}"; then
        return 1
    fi

    case "${prefix}" in
        "${cache_root}"/openssl-*) rm -rf -- "${prefix}" ;;
        *)
            yume_openssl_error "Refusing unsafe OpenSSL install prefix: ${prefix}"
            return 1
            ;;
    esac

    if [[ ! "${jobs}" =~ ^[1-9][0-9]*$ ]]; then
        yume_openssl_error "YUME_OPENSSL_BUILD_JOBS must be a positive integer."
        return 1
    fi
    local brotli_option="no-brotli"
    if yume_openssl_brotli_available; then
        brotli_option="enable-brotli"
    elif [[ "$(yume_openssl_series_tag "${patch_dir}")" != "stock" ]]; then
        yume_openssl_error \
            "The patched openssl-chrome151 backend requires libbrotli development files."
        return 1
    else
        yume_openssl_warn \
            "libbrotli development headers were not found; building OpenSSL without \
brotli. Certificate compression will offer zlib/zstd instead of the cover \
profile's brotli, which is visible in the ClientHello. Install libbrotli-dev to \
close it."
    fi

    yume_openssl_log "Building OpenSSL ${version} with ${jobs} job(s)..."
    (
        cd "${work_dir}"
        ./Configure \
            --prefix="${prefix}" \
            --openssldir="${prefix}/ssl" \
            --libdir=lib \
            shared zlib enable-zstd "${brotli_option}" no-tests
        make -j"${jobs}" build_sw
        make install_sw install_ssldirs
        # install_sw intentionally omits the request configuration.  CI uses
        # this exact openssl binary to mint ephemeral fixture certificates, so
        # keep the checksum-verified source configuration with the otherwise
        # self-contained prefix instead of inheriting a host openssl.cnf.
        install -m 0644 apps/openssl.cnf "${prefix}/ssl/openssl.cnf"
    )
)

yume_openssl_export_github_env() {
    local prefix="$1"
    [[ -n "${GITHUB_ENV:-}" ]] || return 0
    case "${prefix}${PATH:-}${LD_LIBRARY_PATH:-}${PKG_CONFIG_PATH:-}${CMAKE_PREFIX_PATH:-}" in
        *$'\n'*|*$'\r'*)
            yume_openssl_error "Refusing to export newline-containing paths to GitHub Actions."
            return 1
            ;;
    esac
    {
        printf 'OPENSSL_ROOT_DIR=%s\n' "${prefix}"
        printf 'OPENSSL_MODULES=%s\n' "${OPENSSL_MODULES}"
        printf 'LD_LIBRARY_PATH=%s\n' "${LD_LIBRARY_PATH}"
        printf 'PKG_CONFIG_PATH=%s\n' "${PKG_CONFIG_PATH}"
        printf 'CMAKE_PREFIX_PATH=%s\n' "${CMAKE_PREFIX_PATH}"
    } >> "${GITHUB_ENV}"
    if [[ -n "${GITHUB_PATH:-}" ]]; then
        printf '%s/bin\n' "${prefix}" >> "${GITHUB_PATH}"
    fi
}

yume_openssl_ensure() {
    local requested_cache_root="${YUME_CACHE_ROOT:-${HOME}/.cache/yume}"
    local cache_root=""
    local prefix=""
    local found_version=""
    local force_pinned="${YUME_OPENSSL_FORCE_PINNED:-0}"
    local patch_dir="${YUME_OPENSSL_PATCH_DIR:-}"
    local series_tag=""

    if [[ -z "${patch_dir}" ]]; then
        patch_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/patches/openssl"
    fi
    series_tag="$(yume_openssl_series_tag "${patch_dir}")"

    if [[ "${force_pinned}" != "0" && "${force_pinned}" != "1" ]]; then
        yume_openssl_error "YUME_OPENSSL_FORCE_PINNED must be 0 or 1."
        return 1
    fi
    # A non-stock series can only be satisfied by our own build. The host
    # library is unpatched by definition and there is no capability probe for
    # "has YUME's ClientHello patches", so skip host detection entirely rather
    # than accept a library that silently lacks them.
    if [[ "${series_tag}" != "stock" && "${force_pinned}" == "0" ]]; then
        yume_openssl_log \
            "OpenSSL patch series ${series_tag} is active; the host library cannot satisfy it."
        force_pinned=1
    fi
    if [[ "${force_pinned}" == "0" ]] && yume_openssl_detect; then
        found_version="$(pkg-config --modversion openssl)"
        yume_openssl_log "OpenSSL ${found_version} with ML-DSA-87 detected (required >= ${YUME_OPENSSL_MIN_VERSION})."
        return 0
    fi

    if ! mkdir -p "${requested_cache_root}" ||
       ! cache_root="$(cd "${requested_cache_root}" && pwd -P)" ||
       [[ "${cache_root}" == "/" ]]; then
        yume_openssl_error "OpenSSL cache root must be a writable directory below the filesystem root."
        return 1
    fi
    prefix="${cache_root}/openssl-${YUME_OPENSSL_SOURCE_VERSION}-${series_tag}"

    if yume_openssl_activate_prefix "${prefix}" && yume_openssl_detect; then
        found_version="$(pkg-config --modversion openssl)"
        yume_openssl_log "Using cached OpenSSL ${found_version} from ${prefix}."
    else
        found_version="$(pkg-config --modversion openssl 2>/dev/null || true)"
        if [[ -n "${found_version}" ]]; then
            yume_openssl_warn "OpenSSL ${found_version} does not satisfy the >= ${YUME_OPENSSL_MIN_VERSION} ML-DSA requirement."
        else
            yume_openssl_warn "OpenSSL development files were not detected by pkg-config."
        fi
        if [[ "${YUME_SKIP_DEPS:-0}" == "1" || -n "${YUME_VENDOR_ONLY:-}" ]]; then
            yume_openssl_error "Install OpenSSL >= ${YUME_OPENSSL_MIN_VERSION} with ML-DSA-87 support or allow ezbuild to create its pinned user-cache fallback."
            return 1
        fi
        for command_name in perl make tar; do
            if ! command -v "${command_name}" >/dev/null 2>&1; then
                yume_openssl_error "${command_name} is required to build the OpenSSL fallback."
                return 1
            fi
        done
        yume_openssl_build_fallback "${cache_root}" "${prefix}" "${patch_dir}" || return 1
        if ! yume_openssl_activate_prefix "${prefix}" || ! yume_openssl_detect; then
            yume_openssl_error "The OpenSSL fallback completed but ML-DSA-87 is unavailable."
            return 1
        fi
        found_version="$(pkg-config --modversion openssl)"
        yume_openssl_log "Using source-built OpenSSL ${found_version} from ${prefix}."
    fi

    yume_openssl_export_github_env "${prefix}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -euo pipefail
    yume_openssl_ensure
fi
