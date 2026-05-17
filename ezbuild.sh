#!/usr/bin/env bash
set -euo pipefail

# YUME ezbuild: install dependencies and build

LOG_FILE="crashed.log"
: > "${LOG_FILE}"
exec > >(tee -a "${LOG_FILE}") 2>&1

COLOR_RESET="\033[0m"
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_BLUE="\033[0;34m"
COLOR_MAGENTA="\033[0;35m"

MINIMAL=0
TARGET_ARCH=""
CLEAN_ONLY=0
BUILD_DEB=0
BUILD_GUI=0
PORTABLE=0
SKIP_PULL=0
OPENWRT=0
BUSYBOX=0
OPENWRT_SDK=""
SYSROOT_PATH=""
CMAKE_ARGS=()
EXTRA_CMAKE_ARGS=()
WINDOWS_CROSS="${YUME_WINDOWS_CROSS:-0}"
WINDOWS_TOOLCHAIN_PREFIX="${YUME_WINDOWS_TOOLCHAIN_PREFIX:-x86_64-w64-mingw32}"
WINDOWS_TRIPLET="${YUME_WINDOWS_TRIPLET:-x64-mingw-dynamic}"
VCPKG_ROOT="${VCPKG_ROOT:-}"
VCPKG_PREFIX=""
BASEFWX_REPO="${BASEFWX_REPO:-https://github.com/F1xGOD/basefwx.git}"
BASEFWX_REF="${BASEFWX_REF:-${YUME_BASEFWX_REF:-}}"
BASEFWX_REF_FILE="${BASEFWX_REF_FILE:-${PWD}/.basefwx-ref}"
YUME_REQUIRE_ARGON2="${YUME_REQUIRE_ARGON2:-0}"
YUME_REQUIRE_OQS="${YUME_REQUIRE_OQS:-0}"

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

resolve_real_uid() {
    local uid
    uid="$(id -u)"
    if [[ -n "${SUDO_USER:-}" ]]; then
        local sudo_uid
        sudo_uid="$(id -u "${SUDO_USER}" 2>/dev/null || true)"
        if [[ -n "${sudo_uid}" ]]; then
            uid="${sudo_uid}"
        fi
    fi
    echo "${uid}"
}

init_tmp_root() {
    local requested="${YUME_TMP_ROOT:-}"
    if [[ -n "${requested}" ]]; then
        mkdir -p "${requested}"
        echo "${requested}|0"
        return 0
    fi
    local created
    created="$(mktemp -d "${TMPDIR:-/tmp}/yume-ezbuild-${REAL_UID}-XXXXXX")"
    echo "${created}|1"
}

REAL_HOME="$(resolve_real_home)"
REAL_UID="$(resolve_real_uid)"
YUME_CACHE_ROOT="${YUME_CACHE_ROOT:-${REAL_HOME}/.cache/yume}"
mkdir -p "${YUME_CACHE_ROOT}"
IFS='|' read -r YUME_TMP_ROOT YUME_TMP_ROOT_AUTO <<< "$(init_tmp_root)"
APT_UPDATED_FLAG="${APT_UPDATED_FLAG:-${YUME_CACHE_ROOT}/apt-updated}"

if [[ -z "${BASEFWX_REF}" && -f "${BASEFWX_REF_FILE}" ]]; then
    BASEFWX_REF="$(tr -d '[:space:]' < "${BASEFWX_REF_FILE}")"
fi

info()  { echo -e "${COLOR_BLUE}[info] $*${COLOR_RESET}"; }
warn()  { echo -e "${COLOR_YELLOW}[warn] $*${COLOR_RESET}"; }
error() { echo -e "${COLOR_RED}[error] $*${COLOR_RESET}"; }
ok()    { echo -e "${COLOR_GREEN}[ok] $*${COLOR_RESET}"; }
step()  { echo -e "${COLOR_MAGENTA}[step] $*${COLOR_RESET}"; }

usage() {
    cat <<'EOF'
Usage: ./ezbuild.sh [options]

Options:
  --clean                 Remove the build directory and exit
  --minimal               Build a minimal/static YUME
  --gui                   Also build the optional yume-gui desktop app
                          (installs libgl/libglfw/appindicator dev pkgs)
  --portable, --static    Produce single self-contained binaries (no
                          MinGW/vcpkg DLLs alongside). For the cross
                          route this pins WINDOWS_TRIPLET to
                          x64-mingw-static; combine with --gui to get
                          one portable yume-gui.exe.
  --deb, --package-deb    Build a Debian package with CPack
  --arch <arch>           Target arch metadata/toolchain hint
                          examples: x86_64, aarch64, armv8, armv7, mips
  --openwrt               OpenWRT/minimal build mode
  --busybox               BusyBox/minimal build mode
  --openwrt-sdk <path>    OpenWRT SDK path
  -h, --help              Show this help

Useful environment variables:
  YUME_BUILD_DIR          Build directory (default: build)
  YUME_CMAKE_ARGS         Extra CMake arguments
  YUME_TOOLCHAIN_FILE     CMake toolchain file for cross builds
  YUME_TMP_ROOT           Temporary work directory
EOF
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# Fetch the tracking branch and fast-forward if remote is ahead. We never
# rewrite local commits, never touch a dirty tree, and we only operate on
# the current branch's tracking remote. Failure is a warning, not fatal,
# so an offline laptop still builds.
maybe_sync_repo() {
    if [[ $SKIP_PULL -eq 1 ]]; then
        info "Repo sync skipped (--no-pull)."
        return 0
    fi
    if ! need_cmd git; then
        return 0
    fi
    if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        return 0
    fi
    local upstream
    if ! upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null); then
        info "No upstream tracking branch; skipping repo sync."
        return 0
    fi
    if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
        warn "Working tree is dirty; skipping repo sync."
        return 0
    fi
    step "Checking ${upstream} for newer commits..."
    if ! git fetch --quiet 2>/dev/null; then
        warn "git fetch failed; building with the current checkout."
        return 0
    fi
    local local_sha remote_sha base_sha
    local_sha=$(git rev-parse @ 2>/dev/null || echo "")
    remote_sha=$(git rev-parse "@{upstream}" 2>/dev/null || echo "")
    base_sha=$(git merge-base @ "@{upstream}" 2>/dev/null || echo "")
    if [[ -z "$local_sha" || -z "$remote_sha" ]]; then
        return 0
    fi
    if [[ "$local_sha" == "$remote_sha" ]]; then
        ok "Repo is up to date with ${upstream}."
        return 0
    fi
    if [[ "$local_sha" == "$base_sha" ]]; then
        step "Local branch is behind ${upstream}; fast-forwarding..."
        if git merge --ff-only --quiet "@{upstream}"; then
            ok "Pulled new commits from ${upstream}."
        else
            warn "Fast-forward failed; continuing with the existing checkout."
        fi
        return 0
    fi
    if [[ "$remote_sha" == "$base_sha" ]]; then
        info "Local branch has commits not on ${upstream}; nothing to pull."
        return 0
    fi
    warn "Local and ${upstream} have diverged; build will use the local checkout. Resolve manually."
}

init_lock_root() {
    local requested="${YUME_LOCK_ROOT:-${YUME_CACHE_ROOT}/locks}"
    if mkdir -p "${requested}" 2>/dev/null && [[ -w "${requested}" ]]; then
        echo "${requested}"
        return 0
    fi
    mkdir -p "${YUME_TMP_ROOT}/locks"
    echo "${YUME_TMP_ROOT}/locks"
}

hash_string() {
    local input="$1"
    if need_cmd sha256sum; then
        printf '%s' "${input}" | sha256sum | awk '{print $1}'
        return 0
    fi
    if need_cmd shasum; then
        printf '%s' "${input}" | shasum -a 256 | awk '{print $1}'
        return 0
    fi
    printf '%s' "${input}" | cksum | awk '{print $1}'
}

cleanup_temp_assets() {
    if [[ "${YUME_TMP_ROOT_AUTO:-0}" == "1" && -n "${YUME_TMP_ROOT:-}" ]]; then
        rm -rf "${YUME_TMP_ROOT}"
    fi
    # If we unpacked the vendor archive on demand, drop the marker
    # file but leave the extracted tree in place when the build
    # failed — that way the user can inspect what got staged before
    # rerunning. cleanup_unpacked_vendor() does the actual removal
    # and is called explicitly on the success path so a hard failure
    # never wipes the only artifact the user has.
    :
}

YUME_VENDOR_UNPACK_MARKER=".ezbuild-vendor-unpacked"

# Where the prebuilt tarball lives. The same archive ships every
# vendored target (linux-x86_64, macos-arm64, …), so a single tarball
# covers Linux/macOS native and the WINDOWS_CROSS path.
YUME_VENDOR_ARCHIVE_DEFAULT="${PWD}/yume-vendor-prebuilt.tar.xz"

# Extracts yume-vendor-prebuilt.tar.xz into ./vendor/ on demand and
# remembers (in the marker file) exactly which top-level entries we
# created, so cleanup_unpacked_vendor() removes only those — never a
# user-staged vendor/<arch>/ that pre-existed.
ensure_vendor_for_host() {
    local needed_key="${1:-}"
    local archive="${YUME_VENDOR_ARCHIVE:-${YUME_VENDOR_ARCHIVE_DEFAULT}}"

    # If the target vendor dir is already there, do nothing — the
    # repo maintainer either checked it in or unpacked it manually,
    # and either way we leave it alone.
    if [[ -n "${needed_key}" && -d "${PWD}/vendor/${needed_key}" ]]; then
        return 0
    fi
    if [[ ! -f "${archive}" ]]; then
        return 1
    fi
    if ! need_cmd tar; then
        warn "Cannot unpack ${archive}: tar not found."
        return 1
    fi

    step "Unpacking ${archive} for the host build..."
    # List the tar's top-level entries before we extract so the marker
    # records exactly what we owned. Format: one path per line,
    # relative to repo root.
    local marker="${PWD}/vendor/${YUME_VENDOR_UNPACK_MARKER}"
    local before=""
    if [[ -d "${PWD}/vendor" ]]; then
        before="$(ls -A "${PWD}/vendor" 2>/dev/null || true)"
    fi
    mkdir -p "${PWD}/vendor"
    if ! tar -xJf "${archive}" -C "${PWD}"; then
        warn "Vendor archive extraction failed."
        return 1
    fi
    local after=""
    after="$(ls -A "${PWD}/vendor" 2>/dev/null || true)"
    : > "${marker}"
    local entry
    while IFS= read -r entry; do
        [[ -z "${entry}" ]] && continue
        if ! grep -Fxq -- "${entry}" <<<"${before}"; then
            printf 'vendor/%s\n' "${entry}" >> "${marker}"
        fi
    done <<<"${after}"
    ok "Vendor archive unpacked."
    return 0
}

# Remove only the paths we wrote during ensure_vendor_for_host. Safe
# to call when no unpack happened — it just returns. Called explicitly
# at the end of a successful build.
cleanup_unpacked_vendor() {
    local marker="${PWD}/vendor/${YUME_VENDOR_UNPACK_MARKER}"
    if [[ ! -f "${marker}" ]]; then
        return 0
    fi
    if [[ "${YUME_KEEP_VENDOR:-0}" == "1" ]]; then
        info "YUME_KEEP_VENDOR=1: leaving unpacked vendor tree in place."
        return 0
    fi
    step "Cleaning up vendor artifacts unpacked by ezbuild..."
    local path
    while IFS= read -r path; do
        [[ -z "${path}" ]] && continue
        # Defensive: only remove paths inside vendor/.
        case "${path}" in
            vendor/*) rm -rf -- "${PWD}/${path}" ;;
            *) warn "Refusing to remove unexpected path '${path}'." ;;
        esac
    done <"${marker}"
    rm -f "${marker}"
    rmdir "${PWD}/vendor" 2>/dev/null || true
    ok "Vendor cleanup complete."
}

YUME_LOCK_ROOT="$(init_lock_root)"
trap cleanup_temp_assets EXIT

env_truthy() {
    local value="${1:-}"
    case "${value,,}" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

require_feature_or_die() {
    local env_value="${1:-}"
    local feature_name="$2"
    local hint="$3"
    if env_truthy "${env_value}"; then
        error "${feature_name} is mandatory for this build. ${hint}"
        exit 1
    fi
}

apt_update_once() {
    if ! need_cmd apt-get; then
        return 0
    fi
    if [[ -f "${APT_UPDATED_FLAG}" ]]; then
        return 0
    fi
    sudo apt-get update -y
    touch "${APT_UPDATED_FLAG}"
}

detect_vcpkg_root() {
    if [[ -n "${VCPKG_ROOT:-}" && -x "${VCPKG_ROOT}/vcpkg" ]]; then
        echo "${VCPKG_ROOT}"
        return 0
    fi
    for candidate in "${REAL_HOME}/vcpkg" "${REAL_HOME}/src/vcpkg" "${REAL_HOME}/.vcpkg" "/opt/vcpkg"; do
        if [[ -x "${candidate}/vcpkg" ]]; then
            echo "${candidate}"
            return 0
        fi
    done
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
    return 1
}

host_default_vendor_key() {
    local host_os host_arch
    host_os="$(uname -s)"
    host_arch="$(uname -m)"

    case "${host_os}" in
        Linux)
            case "${host_arch}" in
                x86_64|amd64) echo "linux-x86_64" ;;
                i?86) echo "x86" ;;
                aarch64|arm64) echo "armv8" ;;
                armv7l|armv7) echo "armv7" ;;
                *) echo "" ;;
            esac
            ;;
        Darwin)
            case "${host_arch}" in
                x86_64|amd64) echo "macos-x86_64" ;;
                arm64|aarch64) echo "macos-arm64" ;;
                *) echo "" ;;
            esac
            ;;
        *)
            echo ""
            ;;
    esac
}

vendor_dir_for_build() {
    if [[ $OPENWRT -eq 1 && -d "${PWD}/vendor/openwrt-mips" ]]; then
        echo "${PWD}/vendor/openwrt-mips"
        return
    fi
    if [[ $BUSYBOX -eq 1 && -n "${TARGET_ARCH}" && -d "${PWD}/vendor/busybox-${TARGET_ARCH}" ]]; then
        echo "${PWD}/vendor/busybox-${TARGET_ARCH}"
        return
    fi
    if [[ -n "${TARGET_ARCH}" && -d "${PWD}/vendor/${TARGET_ARCH}" ]]; then
        echo "${PWD}/vendor/${TARGET_ARCH}"
        return
    fi

    local host_vendor_key=""
    host_vendor_key="$(host_default_vendor_key)"
    if [[ -n "${host_vendor_key}" && -d "${PWD}/vendor/${host_vendor_key}" ]]; then
        echo "${PWD}/vendor/${host_vendor_key}"
        return
    fi
    echo ""
}

vendor_has_liboqs() {
    local dir="$1"
    [[ -n "${dir}" ]] || return 1
    [[ -f "${dir}/include/oqs/oqs.h" ]] || return 1
    if compgen -G "${dir}/lib/liboqs*" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

vendor_has_argon2() {
    local dir="$1"
    [[ -n "${dir}" ]] || return 1
    [[ -f "${dir}/include/argon2.h" ]] || return 1
    if compgen -G "${dir}/lib/libargon2*" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

vendor_has_cross_prefix() {
    local dir="$1"
    [[ -n "${dir}" ]] || return 1
    [[ -f "${dir}/include/boost/asio.hpp" ]] || return 1
    [[ -f "${dir}/include/openssl/ssl.h" ]] || return 1
    [[ -f "${dir}/include/zlib.h" ]] || return 1
    [[ -d "${dir}/share/boost" ]] || return 1
    [[ -d "${dir}/share/zstd" ]] || return 1
    return 0
}

windows_vendor_dir() {
    local dir="${PWD}/vendor/windows-x86_64"
    if vendor_has_cross_prefix "${dir}"; then
        echo "${dir}"
        return 0
    fi
    return 1
}

macos_vendor_dir() {
    local arch="${YUME_MACOS_VENDOR_ARCH:-}"
    local dir=""
    if [[ "${arch}" == "arm64" ]]; then
        dir="${PWD}/vendor/macos-arm64"
        if vendor_has_cross_prefix "${dir}"; then
            echo "${dir}"
            return 0
        fi
    fi
    if [[ -z "${arch}" || "${arch}" == "x86_64" ]]; then
        dir="${PWD}/vendor/macos-x86_64"
        if vendor_has_cross_prefix "${dir}"; then
            echo "${dir}"
            return 0
        fi
    fi
    return 1
}

detect_liboqs() {
    if need_cmd pkg-config && pkg-config --exists liboqs; then
        return 0
    fi
    if [[ -n "${OPENWRT_USR:-}" ]]; then
        if [[ -f "${OPENWRT_USR}/include/oqs/oqs.h" ]]; then
            return 0
        fi
        if [[ -f "${OPENWRT_USR}/lib/liboqs.so" ]] || [[ -f "${OPENWRT_USR}/lib/liboqs.a" ]]; then
            return 0
        fi
    fi
    if [[ -f /usr/include/oqs/oqs.h ]] || [[ -f /usr/local/include/oqs/oqs.h ]]; then
        return 0
    fi
    if [[ -f /usr/lib/x86_64-linux-gnu/liboqs.a ]] || [[ -f /usr/lib/liboqs.a ]] || [[ -f /usr/local/lib/liboqs.a ]]; then
        return 0
    fi
    if [[ -f /usr/lib/x86_64-linux-gnu/liboqs.so ]] || [[ -f /usr/lib/liboqs.so ]] || [[ -f /usr/local/lib/liboqs.so ]] || [[ -f /usr/lib/x86_64-linux-gnu/liboqs.so.* ]] || [[ -f /usr/lib/liboqs.so.* ]] || [[ -f /usr/local/lib/liboqs.so.* ]]; then
        return 0
    fi
    return 1
}

detect_argon2() {
    if need_cmd pkg-config && pkg-config --exists libargon2; then
        return 0
    fi
    if [[ -n "${OPENWRT_USR:-}" ]]; then
        if [[ -f "${OPENWRT_USR}/include/argon2.h" ]]; then
            return 0
        fi
        if [[ -f "${OPENWRT_USR}/lib/libargon2.so" ]] || [[ -f "${OPENWRT_USR}/lib/libargon2.a" ]]; then
            return 0
        fi
        if [[ -n "$(ls -1 "${OPENWRT_USR}/lib/libargon2.so."* 2>/dev/null | head -n 1)" ]]; then
            return 0
        fi
    fi
    # BUSYBOX cross builds: also check the vendor sysroot we stage to.
    # Without this the function would happily report true based on the
    # host argon2.h alone, but resolve_argon2_sysroot_paths would then
    # return empty paths and the build aborts with
    #   "libargon2 headers found but library missing".
    if [[ "${BUSYBOX:-0}" -eq 1 && -n "${TARGET_ARCH:-}" ]]; then
        local _vendor="${PWD}/vendor/busybox-${TARGET_ARCH}"
        if [[ -f "${_vendor}/include/argon2.h" \
              && ( -f "${_vendor}/lib/libargon2.a" || -f "${_vendor}/lib/libargon2.so" ) ]]; then
            return 0
        fi
        # Cross build but no vendor argon2 staged: refuse to claim true
        # based on host paths — the host .a won't link against the
        # cross compiler.
        return 1
    fi
    if [[ -f /usr/include/argon2.h ]] || [[ -f /usr/local/include/argon2.h ]]; then
        return 0
    fi
    if [[ -f /usr/lib/x86_64-linux-gnu/libargon2.a ]] || [[ -f /usr/lib/libargon2.a ]] || [[ -f /usr/local/lib/libargon2.a ]]; then
        return 0
    fi
    if [[ -f /usr/lib/x86_64-linux-gnu/libargon2.so ]] || [[ -f /usr/lib/libargon2.so ]] || [[ -f /usr/local/lib/libargon2.so ]] || [[ -f /usr/lib/x86_64-linux-gnu/libargon2.so.* ]] || [[ -f /usr/lib/libargon2.so.* ]] || [[ -f /usr/local/lib/libargon2.so.* ]]; then
        return 0
    fi
    return 1
}

liboqs_target_is_mips() {
    if [[ -z "${OPENWRT_USR:-}" ]]; then
        return 1
    fi
    local lib=""
    if [[ -f "${OPENWRT_USR}/lib/liboqs.so" ]]; then
        lib="${OPENWRT_USR}/lib/liboqs.so"
    elif [[ -n "$(ls -1 "${OPENWRT_USR}/lib/liboqs.so."* 2>/dev/null | head -n 1)" ]]; then
        lib="$(ls -1 "${OPENWRT_USR}/lib/liboqs.so."* 2>/dev/null | head -n 1)"
    elif [[ -f "${OPENWRT_USR}/lib/liboqs.a" ]]; then
        lib="${OPENWRT_USR}/lib/liboqs.a"
    else
        return 1
    fi
    if ! need_cmd file; then
        return 0
    fi
    local out=""
    out="$(file -b "${lib}" 2>/dev/null || true)"
    echo "${out}" | grep -qi "mips"
}

detect_liboqs_target() {
    if [[ -n "${OPENWRT_USR:-}" ]]; then
        if [[ -f "${OPENWRT_USR}/include/oqs/oqs.h" ]]; then
            if liboqs_target_is_mips; then
                return 0
            fi
            warn "OpenWRT liboqs in sysroot is not MIPS; PQ will be disabled."
            if [[ -n "${YUME_CLEAN_BAD_OQS:-}" ]]; then
                warn "Removing non-MIPS liboqs from sysroot (YUME_CLEAN_BAD_OQS=1)."
                rm -f "${OPENWRT_USR}/lib/liboqs.so" "${OPENWRT_USR}/lib/liboqs.a" || true
            fi
            return 1
        fi
        if [[ -f "${OPENWRT_USR}/lib/liboqs.so" ]] || [[ -f "${OPENWRT_USR}/lib/liboqs.a" ]]; then
            if liboqs_target_is_mips; then
                return 0
            fi
            warn "OpenWRT liboqs in sysroot is not MIPS; PQ will be disabled."
            if [[ -n "${YUME_CLEAN_BAD_OQS:-}" ]]; then
                warn "Removing non-MIPS liboqs from sysroot (YUME_CLEAN_BAD_OQS=1)."
                rm -f "${OPENWRT_USR}/lib/liboqs.so" "${OPENWRT_USR}/lib/liboqs.a" || true
            fi
            return 1
        fi
    fi
    # Non-OpenWRT cross builds (BusyBox / cross-Linux) stage their
    # liboqs into ${PWD}/vendor/<target>/ via scripts/build-liboqs-target.sh.
    # ezbuild already passes -DBASEFWX_VENDOR_DIR=${PWD}/vendor/busybox-<arch>
    # below (line ~1652) when that dir exists; we also want PQ flagged on
    # so basefwx's CMake actually emits -DBASEFWX_REQUIRE_OQS=ON for the
    # build. Without this hook, the BUSYBOX branch fell straight through
    # to "PQ will be disabled" even when a properly cross-built
    # liboqs.a was sitting at the expected vendor path.
    if [[ "${BUSYBOX:-0}" -eq 1 && -n "${TARGET_ARCH:-}" ]]; then
        local _vendor="${PWD}/vendor/busybox-${TARGET_ARCH}"
        if [[ -f "${_vendor}/include/oqs/oqs.h" \
              && ( -f "${_vendor}/lib/liboqs.a" || -f "${_vendor}/lib/liboqs.so" ) ]]; then
            return 0
        fi
    fi
    return 1
}

resolve_oqs_sysroot_paths() {
    local inc=""
    local lib=""
    if [[ -n "${OPENWRT_USR:-}" && -f "${OPENWRT_USR}/include/oqs/oqs.h" ]]; then
        inc="${OPENWRT_USR}/include"
        if [[ -f "${OPENWRT_USR}/lib/liboqs.a" ]]; then
            lib="${OPENWRT_USR}/lib/liboqs.a"
        elif [[ -f "${OPENWRT_USR}/lib/liboqs.so" ]]; then
            lib="${OPENWRT_USR}/lib/liboqs.so"
        else
            lib="$(ls -1 "${OPENWRT_USR}/lib/liboqs.so."* 2>/dev/null | head -n 1 || true)"
        fi
    elif [[ "${BUSYBOX:-0}" -eq 1 && -n "${TARGET_ARCH:-}" ]]; then
        local _vendor="${PWD}/vendor/busybox-${TARGET_ARCH}"
        if [[ -f "${_vendor}/include/oqs/oqs.h" ]]; then
            inc="${_vendor}/include"
            if [[ -f "${_vendor}/lib/liboqs.a" ]]; then
                lib="${_vendor}/lib/liboqs.a"
            elif [[ -f "${_vendor}/lib/liboqs.so" ]]; then
                lib="${_vendor}/lib/liboqs.so"
            fi
        fi
    fi
    echo "${inc}|${lib}"
}

resolve_argon2_sysroot_paths() {
    local inc=""
    local lib=""
    if [[ -n "${OPENWRT_USR:-}" && -f "${OPENWRT_USR}/include/argon2.h" ]]; then
        inc="${OPENWRT_USR}/include"
        if [[ -f "${OPENWRT_USR}/lib/libargon2.a" ]]; then
            lib="${OPENWRT_USR}/lib/libargon2.a"
        elif [[ -f "${OPENWRT_USR}/lib/libargon2.so" ]]; then
            lib="${OPENWRT_USR}/lib/libargon2.so"
        else
            lib="$(ls -1 "${OPENWRT_USR}/lib/libargon2.so."* 2>/dev/null | head -n 1 || true)"
        fi
    elif [[ "${BUSYBOX:-0}" -eq 1 && -n "${TARGET_ARCH:-}" ]]; then
        # BUSYBOX cross builds stage libargon2 under
        # ${PWD}/vendor/busybox-<arch>/ via build-libargon2-target.sh.
        # Same shape as the OQS sibling fix earlier in this file.
        local _vendor="${PWD}/vendor/busybox-${TARGET_ARCH}"
        if [[ -f "${_vendor}/include/argon2.h" ]]; then
            inc="${_vendor}/include"
            if [[ -f "${_vendor}/lib/libargon2.a" ]]; then
                lib="${_vendor}/lib/libargon2.a"
            elif [[ -f "${_vendor}/lib/libargon2.so" ]]; then
                lib="${_vendor}/lib/libargon2.so"
            fi
        fi
    fi
    echo "${inc}|${lib}"
}

# Pick liboqs paths out of the vendor/ directory for the host platform.
# Linux x86_64 ships liboqs.a; macOS ships liboqs.dylib (with versioned
# symlinks). Returns "<include_dir>|<lib_path>" or an empty pipe pair.
resolve_vendor_oqs_paths() {
    local dir=""
    dir="$(vendor_dir_for_build)"
    if [[ -z "${dir}" ]] || ! vendor_has_liboqs "${dir}"; then
        echo "|"
        return
    fi
    local inc="${dir}/include"
    local lib=""
    if   [[ -f "${dir}/lib/liboqs.a"     ]]; then lib="${dir}/lib/liboqs.a"
    elif [[ -f "${dir}/lib/liboqs.dylib" ]]; then lib="${dir}/lib/liboqs.dylib"
    elif [[ -f "${dir}/lib/liboqs.so"    ]]; then lib="${dir}/lib/liboqs.so"
    else
        lib="$(ls -1 ${dir}/lib/liboqs.* 2>/dev/null | head -n 1 || true)"
    fi
    echo "${inc}|${lib}"
}

# Same but for libargon2.
resolve_vendor_argon2_paths() {
    local dir=""
    dir="$(vendor_dir_for_build)"
    if [[ -z "${dir}" ]] || ! vendor_has_argon2 "${dir}"; then
        echo "|"
        return
    fi
    local inc="${dir}/include"
    local lib=""
    if   [[ -f "${dir}/lib/libargon2.a"     ]]; then lib="${dir}/lib/libargon2.a"
    elif [[ -f "${dir}/lib/libargon2.dylib" ]]; then lib="${dir}/lib/libargon2.dylib"
    elif [[ -f "${dir}/lib/libargon2.so"    ]]; then lib="${dir}/lib/libargon2.so"
    else
        lib="$(ls -1 ${dir}/lib/libargon2.* 2>/dev/null | head -n 1 || true)"
    fi
    echo "${inc}|${lib}"
}

resolve_oqs_host_paths() {
    local inc=""
    local lib=""
    if [[ -f /usr/lib/x86_64-linux-gnu/liboqs.a ]]; then
        lib="/usr/lib/x86_64-linux-gnu/liboqs.a"
    elif [[ -f /usr/lib/liboqs.a ]]; then
        lib="/usr/lib/liboqs.a"
    fi

    if [[ -f /usr/include/oqs/oqs.h ]]; then
        inc="/usr/include"
    elif [[ -f /usr/local/include/oqs/oqs.h ]]; then
        inc="/usr/local/include"
    fi

    if [[ -z "${lib}" ]]; then
        if [[ -f /usr/local/lib/liboqs.a ]]; then
            lib="/usr/local/lib/liboqs.a"
        elif [[ -f /usr/lib/x86_64-linux-gnu/liboqs.so ]]; then
            lib="/usr/lib/x86_64-linux-gnu/liboqs.so"
        elif [[ -f /usr/lib/liboqs.so ]]; then
            lib="/usr/lib/liboqs.so"
        elif [[ -f /usr/local/lib/liboqs.so ]]; then
            lib="/usr/local/lib/liboqs.so"
        elif [[ -n "$(ls -1 /usr/lib/x86_64-linux-gnu/liboqs.so.* 2>/dev/null | head -n 1)" ]]; then
            lib="$(ls -1 /usr/lib/x86_64-linux-gnu/liboqs.so.* 2>/dev/null | head -n 1)"
        elif [[ -n "$(ls -1 /usr/lib/liboqs.so.* 2>/dev/null | head -n 1)" ]]; then
            lib="$(ls -1 /usr/lib/liboqs.so.* 2>/dev/null | head -n 1)"
        else
            lib="$(ls -1 /usr/local/lib/liboqs.so.* 2>/dev/null | head -n 1 || true)"
        fi
    fi
    echo "${inc}|${lib}"
}

build_liboqs_openwrt() {
    if [[ -z "${OPENWRT_SDK:-}" || -z "${YUME_TOOLCHAIN_FILE:-}" || -z "${OPENWRT_USR:-}" ]]; then
        warn "OpenWRT liboqs build skipped: missing SDK/toolchain info."
        return 1
    fi
    if ! need_cmd git || ! need_cmd cmake; then
        warn "OpenWRT liboqs build skipped: git/cmake missing."
        return 1
    fi
    step "OpenWRT SDK: building liboqs from source..."
    local workdir="${YUME_TMP_ROOT}/liboqs-openwrt"
    rm -rf "${workdir}"
    git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git "${workdir}"
    local cc_bin="${CC_PATH:-}"
    local cxx_bin="${CXX_PATH:-}"
    if [[ -z "${cc_bin}" || -z "${cxx_bin}" ]]; then
        local tool_bin=""
        tool_bin="$(find "${OPENWRT_SDK}/staging_dir" -maxdepth 2 -type d -name 'toolchain-*' -print0 2>/dev/null | head -zn 1 | xargs -0 -I{} echo '{}/bin')"
        cc_bin="$(find "${tool_bin}" -maxdepth 1 -type f -name '*-gcc' | head -n 1)"
        cxx_bin="$(find "${tool_bin}" -maxdepth 1 -type f -name '*-g++' | head -n 1)"
    fi
    local sysroot="${SYSROOT_PATH}"
    local cflags="--sysroot=${sysroot}"
    if [[ -d "${sysroot}/usr/include" ]]; then
        cflags="${cflags} -isystem ${sysroot}/usr/include"
    fi
    local toolchain_root=""
    if [[ -n "${tool_bin:-}" ]]; then
        toolchain_root="$(dirname "${tool_bin}")"
    fi
    if [[ -n "${toolchain_root}" && -d "${toolchain_root}/include" ]]; then
        cflags="${cflags} -isystem ${toolchain_root}/include"
    fi
    if [[ -n "${toolchain_root}" && -d "${toolchain_root}/usr/include" ]]; then
        cflags="${cflags} -isystem ${toolchain_root}/usr/include"
    fi
    cmake -S "${workdir}" -B "${workdir}/build" \
        -DCMAKE_TOOLCHAIN_FILE="${YUME_TOOLCHAIN_FILE}" \
        -DCMAKE_SYSROOT="${SYSROOT_PATH}" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT_PATH};${toolchain_root}" \
        -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
        -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
        -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY \
        -DCMAKE_C_COMPILER="${cc_bin}" \
        -DCMAKE_CXX_COMPILER="${cxx_bin}" \
        -DCMAKE_C_FLAGS="${cflags}" \
        -DCMAKE_CXX_FLAGS="${cflags}" \
        -DCMAKE_INSTALL_PREFIX="${OPENWRT_USR}" \
        -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
        -DOQS_DIST_BUILD=ON \
        -DOQS_USE_AVX2=OFF \
        -DOQS_USE_AVX512=OFF \
        -DOQS_USE_SSE2=OFF \
        -DOQS_USE_SVE=OFF \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_BUILD_TESTS=OFF \
        -DOQS_BUILD_BENCHMARKS=OFF \
        -DOQS_BUILD_DEMOS=OFF \
        -DOQS_BUILD_EXAMPLES=OFF \
        -DOQS_BUILD_SHARED_LIBS=OFF \
        -DOQS_BUILD_STATIC_LIBS=ON \
        -DOQS_INSTALL_SHARED=OFF \
        -DOQS_USE_OPENSSL=OFF \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTING=OFF
    cmake --build "${workdir}/build" -j"$(nproc 2>/dev/null || echo 4)"
    if need_cmd sudo; then
        sudo cmake --install "${workdir}/build"
    else
        cmake --install "${workdir}/build"
    fi
    if [[ -f "${OPENWRT_USR}/lib/liboqs.so.0.15.0" && ! -f "${OPENWRT_USR}/lib/liboqs.so" ]]; then
        ln -sf liboqs.so.0.15.0 "${OPENWRT_USR}/lib/liboqs.so"
    fi
    return 0
}

build_liboqs_host() {
    if ! need_cmd git || ! need_cmd cmake; then
        warn "Host liboqs build skipped: git/cmake missing."
        return 1
    fi
    step "Host: building liboqs (static) from source..."
    local workdir="${YUME_TMP_ROOT}/liboqs-host"
    rm -rf "${workdir}"
    git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git "${workdir}"
    cmake -S "${workdir}" -B "${workdir}/build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_BUILD_TESTS=OFF \
        -DOQS_BUILD_BENCHMARKS=OFF \
        -DOQS_BUILD_DEMOS=OFF \
        -DOQS_BUILD_EXAMPLES=OFF \
        -DOQS_BUILD_SHARED_LIBS=OFF \
        -DOQS_BUILD_STATIC_LIBS=ON \
        -DOQS_INSTALL_SHARED=OFF \
        -DOQS_USE_OPENSSL=OFF \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTING=OFF
    cmake --build "${workdir}/build" -j"$(nproc 2>/dev/null || echo 4)"
    cmake --install "${workdir}/build"
    return 0
}

ensure_basefwx() {
    local ref="${BASEFWX_REF:-main}"
    if ! need_cmd git; then
        error "git not found; cannot fetch BaseFWX."
        return 1
    fi
    if [[ -d basefwx ]] && ! git -C basefwx rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        warn "basefwx exists but is not a git repository; replacing it."
        rm -rf basefwx
    fi
    if ! git -C basefwx rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        step "Cloning BaseFWX..."
        git clone --filter=blob:none --no-checkout "${BASEFWX_REPO}" basefwx
    else
        info "BaseFWX already present."
    fi
    step "Syncing BaseFWX to ${ref}..."
    git -C basefwx fetch --depth 1 origin "${ref}"
    git -C basefwx checkout --detach FETCH_HEAD
    ok "BaseFWX ready at $(git -C basefwx rev-parse --short HEAD)."
}

cleanup_vendor() {
    if [[ -d basefwx/cpp/build ]]; then
        step "Removing BaseFWX build cache..."
        rm -rf basefwx/cpp/build || true
    fi
}

install_deps_linux() {
    if need_cmd apt-get; then
        step "Detected apt-get (Debian/Ubuntu). Installing dependencies..."
        apt_update_once
        sudo apt-get install -y \
            build-essential \
            cmake \
            git \
            pkg-config \
            ninja-build \
            curl \
            wget \
            ca-certificates \
            unzip \
            zip \
            xz-utils \
            zstd \
            python3 \
            perl \
            libssl-dev \
            libboost-all-dev \
            libboost-system-dev \
            libboost-thread-dev \
            nlohmann-json3-dev \
            libspdlog-dev \
            zlib1g-dev \
            libzstd-dev \
            libargon2-dev \
            liblzma-dev
        if [[ ${BUILD_GUI} -eq 1 ]]; then
            step "GUI build requested; installing Dear ImGui / GLFW host deps..."
            # Install one package at a time so a missing one (e.g.
            # wayland-protocols on an older or trimmed apt source) is a
            # warning, not a fatal error that prevents the rest from
            # being installed. The CMake side then falls back to X11.
            local gui_packages=(
                libgl-dev
                libglfw3-dev
                libxkbcommon-dev
                libfreetype-dev
                libfontconfig-dev
                libxinerama-dev
                libxcursor-dev
                libxi-dev
                libwayland-dev
                libwayland-bin
                wayland-protocols
                libayatana-appindicator3-dev
            )
            # If the user already has a backports library installed (a
            # common case on Debian stable), the matching -dev package
            # from stable won't satisfy the version pin. Retry the
            # install from <codename>-backports before giving up — same
            # source that supplied the runtime lib.
            local codename=""
            if [[ -r /etc/os-release ]]; then
                # shellcheck disable=SC1091
                codename="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")"
            fi
            local backports_suite=""
            if [[ -n "$codename" ]] \
                && apt-cache policy 2>/dev/null | grep -q "${codename}-backports"; then
                backports_suite="${codename}-backports"
            fi
            for pkg in "${gui_packages[@]}"; do
                if sudo apt-get install -y "$pkg" 2>/dev/null; then
                    continue
                fi
                if [[ -n "$backports_suite" ]] \
                    && sudo apt-get install -y -t "$backports_suite" "$pkg" 2>/dev/null; then
                    info "Installed '${pkg}' from ${backports_suite}."
                    continue
                fi
                warn "apt-get could not install '${pkg}'; continuing."
            done
        fi
        if [[ "${WINDOWS_CROSS}" == "1" ]]; then
            sudo apt-get install -y mingw-w64 || warn "mingw-w64 install failed; Windows cross build may fail."
        fi
        if [[ "${YUME_MACOS_CROSS:-0}" == "1" ]]; then
            sudo apt-get install -y clang lld llvm || warn "clang/llvm install failed; macOS cross build may fail."
        fi
        if apt-cache show liboqs-dev >/dev/null 2>&1; then
            sudo apt-get install -y liboqs-dev || warn "liboqs-dev install failed; PQ features will be disabled unless provided."
        else
            if detect_liboqs; then
                info "liboqs already installed (non-apt); skipping liboqs-dev warning."
            else
                warn "liboqs-dev not available in apt repositories; PQ features will be disabled unless provided."
            fi
        fi
        if [[ -n "${YUME_OQS_STATIC:-}" ]]; then
            local vendor_dir
            vendor_dir="$(vendor_dir_for_build)"
            if vendor_has_liboqs "${vendor_dir}"; then
                info "Vendored liboqs detected; skipping source build."
            elif [[ -f /usr/lib/x86_64-linux-gnu/liboqs.a || -f /usr/local/lib/liboqs.a ]]; then
                info "Static liboqs already available."
            elif [[ -n "${YUME_VENDOR_ONLY:-}" ]]; then
                warn "YUME_VENDOR_ONLY=1 set; skipping liboqs source build."
            else
                warn "YUME_OQS_STATIC=1 set but liboqs.a missing; building liboqs from source."
                build_liboqs_host || warn "Host liboqs build failed; PQ may fall back to shared."
            fi
        fi
        ok "Dependencies installed via apt-get."
        return 0
    fi

    if need_cmd pacman; then
        step "Detected pacman (Arch). Installing dependencies..."
        sudo pacman -Syu --noconfirm \
            base-devel \
            cmake \
            git \
            pkgconf \
            openssl \
            boost \
            nlohmann-json \
            spdlog \
            zlib \
            zstd \
            argon2 \
            liboqs \
            xz
        if [[ ${BUILD_GUI} -eq 1 ]]; then
            step "GUI build requested; installing Dear ImGui / GLFW host deps..."
            sudo pacman -S --noconfirm --needed \
                glfw \
                freetype2 \
                fontconfig \
                libxkbcommon \
                libxinerama \
                libxcursor \
                libxi \
                wayland \
                wayland-protocols \
                libayatana-appindicator \
                || warn "Some GUI dev packages failed to install; tray may be disabled."
        fi
        ok "Dependencies installed via pacman."
        return 0
    fi

    if need_cmd dnf; then
        step "Detected dnf (Fedora/RHEL). Installing dependencies..."
        sudo dnf install -y \
            gcc-c++ \
            make \
            cmake \
            git \
            pkgconf-pkg-config \
            openssl-devel \
            boost-devel \
            nlohmann-json-devel \
            spdlog-devel \
            zlib-devel \
            libzstd-devel \
            argon2-devel \
            liboqs-devel \
            xz-devel
        if [[ ${BUILD_GUI} -eq 1 ]]; then
            step "GUI build requested; installing Dear ImGui / GLFW host deps..."
            sudo dnf install -y \
                glfw-devel \
                freetype-devel \
                fontconfig-devel \
                libxkbcommon-devel \
                libXinerama-devel \
                libXcursor-devel \
                libXi-devel \
                wayland-devel \
                wayland-protocols-devel \
                libayatana-appindicator-gtk3-devel \
                mesa-libGL-devel \
                || warn "Some GUI dev packages failed to install; tray may be disabled."
        fi
        ok "Dependencies installed via dnf."
        return 0
    fi

    if need_cmd zypper; then
        step "Detected zypper (openSUSE). Installing dependencies..."
        sudo zypper install -y \
            gcc-c++ \
            make \
            cmake \
            git \
            pkg-config \
            libopenssl-devel \
            libboost_system-devel \
            libboost_thread-devel \
            nlohmann_json-devel \
            spdlog-devel \
            zlib-devel \
            libzstd-devel \
            libargon2-devel \
            liboqs-devel \
            xz-devel
        if [[ ${BUILD_GUI} -eq 1 ]]; then
            step "GUI build requested; installing Dear ImGui / GLFW host deps..."
            sudo zypper install -y \
                glfw-devel \
                freetype2-devel \
                fontconfig-devel \
                libxkbcommon-devel \
                libXinerama-devel \
                libXcursor-devel \
                libXi-devel \
                wayland-devel \
                wayland-protocols-devel \
                libayatana-appindicator3-devel \
                Mesa-libGL-devel \
                || warn "Some GUI dev packages failed to install; tray may be disabled."
        fi
        ok "Dependencies installed via zypper."
        return 0
    fi

    warn "No supported Linux package manager found."
    return 1
}

install_deps_macos() {
    if ! need_cmd brew; then
        error "Homebrew not found. Install it first: https://brew.sh"
        return 1
    fi
    step "Detected macOS + Homebrew. Installing dependencies..."
    brew update
    brew install \
        cmake \
        git \
        pkg-config \
        openssl@3 \
        boost \
        nlohmann-json \
        spdlog \
        zlib \
        zstd \
        argon2 \
        liboqs \
        xz
    if [[ ${BUILD_GUI} -eq 1 ]]; then
        step "GUI build requested; installing Dear ImGui / GLFW host deps..."
        brew install \
            glfw \
            freetype \
            fontconfig \
            || warn "Some GUI dependencies failed to install via Homebrew."
    fi
    ok "Dependencies installed via Homebrew."
}

install_deps_windows() {
    # Running inside MSYS2's MINGW64 environment: use pacman with the
    # mingw-w64-x86_64-* packages. Those are all prebuilt, so a fresh
    # box gets to a ready-to-build state in a few minutes instead of
    # spending 30-60 min letting vcpkg compile everything against MSVC.
    if [[ "${MSYSTEM:-}" == "MINGW64" || "${MSYSTEM:-}" == "MINGW32" || "${MSYSTEM:-}" == "UCRT64" ]] \
       && need_cmd pacman; then
        step "Detected MSYS2 ${MSYSTEM}. Installing mingw-w64 packages..."
        pacman -S --needed --noconfirm \
            mingw-w64-x86_64-toolchain \
            mingw-w64-x86_64-cmake \
            mingw-w64-x86_64-ninja \
            mingw-w64-x86_64-openssl \
            mingw-w64-x86_64-boost \
            mingw-w64-x86_64-nlohmann-json \
            mingw-w64-x86_64-zstd \
            mingw-w64-x86_64-spdlog \
            mingw-w64-x86_64-liboqs \
            mingw-w64-x86_64-argon2 \
            git zip
        if [[ ${BUILD_GUI} -eq 1 ]]; then
            step "GUI build requested; installing GLFW + Freetype..."
            pacman -S --needed --noconfirm \
                mingw-w64-x86_64-glfw \
                mingw-w64-x86_64-freetype \
                || warn "Some GUI packages failed; the build may fall back."
        fi
        ok "Dependencies installed via pacman (MSYS2)."
        return 0
    fi

    # Bare cmd.exe / cygwin path: keep the Chocolatey fallback for
    # the rare user who really wants MSVC from a shell. The native
    # MSVC route is what ezbuild.bat drives — this branch is the
    # last resort.
    if ! need_cmd choco; then
        error "No supported Windows shell setup detected."
        error "  - For the fast path: install MSYS2 (winget install MSYS2.MSYS2)"
        error "    and re-run from its MINGW64 shell."
        error "  - For MSVC builds: run ezbuild.bat from cmd.exe instead."
        return 1
    fi
    step "Detected Windows + Chocolatey. Installing dependencies..."
    choco install -y \
        visualstudio2022buildtools \
        cmake \
        git \
        openssl \
        boost-msvc-14.3 \
        nlohmann-json \
        spdlog \
        zlib
    warn "liboqs/argon2 packages may require manual install on Windows."
    ok "Dependencies installed via Chocolatey."
}

build_project() {
    local build_dir="${YUME_BUILD_DIR:-build}"
    if need_cmd flock; then
        local build_root
        local lock_key
        local lock_file
        build_root="$(pwd -P)"
        lock_key="$(hash_string "${build_root}/${build_dir}")"
        lock_file="${YUME_LOCK_ROOT}/build-${lock_key}.lock"
        exec 9>"${lock_file}"
        if ! flock -n 9; then
            error "Build directory '${build_dir}' is busy (lock: ${lock_file}). Stop the other build and retry."
            exit 1
        fi
    fi
    step "Cleaning previous build..."
    rm -rf "${build_dir}"
    mkdir -p "${build_dir}"
    step "Configuring build..."
    cmake -B "${build_dir}" "${CMAKE_ARGS[@]}"
    step "Compiling..."
    cmake --build "${build_dir}" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu || echo 4)"
    ok "Build complete."
    if [[ -x "${build_dir}/bin/yume-gui" ]]; then
        info "yume-gui built at ${build_dir}/bin/yume-gui"
    fi
}

debian_arch_for_target() {
    local arch="${1:-}"
    case "${arch}" in
        "" ) echo "" ;;
        x86_64|amd64|linux-x86_64) echo "amd64" ;;
        x86|i386|i486|i586|i686) echo "i386" ;;
        aarch64|arm64|armv8) echo "arm64" ;;
        armv7|armv7l|armhf) echo "armhf" ;;
        armv6|armel) echo "armel" ;;
        mipsel) echo "mipsel" ;;
        mips64el) echo "mips64el" ;;
        mips) echo "mips" ;;
        *) echo "${arch}" ;;
    esac
}

package_deb() {
    local build_dir="${YUME_BUILD_DIR:-build}"
    if ! need_cmd cpack; then
        error "cpack not found; install cmake/cpack and retry."
        exit 1
    fi
    if [[ ! -f "${build_dir}/CPackConfig.cmake" ]]; then
        error "CPackConfig.cmake not found in ${build_dir}; configure failed or packaging is disabled."
        exit 1
    fi
    step "Building Debian package..."
    (cd "${build_dir}" && cpack -G DEB)
    ok "Debian package output:"
    find "${build_dir}" -maxdepth 1 -type f -name '*.deb' -print
}

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --clean)
                CLEAN_ONLY=1
                shift
                ;;
            --minimal)
                MINIMAL=1
                shift
                ;;
            --deb|--package-deb)
                BUILD_DEB=1
                shift
                ;;
            --gui|--with-gui)
                BUILD_GUI=1
                shift
                ;;
            --portable|--static)
                # Produce one self-contained executable: no MinGW
                # runtime DLLs, no vcpkg .dlls alongside. Implies
                # YUME_STATIC + YUME_GUI_PORTABLE + the static vcpkg
                # mingw triplet for the cross route.
                PORTABLE=1
                shift
                ;;
            --no-pull|--skip-pull)
                SKIP_PULL=1
                shift
                ;;
            --openwrt)
                OPENWRT=1
                MINIMAL=1
                shift
                ;;
            --busybox)
                BUSYBOX=1
                MINIMAL=1
                shift
                ;;
            --openwrt-sdk)
                shift
                OPENWRT_SDK="${1:-}"
                if [[ -z "$OPENWRT_SDK" ]]; then
                    error "--openwrt-sdk requires a path to the OpenWRT SDK directory"
                    exit 1
                fi
                shift
                ;;
            --arch)
                shift
                TARGET_ARCH="${1:-}"
                if [[ -z "$TARGET_ARCH" ]]; then
                    error "--arch requires a value (e.g. x86_64, aarch64)"
                    exit 1
                fi
                shift
                ;;
            *)
                warn "Unknown option: $1"
                shift
                ;;
        esac
    done

    if [[ $CLEAN_ONLY -eq 1 ]]; then
        info "YUME ezbuild starting..."
        step "Cleaning build directory..."
        rm -rf "${YUME_BUILD_DIR:-build}"
        # If a previous build left a vendor unpack from a failed run,
        # the marker file at vendor/.ezbuild-vendor-unpacked tells us
        # exactly what to remove. A vendor/ tree without the marker
        # belongs to the user and is not touched.
        cleanup_unpacked_vendor
        ok "Cleaned."
        exit 0
    fi

    info "YUME ezbuild starting..."

    maybe_sync_repo

    if [[ $MINIMAL -eq 1 ]]; then
        warn "Minimal mode: enabling static build and BaseFWX."
        CMAKE_ARGS+=(
            -DYUME_MINIMAL=ON
            -DYUME_STATIC=ON
            -DYUME_USE_BASEFWX=ON
            -DYUME_USE_SPDLOG=OFF
            -DCMAKE_BUILD_TYPE=Release
        )
    fi

    if [[ $BUILD_GUI -eq 1 ]]; then
        if [[ $MINIMAL -eq 1 ]]; then
            warn "--gui ignored: minimal/static builds do not include the GUI."
            BUILD_GUI=0
        else
            info "GUI build enabled (-DYUME_BUILD_GUI=ON)."
            CMAKE_ARGS+=( -DYUME_BUILD_GUI=ON )
        fi
    fi

    if [[ $PORTABLE -eq 1 ]]; then
        info "Portable build: static deps + embedded MinGW runtime."
        # YUME_STATIC turns on static linkage flags for yume/yumed (and
        # transitively their static libs). YUME_GUI_PORTABLE is the
        # GUI-specific knob for -static-libgcc/-static-libstdc++.
        # The cross route also needs the static vcpkg triplet so the
        # dependency libs come in as .a rather than .dll.a.
        CMAKE_ARGS+=( -DYUME_STATIC=ON -DYUME_GUI_PORTABLE=ON )
        if [[ "${WINDOWS_CROSS}" == "1" ]]; then
            WINDOWS_TRIPLET="${YUME_WINDOWS_TRIPLET:-x64-mingw-static}"
            info "WINDOWS_TRIPLET pinned to ${WINDOWS_TRIPLET} for portable cross."
        fi
    fi

    if [[ -n "${YUME_CMAKE_ARGS:-}" ]]; then
        # shellcheck disable=SC2206
        EXTRA_CMAKE_ARGS=(${YUME_CMAKE_ARGS})
        CMAKE_ARGS+=("${EXTRA_CMAKE_ARGS[@]}")
    fi

    if [[ $BUILD_DEB -eq 1 && -n "${TARGET_ARCH}" ]]; then
        CMAKE_ARGS+=(
            "-DCPACK_DEBIAN_PACKAGE_ARCHITECTURE=$(debian_arch_for_target "${TARGET_ARCH}")"
            "-DYUME_DEB_SHLIBDEPS=OFF"
        )
    fi

    if [[ "${WINDOWS_CROSS}" == "1" ]]; then
        local windows_vendor_prefix=""
        local use_vcpkg_toolchain=0
        windows_vendor_prefix="$(windows_vendor_dir || true)"
        if [[ -z "${VCPKG_ROOT}" ]]; then
            VCPKG_ROOT="$(detect_vcpkg_root || true)"
        fi
        if ! command -v "${WINDOWS_TOOLCHAIN_PREFIX}-g++" >/dev/null 2>&1; then
            error "Missing ${WINDOWS_TOOLCHAIN_PREFIX}-g++; install mingw-w64."
            exit 1
        fi
        if [[ -n "${VCPKG_ROOT}" && -x "${VCPKG_ROOT}/vcpkg" ]]; then
            if [[ ! -f "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" ]]; then
                error "vcpkg toolchain file missing at ${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
                exit 1
            fi
            use_vcpkg_toolchain=1
            VCPKG_PREFIX="${VCPKG_ROOT}/installed/${WINDOWS_TRIPLET}"
            # If this triplet hasn't been built yet (typical when the
            # user just switched from x64-mingw-dynamic to mingw-static
            # for a --portable build), populate it. vcpkg compiles the
            # ports from source against the MinGW toolchain we already
            # have; this takes ~20-30 min the first time then caches.
            if [[ ! -f "${VCPKG_PREFIX}/include/openssl/ssl.h" ]]; then
                info "vcpkg packages for ${WINDOWS_TRIPLET} not staged yet."
                local _shim_bin="${YUME_TMP_ROOT:-/tmp}/yume-vcpkg-shim"
                mkdir -p "${_shim_bin}"
                if [[ ! -x "${_shim_bin}/powershell.exe" ]]; then
                    printf '#!/usr/bin/env bash\nexit 0\n' \
                        > "${_shim_bin}/powershell.exe"
                    chmod +x "${_shim_bin}/powershell.exe"
                fi
                local _pkgs="openssl boost-asio boost-system boost-headers \
                             nlohmann-json zstd liboqs argon2 zlib"
                step "Running vcpkg install ${_pkgs} --triplet=${WINDOWS_TRIPLET}"
                CC="${WINDOWS_TOOLCHAIN_PREFIX}-gcc" \
                CXX="${WINDOWS_TOOLCHAIN_PREFIX}-g++" \
                PATH="${_shim_bin}:${PATH}" \
                VCPKG_POWERSHELL_PATH="${_shim_bin}/powershell.exe" \
                "${VCPKG_ROOT}/vcpkg" install --triplet="${WINDOWS_TRIPLET}" ${_pkgs} \
                    || warn "vcpkg install failed; falling back to whatever is present."
            fi
        elif [[ -n "${windows_vendor_prefix}" ]]; then
            VCPKG_PREFIX="${windows_vendor_prefix}"
            info "Windows cross: using vendored dependency prefix at ${VCPKG_PREFIX}"
        else
            error "Windows cross build requires VCPKG_ROOT or vendor/windows-x86_64."
            exit 1
        fi
        # Cross-build isolation. CMAKE_SYSROOT is the one that matters:
        # it sets gcc's `--sysroot=`, which constrains the C preprocessor
        # itself, so `#include_next <errno.h>` cannot fall through into
        # /usr/include/errno.h -> /usr/include/linux/errno.h ->
        # /usr/include/asm/errno.h (which doesn't exist for cross builds
        # on Debian). CMAKE_FIND_ROOT_PATH + the four MODE_* knobs do
        # the same for find_package / pkg_check_modules. Without both,
        # --gui's freetype/fontconfig probes leak -I/usr/include in.
        # Probe the sysroot via the compiler itself for robustness;
        # fall back to the standard Debian path. fullau.sh uses the
        # same approach.
        local _mingw_root=""
        _mingw_root="$(${WINDOWS_TOOLCHAIN_PREFIX}-gcc -print-sysroot 2>/dev/null | sed 's:/*$::' || true)"
        if [[ -z "${_mingw_root}" || "${_mingw_root}" == "/" ]] \
           && [[ -d "/usr/${WINDOWS_TOOLCHAIN_PREFIX}" ]]; then
            _mingw_root="/usr/${WINDOWS_TOOLCHAIN_PREFIX}"
        fi
        CMAKE_ARGS+=(
            "-DCMAKE_SYSTEM_NAME=Windows"
            "-DCMAKE_SYSTEM_PROCESSOR=x86_64"
            "-DCMAKE_C_COMPILER=${WINDOWS_TOOLCHAIN_PREFIX}-gcc"
            "-DCMAKE_CXX_COMPILER=${WINDOWS_TOOLCHAIN_PREFIX}-g++"
            "-DCMAKE_RC_COMPILER=${WINDOWS_TOOLCHAIN_PREFIX}-windres"
            "-DOPENSSL_ROOT_DIR=${VCPKG_PREFIX}"
            "-DCMAKE_PREFIX_PATH=${VCPKG_PREFIX}"
            "-DBoost_DIR=${VCPKG_PREFIX}/share/boost"
            "-DBASEFWX_USE_VENDOR_DEPS=OFF"
            "-DYUME_USE_SPDLOG=OFF"
            "-DYUME_FORCE_CROSS=ON"
            # Force vcpkg's nlohmann_json so every TU sees the same
            # inline-namespace version tag. With the bundled fallback
            # left on, yume_transport_core picks third_party/ (3.11.3)
            # while yume_client_lib picks vcpkg (3.12.0); the mangled
            # symbols don't match and yume.exe fails to link.
            "-DYUME_USE_BUNDLED_NLOHMANN=OFF"
        )
        if [[ -n "${_mingw_root}" && -d "${_mingw_root}" ]]; then
            CMAKE_ARGS+=(
                "-DCMAKE_SYSROOT=${_mingw_root}"
                "-DCMAKE_FIND_ROOT_PATH=${_mingw_root};${VCPKG_PREFIX}"
                "-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER"
                "-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY"
                "-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY"
                "-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY"
            )
        else
            CMAKE_ARGS+=(
                "-DCMAKE_FIND_ROOT_PATH=${VCPKG_PREFIX}"
                "-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER"
                "-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY"
                "-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY"
                "-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY"
            )
        fi
        if [[ ${use_vcpkg_toolchain} -eq 1 ]]; then
            CMAKE_ARGS+=(
                "-DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
                "-DVCPKG_TARGET_TRIPLET=${WINDOWS_TRIPLET}"
                "-DVCPKG_APPLOCAL_DEPS=OFF"
            )
        fi
        if [[ -f "${VCPKG_PREFIX}/lib/libzstd.dll.a" ]]; then
            CMAKE_ARGS+=(
                "-DZSTD_LIBRARY=${VCPKG_PREFIX}/lib/libzstd.dll.a"
                "-DZSTD_INCLUDE_DIR=${VCPKG_PREFIX}/include"
                "-DZSTD_DIR=${VCPKG_PREFIX}/share/zstd"
            )
        elif [[ -f "${VCPKG_PREFIX}/lib/libzstd.a" ]]; then
            CMAKE_ARGS+=(
                "-DZSTD_LIBRARY=${VCPKG_PREFIX}/lib/libzstd.a"
                "-DZSTD_INCLUDE_DIR=${VCPKG_PREFIX}/include"
                "-DZSTD_DIR=${VCPKG_PREFIX}/share/zstd"
            )
        fi
        if [[ -f "${VCPKG_PREFIX}/include/oqs/oqs.h" ]]; then
            if [[ -f "${VCPKG_PREFIX}/lib/liboqs.dll.a" ]]; then
                CMAKE_ARGS+=(
                    "-DOQS_INCLUDE_DIR=${VCPKG_PREFIX}/include"
                    "-DOQS_LIBRARY=${VCPKG_PREFIX}/lib/liboqs.dll.a"
                    "-DOQS_INCLUDE_DIRS=${VCPKG_PREFIX}/include"
                    "-DOQS_LIBRARIES=${VCPKG_PREFIX}/lib/liboqs.dll.a"
                    "-DOQS_FOUND=TRUE"
                )
            elif [[ -f "${VCPKG_PREFIX}/lib/liboqs.a" ]]; then
                CMAKE_ARGS+=(
                    "-DOQS_INCLUDE_DIR=${VCPKG_PREFIX}/include"
                    "-DOQS_LIBRARY=${VCPKG_PREFIX}/lib/liboqs.a"
                    "-DOQS_INCLUDE_DIRS=${VCPKG_PREFIX}/include"
                    "-DOQS_LIBRARIES=${VCPKG_PREFIX}/lib/liboqs.a"
                    "-DOQS_FOUND=TRUE"
                )
            fi
        fi
    fi

    if [[ $OPENWRT -eq 1 || $BUSYBOX -eq 1 ]]; then
        CMAKE_ARGS+=("-DYUME_FORCE_CROSS=ON")
        if [[ -n "$OPENWRT_SDK" ]]; then
            if [[ ! -d "$OPENWRT_SDK" ]]; then
                error "--openwrt-sdk path not found: $OPENWRT_SDK"
                exit 1
            fi
            info "Searching OpenWRT SDK at: $OPENWRT_SDK"
            TOOLCHAIN_DIR="$(find "$OPENWRT_SDK/staging_dir" -maxdepth 2 -type d -name 'toolchain-*' 2>/dev/null | head -n 1)"
            TARGET_DIR="$(find "$OPENWRT_SDK/staging_dir" -maxdepth 2 -type d -name 'target-*' 2>/dev/null | head -n 1)"
            if [[ -z "$TOOLCHAIN_DIR" ]]; then
                error "OpenWRT toolchain directory not found under $OPENWRT_SDK/staging_dir"
                exit 1
            fi
            TOOLCHAIN_BIN="$TOOLCHAIN_DIR/bin"
            CC_PATH="$(find "$TOOLCHAIN_BIN" -maxdepth 1 -type f -name '*-gcc' | head -n 1)"
            CXX_PATH="$(find "$TOOLCHAIN_BIN" -maxdepth 1 -type f -name '*-g++' | head -n 1)"
            AR_PATH="$(find "$TOOLCHAIN_BIN" -maxdepth 1 -type f -name '*-ar' | head -n 1)"
            RANLIB_PATH="$(find "$TOOLCHAIN_BIN" -maxdepth 1 -type f -name '*-ranlib' | head -n 1)"
            STRIP_PATH="$(find "$TOOLCHAIN_BIN" -maxdepth 1 -type f -name '*-strip' | head -n 1)"
            if [[ -z "$CC_PATH" || -z "$CXX_PATH" ]]; then
                error "OpenWRT SDK compilers not found in $TOOLCHAIN_BIN"
                exit 1
            fi
            TOOLCHAIN_FILE="${YUME_TMP_ROOT}/openwrt-toolchain.cmake"
            SYSROOT_PATH="$TOOLCHAIN_DIR"
            if [[ -n "$TARGET_DIR" ]]; then
                SYSROOT_PATH="$TARGET_DIR"
            fi
            OPENWRT_USR="${SYSROOT_PATH}/usr"
            OPENWRT_BOOST_CMAKE="$(find "$OPENWRT_USR/lib/cmake" -maxdepth 2 -type f -name 'BoostConfig.cmake' 2>/dev/null | head -n 1)"
            export STAGING_DIR="${OPENWRT_SDK}/staging_dir"
            cat > "$TOOLCHAIN_FILE" <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ${TARGET_ARCH:-mips})
set(CMAKE_C_COMPILER ${CC_PATH})
set(CMAKE_CXX_COMPILER ${CXX_PATH})
set(CMAKE_AR ${AR_PATH})
set(CMAKE_RANLIB ${RANLIB_PATH})
set(CMAKE_STRIP ${STRIP_PATH})
set(CMAKE_SYSROOT ${SYSROOT_PATH})
set(CMAKE_FIND_ROOT_PATH ${SYSROOT_PATH} ${TOOLCHAIN_DIR})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(ENV{STAGING_DIR} ${OPENWRT_SDK}/staging_dir)
EOF
            YUME_TOOLCHAIN_FILE="$TOOLCHAIN_FILE"
            if [[ -d "$OPENWRT_USR" ]]; then
                CMAKE_ARGS+=("-DOPENSSL_ROOT_DIR=${OPENWRT_USR}")
                CMAKE_ARGS+=("-DCMAKE_PREFIX_PATH=${OPENWRT_USR}")
            fi
        fi

        if [[ -z "${YUME_TOOLCHAIN_FILE:-}" ]]; then
            error "YUME_TOOLCHAIN_FILE is required for --openwrt/--busybox (OpenWRT SDK toolchain file)."
            exit 1
        fi
        if [[ -n "${OPENWRT_USR:-}" ]]; then
            if [[ ! -d "${OPENWRT_USR}/include/openssl" ]]; then
                error "OpenSSL not staged in SDK. Build it inside the SDK first."
                echo "Run inside SDK: make package/feeds/base/openssl/compile V=s"
                exit 1
            fi
            if [[ -z "${OPENWRT_BOOST_CMAKE:-}" ]]; then
                error "Boost not staged in SDK. Build it inside the SDK first."
                echo "Run inside SDK: make package/feeds/packages/boost/compile V=s"
                exit 1
            fi
            CMAKE_ARGS+=("-DBoost_DIR=$(dirname "${OPENWRT_BOOST_CMAKE}")")
            if ! detect_liboqs_target; then
                local vendor_dir
                vendor_dir="$(vendor_dir_for_build)"
                if vendor_has_liboqs "${vendor_dir}"; then
                    info "Vendored liboqs detected; skipping SDK build."
                elif [[ -n "${YUME_VENDOR_ONLY:-}" ]]; then
                    warn "YUME_VENDOR_ONLY=1 set; skipping OpenWRT liboqs build."
                else
                    LIBOQS_MAKEFILE="$(find "${OPENWRT_SDK}/feeds" "${OPENWRT_SDK}/package" -path "*/liboqs/Makefile" 2>/dev/null | head -n 1)"
                    if [[ -n "${LIBOQS_MAKEFILE}" ]]; then
                        step "OpenWRT SDK: building liboqs from feeds..."
                        if [[ "${LIBOQS_MAKEFILE}" == *"/feeds/"* ]]; then
                            FEED_NAME="$(echo "${LIBOQS_MAKEFILE}" | awk -F'/feeds/' '{print $2}' | awk -F'/' '{print $1}')"
                            make -C "${OPENWRT_SDK}" "package/feeds/${FEED_NAME}/liboqs/compile" V=s || warn "liboqs build failed in SDK; PQ may be disabled."
                        else
                            make -C "${OPENWRT_SDK}" "package/liboqs/compile" V=s || warn "liboqs build failed in SDK; PQ may be disabled."
                        fi
                    else
                        warn "OpenWRT SDK does not contain liboqs package; attempting source build..."
                        build_liboqs_openwrt || warn "liboqs source build failed; PQ may be disabled."
                    fi
                fi
            fi
        fi
        # OpenWRT SDKs often lack full static deps; force dynamic.
        # This override is OpenWRT-specific — BUSYBOX targets stage their
        # own per-arch static prefix (vendor/busybox-<arch>) and fullau
        # explicitly verifies libz.a/liblzma.a/libssl.a/etc. are present
        # before requesting -DYUME_STATIC=ON. Clobbering that here would
        # produce dynamic-PIE binaries packaged as `*-busybox-static`,
        # which the release workflow's static-link assertion rejects.
        if [[ $OPENWRT -eq 1 ]]; then
            if [[ " ${CMAKE_ARGS[*]} " == *"-DYUME_STATIC=ON"* ]]; then
                warn "OpenWRT build: forcing YUME_STATIC=OFF to avoid static link of shared libs."
                CMAKE_ARGS=("${CMAKE_ARGS[@]/-DYUME_STATIC=ON/-DYUME_STATIC=OFF}")
            fi
            CMAKE_ARGS+=("-DYUME_STATIC=OFF")
        fi
        CMAKE_ARGS+=("-DBASEFWX_NATIVE_OPT=OFF")
        info "Using toolchain: ${YUME_TOOLCHAIN_FILE}"
        CMAKE_ARGS+=("-DCMAKE_TOOLCHAIN_FILE=${YUME_TOOLCHAIN_FILE}")
        CMAKE_ARGS+=("-DCMAKE_SYSTEM_NAME=Linux")
    fi

    if [[ -n "$TARGET_ARCH" ]]; then
        info "Target architecture: $TARGET_ARCH"
        CMAKE_ARGS+=(
            "-DCMAKE_SYSTEM_PROCESSOR=${TARGET_ARCH}"
            "-DYUME_TARGET_ARCH=${TARGET_ARCH}"
        )
        if [[ -n "${YUME_TOOLCHAIN_FILE:-}" ]]; then
            CMAKE_ARGS+=("-DCMAKE_TOOLCHAIN_FILE=${YUME_TOOLCHAIN_FILE}")
        elif [[ $OPENWRT -eq 0 && $BUSYBOX -eq 0 ]]; then
            warn "No YUME_TOOLCHAIN_FILE set; cross-compile may fail on ${TARGET_ARCH}."
        fi
    fi

    if [[ $OPENWRT -eq 1 || $BUSYBOX -eq 1 ]]; then
        CMAKE_ARGS+=(
            "-DYUME_USE_SPDLOG=OFF"
            "-DYUME_OFFLINE=ON"
        )
    fi

    if need_cmd cmake; then
        ok "CMake detected."
    else
        warn "CMake not found. Will install build dependencies."
    fi

    if [[ "${YUME_SKIP_DEPS:-0}" == "1" ]]; then
        warn "Skipping dependency install (YUME_SKIP_DEPS=1)."
    else
        uname_out="$(uname -s)"
        case "${uname_out}" in
            Linux*)
                install_deps_linux || { error "Dependency install failed."; exit 1; }
                ;;
            Darwin*)
                install_deps_macos || { error "Dependency install failed."; exit 1; }
                ;;
            MINGW*|MSYS*|CYGWIN*)
                install_deps_windows || { error "Dependency install failed."; exit 1; }
                ;;
            *)
                error "Unsupported OS: ${uname_out}"
                exit 1
                ;;
        esac
    fi

    # Set macOS CMAKE paths (even when skipping deps)
    if [[ "$(uname -s)" == "Darwin" ]] && need_cmd brew; then
        local homebrew_prefix
        homebrew_prefix="$(brew --prefix)"
        info "Homebrew prefix: ${homebrew_prefix}"
        # Only add if not already set via YUME_CMAKE_ARGS
        if [[ " ${CMAKE_ARGS[*]:-} " != *"CMAKE_PREFIX_PATH"* ]]; then
            # Find Boost cmake config directory
            local boost_cmake_dir=""
            if [[ -d "${homebrew_prefix}/opt/boost/lib/cmake" ]]; then
                boost_cmake_dir=$(ls -d "${homebrew_prefix}/opt/boost/lib/cmake/Boost-"* 2>/dev/null | head -1 || true)
            fi
            CMAKE_ARGS+=(
                "-DCMAKE_PREFIX_PATH=${homebrew_prefix};${homebrew_prefix}/opt/openssl@3;${homebrew_prefix}/opt/boost"
                "-DOPENSSL_ROOT_DIR=${homebrew_prefix}/opt/openssl@3"
            )
            # Add Boost hints
            if [[ -n "${boost_cmake_dir}" ]]; then
                info "Found Boost cmake config at: ${boost_cmake_dir}"
                CMAKE_ARGS+=("-DBoost_DIR=${boost_cmake_dir}")
            else
                CMAKE_ARGS+=("-DBoost_ROOT=${homebrew_prefix}/opt/boost")
            fi
            CMAKE_ARGS+=("-DBoost_NO_SYSTEM_PATHS=ON")
        fi
    fi

    ensure_basefwx
    cleanup_vendor
    if [[ $OPENWRT -eq 1 || $BUSYBOX -eq 1 ]]; then
        if [[ $OPENWRT -eq 1 && -d "${PWD}/vendor/openwrt-mips" ]]; then
            CMAKE_ARGS+=("-DBASEFWX_VENDOR_DIR=${PWD}/vendor/openwrt-mips")
        elif [[ $BUSYBOX -eq 1 && -n "${TARGET_ARCH}" ]]; then
            if [[ -d "${PWD}/vendor/busybox-${TARGET_ARCH}" ]]; then
                CMAKE_ARGS+=("-DBASEFWX_VENDOR_DIR=${PWD}/vendor/busybox-${TARGET_ARCH}")
            fi
        fi
        if detect_liboqs_target; then
            info "liboqs detected; enabling PQ in BaseFWX."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_OQS=ON")
            IFS='|' read -r _oqs_inc _oqs_lib < <(resolve_oqs_sysroot_paths)
            if [[ -n "${_oqs_inc}" && -n "${_oqs_lib}" ]]; then
                CMAKE_ARGS+=(
                    "-DOQS_INCLUDE_DIR=${_oqs_inc}"
                    "-DOQS_LIBRARY=${_oqs_lib}"
                    "-DOQS_INCLUDE_DIRS=${_oqs_inc}"
                    "-DOQS_LIBRARIES=${_oqs_lib}"
                    "-DOQS_FOUND=TRUE"
                )
                if [[ -n "${_oqs_lib}" && "${_oqs_lib}" == *.a ]]; then
                    CMAKE_ARGS+=("-DOQS_LIBRARY_STATIC=${_oqs_lib}")
                fi
            fi
            # Static-link selection. Old code only checked OPENWRT_USR
            # so this branch tripped over `unbound variable` for the
            # BUSYBOX vendor path now that detect_liboqs_target returns
            # success there too. Probe both, with the resolved .a from
            # resolve_oqs_sysroot_paths as the canonical source of truth.
            _oqs_static_path=""
            if [[ -n "${OPENWRT_USR:-}" && -f "${OPENWRT_USR}/lib/liboqs.a" ]]; then
                _oqs_static_path="${OPENWRT_USR}/lib/liboqs.a"
            elif [[ "${BUSYBOX:-0}" -eq 1 && -n "${TARGET_ARCH:-}" \
                    && -f "${PWD}/vendor/busybox-${TARGET_ARCH}/lib/liboqs.a" ]]; then
                _oqs_static_path="${PWD}/vendor/busybox-${TARGET_ARCH}/lib/liboqs.a"
            fi
            if [[ -n "${YUME_OQS_STATIC:-}" ]] || [[ -n "${_oqs_static_path}" ]]; then
                if [[ -n "${_oqs_static_path}" ]]; then
                    info "Using static liboqs."
                    CMAKE_ARGS+=("-DBASEFWX_OQS_STATIC=ON")
                else
                    warn "YUME_OQS_STATIC=1 set but no static liboqs.a found; falling back to shared."
                fi
            fi
        else
            warn "liboqs not detected for this target; PQ will be disabled."
            require_feature_or_die "${YUME_REQUIRE_OQS}" "liboqs / PQ support" "Provide a sysroot/vendor liboqs or unset YUME_REQUIRE_OQS."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_OQS=OFF")
        fi
        if detect_argon2; then
            IFS='|' read -r _argon2_inc _argon2_lib < <(resolve_argon2_sysroot_paths)
            if [[ -n "${_argon2_inc}" && -n "${_argon2_lib}" ]]; then
                info "OpenWRT libargon2 detected in sysroot; enabling Argon2 in BaseFWX."
                CMAKE_ARGS+=(
                    "-DBASEFWX_REQUIRE_ARGON2=ON"
                    "-DARGON2_INCLUDE_DIR=${_argon2_inc}"
                    "-DARGON2_LIBRARY=${_argon2_lib}"
                    "-DARGON2_INCLUDE_DIRS=${_argon2_inc}"
                    "-DARGON2_LIBRARIES=${_argon2_lib}"
                    "-DARGON2_FOUND=TRUE"
                )
            else
                warn "OpenWRT libargon2 headers found but library missing; disabling Argon2."
                require_feature_or_die "${YUME_REQUIRE_ARGON2}" "libargon2 support" "Provide a sysroot/vendor libargon2 or unset YUME_REQUIRE_ARGON2."
                CMAKE_ARGS+=("-DBASEFWX_REQUIRE_ARGON2=OFF")
            fi
        else
            warn "OpenWRT libargon2 not detected in sysroot; heavy KDF will fall back to HKDF."
            require_feature_or_die "${YUME_REQUIRE_ARGON2}" "libargon2 support" "Provide a sysroot/vendor libargon2 or unset YUME_REQUIRE_ARGON2."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_ARGON2=OFF")
        fi
    elif [[ "${WINDOWS_CROSS}" == "1" ]]; then
        if [[ -f "${VCPKG_PREFIX}/include/oqs/oqs.h" ]]; then
            info "Windows cross: liboqs detected in dependency prefix; enabling PQ in BaseFWX."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_OQS=ON")
        else
            warn "Windows cross: liboqs not detected in dependency prefix; PQ will be disabled."
            require_feature_or_die "${YUME_REQUIRE_OQS}" "liboqs / PQ support" "Ensure the Windows dependency prefix provides liboqs."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_OQS=OFF")
        fi
        if [[ -f "${VCPKG_PREFIX}/include/argon2.h" ]]; then
            info "Windows cross: libargon2 detected in dependency prefix; enabling Argon2 in BaseFWX."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_ARGON2=ON")
        else
            warn "Windows cross: libargon2 not detected in dependency prefix; heavy KDF will fall back to HKDF."
            require_feature_or_die "${YUME_REQUIRE_ARGON2}" "libargon2 support" "Ensure the Windows dependency prefix provides argon2."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_ARGON2=OFF")
        fi
    elif [[ "${YUME_MACOS_CROSS:-0}" == "1" ]]; then
        CMAKE_ARGS+=("-DYUME_FORCE_CROSS=ON")
        local macos_vendor_prefix=""
        macos_vendor_prefix="$(macos_vendor_dir || true)"
        if [[ -n "${macos_vendor_prefix}" ]]; then
            info "macOS cross: using vendored dependency prefix at ${macos_vendor_prefix}"
            CMAKE_ARGS+=(
                "-DBASEFWX_VENDOR_DIR=${macos_vendor_prefix}"
                "-DCMAKE_PREFIX_PATH=${macos_vendor_prefix}"
                "-DOPENSSL_ROOT_DIR=${macos_vendor_prefix}"
                "-DBoost_DIR=${macos_vendor_prefix}/share/boost"
                "-DZSTD_DIR=${macos_vendor_prefix}/share/zstd"
            )
            if [[ -d "${macos_vendor_prefix}/share/spdlog" ]]; then
                CMAKE_ARGS+=("-Dspdlog_DIR=${macos_vendor_prefix}/share/spdlog")
            fi
            if [[ -d "${macos_vendor_prefix}/share/fmt" ]]; then
                CMAKE_ARGS+=("-Dfmt_DIR=${macos_vendor_prefix}/share/fmt")
            fi
        fi
    else
        local host_vendor_dir=""
        host_vendor_dir="$(vendor_dir_for_build)"
        if [[ -n "${host_vendor_dir}" ]]; then
            CMAKE_ARGS+=("-DBASEFWX_VENDOR_DIR=${host_vendor_dir}")
        fi
        if [[ -n "${YUME_OQS_STATIC:-}" ]] && [[ ! -f /usr/lib/x86_64-linux-gnu/liboqs.a && ! -f /usr/local/lib/liboqs.a ]]; then
            local oqs_vendor_dir=""
            oqs_vendor_dir="$(vendor_dir_for_build)"
            if vendor_has_liboqs "${oqs_vendor_dir}"; then
                info "Vendored liboqs detected; skipping source build."
            elif [[ -n "${YUME_VENDOR_ONLY:-}" ]]; then
                warn "YUME_VENDOR_ONLY=1 set; skipping liboqs source build."
            else
                warn "YUME_OQS_STATIC=1 set but liboqs.a missing; building liboqs (static) from source."
                build_liboqs_host || warn "Host liboqs build failed; PQ may fall back to shared."
            fi
        fi
        if detect_liboqs; then
            info "liboqs detected; enabling PQ in BaseFWX."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_OQS=ON")
            IFS='|' read -r _oqs_inc _oqs_lib < <(resolve_oqs_host_paths)
            if [[ -n "${_oqs_inc}" && -n "${_oqs_lib}" ]]; then
                CMAKE_ARGS+=(
                    "-DOQS_INCLUDE_DIR=${_oqs_inc}"
                    "-DOQS_LIBRARY=${_oqs_lib}"
                    "-DOQS_INCLUDE_DIRS=${_oqs_inc}"
                    "-DOQS_LIBRARIES=${_oqs_lib}"
                    "-DOQS_FOUND=TRUE"
                )
                if [[ -n "${_oqs_lib}" && "${_oqs_lib}" == *.a ]]; then
                    CMAKE_ARGS+=("-DOQS_LIBRARY_STATIC=${_oqs_lib}")
                fi
            fi
            if [[ -n "${YUME_OQS_STATIC:-}" ]]; then
                if [[ -f /usr/lib/x86_64-linux-gnu/liboqs.a || -f /usr/local/lib/liboqs.a ]]; then
                    info "Using static liboqs."
                    CMAKE_ARGS+=("-DBASEFWX_OQS_STATIC=ON")
                else
                    warn "YUME_OQS_STATIC=1 set but liboqs.a not found; falling back to shared."
                fi
            fi
        else
            # System liboqs is missing — try vendor/<host>/ before
            # giving up. vendor/ ships liboqs.a on Linux and a
            # versioned liboqs.dylib on macOS, both of which CMake can
            # consume the same way as a system install. If the
            # vendor/ tree isn't on disk, unpack
            # yume-vendor-prebuilt.tar.xz on demand; the marker file
            # remembers what we created so the post-build cleanup
            # only removes our artifacts.
            ensure_vendor_for_host "$(host_default_vendor_key)" || true
            IFS='|' read -r _vendor_oqs_inc _vendor_oqs_lib < <(resolve_vendor_oqs_paths)
            if [[ -n "${_vendor_oqs_inc}" && -n "${_vendor_oqs_lib}" ]]; then
                info "liboqs not on the system; using vendor copy at ${_vendor_oqs_lib}."
                CMAKE_ARGS+=(
                    "-DBASEFWX_REQUIRE_OQS=ON"
                    "-DOQS_INCLUDE_DIR=${_vendor_oqs_inc}"
                    "-DOQS_LIBRARY=${_vendor_oqs_lib}"
                    "-DOQS_INCLUDE_DIRS=${_vendor_oqs_inc}"
                    "-DOQS_LIBRARIES=${_vendor_oqs_lib}"
                    "-DOQS_FOUND=TRUE"
                )
                if [[ "${_vendor_oqs_lib}" == *.a ]]; then
                    CMAKE_ARGS+=(
                        "-DOQS_LIBRARY_STATIC=${_vendor_oqs_lib}"
                        "-DBASEFWX_OQS_STATIC=ON"
                    )
                fi
            else
                warn "liboqs not detected; PQ will be disabled unless you install it."
                require_feature_or_die "${YUME_REQUIRE_OQS}" "liboqs / PQ support" "Install liboqs or stage it in vendor/ before building."
                CMAKE_ARGS+=("-DBASEFWX_REQUIRE_OQS=OFF")
            fi
        fi
        if detect_argon2; then
            info "libargon2 detected; enabling Argon2 in BaseFWX."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_ARGON2=ON")
        else
            # Same vendor fallback as liboqs above. ensure_vendor_for_host
            # may have run already above; calling it again is a no-op
            # when the tree is in place.
            ensure_vendor_for_host "$(host_default_vendor_key)" || true
            IFS='|' read -r _vendor_argon2_inc _vendor_argon2_lib < <(resolve_vendor_argon2_paths)
            if [[ -n "${_vendor_argon2_inc}" && -n "${_vendor_argon2_lib}" ]]; then
                info "libargon2 not on the system; using vendor copy at ${_vendor_argon2_lib}."
                CMAKE_ARGS+=(
                    "-DBASEFWX_REQUIRE_ARGON2=ON"
                    "-DARGON2_INCLUDE_DIR=${_vendor_argon2_inc}"
                    "-DARGON2_LIBRARY=${_vendor_argon2_lib}"
                    "-DARGON2_INCLUDE_DIRS=${_vendor_argon2_inc}"
                    "-DARGON2_LIBRARIES=${_vendor_argon2_lib}"
                    "-DARGON2_FOUND=TRUE"
                )
            else
                warn "libargon2 not detected; heavy KDF will fall back to HKDF."
                require_feature_or_die "${YUME_REQUIRE_ARGON2}" "libargon2 support" "Install libargon2 or stage it in vendor/ before building."
                CMAKE_ARGS+=("-DBASEFWX_REQUIRE_ARGON2=OFF")
            fi
        fi
    fi
    build_project
    if [[ $BUILD_DEB -eq 1 ]]; then
        package_deb
    fi
    local exe_suffix=""
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*)
            exe_suffix=".exe"
            ;;
    esac
    info "Done."
    # The build succeeded — drop any vendor tree we extracted on
    # demand. If the user had a vendor/ checked out, this is a no-op
    # because the marker file we leave behind never claims paths that
    # existed before ezbuild ran. YUME_KEEP_VENDOR=1 disables the
    # cleanup for debugging.
    cleanup_unpacked_vendor
    local build_dir="${YUME_BUILD_DIR:-build}"
    echo -e "${COLOR_GREEN}Run:${COLOR_RESET} ./${build_dir}/bin/yumed${exe_suffix} --config config/yumed.json"
    echo -e "${COLOR_GREEN}Then:${COLOR_RESET} ./${build_dir}/bin/yume${exe_suffix} --config config/yume.json --socks 1080"
}

main "$@"
