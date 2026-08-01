#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
set -euo pipefail

# YUME ezbuild: install dependencies and build

EZBUILD_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/library_detection.sh
source "${EZBUILD_REPO_ROOT}/scripts/lib/library_detection.sh"
# shellcheck source=scripts/lib/user_context.sh
source "${EZBUILD_REPO_ROOT}/scripts/lib/user_context.sh"

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
BUILD_TESTS=0
BUILD_TOOLS=0
BUILD_SELFTEST=0
SELFTEST_ONLY=0
DEV_BUILD=0
NATIVE_OPT=0
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
BASEFWX_REF_FILE="${BASEFWX_REF_FILE:-${PWD}/config/refs/basefwx.ref}"
BASEFWX_SYNC_MODE="${BASEFWX_SYNC_MODE:-auto}"
BASEFWX_EFFECTIVE_SYNC_MODE=""
YUME_REQUIRE_ARGON2="${YUME_REQUIRE_ARGON2:-0}"
YUME_REQUIRE_OQS="${YUME_REQUIRE_OQS:-0}"

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

REAL_HOME="$(yume_real_home)"
REAL_UID="$(yume_real_uid)"
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
  --use-vendor [SRC]      Link PREBUILT liboqs/argon2 instead of compiling
                          them. OFF by default: without this flag every
                          dependency is built from source or taken from the
                          system package manager.
                          SRC may be omitted, or be a .tar.xz path, an
                          already-unpacked directory, or an https URL. With no
                          SRC it downloads from
                          https://deb.fixcraft.jp/yume/. Archives must pass
                          BOTH a pinned SHA-256 and a GPG signature check; the
                          build aborts if either fails.
  --minimal               Build a minimal/static YUME
  --gui                   Also build the optional yume-gui desktop app
                          (installs libgl/libglfw/appindicator dev pkgs)
  --tests                 Build unit-test executables
  --tools                 Build helper tools such as yume-net-map
  --selftest, --include-selftest
                          Build desktop benchmark/self-test tools
                          alongside yume and yumed
  --selftest-only         Build only yume, yumed, and desktop self-test
                          benchmark tools; skips GUI/tests/helper tools
  --dev                   Optimized developer build (RelWithDebInfo) with
                          opt-in low-level timing diagnostics compiled in
  --native                Tune for this host CPU (-march/-mtune=native);
                          fastest locally, not portable to older CPUs
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
  BASEFWX_SYNC_MODE       BaseFWX checkout policy:
                          auto (preserve an attached developer branch),
                          worktree (never fetch/checkout), or
                          pinned (require a clean tree and use the pin)
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
}

# Prebuilt vendor libraries are OPT-IN and off by default.
#
# Linking a binary someone else compiled is a trust decision, and it is not
# ezbuild's to make silently. Without --use-vendor every dependency is built
# from source or taken from the system package manager, which is what a user
# who does not trust prebuilt blobs expects to happen by default.
#
# --use-vendor            use the archive/directory shipped or configured
# --use-vendor <path>     use a specific .tar.xz or an already-unpacked dir
# --use-vendor <url>      download, then verify SHA-256 *and* GPG signature
YUME_USE_VENDOR=0
YUME_VENDOR_SOURCE=""
YUME_VENDOR_ROOT="${YUME_VENDOR_ROOT:-${PWD}/vendor}"
YUME_VENDOR_ACQUIRED=0

vendor_access_enabled() {
    [[ "${YUME_USE_VENDOR:-0}" == "1" || "${YUME_STAGED_VENDOR_ALLOWED:-0}" == "1" ]]
}

# Verification lives in scripts/vendor_prebuilt.sh, which is the single
# implementation shared by ezbuild.sh, fullau.sh and CI. It pins both the
# SHA-256 and the release key *fingerprint* — a bare `gpg --verify` would
# accept a valid signature from any key in the caller's keyring, which is
# not a check at all.
#
# It also owns YUME_VENDOR_ARCHIVE_DEFAULT / YUME_VENDOR_URL_DEFAULT and the
# temporary download path, so those are no longer duplicated here.
# shellcheck source=scripts/vendor_prebuilt.sh
source "${PWD}/scripts/vendor_prebuilt.sh"

# A verified archive is extracted below YUME_TMP_ROOT. Existing repository
# vendor/ content is read only after an explicit opt-in.

ensure_vendor_for_host() {
    local needed_key="${1:-}"

    # Only a direct --use-vendor request may acquire prebuilts. fullau uses
    # YUME_STAGED_VENDOR_ALLOWED for its isolated, source-built/verified tree.
    if ! vendor_access_enabled; then
        return 1
    fi

    local requested="${YUME_VENDOR_SOURCE:-${YUME_VENDOR_ARCHIVE:-}}"

    # An already-unpacked directory may be either the archive root
    # (<dir>/vendor/<target>) or vendor/ itself.
    if [[ -n "${requested}" && -d "${requested}" ]]; then
        if ! yume_vendor_directory_root "${requested}" YUME_VENDOR_ROOT; then
            return 1
        fi
        if [[ -n "${needed_key}" && ! -d "${YUME_VENDOR_ROOT}/${needed_key}" ]]; then
            warn "Vendor target '${needed_key}' is missing from ${YUME_VENDOR_ROOT}."
            return 1
        fi
        warn "Using prebuilt vendor libraries from ${requested} (not built from source)."
        YUME_VENDOR_ACQUIRED=1
        return 0
    fi

    # A tree staged by fullau has already been source-built or verified. A tree
    # acquired earlier in this ezbuild invocation has already passed the same
    # decision. Do not silently trust unrelated ignored repo residue merely
    # because --use-vendor was given without an explicit directory.
    if [[ ("${YUME_STAGED_VENDOR_ALLOWED:-0}" == "1" ||
           "${YUME_VENDOR_ACQUIRED}" == "1") &&
          -n "${needed_key}" && -d "${YUME_VENDOR_ROOT}/${needed_key}" ]]; then
        return 0
    fi

    # Resolve to a verified local archive: the committed path if present,
    # otherwise the published URL. Both the SHA-256 and the release-key
    # fingerprint must match or this returns non-zero and we build from source.
    local archive=""
    if ! yume_vendor_obtain "${requested}" archive; then
        return 1
    fi

    warn "Using PREBUILT vendor libraries — these binaries were not compiled on this machine."
    warn "  Omit --use-vendor to build every dependency from source instead."

    if ! need_cmd tar; then
        warn "Cannot unpack ${archive}: tar not found."
        yume_vendor_cleanup "${archive}"
        return 1
    fi

    local extract_root="${YUME_TMP_ROOT}/vendor-prebuilt"
    mkdir -p "${extract_root}"
    step "Unpacking the verified vendor archive into ${extract_root}..."
    if ! yume_vendor_ensure_extracted "${extract_root}" "${archive}"; then
        return 1
    fi
    YUME_VENDOR_ROOT="${extract_root}/vendor"
    if [[ -n "${needed_key}" && ! -d "${YUME_VENDOR_ROOT}/${needed_key}" ]]; then
        warn "Vendor target '${needed_key}' is missing from the verified archive."
        return 1
    fi
    YUME_VENDOR_ACQUIRED=1
    ok "Vendor archive unpacked."
    return 0
}

YUME_LOCK_ROOT="$(init_lock_root)"
trap cleanup_temp_assets EXIT

env_truthy() {
    # Lowercase via tr, not ${x,,}: the latter is a bash-4 expansion and macOS
    # still ships bash 3.2 as /bin/bash, where it is a syntax error. tr keeps
    # this runnable under the stock Mac shell.
    local value
    value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    case "${value}" in
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
    if ! sudo apt-get update -y; then
        return 1
    fi
    touch "${APT_UPDATED_FLAG}"
}

dpkg_pkg_installed() {
    local pkg="$1"
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'
}

# Install only packages that are not already on the system. Skips apt-get
# entirely when the list is satisfied — avoids a full dependency-tree walk
# per package on repeat ezbuild runs.
apt_install_if_missing() {
    local missing=()
    local pkg
    for pkg in "$@"; do
        if ! dpkg_pkg_installed "$pkg"; then
            missing+=("$pkg")
        fi
    done
    if ((${#missing[@]} == 0)); then
        return 0
    fi
    apt_update_once || return 1
    sudo apt-get install -y "${missing[@]}"
}

apt_install_gui_package() {
    local pkg="$1"
    local backports_suite="${2:-}"
    if dpkg_pkg_installed "$pkg"; then
        return 0
    fi
    if sudo apt-get install -y "$pkg" 2>/dev/null; then
        return 0
    fi
    if [[ -n "$backports_suite" ]] \
        && sudo apt-get install -y -t "$backports_suite" "$pkg" 2>/dev/null; then
        info "Installed '${pkg}' from ${backports_suite}."
        return 0
    fi
    return 1
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

requested_vendor_key() {
    if [[ $OPENWRT -eq 1 ]]; then
        echo "openwrt-mips"
        return
    fi
    if [[ $BUSYBOX -eq 1 ]]; then
        case "${TARGET_ARCH:-}" in
            aarch64|arm64) echo "armv8" ;;
            armhf|armv7l) echo "armv7" ;;
            i386|i486|i586|i686) echo "x86" ;;
            *) echo "${TARGET_ARCH:-}" ;;
        esac
        return
    fi
    if [[ "${WINDOWS_CROSS}" == "1" ]]; then
        echo "windows-x86_64"
        return
    fi
    if [[ "${YUME_MACOS_CROSS:-0}" == "1" ]]; then
        case "${YUME_MACOS_VENDOR_ARCH:-x86_64}" in
            arm64|aarch64) echo "macos-arm64" ;;
            *) echo "macos-x86_64" ;;
        esac
        return
    fi
    case "${TARGET_ARCH:-}" in
        aarch64|arm64) echo "armv8" ;;
        armhf|armv7l) echo "armv7" ;;
        i386|i486|i586|i686) echo "x86" ;;
        "") host_default_vendor_key ;;
        *) echo "${TARGET_ARCH}" ;;
    esac
}

# Vendor directory for a BusyBox cross target.
#
# BusyBox targets link the same static archives as their non-BusyBox siblings.
# The prebuilt archive used to ship busybox-armv7 / busybox-armv8 / busybox-x86
# as byte-identical copies of armv7 / armv8 / x86; the 2026-07-24 vendor rework
# dropped the duplicates but the lookup paths below still named only the
# busybox-* form, so --use-vendor stopped finding liboqs/argon2 for those
# targets even though an identical library was one directory over.
#
# Prefer a locally staged busybox-<arch> — build-liboqs-target.sh and
# release.yml still install there — then fall back to the plain <arch> that the
# archive actually ships. Returns non-zero (and prints nothing) if neither
# exists; callers keep their previous "not found" behaviour in that case.
busybox_vendor_dir() {
    if ! vendor_access_enabled; then
        return 1
    fi
    local arch="${1:-${TARGET_ARCH:-}}"
    if [[ -z "${arch}" ]]; then
        return 1
    fi
    case "${arch}" in
        aarch64|arm64) arch="armv8" ;;
        armhf|armv7l) arch="armv7" ;;
        i386|i486|i586|i686) arch="x86" ;;
    esac
    local candidate
    for candidate in "${YUME_VENDOR_ROOT}/busybox-${arch}" "${YUME_VENDOR_ROOT}/${arch}"; do
        if [[ -d "${candidate}" ]]; then
            printf '%s' "${candidate}"
            return 0
        fi
    done
    return 1
}

vendor_dir_for_build() {
    if ! vendor_access_enabled; then
        echo ""
        return
    fi
    if [[ $OPENWRT -eq 1 && -d "${YUME_VENDOR_ROOT}/openwrt-mips" ]]; then
        echo "${YUME_VENDOR_ROOT}/openwrt-mips"
        return
    fi
    if [[ $BUSYBOX -eq 1 && -n "${TARGET_ARCH}" ]]; then
        busybox_vendor_dir "${TARGET_ARCH}" || true
        return
    fi
    if [[ -n "${TARGET_ARCH}" && -d "${YUME_VENDOR_ROOT}/${TARGET_ARCH}" ]]; then
        echo "${YUME_VENDOR_ROOT}/${TARGET_ARCH}"
        return
    fi

    local host_vendor_key=""
    host_vendor_key="$(host_default_vendor_key)"
    if [[ -n "${host_vendor_key}" && -d "${YUME_VENDOR_ROOT}/${host_vendor_key}" ]]; then
        echo "${YUME_VENDOR_ROOT}/${host_vendor_key}"
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
    if ! vendor_access_enabled; then
        return 1
    fi
    local dir="${YUME_VENDOR_ROOT}/windows-x86_64"
    if vendor_has_cross_prefix "${dir}"; then
        echo "${dir}"
        return 0
    fi
    return 1
}

macos_vendor_dir() {
    if ! vendor_access_enabled; then
        return 1
    fi
    local arch="${YUME_MACOS_VENDOR_ARCH:-}"
    local dir=""
    if [[ "${arch}" == "arm64" ]]; then
        dir="${YUME_VENDOR_ROOT}/macos-arm64"
        if vendor_has_cross_prefix "${dir}"; then
            echo "${dir}"
            return 0
        fi
    fi
    if [[ -z "${arch}" || "${arch}" == "x86_64" ]]; then
        dir="${YUME_VENDOR_ROOT}/macos-x86_64"
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
        if yume_library_artifact_exists liboqs "${OPENWRT_USR}/lib"; then
            return 0
        fi
    fi
    if [[ -f /usr/include/oqs/oqs.h ]] || [[ -f /usr/local/include/oqs/oqs.h ]]; then
        return 0
    fi
    if yume_library_artifact_exists liboqs \
        /usr/lib/x86_64-linux-gnu /usr/lib /usr/local/lib; then
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
        if yume_library_artifact_exists libargon2 "${OPENWRT_USR}/lib"; then
            return 0
        fi
    fi
    # BUSYBOX cross builds: also check the vendor sysroot we stage to.
    # Without this the function would happily report true based on the
    # host argon2.h alone, but resolve_argon2_sysroot_paths would then
    # return empty paths and the build aborts with
    #   "libargon2 headers found but library missing".
    if [[ "${BUSYBOX:-0}" -eq 1 && -n "${TARGET_ARCH:-}" ]]; then
        local _vendor
        _vendor="$(busybox_vendor_dir || true)"
        if [[ -n "${_vendor}" && -f "${_vendor}/include/argon2.h" \
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
    if yume_library_artifact_exists libargon2 \
        /usr/lib/x86_64-linux-gnu /usr/lib /usr/local/lib; then
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
    # liboqs into the selected vendor root via scripts/build-liboqs-target.sh.
    # ezbuild passes the resolved BusyBox/plain architecture prefix
    # below (line ~1652) when that dir exists; we also want PQ flagged on
    # so basefwx's CMake actually emits -DBASEFWX_REQUIRE_OQS=ON for the
    # build. Without this hook, the BUSYBOX branch fell straight through
    # to "PQ will be disabled" even when a properly cross-built
    # liboqs.a was sitting at the expected vendor path.
    if [[ "${BUSYBOX:-0}" -eq 1 && -n "${TARGET_ARCH:-}" ]]; then
        local _vendor
        _vendor="$(busybox_vendor_dir || true)"
        if [[ -n "${_vendor}" && -f "${_vendor}/include/oqs/oqs.h" \
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
        local _vendor
        _vendor="$(busybox_vendor_dir || true)"
        if [[ -n "${_vendor}" && -f "${_vendor}/include/oqs/oqs.h" ]]; then
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
        # the selected vendor prefix via build-libargon2-target.sh.
        # Same shape as the OQS sibling fix earlier in this file.
        local _vendor
        _vendor="$(busybox_vendor_dir || true)"
        if [[ -n "${_vendor}" && -f "${_vendor}/include/argon2.h" ]]; then
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

append_selected_vendor_crypto_args() {
    local oqs_inc=""
    local oqs_lib=""
    local argon2_inc=""
    local argon2_lib=""
    IFS='|' read -r oqs_inc oqs_lib < <(resolve_vendor_oqs_paths)
    IFS='|' read -r argon2_inc argon2_lib < <(resolve_vendor_argon2_paths)

    if [[ -z "${oqs_inc}" || -z "${oqs_lib}" ]]; then
        error "Selected vendor root does not contain a complete liboqs target."
        return 1
    fi
    if [[ -z "${argon2_inc}" || -z "${argon2_lib}" ]]; then
        error "Selected vendor root does not contain a complete libargon2 target."
        return 1
    fi

    info "Using selected vendor liboqs at ${oqs_lib}."
    info "Using selected vendor libargon2 at ${argon2_lib}."
    CMAKE_ARGS+=(
        "-DBASEFWX_REQUIRE_OQS=ON"
        "-DBASEFWX_USE_VENDOR_OQS=ON"
        "-DOQS_INCLUDE_DIR=${oqs_inc}"
        "-DOQS_LIBRARY=${oqs_lib}"
        "-DOQS_INCLUDE_DIRS=${oqs_inc}"
        "-DOQS_LIBRARIES=${oqs_lib}"
        "-DOQS_FOUND=TRUE"
        "-DBASEFWX_REQUIRE_ARGON2=ON"
        "-DBASEFWX_USE_VENDOR_ARGON2=ON"
        "-DARGON2_INCLUDE_DIR=${argon2_inc}"
        "-DARGON2_LIBRARY=${argon2_lib}"
        "-DARGON2_INCLUDE_DIRS=${argon2_inc}"
        "-DARGON2_LIBRARIES=${argon2_lib}"
        "-DARGON2_FOUND=TRUE"
    )
    if [[ "${oqs_lib}" == *.a ]]; then
        CMAKE_ARGS+=(
            "-DOQS_LIBRARY_STATIC=${oqs_lib}"
            "-DBASEFWX_OQS_STATIC=ON"
        )
    fi
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
    cmake --build "${workdir}/build" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
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
    cmake --build "${workdir}/build" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
    cmake --install "${workdir}/build"
    return 0
}

ensure_basefwx() {
    local ref="${BASEFWX_REF:-}"
    local mode="${BASEFWX_SYNC_MODE}"
    local created=0
    local repo_present=0
    if ! need_cmd git; then
        error "git not found; cannot fetch BaseFWX."
        return 1
    fi
    case "${mode}" in
        auto|worktree|pinned)
            ;;
        *)
            error "Invalid BASEFWX_SYNC_MODE='${mode}'; expected auto, worktree, or pinned."
            return 1
            ;;
    esac

    if [[ -e basefwx || -L basefwx ]]; then
        if [[ ! -d basefwx ]]; then
            error "basefwx exists but is not a directory; refusing to replace it."
            return 1
        fi

        # `git -C basefwx rev-parse --is-inside-work-tree` is insufficient:
        # Git walks upward, so a plain basefwx/ directory inside this YUME
        # checkout would be misidentified as the enclosing YUME repository.
        # Require basefwx/ itself to be the canonical worktree root before any
        # fetch, checkout, or status command can target it.
        local expected_root discovered_root canonical_discovered_root=""
        expected_root="$(cd basefwx && pwd -P)"
        discovered_root="$(git -C basefwx rev-parse --show-toplevel 2>/dev/null || true)"
        if [[ -n "${discovered_root}" && -d "${discovered_root}" ]]; then
            canonical_discovered_root="$(cd "${discovered_root}" && pwd -P)"
        fi
        if [[ -z "${canonical_discovered_root}" ||
              "${canonical_discovered_root}" != "${expected_root}" ]]; then
            error "basefwx exists but is not the root of a Git worktree; refusing to replace or mutate it."
            error "Move it aside explicitly, or set up the BaseFWX checkout manually."
            return 1
        fi
        repo_present=1
    fi

    if [[ ${repo_present} -eq 0 && "${mode}" == "worktree" ]]; then
        error "BASEFWX_SYNC_MODE=worktree requires an existing BaseFWX Git worktree."
        return 1
    fi
    if [[ ${repo_present} -eq 0 ]]; then
        if [[ -z "${ref}" ]]; then
            error "Pinned BaseFWX setup requires BASEFWX_REF or a non-empty ${BASEFWX_REF_FILE}."
            return 1
        fi
        step "Cloning BaseFWX..."
        git clone --filter=blob:none --no-checkout "${BASEFWX_REPO}" basefwx ||
            return 1
        created=1
    else
        info "BaseFWX already present."
    fi

    local current_branch=""
    current_branch="$(git -C basefwx symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
    if [[ "${mode}" == "auto" ]]; then
        if [[ ${created} -eq 0 && -n "${current_branch}" ]]; then
            mode="worktree"
        else
            mode="pinned"
        fi
    fi
    BASEFWX_EFFECTIVE_SYNC_MODE="${mode}"

    if [[ "${mode}" == "worktree" ]]; then
        if [[ ! -f basefwx/cpp/CMakeLists.txt ]]; then
            error "BaseFWX worktree is incomplete: basefwx/cpp/CMakeLists.txt is missing."
            return 1
        fi
        local current_sha requested_sha=""
        if ! current_sha="$(git -C basefwx rev-parse HEAD)"; then
            error "Could not resolve the current BaseFWX worktree commit."
            return 1
        fi
        requested_sha="$(git -C basefwx rev-parse --verify "${ref}^{commit}" 2>/dev/null || true)"
        if [[ -n "${requested_sha}" && "${current_sha}" != "${requested_sha}" ]]; then
            warn "Using BaseFWX developer worktree at ${current_sha:0:12}; configured pin is ${requested_sha:0:12}."
            warn "Use BASEFWX_SYNC_MODE=pinned for a clean, reproducible pinned build."
        else
            info "Using existing BaseFWX developer worktree without fetching or changing branches."
        fi
        if [[ "$(git -C basefwx rev-parse --is-shallow-repository 2>/dev/null || true)" == "true" ]]; then
            warn "BaseFWX developer worktree is shallow; repair its history with 'git -C basefwx fetch --unshallow origin'."
        fi
        ok "BaseFWX worktree ready at $(git -C basefwx rev-parse --short HEAD)."
        return 0
    fi

    if [[ -z "${ref}" ]]; then
        error "BASEFWX_SYNC_MODE=pinned requires BASEFWX_REF or a non-empty ${BASEFWX_REF_FILE}."
        return 1
    fi

    # A fresh --no-checkout clone reports the entire tree as staged-deleted
    # until its first checkout. That is initialization state, not user work.
    if [[ ${created} -eq 0 ]]; then
        local worktree_status
        if ! worktree_status="$(git -C basefwx status --porcelain --untracked-files=normal)"; then
            error "Could not inspect the BaseFWX worktree; refusing to switch it in pinned mode."
            return 1
        fi
        if [[ -n "${worktree_status}" ]]; then
            error "BaseFWX has local changes; refusing to switch it in pinned mode."
            error "Use BASEFWX_SYNC_MODE=worktree to build the current developer checkout."
            return 1
        fi
    fi
    step "Syncing BaseFWX to ${ref}..."
    git -C basefwx fetch origin "${ref}" || return 1
    local requested_sha current_sha
    if ! requested_sha="$(git -C basefwx rev-parse "FETCH_HEAD^{commit}")"; then
        error "Could not resolve the fetched BaseFWX commit for ${ref}."
        return 1
    fi
    current_sha="$(git -C basefwx rev-parse HEAD 2>/dev/null || true)"
    if [[ ${created} -eq 1 ]]; then
        # A --no-checkout clone can already have HEAD at requested_sha while
        # its worktree is still empty. The first checkout is mandatory even
        # when the commit IDs compare equal.
        git -C basefwx checkout --no-overwrite-ignore --detach "${requested_sha}" ||
            return 1
    elif [[ "${current_sha}" != "${requested_sha}" ]]; then
        # Ignored developer artifacts are not visible to the dirty-worktree
        # preflight. Refuse rather than overwrite one when the requested
        # commit starts tracking the same path.
        git -C basefwx checkout --no-overwrite-ignore --detach "${requested_sha}" ||
            return 1
    else
        info "BaseFWX is already at the configured ref; preserving its current branch attachment."
    fi
    if [[ ! -f basefwx/cpp/CMakeLists.txt ]]; then
        error "Pinned BaseFWX checkout is incomplete: basefwx/cpp/CMakeLists.txt is missing."
        return 1
    fi
    ok "BaseFWX ready at $(git -C basefwx rev-parse --short HEAD)."
}

prepare_basefwx_build_cache() {
    if [[ "${BASEFWX_EFFECTIVE_SYNC_MODE:-}" == "worktree" ]]; then
        info "Preserving BaseFWX developer build cache in worktree mode."
        return 0
    fi
    if [[ -d basefwx/cpp/build ]]; then
        step "Removing BaseFWX build cache..."
        if ! rm -rf basefwx/cpp/build; then
            error "Could not remove the BaseFWX build cache for pinned mode."
            return 1
        fi
    fi
}

install_deps_linux() {
    if need_cmd apt-get; then
        step "Detected apt-get (Debian/Ubuntu). Installing dependencies..."
        apt_install_if_missing \
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
            liblzma-dev || return 1
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
                if dpkg_pkg_installed "$pkg"; then
                    continue
                fi
                if apt_install_gui_package "$pkg" "$backports_suite"; then
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
            libnghttp2 \
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
            libnghttp2-devel \
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
            libnghttp2-devel \
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
        nghttp2 \
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
            mingw-w64-x86_64-nghttp2 \
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
    local jobs
    jobs="$(nproc 2>/dev/null || sysctl -n hw.ncpu || echo 4)"
    if [[ ${SELFTEST_ONLY:-0} -eq 1 ]]; then
        cmake --build "${build_dir}" \
            --target yume yumed yume-selftest yume-basefwx-bench yume-relay-bench \
            -j"${jobs}"
    else
        cmake --build "${build_dir}" -j"${jobs}"
    fi
    ok "Build complete."
    if [[ -x "${build_dir}/bin/Yume.app/Contents/MacOS/Yume" ]]; then
        info "Yume.app built at ${build_dir}/bin/Yume.app"
    elif [[ -x "${build_dir}/bin/yume-gui" ]]; then
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
            --use-vendor)
                YUME_USE_VENDOR=1
                # Optional argument: a path, a directory, or an https URL.
                # Anything starting with '-' is the next flag, not our value.
                if [[ -n "${2:-}" && "${2}" != -* ]]; then
                    YUME_VENDOR_SOURCE="$2"
                    shift 2
                else
                    shift
                fi
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
            --tests|--with-tests)
                BUILD_TESTS=1
                shift
                ;;
            --tools|--with-tools)
                BUILD_TOOLS=1
                shift
                ;;
            --selftest|--with-selftest|--include-selftest)
                BUILD_SELFTEST=1
                shift
                ;;
            --selftest-only|--only-selftest)
                BUILD_SELFTEST=1
                SELFTEST_ONLY=1
                shift
                ;;
            --dev)
                DEV_BUILD=1
                shift
                ;;
            --native)
                NATIVE_OPT=1
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
        ok "Cleaned."
        exit 0
    fi

    info "YUME ezbuild starting..."

    maybe_sync_repo

    if [[ "${YUME_USE_VENDOR}" == "1" ]]; then
        local vendor_key=""
        vendor_key="$(requested_vendor_key)"
        if [[ -z "${vendor_key}" ]]; then
            error "Cannot determine the vendor target for this build."
            exit 1
        fi
        if ! ensure_vendor_for_host "${vendor_key}"; then
            error "Requested vendor target '${vendor_key}' is unavailable or failed verification."
            exit 1
        fi
    fi

    if [[ $BUILD_SELFTEST -eq 1 ]]; then
        if [[ "${WINDOWS_CROSS}" == "1" || $OPENWRT -eq 1 || $BUSYBOX -eq 1 ]]; then
            error "Self-test builds are native desktop-only; do not combine --selftest/--selftest-only with Windows cross, OpenWRT, or BusyBox modes."
            exit 1
        fi
    fi

    if [[ $MINIMAL -eq 1 ]]; then
        if [[ $DEV_BUILD -eq 1 ]]; then
            error "--dev cannot be combined with minimal/OpenWRT/BusyBox production builds."
            exit 1
        fi
        warn "Minimal mode: enabling static build and BaseFWX."
        CMAKE_ARGS+=(
            -DYUME_MINIMAL=ON
            -DYUME_STATIC=ON
            -DYUME_USE_BASEFWX=ON
            -DYUME_USE_SPDLOG=OFF
            -DCMAKE_BUILD_TYPE=Release
        )
    fi

    if [[ $SELFTEST_ONLY -eq 1 ]]; then
        if [[ $BUILD_GUI -eq 1 || $BUILD_TESTS -eq 1 || $BUILD_TOOLS -eq 1 ]]; then
            warn "--selftest-only ignores --gui, --tests, and --tools; only self-test target set will be built."
        fi
        BUILD_GUI=0
        BUILD_TESTS=0
        BUILD_TOOLS=0
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

    if [[ $BUILD_TESTS -eq 1 ]]; then
        info "Unit-test executables enabled (-DYUME_BUILD_TESTING=ON)."
        CMAKE_ARGS+=( -DYUME_BUILD_TESTING=ON )
    fi

    if [[ $BUILD_TOOLS -eq 1 ]]; then
        info "Helper tools enabled (-DYUME_BUILD_TOOLS=ON)."
        CMAKE_ARGS+=( -DYUME_BUILD_TOOLS=ON )
    fi

    if [[ $BUILD_SELFTEST -eq 1 ]]; then
        info "Self-test benchmark tools enabled (-DYUME_BUILD_SELFTEST=ON)."
        info "Self-test builds enable LAN bridge compile support for routed loopback benchmarks."
        CMAKE_ARGS+=( -DYUME_BUILD_SELFTEST=ON -DYUME_FEATURE_LAN_BRIDGE=ON )
    fi

    # Keep the normal path unambiguously production-grade. Debug timing code is
    # selected by configuration and therefore cannot leak into Release even if
    # YUME_TIMING is present in the environment. Self-test is a developer mode;
    # it stays optimized (-O3/LTO in CMake) while retaining symbols and hooks.
    if [[ $DEV_BUILD -eq 1 || $BUILD_SELFTEST -eq 1 ]]; then
        info "Build mode: RelWithDebInfo (developer diagnostics available; runtime opt-in)."
        CMAKE_ARGS+=( -DCMAKE_BUILD_TYPE=RelWithDebInfo )
    else
        info "Build mode: Release (developer diagnostics compiled out)."
        CMAKE_ARGS+=( -DCMAKE_BUILD_TYPE=Release )
    fi
    CMAKE_ARGS+=( -DYUME_LTO=ON -DYUME_FAST_MATH=OFF )

    if [[ $NATIVE_OPT -eq 1 ]]; then
        info "Host CPU tuning enabled; resulting binaries are not portable."
        CMAKE_ARGS+=( -DYUME_NATIVE_OPT=ON )
    else
        CMAKE_ARGS+=( -DYUME_NATIVE_OPT=OFF )
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

    # YUME 2.0 uses nghttp2's v2 receive/submit APIs. Native desktop builds
    # require >= 1.64; older stable distributions get a pinned, checksum-
    # verified lib-only build in the user's cache. Cross targets need their
    # own target-architecture nghttp2 and are intentionally handled by their
    # toolchain/vendor prefix instead of this host fallback.
    if [[ $OPENWRT -eq 0 && $BUSYBOX -eq 0 \
          && "${WINDOWS_CROSS}" != "1" && "${YUME_MACOS_CROSS:-0}" != "1" ]]; then
        if [[ ! -f "${PWD}/scripts/ensure-nghttp2.sh" ]]; then
            error "Missing scripts/ensure-nghttp2.sh; cannot verify the HTTP/2 dependency."
            exit 1
        fi
        # shellcheck disable=SC1091
        source "${PWD}/scripts/ensure-nghttp2.sh"
        yume_nghttp2_ensure || { error "libnghttp2 dependency setup failed."; exit 1; }
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
    prepare_basefwx_build_cache
    if [[ $OPENWRT -eq 1 || $BUSYBOX -eq 1 ]]; then
        if [[ $OPENWRT -eq 1 && -d "${YUME_VENDOR_ROOT}/openwrt-mips" ]] && vendor_access_enabled; then
            CMAKE_ARGS+=("-DBASEFWX_VENDOR_DIR=${YUME_VENDOR_ROOT}/openwrt-mips")
        elif [[ $BUSYBOX -eq 1 && -n "${TARGET_ARCH}" ]]; then
            local busybox_prefix=""
            busybox_prefix="$(busybox_vendor_dir || true)"
            if [[ -n "${busybox_prefix}" ]]; then
                CMAKE_ARGS+=("-DBASEFWX_VENDOR_DIR=${busybox_prefix}")
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
            elif [[ "${BUSYBOX:-0}" -eq 1 && -n "${TARGET_ARCH:-}" ]]; then
                local busybox_static_prefix=""
                busybox_static_prefix="$(busybox_vendor_dir || true)"
                if [[ -n "${busybox_static_prefix}" && -f "${busybox_static_prefix}/lib/liboqs.a" ]]; then
                    _oqs_static_path="${busybox_static_prefix}/lib/liboqs.a"
                fi
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
        # Disable LTO and native optimization for macOS cross-compilation to prevent LLVM bitcode
        CMAKE_ARGS+=("-DBASEFWX_NATIVE_OPT=OFF" "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF" "-DBUILD_SHARED_LIBS=ON")
        # Disable tests for macOS cross builds (linking issues with bitcode objects)
        CMAKE_ARGS+=("-DBUILD_TESTING=OFF" "-DYUME_BUILD_TESTING=OFF")
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
            # An explicit --use-vendor selection, or fullau's isolated
            # source-built staging tree, is the dependency source the caller
            # asked us to use. Do not silently replace either with unrelated
            # system libraries just because pkg-config can see them.
            if ! append_selected_vendor_crypto_args; then
                error "Selected vendor crypto dependencies are incomplete."
                exit 1
            fi
        fi
        if [[ -z "${host_vendor_dir}" && -n "${YUME_OQS_STATIC:-}" ]] &&
           [[ ! -f /usr/lib/x86_64-linux-gnu/liboqs.a &&
              ! -f /usr/local/lib/liboqs.a ]]; then
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
        if [[ -n "${host_vendor_dir}" ]]; then
            :
        elif detect_liboqs; then
            info "liboqs detected; enabling PQ in BaseFWX."
            CMAKE_ARGS+=(
                "-DBASEFWX_REQUIRE_OQS=ON"
                "-DBASEFWX_USE_VENDOR_OQS=OFF"
            )
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
            # System liboqs is missing. Try the explicitly selected vendor
            # root before giving up; the access gate prevents a default build
            # from seeing arbitrary ignored repository residue.
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
        if [[ -n "${host_vendor_dir}" ]]; then
            :
        elif detect_argon2; then
            info "libargon2 detected; enabling Argon2 in BaseFWX."
            CMAKE_ARGS+=(
                "-DBASEFWX_REQUIRE_ARGON2=ON"
                "-DBASEFWX_USE_VENDOR_ARGON2=OFF"
            )
        else
            # Same selected-root fallback as liboqs above.
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
    local build_dir="${YUME_BUILD_DIR:-build}"
    echo -e "${COLOR_GREEN}Server:${COLOR_RESET} ./${build_dir}/bin/yumed${exe_suffix}"
    echo -e "${COLOR_GREEN}Client:${COLOR_RESET} ./${build_dir}/bin/yume${exe_suffix}"
    echo -e "${COLOR_GREEN}Ready test kit:${COLOR_RESET} python3 tools/yume_setup.py init --output \"\$HOME/yume-test-kit\" --host SERVER_IP --tls-name SERVER_NAME --client-name phone"
    echo "The generated server/start-yumed and clients/phone/start-socks launchers use ./${build_dir}/bin automatically."
    if [[ $BUILD_SELFTEST -eq 1 ]]; then
        echo -e "${COLOR_GREEN}Benchmark smoke:${COLOR_RESET} ./${build_dir}/bin/yume${exe_suffix} --quick-bench"
        echo -e "${COLOR_GREEN}Full benchmark:${COLOR_RESET} ./${build_dir}/bin/yume${exe_suffix} --full-bench"
    fi
}

main "$@"
