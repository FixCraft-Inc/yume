#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
set -euo pipefail

# YUME ezbuild: install dependencies and build the native Linux programs.

EZBUILD_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

CLEAN_ONLY=0
BUILD_DEB=0
BUILD_TESTS=0
DEV_BUILD=0
NATIVE_OPT=0
SKIP_PULL=0
CMAKE_ARGS=()
EXTRA_CMAKE_ARGS=()

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

info()  { echo -e "${COLOR_BLUE}[info] $*${COLOR_RESET}"; }
warn()  { echo -e "${COLOR_YELLOW}[warn] $*${COLOR_RESET}"; }
error() { echo -e "${COLOR_RED}[error] $*${COLOR_RESET}"; }
ok()    { echo -e "${COLOR_GREEN}[ok] $*${COLOR_RESET}"; }
step()  { echo -e "${COLOR_MAGENTA}[step] $*${COLOR_RESET}"; }

usage() {
    cat <<'EOF'
Usage: ./ezbuild.sh [options]

Builds the native yume and yumed programs for Linux against the pinned,
patched OpenSSL.

Options:
  --clean                 Remove the build directory and exit
  --tests                 Build the test executables
  --dev                   Optimized developer build (RelWithDebInfo) with
                          opt-in low-level timing diagnostics compiled in
  --native                Tune for this host CPU (-march/-mtune=native),
                          fastest locally but not portable to older CPUs
  --deb, --package-deb    Build a Debian package with CPack
  --no-pull, --skip-pull  Build the checkout as it is, without fetching
  -h, --help              Show this help

Useful environment variables:
  YUME_BUILD_DIR          Build directory (default: build)
  YUME_BUILD_JOBS         Parallel compile jobs (default: 2)
  YUME_CMAKE_ARGS         Extra CMake arguments, such as
                          -DYUME_BUILD_BASEFWX_MODULES=ON
  YUME_SKIP_DEPS          Set to 1 to skip installing system packages
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
}

YUME_LOCK_ROOT="$(init_lock_root)"
trap cleanup_temp_assets EXIT

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
# entirely when the list is satisfied, which avoids a full dependency-tree
# walk per package on repeat ezbuild runs.
apt_install_if_missing() {
    local missing=()
    local pkg
    for pkg in "$@"; do
        if ! dpkg_pkg_installed "$pkg"; then
            missing+=("$pkg")
        fi
    done
    local missing_count="${#missing[@]}"
    if ((missing_count == 0)); then
        return 0
    fi
    apt_update_once || return 1
    sudo apt-get install -y "${missing[@]}"
}

# The patched OpenSSL needs the Brotli headers to offer Chrome's certificate
# compression, so every package list names them.
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
            libsystemd-dev \
            libboost-thread-dev \
            nlohmann-json3-dev \
            zlib1g-dev \
            libzstd-dev \
            libbrotli-dev \
            libnghttp2-dev || return 1
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
            zlib \
            zstd \
            brotli \
            libnghttp2 \
            systemd
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
            zlib-devel \
            libzstd-devel \
            brotli-devel \
            libnghttp2-devel \
            systemd-devel
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
            zlib-devel \
            libzstd-devel \
            libbrotli-devel \
            libnghttp2-devel \
            systemd-devel
        ok "Dependencies installed via zypper."
        return 0
    fi

    warn "No supported Linux package manager found."
    return 1
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
    # Keep prior objects and evidence intact. A dedicated directory also
    # prevents an old cache from silently selecting another runtime.
    if [[ -f "${build_dir}/CMakeCache.txt" ]] &&
       ! grep -q '^YUME_BUILD_NATIVE_APPLICATION:BOOL=ON$' "${build_dir}/CMakeCache.txt"; then
        error "Existing build predates native integration; select a fresh YUME_BUILD_DIR."
        exit 1
    fi
    mkdir -p "${build_dir}"
    step "Configuring build..."
    cmake -B "${build_dir}" "${CMAKE_ARGS[@]}"
    step "Compiling..."
    local jobs
    jobs="${YUME_BUILD_JOBS:-2}"
    [[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { error "YUME_BUILD_JOBS must be positive"; exit 1; }
    cmake --build "${build_dir}" -j"${jobs}"
    ok "Build complete."
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
    local arg
    for arg in "$@"; do
        case "${arg}" in
            -h|--help)
                usage
                exit 0
                ;;
            --clean)
                CLEAN_ONLY=1
                ;;
            --deb|--package-deb)
                BUILD_DEB=1
                ;;
            --tests|--with-tests)
                BUILD_TESTS=1
                ;;
            --dev)
                DEV_BUILD=1
                ;;
            --native)
                NATIVE_OPT=1
                ;;
            --no-pull|--skip-pull)
                SKIP_PULL=1
                ;;
            *)
                # A removed option must not fall through to an ordinary build.
                error "Unknown option: ${arg}"
                usage
                exit 2
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
    if [[ "$(uname -s)" != "Linux" ]]; then
        error "ezbuild.sh builds the native Linux programs only."
        exit 1
    fi

    maybe_sync_repo

    CMAKE_ARGS+=( -DYUME_BUILD_NATIVE_APPLICATION=ON )

    if [[ $BUILD_TESTS -eq 1 ]]; then
        info "Unit-test executables enabled (-DYUME_BUILD_TESTING=ON)."
        CMAKE_ARGS+=( -DYUME_BUILD_TESTING=ON )
    fi

    # Keep the normal path unambiguously production-grade. Debug timing code is
    # selected by configuration and therefore cannot leak into Release.
    if [[ $DEV_BUILD -eq 1 ]]; then
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

    if [[ -n "${YUME_CMAKE_ARGS:-}" ]]; then
        # shellcheck disable=SC2206
        EXTRA_CMAKE_ARGS=(${YUME_CMAKE_ARGS})
        CMAKE_ARGS+=("${EXTRA_CMAKE_ARGS[@]}")
    fi

    if need_cmd cmake; then
        ok "CMake detected."
    else
        warn "CMake not found. Will install build dependencies."
    fi

    if [[ "${YUME_SKIP_DEPS:-0}" == "1" ]]; then
        warn "Skipping dependency install (YUME_SKIP_DEPS=1)."
    else
        install_deps_linux || { error "Dependency install failed."; exit 1; }
    fi

    # YTP/1 needs OpenSSL 3.5 with the pinned Chrome ClientHello patch. A host
    # without it gets a pinned, checksum-verified build in the user's cache.
    if [[ ! -f "${PWD}/scripts/ensure-openssl.sh" ]]; then
        error "Missing scripts/ensure-openssl.sh; cannot prepare the patched OpenSSL."
        exit 1
    fi
    # shellcheck disable=SC1091
    source "${PWD}/scripts/ensure-openssl.sh"
    yume_openssl_ensure || { error "OpenSSL dependency setup failed."; exit 1; }

    # The HTTP/2 carrier uses nghttp2's v2 receive and submit APIs, available
    # from 1.64. Older distributions get a pinned, checksum-verified lib-only
    # build in the user's cache.
    if [[ ! -f "${PWD}/scripts/ensure-nghttp2.sh" ]]; then
        error "Missing scripts/ensure-nghttp2.sh; cannot verify the HTTP/2 dependency."
        exit 1
    fi
    # shellcheck disable=SC1091
    source "${PWD}/scripts/ensure-nghttp2.sh"
    yume_nghttp2_ensure || { error "libnghttp2 dependency setup failed."; exit 1; }

    build_project
    if [[ $BUILD_DEB -eq 1 ]]; then
        package_deb
    fi
    info "Done."
    local build_dir="${YUME_BUILD_DIR:-build}"
    echo -e "${COLOR_GREEN}Runtime:${COLOR_RESET} YUME development product using native YTP/1 (schema 1)"
    echo -e "${COLOR_GREEN}Server:${COLOR_RESET} ./${build_dir}/bin/yumed"
    echo -e "${COLOR_GREEN}Client:${COLOR_RESET} ./${build_dir}/bin/yume"
    echo -e "${COLOR_GREEN}Ready test kit:${COLOR_RESET} python3 tools/yume_setup.py init --output \"\$HOME/yume-test-kit\" --host SERVER_IP --client-name phone"
    echo "Set YUMED_BIN and YUME_BIN to the absolute paths above when using the generated launchers."
    echo "Native application integration remains experimental; see docs/IMPLEMENTATION_STATUS.md for capability blockers."
}

main "$@"
