#!/usr/bin/env bash
set -euo pipefail

# YUME ezbuild: install deps + build with a friendly UI

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
APT_UPDATED_FLAG="${APT_UPDATED_FLAG:-/tmp/yume-apt-updated}"

info()  { echo -e "${COLOR_BLUE}✨ $*${COLOR_RESET}"; }
warn()  { echo -e "${COLOR_YELLOW}⚠️  $*${COLOR_RESET}"; }
error() { echo -e "${COLOR_RED}❌ $*${COLOR_RESET}"; }
ok()    { echo -e "${COLOR_GREEN}✅ $*${COLOR_RESET}"; }
step()  { echo -e "${COLOR_MAGENTA}🚀 $*${COLOR_RESET}"; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1
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
    for candidate in "${HOME}/vcpkg" "${HOME}/src/vcpkg" "/opt/vcpkg"; do
        if [[ -x "${candidate}/vcpkg" ]]; then
            echo "${candidate}"
            return 0
        fi
    done
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
    if [[ -f "${dir}/lib/liboqs.a" || -f "${dir}/lib/liboqs.so" ]]; then
        return 0
    fi
    return 1
}

vendor_has_argon2() {
    local dir="$1"
    [[ -n "${dir}" ]] || return 1
    [[ -f "${dir}/include/argon2.h" ]] || return 1
    if [[ -f "${dir}/lib/libargon2.a" || -f "${dir}/lib/libargon2.so" ]]; then
        return 0
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
    local workdir="/tmp/yume-liboqs-openwrt"
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
    local workdir="/tmp/yume-liboqs-host"
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
    if [[ -d basefwx ]]; then
        info "BaseFWX already present."
        return 0
    fi
    step "Cloning BaseFWX..."
    if ! need_cmd git; then
        error "git not found; cannot fetch BaseFWX."
        return 1
    fi
    git clone https://github.com/F1xGOD/basefwx.git
    ok "BaseFWX cloned."
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
    ok "Dependencies installed via Homebrew."
}

install_deps_windows() {
    if ! need_cmd choco; then
        error "Chocolatey not found. Please install it from https://chocolatey.org"
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
        local lock_file="/tmp/yume-build-${build_dir//\//_}.lock"
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
}

main() {
    info "YUME ezbuild starting..."

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --clean)
                CLEAN_ONLY=1
                shift
                ;;
            --minimal)
                MINIMAL=1
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
        step "Cleaning build directory..."
        rm -rf "${YUME_BUILD_DIR:-build}"
        ok "Cleaned."
        exit 0
    fi

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

    if [[ -n "${YUME_CMAKE_ARGS:-}" ]]; then
        # shellcheck disable=SC2206
        EXTRA_CMAKE_ARGS=(${YUME_CMAKE_ARGS})
        CMAKE_ARGS+=("${EXTRA_CMAKE_ARGS[@]}")
    fi

    if [[ "${WINDOWS_CROSS}" == "1" ]]; then
        if [[ -z "${VCPKG_ROOT}" ]]; then
            VCPKG_ROOT="$(detect_vcpkg_root || true)"
        fi
        if [[ -z "${VCPKG_ROOT}" || ! -x "${VCPKG_ROOT}/vcpkg" ]]; then
            error "Windows cross build requires VCPKG_ROOT (set to your vcpkg clone)."
            exit 1
        fi
        if [[ ! -f "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" ]]; then
            error "vcpkg toolchain file missing at ${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
            exit 1
        fi
        if ! command -v "${WINDOWS_TOOLCHAIN_PREFIX}-g++" >/dev/null 2>&1; then
            error "Missing ${WINDOWS_TOOLCHAIN_PREFIX}-g++; install mingw-w64."
            exit 1
        fi
        VCPKG_PREFIX="${VCPKG_ROOT}/installed/${WINDOWS_TRIPLET}"
        CMAKE_ARGS+=(
            "-DCMAKE_SYSTEM_NAME=Windows"
            "-DCMAKE_C_COMPILER=${WINDOWS_TOOLCHAIN_PREFIX}-gcc"
            "-DCMAKE_CXX_COMPILER=${WINDOWS_TOOLCHAIN_PREFIX}-g++"
            "-DCMAKE_RC_COMPILER=${WINDOWS_TOOLCHAIN_PREFIX}-windres"
            "-DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
            "-DVCPKG_TARGET_TRIPLET=${WINDOWS_TRIPLET}"
            "-DVCPKG_APPLOCAL_DEPS=OFF"
            "-DOPENSSL_ROOT_DIR=${VCPKG_PREFIX}"
            "-DBASEFWX_USE_VENDOR_DEPS=OFF"
            "-DYUME_FORCE_CROSS=ON"
        )
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
            TOOLCHAIN_FILE="/tmp/yume-openwrt-toolchain.cmake"
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
        # If static libs are missing in the SDK, fall back to dynamic.
        # OpenWRT SDKs often lack full static deps; force dynamic by default.
        if [[ " ${CMAKE_ARGS[*]} " == *"-DYUME_STATIC=ON"* ]]; then
            warn "OpenWRT build: forcing YUME_STATIC=OFF to avoid static link of shared libs."
            CMAKE_ARGS=("${CMAKE_ARGS[@]/-DYUME_STATIC=ON/-DYUME_STATIC=OFF}")
        fi
        CMAKE_ARGS+=("-DYUME_STATIC=OFF")
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
            info "OpenWRT liboqs detected in sysroot; enabling PQ in BaseFWX."
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
            if [[ -n "${YUME_OQS_STATIC:-}" ]] || [[ -f "${OPENWRT_USR}/lib/liboqs.a" ]]; then
                if [[ -f "${OPENWRT_USR}/lib/liboqs.a" ]]; then
                    info "OpenWRT: using static liboqs."
                    CMAKE_ARGS+=("-DBASEFWX_OQS_STATIC=ON")
                else
                    warn "OpenWRT: YUME_OQS_STATIC=1 set but liboqs.a missing; falling back to shared."
                fi
            fi
        else
            warn "OpenWRT liboqs not detected in sysroot; PQ will be disabled."
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
                CMAKE_ARGS+=("-DBASEFWX_REQUIRE_ARGON2=OFF")
            fi
        else
            warn "OpenWRT libargon2 not detected in sysroot; heavy KDF will fall back to HKDF."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_ARGON2=OFF")
        fi
    elif [[ "${WINDOWS_CROSS}" == "1" ]]; then
        if [[ -f "${VCPKG_PREFIX}/include/oqs/oqs.h" ]]; then
            info "Windows cross: liboqs detected in vcpkg; enabling PQ in BaseFWX."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_OQS=ON")
        else
            warn "Windows cross: liboqs not detected in vcpkg; PQ will be disabled."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_OQS=OFF")
        fi
        if [[ -f "${VCPKG_PREFIX}/include/argon2.h" ]]; then
            info "Windows cross: libargon2 detected in vcpkg; enabling Argon2 in BaseFWX."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_ARGON2=ON")
        else
            warn "Windows cross: libargon2 not detected in vcpkg; heavy KDF will fall back to HKDF."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_ARGON2=OFF")
        fi
    elif [[ "${YUME_MACOS_CROSS:-0}" == "1" ]]; then
        CMAKE_ARGS+=("-DYUME_FORCE_CROSS=ON")
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
            warn "liboqs not detected; PQ will be disabled unless you install it."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_OQS=OFF")
        fi
        if detect_argon2; then
            info "libargon2 detected; enabling Argon2 in BaseFWX."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_ARGON2=ON")
        else
            warn "libargon2 not detected; heavy KDF will fall back to HKDF."
            CMAKE_ARGS+=("-DBASEFWX_REQUIRE_ARGON2=OFF")
        fi
    fi
    build_project
    local exe_suffix=""
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*)
            exe_suffix=".exe"
            ;;
    esac
    info "Done! 🎉"
    local build_dir="${YUME_BUILD_DIR:-build}"
    echo -e "${COLOR_GREEN}Run:${COLOR_RESET} ./${build_dir}/bin/yumed${exe_suffix} --config config/yumed.json"
    echo -e "${COLOR_GREEN}Then:${COLOR_RESET} ./${build_dir}/bin/yume${exe_suffix} --config config/yume.json --socks 1080"
}

main "$@"
