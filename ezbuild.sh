#!/usr/bin/env bash
set -euo pipefail

# YUME ezbuild: install deps + build with a friendly UI

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
CMAKE_ARGS=()

info()  { echo -e "${COLOR_BLUE}✨ $*${COLOR_RESET}"; }
warn()  { echo -e "${COLOR_YELLOW}⚠️  $*${COLOR_RESET}"; }
error() { echo -e "${COLOR_RED}❌ $*${COLOR_RESET}"; }
ok()    { echo -e "${COLOR_GREEN}✅ $*${COLOR_RESET}"; }
step()  { echo -e "${COLOR_MAGENTA}🚀 $*${COLOR_RESET}"; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1
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
        sudo apt-get update -y
        sudo apt-get install -y \
            build-essential \
            cmake \
            git \
            pkg-config \
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
        if apt-cache show liboqs-dev >/dev/null 2>&1; then
            sudo apt-get install -y liboqs-dev || warn "liboqs-dev install failed; PQ features will be disabled unless provided."
        else
            warn "liboqs-dev not available in apt repositories; PQ features will be disabled unless provided."
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
    step "Cleaning previous build..."
    rm -rf build
    mkdir -p build
    step "Configuring build..."
    cmake -B build "${CMAKE_ARGS[@]}"
    step "Compiling..."
    cmake --build build -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu || echo 4)"
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
        rm -rf build
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

    if [[ $OPENWRT -eq 1 || $BUSYBOX -eq 1 ]]; then
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
EOF
            YUME_TOOLCHAIN_FILE="$TOOLCHAIN_FILE"
        fi

        if [[ -z "${YUME_TOOLCHAIN_FILE:-}" ]]; then
            error "YUME_TOOLCHAIN_FILE is required for --openwrt/--busybox (OpenWRT SDK toolchain file)."
            exit 1
        fi
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

    if need_cmd cmake; then
        ok "CMake detected."
    else
        warn "CMake not found. Will install build dependencies."
    fi

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

    ensure_basefwx
    cleanup_vendor
    build_project
    info "Done! 🎉"
    echo -e "${COLOR_GREEN}Run:${COLOR_RESET} ./build/bin/yumed --config config/yumed.json"
    echo -e "${COLOR_GREEN}Then:${COLOR_RESET} ./build/bin/yume --config config/yume.json --socks 1080"
}

main "$@"
