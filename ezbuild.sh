#!/usr/bin/env bash
set -euo pipefail

# YUME ezbuild: install deps + build with a friendly UI

COLOR_RESET="\033[0m"
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_BLUE="\033[0;34m"
COLOR_MAGENTA="\033[0;35m"

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
    cmake -B build
    step "Compiling..."
    cmake --build build -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu || echo 4)"
    ok "Build complete."
}

main() {
    info "YUME ezbuild starting..."

    if [[ "${1:-}" == "--clean" ]]; then
        step "Cleaning build directory..."
        rm -rf build
        ok "Cleaned."
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
    echo -e "${COLOR_GREEN}Run:${COLOR_RESET} ./build/yumed --config config/yumed.json"
    echo -e "${COLOR_GREEN}Then:${COLOR_RESET} ./build/yume --config config/yume.json --socks 1080"
}

main "$@"
