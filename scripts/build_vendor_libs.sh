#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="${ROOT_DIR}/vendor"

TARGET="host"
OPENWRT_SDK=""
SYSROOT=""
TOOLCHAIN_PREFIX=""
KEEP_SOURCES=0
FORCE=0
AUTO_CLONE=1
OPENWRT_SDK_VERSION="24.10.0"
OPENWRT_SDK_TARGET="ath79-nand"
OPENWRT_SDK_NAME="openwrt-sdk-${OPENWRT_SDK_VERSION}-${OPENWRT_SDK_TARGET}_gcc-13.3.0_musl.Linux-x86_64"
OPENWRT_SDK_URL="https://downloads.openwrt.org/releases/${OPENWRT_SDK_VERSION}/targets/ath79/nand/${OPENWRT_SDK_NAME}.tar.zst"
OPENWRT_SDK_PREFERRED=""
OPENWRT_SDK_CACHE_DIR=""
VCPKG_ROOT=""
VCPKG_TRIPLET=""
OSXCROSS_ROOT=""
MACOS_SDK=""
ARCHIVE_PATH=""

usage() {
    cat <<EOF
Usage: $0 [--target host|openwrt-mips|aarch64|armv7|armv8|x86|x86_64|busybox-armv7|busybox-armv8|busybox-x86|busybox-x86_64|windows-x86_64|macos-x86_64|macos-arm64|all] [--openwrt-sdk PATH] [--sysroot PATH] [--toolchain-prefix PREFIX] [--vcpkg-root PATH] [--vcpkg-triplet TRIPLET] [--osxcross-root PATH] [--macos-sdk PATH] [--archive PATH] [--keep-sources] [--no-clone] [--force]

Build and stage liboqs + argon2 into ${VENDOR_DIR}/<target>/{include,lib}

Examples:
  $0 --target host
  $0 --target openwrt-mips --openwrt-sdk /path/to/openwrt-sdk
  $0 --target aarch64 --toolchain-prefix aarch64-linux-gnu --sysroot /path/to/sysroot
  $0 --target windows-x86_64 --vcpkg-root ~/vcpkg --vcpkg-triplet x64-mingw-dynamic
  $0 --target macos-x86_64 --vcpkg-root ~/vcpkg --vcpkg-triplet x64-osx --osxcross-root ~/osxcross --macos-sdk ~/osxcross/target/SDK/MacOSX11.3.sdk

Notes:
  - Uses LIBOQS_SRC and ARGON2_SRC (defaults: \$HOME/liboqs, \$HOME/argon2).
  - Use --force to rebuild even if vendor outputs exist.
  - Windows/macOS targets stage liboqs/argon2 from vcpkg.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET="${2:-}"
            shift 2
            ;;
        --openwrt-sdk)
            OPENWRT_SDK="${2:-}"
            shift 2
            ;;
        --sysroot)
            SYSROOT="${2:-}"
            shift 2
            ;;
        --toolchain-prefix)
            TOOLCHAIN_PREFIX="${2:-}"
            shift 2
            ;;
        --vcpkg-root)
            VCPKG_ROOT="${2:-}"
            shift 2
            ;;
        --vcpkg-triplet)
            VCPKG_TRIPLET="${2:-}"
            shift 2
            ;;
        --osxcross-root)
            OSXCROSS_ROOT="${2:-}"
            shift 2
            ;;
        --macos-sdk)
            MACOS_SDK="${2:-}"
            shift 2
            ;;
        --archive)
            ARCHIVE_PATH="${2:-}"
            shift 2
            ;;
        --keep-sources)
            KEEP_SOURCES=1
            shift
            ;;
        --no-clone)
            AUTO_CLONE=0
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

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

REAL_HOME="$(resolve_real_home)"
OPENWRT_SDK_PREFERRED="${REAL_HOME}/openwrt-sdk-${OPENWRT_SDK_VERSION}-${OPENWRT_SDK_TARGET}_gcc-13.3.0_musl.Linux-x86_64"
OPENWRT_SDK_CACHE_DIR="${REAL_HOME}/.cache/yume"

detect_vcpkg_root() {
    if [[ -n "${VCPKG_ROOT}" && -x "${VCPKG_ROOT}/vcpkg" ]]; then
        echo "${VCPKG_ROOT}"
        return 0
    fi
    local candidate
    for candidate in "${REAL_HOME}/vcpkg" "${REAL_HOME}/.vcpkg"; do
        if [[ -x "${candidate}/vcpkg" ]]; then
            echo "${candidate}"
            return 0
        fi
    done
    return 1
}

ensure_vcpkg() {
    if [[ -z "${VCPKG_ROOT}" ]]; then
        VCPKG_ROOT="$(detect_vcpkg_root || true)"
    fi
    if [[ -n "${VCPKG_ROOT}" && -x "${VCPKG_ROOT}/vcpkg" ]]; then
        return 0
    fi
    if [[ ${AUTO_CLONE} -ne 1 ]]; then
        echo "vcpkg not found; set --vcpkg-root or VCPKG_ROOT." >&2
        exit 1
    fi
    VCPKG_ROOT="${REAL_HOME}/vcpkg"
    echo "Cloning vcpkg into ${VCPKG_ROOT}..."
    git clone --depth 1 https://github.com/microsoft/vcpkg.git "${VCPKG_ROOT}"
    "${VCPKG_ROOT}/bootstrap-vcpkg.sh" -disableMetrics
}

resolve_osxcross_root() {
    if [[ -n "${OSXCROSS_ROOT}" && -d "${OSXCROSS_ROOT}" ]]; then
        echo "${OSXCROSS_ROOT}"
        return 0
    fi
    local candidate
    for candidate in "${REAL_HOME}/osxcross" "/opt/osxcross"; do
        if [[ -d "${candidate}" ]]; then
            echo "${candidate}"
            return 0
        fi
    done
    return 1
}

if [[ -z "${OSXCROSS_ROOT}" ]]; then
    OSXCROSS_ROOT="$(resolve_osxcross_root || true)"
fi

ensure_macos_sdk_tarball() {
    local sdk_src="${REAL_HOME}/macos-sdk"
    local tarballs="${OSXCROSS_ROOT}/tarballs"
    mkdir -p "${tarballs}"
    if ls "${tarballs}/MacOSX"*.sdk.tar.* >/dev/null 2>&1; then
        return 0
    fi
    if [[ -d "${sdk_src}" ]]; then
        local sdk_dir
        sdk_dir="$(ls -d "${sdk_src}/MacOSX"*.sdk 2>/dev/null | sort -V | tail -n 1 || true)"
        if [[ -n "${sdk_dir}" ]]; then
            local sdk_name
            sdk_name="$(basename "${sdk_dir}")"
            tar -cJf "${tarballs}/${sdk_name}.tar.xz" -C "${sdk_src}" "${sdk_name}"
            return 0
        fi
        local sdk_tar
        sdk_tar="$(ls "${sdk_src}/MacOSX"*.sdk.tar.* 2>/dev/null | sort -V | tail -n 1 || true)"
        if [[ -n "${sdk_tar}" ]]; then
            cp -f "${sdk_tar}" "${tarballs}/"
            return 0
        fi
    fi
    echo "macOS SDK not found in ${sdk_src}; place MacOSX*.sdk or MacOSX*.sdk.tar.xz there." >&2
    return 1
}

ensure_osxcross() {
    if ! is_macos_target; then
        return 0
    fi
    if [[ -n "${OSXCROSS_ROOT}" && -d "${OSXCROSS_ROOT}" ]]; then
        :
    else
        if [[ ${AUTO_CLONE} -ne 1 ]]; then
            echo "osxcross not found; set --osxcross-root." >&2
            exit 1
        fi
        OSXCROSS_ROOT="${REAL_HOME}/osxcross"
        if [[ ! -d "${OSXCROSS_ROOT}" ]]; then
            echo "Cloning osxcross into ${OSXCROSS_ROOT}..."
            git clone --depth 1 https://github.com/tpoechtrager/osxcross.git "${OSXCROSS_ROOT}"
        fi
    fi
    if ! ensure_macos_sdk_tarball; then
        echo "osxcross requires a macOS SDK tarball; see README for details." >&2
        exit 1
    fi
    if [[ ! -d "${OSXCROSS_ROOT}/target/bin" ]]; then
        (cd "${OSXCROSS_ROOT}" && UNATTENDED=1 ./build.sh)
    fi
}

if [[ -z "${MACOS_SDK}" && -n "${OSXCROSS_ROOT:-}" ]]; then
    MACOS_SDK="$(ls -d "${OSXCROSS_ROOT}/target/SDK/MacOSX"*.sdk 2>/dev/null | sort -V | tail -n 1 || true)"
fi

resolve_macos_toolchain() {
    local desired_arch="x86_64"
    case "${TARGET}" in
        macos-arm64) desired_arch="arm64" ;;
    esac
    local bin_dir=""
    if [[ -n "${OSXCROSS_ROOT}" && -d "${OSXCROSS_ROOT}/target/bin" ]]; then
        bin_dir="${OSXCROSS_ROOT}/target/bin"
    fi
    local cxx=""
    if [[ -n "${MACOS_TOOLCHAIN_PREFIX:-}" ]]; then
        cxx="$(command -v "${MACOS_TOOLCHAIN_PREFIX}-clang++" 2>/dev/null || true)"
    fi
    if [[ -z "${cxx}" && -n "${bin_dir}" ]]; then
        if [[ "${desired_arch}" == "x86_64" && -x "${bin_dir}/o64-clang++" ]]; then
            cxx="${bin_dir}/o64-clang++"
        elif [[ "${desired_arch}" == "arm64" && -x "${bin_dir}/oa64-clang++" ]]; then
            cxx="${bin_dir}/oa64-clang++"
        fi
    fi
    if [[ -z "${cxx}" && -n "${bin_dir}" ]]; then
        if [[ "${desired_arch}" == "arm64" ]]; then
            cxx="$(ls "${bin_dir}"/arm64-apple-darwin*-clang++ "${bin_dir}"/aarch64-apple-darwin*-clang++ 2>/dev/null | head -n 1 || true)"
        else
            cxx="$(ls "${bin_dir}"/x86_64-apple-darwin*-clang++ "${bin_dir}"/x86_64h-apple-darwin*-clang++ 2>/dev/null | head -n 1 || true)"
        fi
    fi
    if [[ -z "${cxx}" ]]; then
        return 1
    fi
    local cc="${cxx/clang++/clang}"
    if [[ ! -x "${cc}" ]]; then
        local alt="${cxx%++}"
        if [[ -x "${alt}" ]]; then
            cc="${alt}"
        else
            return 1
        fi
    fi
    local sdk=""
    if [[ -n "${MACOS_SDK}" ]]; then
        if [[ -d "${MACOS_SDK}" ]]; then
            sdk="${MACOS_SDK}"
        elif [[ -n "${OSXCROSS_ROOT}" && -d "${OSXCROSS_ROOT}/target/SDK/${MACOS_SDK}" ]]; then
            sdk="${OSXCROSS_ROOT}/target/SDK/${MACOS_SDK}"
        fi
    fi
    if [[ -z "${sdk}" && -n "${OSXCROSS_ROOT}" ]]; then
        sdk="$(ls -d "${OSXCROSS_ROOT}/target/SDK/MacOSX"*.sdk 2>/dev/null | sort -V | tail -n 1 || true)"
    fi
    if [[ -z "${sdk}" ]]; then
        return 2
    fi
    local arch="x86_64"
    case "${cxx}" in
        *oa64*|*aarch64*|*arm64*|*armv8*) arch="arm64" ;;
    esac
    echo "${cc}|${cxx}|${sdk}|${arch}|${bin_dir}"
}

is_windows_target() {
    [[ "${TARGET}" == windows-* ]]
}

is_macos_target() {
    [[ "${TARGET}" == macos-* ]]
}

ensure_dockcross() {
    local image="$1"
    local script_path="$2"
    if [[ -x "${script_path}" ]]; then
        return 0
    fi
    docker run --rm "${image}" > "${script_path}"
    chmod +x "${script_path}"
}

target_dir() {
    local target="$1"
    if [[ "${target}" == "host" ]]; then
        echo "linux-x86_64"
    elif [[ "${target}" == "windows-x86_64" ]]; then
        echo "windows-x86_64"
    elif [[ "${target}" == "macos-x86_64" ]]; then
        echo "macos-x86_64"
    elif [[ "${target}" == "macos-arm64" ]]; then
        echo "macos-arm64"
    else
        echo "${target}"
    fi
}

vendor_complete() {
    local target="$1"
    if [[ ${FORCE} -eq 1 ]]; then
        return 1
    fi
    local base="${VENDOR_DIR}/$(target_dir "${target}")"
    [[ -f "${base}/include/oqs/oqs.h" ]] || return 1
    [[ -f "${base}/include/argon2.h" ]] || return 1
    if [[ -f "${base}/lib/liboqs.a" || -f "${base}/lib/liboqs.so" ]]; then
        :
    else
        return 1
    fi
    if [[ -f "${base}/lib/libargon2.a" || -f "${base}/lib/libargon2.so" ]]; then
        return 0
    fi
    return 1
}

install_vcpkg_packages() {
    local triplet="$1"
    local vcpkg_bin="${VCPKG_ROOT}/vcpkg"
    local vcpkg_prefix="${VCPKG_ROOT}/installed/${triplet}"
    local shim_bin=""
    local powershell_stub=""
    local chainload_toolchain=""
    local overlay_triplets_dir=""
    local env_path="${PATH}"
    if [[ ! -x "${vcpkg_bin}" ]]; then
        echo "vcpkg not found at ${vcpkg_bin}" >&2
        exit 1
    fi
    if is_windows_target; then
        shim_bin="/tmp/yume-vcpkg-win-shim"
        powershell_stub="${shim_bin}/powershell.exe"
        mkdir -p "${shim_bin}"
        if [[ ! -x "${powershell_stub}" ]]; then
            cat > "${powershell_stub}" <<'EOS'
#!/usr/bin/env bash
exit 0
EOS
            chmod +x "${powershell_stub}"
        fi
        env_path="${shim_bin}:${env_path}"
    fi
    if is_macos_target; then
        if [[ -z "${MACOS_DEPLOYMENT_TARGET:-}" ]]; then
            MACOS_DEPLOYMENT_TARGET="10.15"
        fi
        local toolchain_info=""
        toolchain_info="$(resolve_macos_toolchain || true)"
        if [[ -z "${toolchain_info}" ]]; then
            echo "macOS toolchain not found; set --osxcross-root and --macos-sdk." >&2
            exit 1
        fi
        local cc="" cxx="" sdk="" arch="" bin_dir=""
        local ar_path="" ranlib_path="" ld_path=""
        IFS='|' read -r cc cxx sdk arch bin_dir <<< "${toolchain_info}"
        shim_bin="/tmp/yume-vcpkg-osx-shim-${arch}"
        mkdir -p "${shim_bin}"
        if [[ -n "${bin_dir}" ]]; then
            local install_tool=""
            if [[ "${arch}" == "arm64" ]]; then
                install_tool="$(ls "${bin_dir}"/arm64-apple-darwin*-install_name_tool "${bin_dir}"/aarch64-apple-darwin*-install_name_tool 2>/dev/null | head -n 1 || true)"
            else
                install_tool="$(ls "${bin_dir}"/x86_64-apple-darwin*-install_name_tool "${bin_dir}"/x86_64h-apple-darwin*-install_name_tool 2>/dev/null | head -n 1 || true)"
            fi
            if [[ -n "${install_tool}" ]]; then
                ln -sf "${install_tool}" "${shim_bin}/install_name_tool"
            fi
            local otool=""
            if [[ "${arch}" == "arm64" ]]; then
                otool="$(ls "${bin_dir}"/arm64-apple-darwin*-otool "${bin_dir}"/aarch64-apple-darwin*-otool 2>/dev/null | head -n 1 || true)"
            else
                otool="$(ls "${bin_dir}"/x86_64-apple-darwin*-otool "${bin_dir}"/x86_64h-apple-darwin*-otool 2>/dev/null | head -n 1 || true)"
            fi
            if [[ -n "${otool}" ]]; then
                ln -sf "${otool}" "${shim_bin}/otool"
            fi
            local lipo=""
            if [[ "${arch}" == "arm64" ]]; then
                lipo="$(ls "${bin_dir}"/arm64-apple-darwin*-lipo "${bin_dir}"/aarch64-apple-darwin*-lipo 2>/dev/null | head -n 1 || true)"
            else
                lipo="$(ls "${bin_dir}"/x86_64-apple-darwin*-lipo "${bin_dir}"/x86_64h-apple-darwin*-lipo 2>/dev/null | head -n 1 || true)"
            fi
            if [[ -n "${lipo}" ]]; then
                ln -sf "${lipo}" "${shim_bin}/lipo"
            fi
            local strip=""
            if [[ "${arch}" == "arm64" ]]; then
                strip="$(ls "${bin_dir}"/arm64-apple-darwin*-strip "${bin_dir}"/aarch64-apple-darwin*-strip 2>/dev/null | head -n 1 || true)"
            else
                strip="$(ls "${bin_dir}"/x86_64-apple-darwin*-strip "${bin_dir}"/x86_64h-apple-darwin*-strip 2>/dev/null | head -n 1 || true)"
            fi
            if [[ -n "${strip}" ]]; then
                ln -sf "${strip}" "${shim_bin}/strip"
            fi
            local ranlib=""
            if [[ "${arch}" == "arm64" ]]; then
                ranlib="$(ls "${bin_dir}"/arm64-apple-darwin*-ranlib "${bin_dir}"/aarch64-apple-darwin*-ranlib 2>/dev/null | head -n 1 || true)"
            else
                ranlib="$(ls "${bin_dir}"/x86_64-apple-darwin*-ranlib "${bin_dir}"/x86_64h-apple-darwin*-ranlib 2>/dev/null | head -n 1 || true)"
            fi
            if [[ -n "${ranlib}" ]]; then
                ln -sf "${ranlib}" "${shim_bin}/ranlib"
                ranlib_path="${ranlib}"
            fi
            local ar=""
            if [[ "${arch}" == "arm64" ]]; then
                ar="$(ls "${bin_dir}"/arm64-apple-darwin*-ar "${bin_dir}"/aarch64-apple-darwin*-ar 2>/dev/null | head -n 1 || true)"
            else
                ar="$(ls "${bin_dir}"/x86_64-apple-darwin*-ar "${bin_dir}"/x86_64h-apple-darwin*-ar 2>/dev/null | head -n 1 || true)"
            fi
            if [[ -n "${ar}" ]]; then
                ln -sf "${ar}" "${shim_bin}/ar"
                ar_path="${ar}"
            fi
            if [[ "${arch}" == "arm64" ]]; then
                ld_path="$(ls "${bin_dir}"/arm64-apple-darwin*-ld "${bin_dir}"/aarch64-apple-darwin*-ld 2>/dev/null | head -n 1 || true)"
            else
                ld_path="$(ls "${bin_dir}"/x86_64-apple-darwin*-ld "${bin_dir}"/x86_64h-apple-darwin*-ld 2>/dev/null | head -n 1 || true)"
            fi
            if [[ -n "${ld_path}" ]]; then
                ln -sf "${ld_path}" "${shim_bin}/ld"
                ln -sf "${ld_path}" "${shim_bin}/ld64"
            fi
        fi

        chainload_toolchain="/tmp/yume-vcpkg-osx-toolchain-${arch}.cmake"
        if [[ -z "${MACOS_DEPLOYMENT_TARGET:-}" ]]; then
            MACOS_DEPLOYMENT_TARGET="10.15"
        fi
        cat > "${chainload_toolchain}" <<EOF
set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_SYSTEM_PROCESSOR ${arch})
set(CMAKE_C_COMPILER ${cc})
set(CMAKE_CXX_COMPILER ${cxx})
set(CMAKE_OSX_SYSROOT ${sdk})
set(CMAKE_OSX_ARCHITECTURES ${arch})
set(CMAKE_OSX_DEPLOYMENT_TARGET ${MACOS_DEPLOYMENT_TARGET} CACHE STRING "" FORCE)
set(CMAKE_PREFIX_PATH ${vcpkg_prefix})
set(OPENSSL_ROOT_DIR ${vcpkg_prefix})
set(CMAKE_FIND_ROOT_PATH ${sdk} ${vcpkg_prefix})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
EOF
        if [[ -n "${ld_path}" ]]; then
            echo "set(CMAKE_LINKER ${ld_path})" >> "${chainload_toolchain}"
        fi
        if [[ -n "${ar_path}" ]]; then
            echo "set(CMAKE_AR ${ar_path})" >> "${chainload_toolchain}"
        fi
        if [[ -n "${ranlib_path}" ]]; then
            echo "set(CMAKE_RANLIB ${ranlib_path})" >> "${chainload_toolchain}"
        fi

        overlay_triplets_dir="/tmp/yume-vcpkg-triplets"
        mkdir -p "${overlay_triplets_dir}"
        cat > "${overlay_triplets_dir}/${triplet}.cmake" <<EOF
set(VCPKG_TARGET_ARCHITECTURE ${arch})
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_CMAKE_SYSTEM_NAME Darwin)
set(VCPKG_OSX_ARCHITECTURES ${arch})
set(VCPKG_OSX_DEPLOYMENT_TARGET ${MACOS_DEPLOYMENT_TARGET})
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${chainload_toolchain}")
EOF

        env_path="${shim_bin}:${bin_dir}:${env_path}"
        export OSXCROSS_ROOT="${OSXCROSS_ROOT}"
        export SDKROOT="${sdk}"
        export VCPKG_CHAINLOAD_TOOLCHAIN_FILE="${chainload_toolchain}"
        export OPENSSL_ROOT_DIR="${vcpkg_prefix}"
        export CC="${cc}"
        export CXX="${cxx}"
        export MACOSX_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET}"
    fi

    if [[ ! -d "${VCPKG_ROOT}/installed/${triplet}" ]]; then
        echo "vcpkg prefix missing for ${triplet}; clearing stale status."
        local stale_pkgs=""
        stale_pkgs="$("${vcpkg_bin}" list --triplet "${triplet}" | awk -F: '$2=="'${triplet}'"{print $1}' | sed 's/\\[.*\\]//' | sort -u)"
        if [[ -n "${stale_pkgs}" ]]; then
            PATH="${env_path}" VCPKG_POWERSHELL_PATH="${powershell_stub:-}" \
                "${vcpkg_bin}" remove --recurse --triplet "${triplet}" ${stale_pkgs} >/dev/null 2>&1 || true
        fi
    fi
    if [[ -d "${VCPKG_ROOT}/installed/${triplet}" && ! -f "${VCPKG_ROOT}/installed/${triplet}/include/openssl/ssl.h" ]]; then
        echo "openssl headers missing for ${triplet}; forcing reinstall."
        PATH="${env_path}" VCPKG_POWERSHELL_PATH="${powershell_stub:-}" \
            "${vcpkg_bin}" remove --recurse --triplet "${triplet}" openssl >/dev/null 2>&1 || true
    fi

    PATH="${env_path}" \
        VCPKG_POWERSHELL_PATH="${powershell_stub:-}" \
        "${vcpkg_bin}" install --triplet "${triplet}" ${overlay_triplets_dir:+--overlay-triplets="${overlay_triplets_dir}"} openssl liboqs argon2
}

stage_vcpkg_libs() {
    local triplet="$1"
    local vcpkg_prefix="${VCPKG_ROOT}/installed/${triplet}"
    if [[ ! -d "${vcpkg_prefix}" ]]; then
        echo "vcpkg prefix not found: ${vcpkg_prefix}" >&2
        exit 1
    fi
    mkdir -p "${inc_dir}/oqs" "${lib_dir}"
    cp -a "${vcpkg_prefix}/include/oqs" "${inc_dir}/" 2>/dev/null || true
    if [[ -f "${vcpkg_prefix}/include/argon2.h" ]]; then
        cp -a "${vcpkg_prefix}/include/argon2.h" "${inc_dir}/"
    fi
    if compgen -G "${vcpkg_prefix}/lib/liboqs"* >/dev/null 2>&1; then
        cp -a "${vcpkg_prefix}/lib/liboqs"* "${lib_dir}/"
    fi
    if compgen -G "${vcpkg_prefix}/lib/libargon2"* >/dev/null 2>&1; then
        cp -a "${vcpkg_prefix}/lib/libargon2"* "${lib_dir}/"
    fi
    if is_windows_target && compgen -G "${vcpkg_prefix}/bin/"*.dll >/dev/null 2>&1; then
        cp -a "${vcpkg_prefix}/bin/"*.dll "${lib_dir}/" 2>/dev/null || true
    fi
}

docker_build_vendor() {
    local label="$1"
    local image="$2"
    local script_path="/tmp/dockcross-vendor-${label}"
    if vendor_complete "${label}"; then
        echo "Vendored libs already present for ${label}; skipping."
        return 0
    fi
    if [[ -z "${LIBOQS_SRC}" || ! -d "${LIBOQS_SRC}" ]]; then
        echo "liboqs not found at ${LIBOQS_SRC}; set LIBOQS_SRC before docker build." >&2
        exit 1
    fi
    if [[ -z "${ARGON2_SRC}" || ! -d "${ARGON2_SRC}" ]]; then
        echo "argon2 not found at ${ARGON2_SRC}; set ARGON2_SRC before docker build." >&2
        exit 1
    fi
    ensure_dockcross "${image}" "${script_path}"
    DOCKCROSS_ARGS="-v ${VENDOR_DIR}:${VENDOR_DIR} -v ${LIBOQS_SRC}:/deps/liboqs:ro -v ${ARGON2_SRC}:/deps/argon2:ro" "${script_path}" bash -lc "
        set -euo pipefail
        cd /work
        cp -a /deps/liboqs /tmp/yume-liboqs-src
        cp -a /deps/argon2 /tmp/yume-argon2-src
        CC_PATH=\"\${CC:-}\"
        if [[ -z \"\${CC_PATH}\" ]]; then
            if [[ -n \"\${CROSS_TRIPLE:-}\" ]]; then
                CC_PATH=\"\${CROSS_TRIPLE}-gcc\"
            else
                CC_PATH=\"\$(ls /usr/xcc/*/bin/*-gcc 2>/dev/null | head -n 1 || true)\"
            fi
        fi
        if [[ -z \"\${CC_PATH}\" ]]; then
            echo \"dockcross compiler not found\" >&2
            exit 1
        fi
        if [[ ! -x \"\${CC_PATH}\" ]]; then
            CC_PATH=\"\$(command -v \"\${CC_PATH}\" 2>/dev/null || true)\"
        fi
        if [[ -z \"\${CC_PATH}\" ]]; then
            echo \"dockcross compiler not found\" >&2
            exit 1
        fi
        PREFIX=\"\${CC_PATH%-gcc}\"
        SYSROOT=\"\$(\${CC_PATH} -print-sysroot 2>/dev/null || true)\"
        if [[ -z \"\${SYSROOT}\" || \"\${SYSROOT}\" == \"/\" ]]; then
            CC_BIN_DIR=\"\$(dirname \"\${CC_PATH}\")\"
            CC_PREFIX_DIR=\"\$(dirname \"\${CC_BIN_DIR}\")\"
            CAND_SYSROOT=\"\${CC_PREFIX_DIR}/\$(basename \"\${CC_PREFIX_DIR}\")/sysroot\"
            if [[ -d \"\${CAND_SYSROOT}\" ]]; then
                SYSROOT=\"\${CAND_SYSROOT}\"
            elif [[ -d \"\${CC_PREFIX_DIR}/sysroot\" ]]; then
                SYSROOT=\"\${CC_PREFIX_DIR}/sysroot\"
            elif [[ -d \"\${CC_PREFIX_DIR}/\$(basename \"\${CC_PREFIX_DIR}\")\" ]]; then
                SYSROOT=\"\${CC_PREFIX_DIR}/\$(basename \"\${CC_PREFIX_DIR}\")\"
            fi
        fi
        if [[ -z \"\${SYSROOT}\" ]]; then
            echo \"dockcross sysroot not found\" >&2
            echo \"CC_PATH=\${CC_PATH}\" >&2
            echo \"PREFIX=\${PREFIX}\" >&2
            echo \"CC_BIN_DIR=\${CC_BIN_DIR:-}\" >&2
            echo \"CC_PREFIX_DIR=\${CC_PREFIX_DIR:-}\" >&2
            echo \"CAND_SYSROOT=\${CAND_SYSROOT:-}\" >&2
            echo \"CROSS_TRIPLE=\${CROSS_TRIPLE:-}\" >&2
            echo \"CC=\${CC:-}\" >&2
            if [[ \"${label}\" == \"x86\" || \"${label}\" == \"busybox-x86\" ]]; then
                SYSROOT=\"/\"
            else
                exit 1
            fi
        fi
        LIBOQS_SRC=/tmp/yume-liboqs-src ARGON2_SRC=/tmp/yume-argon2-src \
          ./scripts/build_vendor_libs.sh --target \"${label}\" --toolchain-prefix \"\${PREFIX}\" --sysroot \"\${SYSROOT}\" ${FORCE:+--force}
    "
}

fetch_url() {
    local url="$1"
    local out="$2"
    if need_cmd curl; then
        curl -L --fail -o "${out}" "${url}"
    elif need_cmd wget; then
        wget -O "${out}" "${url}"
    else
        echo "Missing downloader (curl or wget) for ${url}" >&2
        exit 1
    fi
}

ensure_openwrt_sdk() {
    local base_dir
    base_dir="$(dirname "${OPENWRT_SDK_PREFERRED}")"
    local sdk_dir="${OPENWRT_SDK_PREFERRED}"
    if [[ -z "${OPENWRT_SDK}" && -d "${OPENWRT_SDK_PREFERRED}" ]]; then
        OPENWRT_SDK="${OPENWRT_SDK_PREFERRED}"
        return 0
    fi
    if [[ -n "${OPENWRT_SDK}" && -d "${OPENWRT_SDK}" ]]; then
        return 0
    fi
    if [[ -d "${sdk_dir}" ]]; then
        OPENWRT_SDK="${sdk_dir}"
        return 0
    fi
    if [[ ${AUTO_CLONE} -ne 1 ]]; then
        echo "OpenWRT SDK not found; set --openwrt-sdk or place it at:" >&2
        echo "  ${OPENWRT_SDK_PREFERRED}" >&2
        exit 1
    fi
    mkdir -p "${base_dir}"
    mkdir -p "${OPENWRT_SDK_CACHE_DIR}"
    local archive="${OPENWRT_SDK_CACHE_DIR}/${OPENWRT_SDK_NAME}.tar.zst"
    if [[ ! -s "${archive}" ]]; then
        fetch_url "${OPENWRT_SDK_URL}" "${archive}"
    fi
    if command -v zstd >/dev/null 2>&1; then
        tar -I zstd -xf "${archive}" -C "${base_dir}"
    elif command -v unzstd >/dev/null 2>&1; then
        unzstd -c "${archive}" | tar -xf - -C "${base_dir}"
    else
        echo "Missing zstd or unzstd to extract ${archive}" >&2
        exit 1
    fi
    if [[ ! -d "${sdk_dir}" ]]; then
        echo "OpenWRT SDK extraction failed; expected ${sdk_dir}" >&2
        exit 1
    fi
    OPENWRT_SDK="${sdk_dir}"
}

if ! need_cmd git || ! need_cmd cmake || ! need_cmd make; then
    echo "Missing required tools: git/cmake/make" >&2
    exit 1
fi

LIBOQS_SRC="${LIBOQS_SRC:-${REAL_HOME}/liboqs}"
ARGON2_SRC="${ARGON2_SRC:-${REAL_HOME}/argon2}"

cleanup_sources() {
    if [[ $KEEP_SOURCES -eq 0 ]]; then
        if [[ "${LIBOQS_SRC}" == /tmp/* ]]; then
            rm -rf "${LIBOQS_SRC}"
        fi
        if [[ "${ARGON2_SRC}" == /tmp/* ]]; then
            rm -rf "${ARGON2_SRC}"
        fi
    fi
}
trap cleanup_sources EXIT

clone_sources() {
    if [[ ! -d "${LIBOQS_SRC}" ]]; then
        if [[ ${AUTO_CLONE} -ne 1 ]]; then
            echo "liboqs not found at ${LIBOQS_SRC}; set LIBOQS_SRC or install it there." >&2
            exit 1
        fi
        echo "Cloning liboqs into ${LIBOQS_SRC}..."
        git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git "${LIBOQS_SRC}"
    fi
    if [[ ! -d "${ARGON2_SRC}" ]]; then
        if [[ ${AUTO_CLONE} -ne 1 ]]; then
            echo "argon2 not found at ${ARGON2_SRC}; set ARGON2_SRC or clone it there." >&2
            exit 1
        fi
        echo "Cloning argon2 into ${ARGON2_SRC}..."
        git clone --depth 1 https://github.com/P-H-C/phc-winner-argon2.git "${ARGON2_SRC}"
    fi
}

prepare_toolchain() {
    if [[ "${TARGET}" == "host" ]]; then
        return 0
    fi

    if is_windows_target || is_macos_target; then
        ensure_vcpkg
        if [[ -z "${VCPKG_TRIPLET}" ]]; then
            if is_windows_target; then
                VCPKG_TRIPLET="x64-mingw-dynamic"
            else
                VCPKG_TRIPLET="x64-osx"
            fi
        fi
        if is_macos_target; then
            ensure_osxcross
            if [[ -z "${MACOS_SDK}" ]]; then
                MACOS_SDK="$(ls -d "${OSXCROSS_ROOT}/target/SDK/MacOSX"*.sdk 2>/dev/null | sort -V | tail -n 1 || true)"
            fi
            if [[ -z "${MACOS_SDK}" ]]; then
                echo "macOS SDK not found under ${OSXCROSS_ROOT}/target/SDK; set --macos-sdk." >&2
                exit 1
            fi
        fi
        return 0
    fi

    if [[ "${TARGET}" == "openwrt-mips" ]]; then
        ensure_openwrt_sdk
        local toolchain_dir
        toolchain_dir="$(find "${OPENWRT_SDK}/staging_dir" -maxdepth 2 -type d -name 'toolchain-*' | head -n 1)"
        local target_dir
        target_dir="$(find "${OPENWRT_SDK}/staging_dir" -maxdepth 2 -type d -name 'target-*' | head -n 1)"
        if [[ -z "${toolchain_dir}" || -z "${target_dir}" ]]; then
            echo "OpenWRT SDK toolchain/target not found under ${OPENWRT_SDK}/staging_dir" >&2
            exit 1
        fi
        SYSROOT="${target_dir}"
        TOOLCHAIN_PREFIX="$(find "${toolchain_dir}/bin" -maxdepth 1 -type f -name '*-gcc' | head -n 1 | sed 's/-gcc$//')"
        if [[ -z "${TOOLCHAIN_PREFIX}" ]]; then
            echo "OpenWRT toolchain prefix not found" >&2
            exit 1
        fi
        return 0
    fi

    if [[ "${TARGET}" == "aarch64" || "${TARGET}" == "armv8" || "${TARGET}" == "armv7" || "${TARGET}" == "x86" || "${TARGET}" == "x86_64" || "${TARGET}" == "busybox-armv8" || "${TARGET}" == "busybox-armv7" || "${TARGET}" == "busybox-x86" || "${TARGET}" == "busybox-x86_64" ]]; then
        if [[ -z "${TOOLCHAIN_PREFIX}" || -z "${SYSROOT}" ]]; then
            echo "--toolchain-prefix and --sysroot are required for ${TARGET}" >&2
            exit 1
        fi
        return 0
    fi

    echo "Unsupported target: ${TARGET}" >&2
    exit 1
}

if [[ "${TARGET}" == "all" ]]; then
    if ! need_cmd docker; then
        echo "docker is required for --target all" >&2
        exit 1
    fi
    # Host + OpenWRT MIPS locally, others via dockcross.
    ./scripts/build_vendor_libs.sh --target host ${FORCE:+--force}
    ./scripts/build_vendor_libs.sh --target openwrt-mips ${FORCE:+--force}
    docker_build_vendor "armv7" "dockcross/linux-armv7"
    docker_build_vendor "armv8" "dockcross/linux-arm64"
    docker_build_vendor "x86" "dockcross/linux-x86"
    docker_build_vendor "busybox-armv7" "dockcross/linux-armv7"
    docker_build_vendor "busybox-armv8" "dockcross/linux-arm64"
    docker_build_vendor "busybox-x86" "dockcross/linux-x86"
    if [[ -n "${VCPKG_ROOT}" || -x "${REAL_HOME}/vcpkg/vcpkg" ]]; then
        ./scripts/build_vendor_libs.sh --target windows-x86_64 --vcpkg-root "${VCPKG_ROOT:-${REAL_HOME}/vcpkg}" ${FORCE:+--force} || true
        if [[ -n "${OSXCROSS_ROOT}" || -d "${REAL_HOME}/osxcross" ]]; then
            ./scripts/build_vendor_libs.sh --target macos-x86_64 --vcpkg-root "${VCPKG_ROOT:-${REAL_HOME}/vcpkg}" --osxcross-root "${OSXCROSS_ROOT:-${REAL_HOME}/osxcross}" ${MACOS_SDK:+--macos-sdk "${MACOS_SDK}"} ${FORCE:+--force} || true
        else
            echo "Skipping macOS vendor build; osxcross not found." >&2
        fi
    else
        echo "Skipping Windows/macOS vendor build; vcpkg not found." >&2
    fi
    if [[ -n "${ARCHIVE_PATH}" ]]; then
        tar -cJf "${ARCHIVE_PATH}" -C "${VENDOR_DIR}" .
        echo "Vendor archive created at: ${ARCHIVE_PATH}"
    fi
    exit 0
fi

stage_dir="${VENDOR_DIR}/$(target_dir "${TARGET}")"
inc_dir="${stage_dir}/include"
lib_dir="${stage_dir}/lib"
mkdir -p "${inc_dir}" "${lib_dir}"

prune_stage_dir() {
    rm -rf "${stage_dir}/bin" "${stage_dir}/share"
    rm -rf "${stage_dir}/lib/pkgconfig" "${stage_dir}/lib/cmake"
    find "${stage_dir}" -type f -name "*.la" -delete 2>/dev/null || true
}

if vendor_complete "${TARGET}"; then
    echo "Vendored libs already present for ${TARGET}; skipping."
    exit 0
fi

USE_SYSROOT=1
if [[ -z "${SYSROOT}" || "${SYSROOT}" == "/" ]]; then
    USE_SYSROOT=0
fi

build_liboqs() {
    local build_dir="/tmp/yume-liboqs-build-${TARGET}"
    rm -rf "${build_dir}"
    mkdir -p "${build_dir}"

    if [[ "${TARGET}" == "openwrt-mips" ]]; then
        export STAGING_DIR="${OPENWRT_SDK}/staging_dir"
    fi

    local cmake_args=(
        -DCMAKE_BUILD_TYPE=Release
        -DOQS_DIST_BUILD=ON
        -DOQS_USE_AVX2=OFF
        -DOQS_USE_AVX512=OFF
        -DOQS_USE_SSE2=OFF
        -DOQS_USE_SVE=OFF
        -DOQS_BUILD_ONLY_LIB=ON
        -DOQS_BUILD_TESTS=OFF
        -DOQS_BUILD_BENCHMARKS=OFF
        -DOQS_BUILD_DEMOS=OFF
        -DOQS_BUILD_EXAMPLES=OFF
        -DOQS_BUILD_SHARED_LIBS=OFF
        -DOQS_BUILD_STATIC_LIBS=ON
        -DOQS_INSTALL_SHARED=OFF
        -DOQS_USE_OPENSSL=OFF
        -DBUILD_SHARED_LIBS=OFF
        -DBUILD_TESTING=OFF
        -DCMAKE_INSTALL_PREFIX="${stage_dir}"
    )

    if [[ "${TARGET}" != "host" ]]; then
        cmake_args+=(
            -DCMAKE_SYSTEM_NAME=Linux
        )
        cmake_args+=(
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        )
        if [[ ${USE_SYSROOT} -eq 1 ]]; then
            cmake_args+=(
                -DCMAKE_SYSROOT="${SYSROOT}"
                -DCMAKE_FIND_ROOT_PATH="${SYSROOT}"
                -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER
                -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY
                -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY
                -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY
            )
        fi
        cmake_args+=(
            -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON
        )
        cmake_args+=(
            -DCMAKE_C_COMPILER="${TOOLCHAIN_PREFIX}-gcc"
            -DCMAKE_CXX_COMPILER="${TOOLCHAIN_PREFIX}-g++"
            -DCMAKE_AR="${TOOLCHAIN_PREFIX}-ar"
            -DCMAKE_RANLIB="${TOOLCHAIN_PREFIX}-ranlib"
            -DCMAKE_STRIP="${TOOLCHAIN_PREFIX}-strip"
        )
    else
        cmake_args+=(
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        )
    fi

    cmake -S "${LIBOQS_SRC}" -B "${build_dir}" "${cmake_args[@]}"
    cmake --build "${build_dir}" -j"$(nproc 2>/dev/null || echo 4)"
    cmake --install "${build_dir}"
}

build_argon2() {
    make -C "${ARGON2_SRC}" clean || true
    local argon2_inc="${ARGON2_SRC}/include"
    local make_args=(
        CFLAGS="-I${argon2_inc} -fPIC"
        OPTTARGET=generic
        LIBRARY_REL=lib
        PKGCONFIG_REL=lib
        BINARY_REL=bin
        INCLUDE_REL=include
    )
    if [[ "${TARGET}" != "host" ]]; then
        if [[ "${TARGET}" == "openwrt-mips" ]]; then
            export STAGING_DIR="${OPENWRT_SDK}/staging_dir"
        fi
        make_args+=(
            CC="${TOOLCHAIN_PREFIX}-gcc"
            AR="${TOOLCHAIN_PREFIX}-ar"
            RANLIB="${TOOLCHAIN_PREFIX}-ranlib"
        )
        if [[ ${USE_SYSROOT} -eq 1 ]]; then
            make_args+=(
                CFLAGS="--sysroot=${SYSROOT} -I${SYSROOT}/usr/include -I${argon2_inc} -fPIC"
            )
        else
            make_args+=(
                CFLAGS="-I${argon2_inc} -fPIC"
            )
        fi
        make -C "${ARGON2_SRC}" "${make_args[@]}"
        local install_cflags="--sysroot=${SYSROOT} -I${SYSROOT}/usr/include -I${argon2_inc} -fPIC"
        if [[ ${USE_SYSROOT} -ne 1 ]]; then
            install_cflags="-I${argon2_inc} -fPIC"
        fi
        make -C "${ARGON2_SRC}" install \
            DESTDIR="${stage_dir}" \
            PREFIX=/ \
            LIBRARY_REL=lib \
            PKGCONFIG_REL=lib \
            BINARY_REL=bin \
            INCLUDE_REL=include \
            CC="${TOOLCHAIN_PREFIX}-gcc" \
            AR="${TOOLCHAIN_PREFIX}-ar" \
            RANLIB="${TOOLCHAIN_PREFIX}-ranlib" \
            OPTTARGET=generic \
            CFLAGS="${install_cflags}"
    else
        make -C "${ARGON2_SRC}" "${make_args[@]}"
        make -C "${ARGON2_SRC}" install \
            DESTDIR="${stage_dir}" \
            PREFIX=/ \
            LIBRARY_REL=lib \
            PKGCONFIG_REL=lib \
            BINARY_REL=bin \
            INCLUDE_REL=include
    fi
}

if ! is_windows_target && ! is_macos_target; then
    clone_sources
fi
prepare_toolchain

if is_windows_target || is_macos_target; then
    if vendor_complete "${TARGET}"; then
        echo "Vendored libs already present for ${TARGET}; skipping."
        exit 0
    fi
    install_vcpkg_packages "${VCPKG_TRIPLET}"
    stage_vcpkg_libs "${VCPKG_TRIPLET}"
    prune_stage_dir
    echo "Vendored libs staged at: ${stage_dir}"
    if [[ -n "${ARCHIVE_PATH}" ]]; then
        tar -cJf "${ARCHIVE_PATH}" -C "${VENDOR_DIR}" "$(target_dir "${TARGET}")"
        echo "Vendor archive created at: ${ARCHIVE_PATH}"
    fi
    exit 0
fi

build_liboqs
build_argon2
prune_stage_dir

echo "Vendored libs staged at: ${stage_dir}"
if [[ -n "${ARCHIVE_PATH}" ]]; then
    tar -cJf "${ARCHIVE_PATH}" -C "${VENDOR_DIR}" "$(target_dir "${TARGET}")"
    echo "Vendor archive created at: ${ARCHIVE_PATH}"
fi
