#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

# Ensure osxcross has one macOS SDK archive. Prefer an unpacked SDK under the
# invoking user's home, then an already archived SDK from the same directory.
yume_ensure_macos_sdk_tarball() {
    local real_home="${1:-}"
    local osxcross_root="${2:-}"
    if [[ -z "${real_home}" || -z "${osxcross_root}" ]]; then
        printf 'macOS SDK staging requires home and osxcross paths.\n' >&2
        return 1
    fi

    local sdk_src="${real_home}/macos-sdk"
    local tarballs="${osxcross_root}/tarballs"
    mkdir -p "${tarballs}"
    if compgen -G "${tarballs}/MacOSX*.sdk.tar.*" >/dev/null 2>&1; then
        return 0
    fi
    if [[ -d "${sdk_src}" ]]; then
        local sdk_dir
        sdk_dir="$(
            compgen -G "${sdk_src}/MacOSX*.sdk" |
                sort -V |
                tail -n 1 || true
        )"
        if [[ -n "${sdk_dir}" && -d "${sdk_dir}" ]]; then
            local sdk_name
            sdk_name="$(basename "${sdk_dir}")"
            tar -cJf "${tarballs}/${sdk_name}.tar.xz" \
                -C "${sdk_src}" "${sdk_name}"
            return 0
        fi

        local sdk_tar
        sdk_tar="$(
            compgen -G "${sdk_src}/MacOSX*.sdk.tar.*" |
                sort -V |
                tail -n 1 || true
        )"
        if [[ -n "${sdk_tar}" && -f "${sdk_tar}" ]]; then
            cp -f "${sdk_tar}" "${tarballs}/"
            return 0
        fi
    fi
    printf 'macOS SDK not found in %s; place MacOSX*.sdk or MacOSX*.sdk.tar.xz there.\n' \
        "${sdk_src}" >&2
    return 1
}
