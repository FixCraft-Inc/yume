#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

yume_real_home() {
    local home="${HOME}"
    if [[ -n "${SUDO_USER:-}" ]]; then
        local sudo_home
        sudo_home="$(
            getent passwd "${SUDO_USER}" 2>/dev/null |
                cut -d: -f6 || true
        )"
        if [[ -n "${sudo_home}" ]]; then
            home="${sudo_home}"
        fi
    fi
    printf '%s\n' "${home}"
}

yume_real_uid() {
    local uid
    uid="$(id -u)"
    if [[ -n "${SUDO_USER:-}" ]]; then
        local sudo_uid
        sudo_uid="$(id -u "${SUDO_USER}" 2>/dev/null || true)"
        if [[ -n "${sudo_uid}" ]]; then
            uid="${sudo_uid}"
        fi
    fi
    printf '%s\n' "${uid}"
}

yume_real_gid() {
    local gid
    gid="$(id -g)"
    if [[ -n "${SUDO_USER:-}" ]]; then
        local sudo_gid
        sudo_gid="$(id -g "${SUDO_USER}" 2>/dev/null || true)"
        if [[ -n "${sudo_gid}" ]]; then
            gid="${sudo_gid}"
        fi
    fi
    printf '%s\n' "${gid}"
}
