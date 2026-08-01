#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

# Return success when any directory contains a regular library artifact for
# the requested stem. Versioned shared objects are expanded by Bash in the
# caller's filesystem; unlike [[ -f path.so.* ]], this does not test a literal
# filename containing '*'.
yume_library_artifact_exists() {
    local stem="${1:-}"
    if [[ -z "${stem}" || "${stem}" == */* ]]; then
        return 2
    fi
    shift

    local dir candidate
    for dir in "$@"; do
        [[ -n "${dir}" ]] || continue
        if [[ -f "${dir}/${stem}.so" || -f "${dir}/${stem}.a" ]]; then
            return 0
        fi
        for candidate in "${dir}/${stem}.so."*; do
            if [[ "${candidate}" != *'*'* && -f "${candidate}" ]]; then
                return 0
            fi
        done
    done
    return 1
}
