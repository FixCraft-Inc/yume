#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

_yume_safe_path_error() {
    printf '[path-safety][error] %s\n' "$*" >&2
}

# Print the canonical path for a direct child of an existing root directory.
# Rejecting separators and dot components keeps a caller-controlled child name
# from escaping the validated root.
yume_direct_child_path() {
    local root="${1:-}"
    local child="${2:-}"

    if [[ -z "${root}" || ! -d "${root}" ]]; then
        _yume_safe_path_error "root directory is missing or empty"
        return 1
    fi

    local canonical_root
    canonical_root="$(cd -- "${root}" && pwd -P)" || return 1
    if [[ -z "${canonical_root}" || "${canonical_root}" == "/" ]]; then
        _yume_safe_path_error "refusing unsafe root: ${canonical_root:-<empty>}"
        return 1
    fi

    case "${child}" in
        ""|"."|".."|*/*)
            _yume_safe_path_error "refusing non-child path component: ${child:-<empty>}"
            return 1
            ;;
    esac

    printf '%s/%s\n' "${canonical_root}" "${child}"
}

# Remove one or more named direct children of an existing root directory.
# Every target is resolved independently before any recursive deletion.
yume_remove_direct_children() {
    local root="${1:-}"
    shift || true
    if [[ $# -eq 0 ]]; then
        _yume_safe_path_error "no child paths supplied"
        return 1
    fi

    local child target
    for child in "$@"; do
        target="$(yume_direct_child_path "${root}" "${child}")" || return 1
        rm -rf -- "${target:?}"
    done
}
