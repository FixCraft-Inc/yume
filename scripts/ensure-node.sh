#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

# Provide the Node.js runtime the cover tools pin, for their tests. The
# evidence profile chrome151-node24-v1 models a Node 24.18 cover server, the
# capture scripts refuse any other Node, and tools/cover-node/package.json
# declares the same engine, so the tests of that server run on it too.
#
# Source this file and call yume_node_ensure. It downloads the official
# linux-x64 build once into YUME_CACHE_ROOT, checks it against the SHA-256
# below (taken from https://nodejs.org/dist/v24.18.0/SHASUMS256.txt), and
# exports YUME_NODE_EXECUTABLE for CMake. Every step is checked, because a
# caller that tests this function's status turns set -e off inside it.

YUME_NODE_VERSION="24.18.0"
YUME_NODE_ARCHIVE="node-v${YUME_NODE_VERSION}-linux-x64.tar.xz"
YUME_NODE_SHA256="55aa7153f9d88f28d765fcdad5ae6945b5c0f98a36881703817e4c450fa76742"

yume_node_error() {
    if declare -F error >/dev/null 2>&1
    then
        error "$*"
    else
        printf '[error] %s\n' "$*" >&2
    fi
}

yume_node_log() {
    if declare -F info >/dev/null 2>&1
    then
        info "$*"
    else
        printf '[info] %s\n' "$*" >&2
    fi
}

# Succeeds when the prefix holds the pinned build this helper verified.
yume_node_valid_prefix() {
    local prefix="$1"
    [[ -f "${prefix}/.yume-verified" ]] || return 1
    [[ -x "${prefix}/bin/node" ]] || return 1
    [[ "$("${prefix}/bin/node" --version 2>/dev/null)" == "v${YUME_NODE_VERSION}" ]]
}

yume_node_ensure() {
    local cache_root="${YUME_CACHE_ROOT:-${HOME}/.cache/yume}"
    local prefix="${cache_root}/node-v${YUME_NODE_VERSION}-linux-x64"
    local url="https://nodejs.org/dist/v${YUME_NODE_VERSION}/${YUME_NODE_ARCHIVE}"
    local work=""
    local actual=""

    if yume_node_valid_prefix "${prefix}"
    then
        export YUME_NODE_EXECUTABLE="${prefix}/bin/node"
        return 0
    fi
    if [[ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]]
    then
        yume_node_error "The pinned Node ${YUME_NODE_VERSION} is provided for Linux x86-64 only."
        return 1
    fi
    if ! command -v curl >/dev/null 2>&1
    then
        yume_node_error "curl is required to fetch Node ${YUME_NODE_VERSION}."
        return 1
    fi
    if ! mkdir -p "${cache_root}"
    then
        yume_node_error "Cannot create the cache directory ${cache_root}."
        return 1
    fi
    if ! work="$(mktemp -d "${cache_root}/node-download.XXXXXX")"
    then
        yume_node_error "Cannot create a download directory under ${cache_root}."
        return 1
    fi
    yume_node_log "Downloading the pinned Node ${YUME_NODE_VERSION}..."
    if ! curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
        --output "${work}/${YUME_NODE_ARCHIVE}" "${url}"
    then
        rm -rf -- "${work}"
        yume_node_error "Could not download Node ${YUME_NODE_VERSION} from ${url}."
        return 1
    fi
    actual="$(sha256sum "${work}/${YUME_NODE_ARCHIVE}" | awk '{print $1}')"
    if [[ "${actual}" != "${YUME_NODE_SHA256}" ]]
    then
        rm -rf -- "${work}"
        yume_node_error "Node ${YUME_NODE_VERSION} checksum mismatch, so the download was removed."
        return 1
    fi
    if ! tar -xJf "${work}/${YUME_NODE_ARCHIVE}" -C "${work}"
    then
        rm -rf -- "${work}"
        yume_node_error "Could not extract Node ${YUME_NODE_VERSION}."
        return 1
    fi
    # The prefix is fixed beneath the cache root, and the new tree replaces
    # it whole, so a partial earlier attempt is never accepted.
    if ! { rm -rf -- "${prefix}" && mv -- "${work}/node-v${YUME_NODE_VERSION}-linux-x64" "${prefix}" &&
        touch "${prefix}/.yume-verified"; }
    then
        rm -rf -- "${work}" "${prefix}"
        yume_node_error "Could not install Node ${YUME_NODE_VERSION} into ${prefix}."
        return 1
    fi
    rm -rf -- "${work}"
    if ! yume_node_valid_prefix "${prefix}"
    then
        yume_node_error "The installed Node does not report version ${YUME_NODE_VERSION}."
        return 1
    fi
    export YUME_NODE_EXECUTABLE="${prefix}/bin/node"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]
then
    set -euo pipefail
    yume_node_ensure
    printf '%s\n' "${YUME_NODE_EXECUTABLE}"
fi
