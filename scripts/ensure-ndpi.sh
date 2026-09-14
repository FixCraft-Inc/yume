#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
#
# Builds the pinned nDPI release used for DPI smoke observations of YUME
# sessions. nDPI is evaluation tooling that YUME never links or ships, so the
# pin lives here and not in config/dependencies.json. A clone of the release
# tag must resolve to the pinned commit before anything is built.
set -euo pipefail
umask 077

readonly NDPI_TAG="6.0"
readonly NDPI_COMMIT="1a5293396337f9a72dfee1fa070b2c4b0a0a3aaf"
readonly NDPI_REPOSITORY="https://github.com/ntop/nDPI.git"

usage() {
    cat >&2 <<'USAGE'
Usage: scripts/ensure-ndpi.sh [--prefix DIR] [--libpcap-prefix DIR] [--jobs N]

Prints the pinned ndpiReader path. An existing prefix is reused only when its
manifest names the pinned commit and the recorded binary hash still matches.
--libpcap-prefix names a directory with include/pcap/pcap.h and
lib/libpcap.so, for hosts without system libpcap headers.
USAGE
}

cache="${XDG_CACHE_HOME:-$HOME/.cache}/yume"
prefix="$cache/ndpi-${NDPI_TAG}-${NDPI_COMMIT:0:12}"
libpcap_prefix=""
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix) prefix="${2:?--prefix needs a directory}"; shift 2 ;;
        --libpcap-prefix) libpcap_prefix="${2:?--libpcap-prefix needs a directory}"; shift 2 ;;
        --jobs) jobs="${2:?--jobs needs a count}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'ensure-ndpi: unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
    esac
done
if ! [[ "$jobs" =~ ^[1-9][0-9]{0,2}$ ]]; then
    echo "ensure-ndpi: --jobs must be a positive integer" >&2
    exit 2
fi

manifest="$prefix/ndpi-manifest.txt"
reader="$prefix/bin/ndpiReader"
if [ -e "$prefix" ]; then
    if [ -f "$manifest" ] && [ -x "$reader" ] &&
       grep -qx "commit=$NDPI_COMMIT" "$manifest" &&
       [ "$(sha256sum "$reader" | cut -d' ' -f1)" = "$(sed -n 's/^ndpiReader_sha256=//p' "$manifest")" ]; then
        printf '%s\n' "$reader"
        exit 0
    fi
    echo "ensure-ndpi: $prefix is not the pinned build; remove it explicitly to rebuild" >&2
    exit 1
fi

for tool in git autoconf automake libtoolize make pkg-config cc sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ensure-ndpi: missing $tool" >&2; exit 1; }
done
if [ -n "$libpcap_prefix" ]; then
    if [ ! -f "$libpcap_prefix/include/pcap/pcap.h" ] || [ ! -e "$libpcap_prefix/lib/libpcap.so" ]; then
        echo "ensure-ndpi: $libpcap_prefix lacks include/pcap/pcap.h or lib/libpcap.so" >&2
        exit 1
    fi
elif [ ! -f /usr/include/pcap/pcap.h ] && ! pkg-config --exists libpcap; then
    echo "ensure-ndpi: libpcap headers are missing; install them or pass --libpcap-prefix" >&2
    exit 1
fi

mkdir -p "$(dirname "$prefix")"
work="$(mktemp -d "${TMPDIR:-/tmp}/yume-ndpi-build.XXXXXX")"
staging="$(mktemp -d "$prefix.partial.XXXXXX")"
trap 'rm -rf "$work" "$staging"' EXIT

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$NDPI_TAG" \
    "$NDPI_REPOSITORY" "$work/src"
actual="$(git -C "$work/src" rev-parse HEAD)"
if [ "$actual" != "$NDPI_COMMIT" ]; then
    echo "ensure-ndpi: tag $NDPI_TAG resolved to $actual, expected $NDPI_COMMIT" >&2
    exit 1
fi

configure_args=()
if [ -n "$libpcap_prefix" ]; then
    configure_args+=("--with-libpcap=$libpcap_prefix")
fi
# nDPI's autogen.sh only regenerates the build system.
(
    cd "$work/src"
    ./autogen.sh
    ./configure "${configure_args[@]}"
    make -j"$jobs"
) > "$work/build.log" 2>&1 || {
    tail -40 "$work/build.log" >&2
    echo "ensure-ndpi: build failed" >&2
    exit 1
}

mkdir -p "$staging/bin"
install -m 0755 "$work/src/example/ndpiReader" "$staging/bin/ndpiReader"
install -m 0644 "$work/src/COPYING" "$staging/COPYING"
{
    echo "tag=$NDPI_TAG"
    echo "commit=$NDPI_COMMIT"
    echo "repository=$NDPI_REPOSITORY"
    echo "libpcap_prefix=${libpcap_prefix:-system}"
    echo "ndpiReader_sha256=$(sha256sum "$staging/bin/ndpiReader" | cut -d' ' -f1)"
} > "$staging/ndpi-manifest.txt"
chmod 0755 "$staging" "$staging/bin"
mv "$staging" "$prefix"
printf '%s\n' "$reader"
