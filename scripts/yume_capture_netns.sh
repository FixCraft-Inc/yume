#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
#
# Creates and enters the loopback-only network namespace that capture runs
# require.
#
# Chrome performs its own startup service calls (optimization guide, GAIA
# account listing, time sync) before it will service a navigation, and those
# block the browser's network pipeline for about ten seconds at a time. A
# capture driver waiting on `Page.navigate` therefore times out, and the
# resulting capture also contains real Chrome-to-Google TLS connections that the
# fixture workload never produced. Making those requests fail fast does not
# help; Chrome only skips the work when no network exists at all.
#
# Entering the namespace as the invoking user rather than as root keeps Chrome's
# user-namespace sandbox available and leaves captured artifacts owned by that
# user. Only namespace creation needs privilege.

set -euo pipefail
umask 077

readonly NETNS_NAME='yume-capture'

usage() {
    cat >&2 <<'USAGE'
usage: yume_capture_netns.sh setup
       yume_capture_netns.sh teardown
       yume_capture_netns.sh exec -- <command> [args...]

setup and teardown need root; run them under sudo. exec drops back to the
invoking user (SUDO_UID/SUDO_GID when present) before running the command.
USAGE
    exit 2
}

require_root() {
    if [[ $(id -u) -ne 0 ]]; then
        echo "$1 requires root; rerun under sudo" >&2
        exit 1
    fi
}

resolve() {
    local found
    if ! found=$(command -v "$1"); then
        echo "required executable not found: $1" >&2
        exit 1
    fi
    printf '%s' "$found"
}

ip_bin=$(resolve ip)
setpriv_bin=$(resolve setpriv)
readonly ip_bin setpriv_bin

case ${1:-} in
setup)
    require_root setup
    if ! "$ip_bin" netns list | grep -qx "$NETNS_NAME"; then
        "$ip_bin" netns add "$NETNS_NAME"
    fi
    # Without this the fixture on 127.0.0.1 is unreachable.
    "$ip_bin" netns exec "$NETNS_NAME" "$ip_bin" link set lo up
    echo "$NETNS_NAME ready (loopback only)"
    ;;
teardown)
    require_root teardown
    "$ip_bin" netns delete "$NETNS_NAME" 2>/dev/null || true
    echo "$NETNS_NAME removed"
    ;;
exec)
    require_root exec
    shift
    [[ ${1:-} == '--' ]] && shift
    [[ $# -gt 0 ]] || usage
    target_uid=${SUDO_UID:-0}
    target_gid=${SUDO_GID:-0}
    if [[ $target_uid -eq 0 ]]; then
        echo 'refusing to run a capture as root; invoke through sudo as the capture user' >&2
        exit 1
    fi
    # setpriv changes credentials but not the environment, so without this the
    # capture inherits root's HOME and writes to (or fails on) /root, and Git
    # reads root's configuration instead of the capture user's.
    target_user=$(getent passwd "$target_uid" | cut -d: -f1)
    target_home=$(getent passwd "$target_uid" | cut -d: -f6)
    if [[ -z $target_user || -z $target_home ]]; then
        echo "cannot resolve passwd entry for uid $target_uid" >&2
        exit 1
    fi
    exec env "HOME=$target_home" "USER=$target_user" "LOGNAME=$target_user" \
        "$ip_bin" netns exec "$NETNS_NAME" \
        "$setpriv_bin" --reuid="$target_uid" --regid="$target_gid" --init-groups \
        "$@"
    ;;
*)
    usage
    ;;
esac
