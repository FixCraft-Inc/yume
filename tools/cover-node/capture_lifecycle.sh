#!/usr/bin/env bash
# YUME - bounded lifetime of the Chrome evidence capture's direct children.
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

# Only pass a child owned by this shell. A completed child is reaped with its
# actual exit status. A deadline also returns 124; check liveness to distinguish
# it from a completed child that itself exited with status 124.
wait_capture_child() {
    local pid=$1
    local deadline=$((SECONDS + $2))
    while kill -0 "$pid" 2>/dev/null; do
        if (( SECONDS >= deadline )); then
            return 124
        fi
        sleep 0.05
    done
    wait "$pid"
}

stop_capture_child() {
    local pid=$1
    local status=0
    kill "$pid" 2>/dev/null || true
    wait_capture_child "$pid" 5 || status=$?
    if (( status != 124 )) || ! kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    kill -KILL "$pid" 2>/dev/null || true
    status=0
    wait_capture_child "$pid" 2 || status=$?
    if (( status == 124 )) && kill -0 "$pid" 2>/dev/null; then
        echo "capture child $pid did not exit after SIGKILL" >&2
        return 1
    fi
}

wait_capture_devtools() {
    local pid=$1
    local port=$2
    local deadline=$((SECONDS + $3))
    while (( SECONDS < deadline )); do
        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi
        # A listener can accept TCP and then never answer HTTP. Bound each
        # request as well as the readiness loop.
        if curl --silent --fail --connect-timeout 1 --max-time 1 \
                "http://127.0.0.1:$port/json/version" >/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}
