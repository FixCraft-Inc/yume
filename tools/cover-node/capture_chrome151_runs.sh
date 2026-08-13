#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

set -euo pipefail

readonly EXPECTED_CHROME_VERSION='Google Chrome 151.0.7922.71'
readonly EXPECTED_CHROME_BINARY_SHA256='4cf210c4a0aeee3e69a73639260918a7448626d6b99892ec61e20750bc7c7079'
readonly EXPECTED_NODE_VERSION='v24.18.0'
readonly EXPECTED_NODE_BINARY_SHA256='41a74efb34cbde5c7632cdac0cf8bd1a14d0b8d73dc1e82755014d9a9ce70f5c'
readonly DEFAULT_CHROME_LAUNCHER='/opt/google/chrome/google-chrome'
readonly DEFAULT_CHROME_BINARY='/opt/google/chrome/chrome'
readonly DEFAULT_RUNS=5
readonly DEFAULT_IDLE_MS=42000

usage() {
    cat <<'EOF'
usage: capture_chrome151_runs.sh <output-directory> <node-24.18.0-binary> [runs] [idle-ms]

Captures normal (non-headless) Google Chrome 151 against the pinned Node 24
cover fixture. DISPLAY must refer to a usable, unprivileged X display. Raw
IncludeSensitive NetLogs remain in the output directory and must not be
committed; only reviewed sanitized artifacts belong in the repository.
EOF
}

if [[ $# -lt 2 || $# -gt 4 ]]; then
    usage >&2
    exit 2
fi

readonly output_dir=$1
readonly node_bin=$2
readonly run_count=${3:-$DEFAULT_RUNS}
readonly idle_ms=${4:-$DEFAULT_IDLE_MS}
readonly chrome_launcher=${YUME_CHROME_LAUNCHER:-$DEFAULT_CHROME_LAUNCHER}
readonly chrome_binary=${YUME_CHROME_BINARY:-$DEFAULT_CHROME_BINARY}
readonly capture_tls_wire=${YUME_CAPTURE_TLS_WIRE:-0}
readonly repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)

if [[ ! $run_count =~ ^[1-9][0-9]*$ || $run_count -gt 20 ]]; then
    echo 'runs must be an integer in 1..20' >&2
    exit 2
fi
if [[ ! $idle_ms =~ ^[0-9]+$ || $idle_ms -gt 120000 ]]; then
    echo 'idle-ms must be an integer in 0..120000' >&2
    exit 2
fi
if [[ -z ${DISPLAY:-} ]]; then
    echo 'DISPLAY must be set; headless Chrome is intentionally not accepted' >&2
    exit 1
fi
if [[ $capture_tls_wire != 0 && $capture_tls_wire != 1 ]]; then
    echo 'YUME_CAPTURE_TLS_WIRE must be 0 or 1' >&2
    exit 2
fi
for executable in "$node_bin" "$chrome_launcher" "$chrome_binary"; do
    if [[ ! -x $executable ]]; then
        echo "required executable is missing: $executable" >&2
        exit 1
    fi
done

readonly chrome_version=$(
    $chrome_launcher --version | sed -e 's/[[:space:]]*$//'
)
readonly node_version=$($node_bin --version | sed -e 's/[[:space:]]*$//')
readonly chrome_sha256=$(sha256sum -- "$chrome_binary" | awk '{print $1}')
readonly node_sha256=$(sha256sum -- "$node_bin" | awk '{print $1}')
if [[ $chrome_version != "$EXPECTED_CHROME_VERSION" ]]; then
    echo "Chrome version mismatch: got '$chrome_version'" >&2
    exit 1
fi
if [[ $chrome_sha256 != "$EXPECTED_CHROME_BINARY_SHA256" ]]; then
    echo "Chrome binary SHA-256 mismatch: got '$chrome_sha256'" >&2
    exit 1
fi
if [[ $node_version != "$EXPECTED_NODE_VERSION" ]]; then
    echo "Node version mismatch: got '$node_version'" >&2
    exit 1
fi
if [[ $node_sha256 != "$EXPECTED_NODE_BINARY_SHA256" ]]; then
    echo "Node binary SHA-256 mismatch: got '$node_sha256'" >&2
    exit 1
fi
if [[ -e $output_dir ]]; then
    echo "output path already exists: $output_dir" >&2
    exit 1
fi

mkdir -m 0700 -- "$output_dir"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$output_dir/server.key" -out "$output_dir/server.crt" \
    -days 1 -nodes -subj /CN=localhost \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
chmod 0600 -- "$output_dir/server.key"

cat >"$output_dir/environment.json" <<EOF
{
  "chrome_version": "$chrome_version",
  "chrome_binary": "$chrome_binary",
  "chrome_binary_sha256": "$chrome_sha256",
  "node_version": "$node_version",
  "node_binary_sha256": "$node_sha256",
  "display": "$DISPLAY",
  "runs": $run_count,
  "idle_ms": $idle_ms,
  "tls_wire_evidence": $capture_tls_wire
}
EOF

node_pid=''
chrome_pid=''
relay_pid=''
cleanup_children() {
    if [[ -n $chrome_pid ]]; then
        kill "$chrome_pid" 2>/dev/null || true
        wait "$chrome_pid" 2>/dev/null || true
        chrome_pid=''
    fi
    if [[ -n $relay_pid ]]; then
        kill "$relay_pid" 2>/dev/null || true
        wait "$relay_pid" 2>/dev/null || true
        relay_pid=''
    fi
    if [[ -n $node_pid ]]; then
        kill "$node_pid" 2>/dev/null || true
        wait "$node_pid" 2>/dev/null || true
        node_pid=''
    fi
}
trap cleanup_children EXIT INT TERM

readonly cover_port=39443
readonly cover_backend_port=39444
readonly devtools_port=39222
if ss -ltn | rg -q ":(${cover_port}|${cover_backend_port}|${devtools_port})\\b"; then
    echo 'capture ports 39443, 39444, or 39222 are already in use' >&2
    exit 1
fi

for run_index in $(seq 1 "$run_count"); do
    run_name=$(printf 'run-%02d' "$run_index")
    run_dir="$output_dir/$run_name"
    mkdir -m 0700 -- "$run_dir"

    node_port=$cover_port
    if [[ $capture_tls_wire == 1 ]]; then
        node_port=$cover_backend_port
    fi
    YUME_COVER_HOST=127.0.0.1 \
    YUME_COVER_PORT=$node_port \
    YUME_COVER_TLS_KEY="$output_dir/server.key" \
    YUME_COVER_TLS_CERT="$output_dir/server.crt" \
        "$node_bin" "$repo_root/tools/cover-node/server.mjs" \
        >"$run_dir/node.log" 2>&1 &
    node_pid=$!

    if [[ $capture_tls_wire == 1 ]]; then
        "$repo_root/scripts/yume_tls_wire.py" relay \
            --listen "127.0.0.1:$cover_port" \
            --target "127.0.0.1:$cover_backend_port" \
            --output "$run_dir/tls-wire.json" \
            --ready-file "$run_dir/tls-wire-ready.json" \
            --timeout 120 >"$run_dir/tls-wire.log" 2>&1 &
        relay_pid=$!
        relay_ready=0
        for _ in $(seq 1 100); do
            if [[ -f $run_dir/tls-wire-ready.json ]]; then
                relay_ready=1
                break
            fi
            if ! kill -0 "$relay_pid" 2>/dev/null; then
                break
            fi
            sleep 0.05
        done
        if [[ $relay_ready != 1 ]]; then
            sed -n '1,160p' "$run_dir/tls-wire.log" >&2
            echo "$run_name: TLS wire relay did not become ready" >&2
            exit 1
        fi
    fi

    "$chrome_launcher" \
        --disable-gpu \
        --no-first-run \
        --disable-background-networking \
        --disable-component-update \
        --disable-sync \
        --disable-quic \
        --ignore-certificate-errors \
        --remote-debugging-address=127.0.0.1 \
        --remote-debugging-port=$devtools_port \
        --user-data-dir="$run_dir/profile" \
        --log-net-log="$run_dir/netlog.json" \
        --net-log-capture-mode=IncludeSensitive \
        about:blank >"$run_dir/chrome.log" 2>&1 &
    chrome_pid=$!

    ready=0
    for _ in $(seq 1 150); do
        if curl --silent --fail \
            "http://127.0.0.1:$devtools_port/json/version" >/dev/null; then
            ready=1
            break
        fi
        if ! kill -0 "$chrome_pid" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done
    if [[ $ready != 1 ]]; then
        sed -n '1,160p' "$run_dir/chrome.log" >&2
        echo "$run_name: Chrome DevTools did not become ready" >&2
        exit 1
    fi

    "$node_bin" "$repo_root/tools/cover-node/capture_chrome.mjs" \
        "$devtools_port" "https://localhost:$cover_port/" "$idle_ms"
    wait "$chrome_pid" || true
    chrome_pid=''
    if [[ -n $relay_pid ]]; then
        wait "$relay_pid"
        relay_pid=''
        rm -f -- "$run_dir/tls-wire-ready.json"
    fi
    kill "$node_pid" 2>/dev/null || true
    wait "$node_pid" 2>/dev/null || true
    node_pid=''

    # Give Chrome's NetLog writer a bounded flush interval after Browser.close.
    # The sanitizer can recover a small number of independently malformed
    # event lines, but still rejects missing target-session semantics.
    sleep 0.2
    "$node_bin" "$repo_root/tools/cover-node/sanitize_netlog.mjs" \
        "$run_dir/netlog.json" "localhost:$cover_port" \
        >"$run_dir/sanitized.json"
    checksum_files=("$run_dir/netlog.json" "$run_dir/sanitized.json")
    if [[ -f $run_dir/tls-wire.json ]]; then
        checksum_files+=("$run_dir/tls-wire.json")
    fi
    sha256sum -- "${checksum_files[@]}" >"$run_dir/SHA256SUMS"
    rm -rf -- "$run_dir/profile"
    echo "$run_name: complete"
done

echo "Chrome 151 evidence captured in $output_dir"
