#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

set -euo pipefail
umask 077

readonly EXPECTED_CHROME_VERSION='Google Chrome 151.0.7922.71'
readonly EXPECTED_CHROME_LAUNCHER_SHA256='aea09d69ce7f24d5901f6bfb15dd44d0c856e793e0a498f8d8393ec7d2c308ec'
readonly EXPECTED_CHROME_BINARY_SHA256='4cf210c4a0aeee3e69a73639260918a7448626d6b99892ec61e20750bc7c7079'
readonly EXPECTED_NODE_VERSION='v24.18.0'
readonly EXPECTED_NODE_BINARY_SHA256='41a74efb34cbde5c7632cdac0cf8bd1a14d0b8d73dc1e82755014d9a9ce70f5c'
readonly DEFAULT_CHROME_LAUNCHER='/opt/google/chrome/google-chrome'
readonly DEFAULT_CHROME_BINARY='/opt/google/chrome/chrome'
readonly DEFAULT_RUNS=5
readonly DEFAULT_IDLE_MS=42000
readonly GIT_TIMEOUT_SECONDS=10

git_identity() {
    local revision=$1
    "$timeout_bin" --signal=TERM --kill-after=1s "$GIT_TIMEOUT_SECONDS" \
        "$git_bin" -C "$repo_root" rev-parse --verify "$revision"
}

require_clean_source() {
    if ! "$timeout_bin" --signal=TERM --kill-after=1s "$GIT_TIMEOUT_SECONDS" \
            "$git_bin" -C "$repo_root" diff --quiet --no-ext-diff --; then
        echo 'capture source checkout is not clean or Git timed out' >&2
        return 1
    fi
    if ! "$timeout_bin" --signal=TERM --kill-after=1s "$GIT_TIMEOUT_SECONDS" \
            "$git_bin" -C "$repo_root" diff --cached --quiet --no-ext-diff --; then
        echo 'capture source checkout is not clean or Git timed out' >&2
        return 1
    fi
    local untracked
    if ! untracked=$("$timeout_bin" --signal=TERM --kill-after=1s \
            "$GIT_TIMEOUT_SECONDS" "$BASH" -c '
                "$1" -C "$2" ls-files --others --exclude-standard \
                    -- ":/*" | head -c 1
                status=${PIPESTATUS[0]}
                (( status == 0 || status == 141 ))
            ' capture-untracked "$git_bin" "$repo_root"); then
        echo 'capture source untracked-file check failed or timed out' >&2
        return 1
    fi
    if [[ -n $untracked ]]; then
        echo 'capture source checkout is not clean' >&2
        return 1
    fi
}

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

readonly output_dir_input=$1
readonly node_bin_input=$2
readonly run_count=${3:-$DEFAULT_RUNS}
readonly idle_ms=${4:-$DEFAULT_IDLE_MS}
readonly chrome_launcher_input=${YUME_CHROME_LAUNCHER:-$DEFAULT_CHROME_LAUNCHER}
readonly chrome_binary_input=${YUME_CHROME_BINARY:-$DEFAULT_CHROME_BINARY}
readonly capture_tls_wire=${YUME_CAPTURE_TLS_WIRE:-0}
readonly capture_tls_cert_input=${YUME_CAPTURE_TLS_CERT:-}
readonly capture_tls_key_input=${YUME_CAPTURE_TLS_KEY:-}
readonly capture_sni=${YUME_CAPTURE_SNI:-localhost}
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
if (( EUID == 0 )); then
    echo 'normal Chrome capture must run as an unprivileged user' >&2
    exit 1
fi
if [[ $capture_tls_wire != 0 && $capture_tls_wire != 1 ]]; then
    echo 'YUME_CAPTURE_TLS_WIRE must be 0 or 1' >&2
    exit 2
fi
if [[ -n $capture_tls_cert_input && -z $capture_tls_key_input ]] ||
   [[ -z $capture_tls_cert_input && -n $capture_tls_key_input ]]; then
    echo 'YUME_CAPTURE_TLS_CERT and YUME_CAPTURE_TLS_KEY must be set together' >&2
    exit 2
fi
if [[ ! $capture_sni =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; then
    echo 'YUME_CAPTURE_SNI must be a non-empty DNS name' >&2
    exit 2
fi
unshare_bin=$(command -v unshare || true)
timeout_bin=$(command -v timeout || true)
git_bin=$(command -v git || true)
readonly unshare_bin timeout_bin git_bin
for executable in "$timeout_bin" "$git_bin" \
    "$node_bin_input" "$chrome_launcher_input" "$chrome_binary_input" "$unshare_bin"; do
    if [[ ! -x $executable ]]; then
        echo "required executable is missing: $executable" >&2
        exit 1
    fi
done

# Capture runs must have no network egress. Chrome will not service a navigation
# until its own startup service calls finish, and those block the browser's
# network pipeline for about ten seconds at a time; the driver's bounded CDP
# deadline expires first. Any capture taken with egress also records real
# Chrome-to-Google TLS connections that the fixture workload never produced.
# Failing closed here is deliberate: a contaminated capture is worse than none.
require_isolated_network() {
    local interfaces
    interfaces=$(ip -o link show | awk -F': ' '{print $2}')
    if [[ $interfaces != 'lo' ]] || [[ -n $(ip route show default) ]]; then
        cat >&2 <<'ISOLATION'
capture requires the loopback-only network namespace

  sudo scripts/yume_capture_netns.sh setup
  sudo scripts/yume_capture_netns.sh exec -- <this command>

Only namespace creation needs privilege; the capture itself runs as the
invoking user so Chrome keeps its user-namespace sandbox.
ISOLATION
        return 1
    fi
}

node_bin=$(realpath -e -- "$node_bin_input")
chrome_launcher=$(realpath -e -- "$chrome_launcher_input")
chrome_binary=$(realpath -e -- "$chrome_binary_input")
readonly node_bin chrome_launcher chrome_binary
chrome_launcher_sha256=$(sha256sum -- "$chrome_launcher" | awk '{print $1}')
chrome_sha256=$(sha256sum -- "$chrome_binary" | awk '{print $1}')
node_sha256=$(sha256sum -- "$node_bin" | awk '{print $1}')
readonly chrome_launcher_sha256 chrome_sha256 node_sha256
if [[ $chrome_launcher_sha256 != "$EXPECTED_CHROME_LAUNCHER_SHA256" ]]; then
    echo "Chrome launcher SHA-256 mismatch: got '$chrome_launcher_sha256'" >&2
    exit 1
fi
if [[ $chrome_sha256 != "$EXPECTED_CHROME_BINARY_SHA256" ]]; then
    echo "Chrome binary SHA-256 mismatch: got '$chrome_sha256'" >&2
    exit 1
fi
if [[ $(realpath -e -- "$(dirname -- "$chrome_launcher")/chrome") != \
      $(realpath -e -- "$chrome_binary") ]]; then
    echo 'Chrome launcher and binary must be adjacent in the same installation' >&2
    exit 1
fi
if [[ $node_sha256 != "$EXPECTED_NODE_BINARY_SHA256" ]]; then
    echo "Node binary SHA-256 mismatch: got '$node_sha256'" >&2
    exit 1
fi
chrome_version=$(
    "$chrome_launcher" --version | sed -e 's/[[:space:]]*$//'
)
node_version=$("$node_bin" --version | sed -e 's/[[:space:]]*$//')
readonly chrome_version node_version
if [[ $chrome_version != "$EXPECTED_CHROME_VERSION" ]]; then
    echo "Chrome version mismatch: got '$chrome_version'" >&2
    exit 1
fi
if [[ $node_version != "$EXPECTED_NODE_VERSION" ]]; then
    echo "Node version mismatch: got '$node_version'" >&2
    exit 1
fi
if ! "$unshare_bin" --user --map-root-user true; then
    echo 'Chrome user-namespace sandbox is unavailable' >&2
    exit 1
fi
source_commit=$(git_identity 'HEAD^{commit}')
source_tree=$(git_identity 'HEAD^{tree}')
readonly source_commit source_tree
if ! require_clean_source; then
    exit 1
fi
if [[ -e $output_dir_input ]]; then
    echo "output path already exists: $output_dir_input" >&2
    exit 1
fi

output_leaf=$(basename -- "$output_dir_input")
if [[ $output_leaf == '.' || $output_leaf == '..' ]]; then
    echo "output path must name a fresh child directory: $output_dir_input" >&2
    exit 1
fi
output_parent=$(realpath -e -- "$(dirname -- "$output_dir_input")")
readonly output_leaf output_parent
readonly output_dir="$output_parent/$output_leaf"
if [[ -e $output_dir ]]; then
    echo "resolved output path already exists: $output_dir" >&2
    exit 1
fi
case "$output_dir/" in
    "$repo_root/"*)
        echo 'capture output must be outside the source checkout' >&2
        exit 1
        ;;
esac
git_ancestor=$output_parent
while :; do
    if [[ -e $git_ancestor/.git || -L $git_ancestor/.git ]]; then
        echo 'capture output must be outside every Git worktree' >&2
        exit 1
    fi
    [[ $git_ancestor == / ]] && break
    git_ancestor=$(dirname -- "$git_ancestor")
done

mkdir -m 0700 -- "$output_dir"
readonly runtime_root="$output_dir/runtime-source"
runtime_sources=(
    tools/cover-node/server.mjs
    tools/cover-node/workload.mjs
    tools/cover-node/workload-v1.json
    tools/cover-node/capture_chrome.mjs
    tools/cover-node/sanitize_netlog.mjs
    tools/cover-node/capture_yume151_runs.sh
    scripts/yume_capture_binary_provenance.py
    scripts/yume_capture_manifest.py
    scripts/yume_capture_finalize.py
    scripts/release_preflight.py
    scripts/generate_transport_profiles.py
    scripts/yume_dependencies.py
    scripts/yume_bench_common.py
    scripts/yume_bench_resources.py
    scripts/yume_tls_wire.py
    tests/fixtures/chrome151-node24/manifest.json
)
mkdir -m 0700 -- "$runtime_root"
for relative in "${runtime_sources[@]}"; do
    install -D -m 0400 -- "$repo_root/$relative" "$runtime_root/$relative"
done
(
    cd -- "$runtime_root"
    sha256sum -- "${runtime_sources[@]}" >SHA256SUMS
)
chmod 0400 -- "$runtime_root/SHA256SUMS"
if [[ -n $capture_tls_cert_input ]]; then
    capture_tls_cert=$(realpath -e -- "$capture_tls_cert_input")
    capture_tls_key=$(realpath -e -- "$capture_tls_key_input")
    readonly capture_tls_cert capture_tls_key
    if [[ ! -f $capture_tls_cert || ! -r $capture_tls_cert ||
          ! -f $capture_tls_key || ! -r $capture_tls_key ]]; then
        echo 'supplied TLS certificate and key must be readable regular files' >&2
        exit 1
    fi
    key_mode=$(stat -c '%a' -- "$capture_tls_key")
    readonly key_mode
    if (( (8#$key_mode & 077) != 0 )); then
        echo 'supplied TLS private key must not be group/world accessible' >&2
        exit 1
    fi
    if ! openssl x509 -in "$capture_tls_cert" -noout \
            -checkhost "$capture_sni" >/dev/null 2>&1; then
        echo 'supplied TLS certificate does not cover YUME_CAPTURE_SNI' >&2
        exit 1
    fi
    cp --no-preserve=mode,ownership,timestamps -- \
        "$capture_tls_cert" "$output_dir/server.crt"
    chmod 0600 -- "$output_dir/server.crt"
    server_key=$capture_tls_key
else
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$output_dir/server.key" -out "$output_dir/server.crt" \
        -days 1 -nodes -subj "/CN=$capture_sni" \
        -addext "subjectAltName=DNS:$capture_sni,IP:127.0.0.1" >/dev/null 2>&1
    chmod 0600 -- "$output_dir/server.key" "$output_dir/server.crt"
    server_key="$output_dir/server.key"
fi
readonly server_key
certificate_sha256=$(sha256sum -- "$output_dir/server.crt" | awk '{print $1}')
server_key_sha256=$(sha256sum -- "$server_key" | awk '{print $1}')
readonly certificate_sha256 server_key_sha256

python3 "$runtime_root/scripts/yume_capture_manifest.py" \
    --output "$output_dir/environment.json" \
    --arm normal \
    --repo "$repo_root" \
    --certificate "$output_dir/server.crt" \
    --sni "$capture_sni" \
    --runs "$run_count" \
    --idle-ms "$idle_ms" \
    --chrome-version "$chrome_version" \
    --chrome-launcher "$chrome_launcher" \
    --chrome-launcher-sha256 "$chrome_launcher_sha256" \
    --chrome-binary "$chrome_binary" \
    --chrome-binary-sha256 "$chrome_sha256" \
    --chrome-sandbox user-namespace \
    --node-version "$node_version" \
    --node-binary-sha256 "$node_sha256" \
    --display "$DISPLAY" \
    --tls-wire-evidence "$capture_tls_wire"

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

if ! require_isolated_network; then
    exit 1
fi

readonly cover_port=39443
readonly cover_backend_port=39444
readonly devtools_port=39222
if ss -ltn | rg -q ":(${cover_port}|${cover_backend_port}|${devtools_port})\\b"; then
    echo 'capture ports 39443, 39444, or 39222 are already in use' >&2
    exit 1
fi

wait_for_loopback_listener() {
    local port=$1
    local pid=$2
    for _ in $(seq 1 100); do
        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi
        if ss -H -ltn "src 127.0.0.1 and sport = :$port" | rg -q .; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

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
    YUME_COVER_TLS_KEY="$server_key" \
    YUME_COVER_TLS_CERT="$output_dir/server.crt" \
        "$node_bin" "$runtime_root/tools/cover-node/server.mjs" \
        >"$run_dir/node.log" 2>&1 &
    node_pid=$!
    if ! wait_for_loopback_listener "$node_port" "$node_pid"; then
        sed -n '1,160p' "$run_dir/node.log" >&2
        echo "$run_name: Node cover did not become ready" >&2
        exit 1
    fi

    if [[ $capture_tls_wire == 1 ]]; then
        python3 "$runtime_root/scripts/yume_tls_wire.py" relay \
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
        --disable-setuid-sandbox \
        --no-first-run \
        --disable-background-networking \
        --disable-component-update \
        --disable-sync \
        --disable-quic \
        --ignore-certificate-errors \
        --host-resolver-rules="MAP $capture_sni 127.0.0.1, EXCLUDE localhost" \
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

    "$node_bin" "$runtime_root/tools/cover-node/capture_chrome.mjs" \
        "$devtools_port" "https://$capture_sni:$cover_port/" "$idle_ms"
    if ! wait "$chrome_pid"; then
        echo "$run_name: Chrome exited unsuccessfully" >&2
        exit 1
    fi
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
    "$node_bin" "$runtime_root/tools/cover-node/sanitize_netlog.mjs" \
        "$run_dir/netlog.json" "$capture_sni:$cover_port" \
        >"$run_dir/sanitized.json"
    (
        cd -- "$run_dir"
        checksum_files=(netlog.json sanitized.json)
        if [[ -f tls-wire.json ]]; then
            checksum_files+=(tls-wire.json)
        fi
        sha256sum -- "${checksum_files[@]}" >SHA256SUMS
    )
    rm -rf -- "$run_dir/profile"
    echo "$run_name: complete"
done

final_chrome_launcher_sha256=$(sha256sum -- "$chrome_launcher" | awk '{print $1}')
final_chrome_sha256=$(sha256sum -- "$chrome_binary" | awk '{print $1}')
final_node_sha256=$(sha256sum -- "$node_bin" | awk '{print $1}')
final_certificate_sha256=$(sha256sum -- "$output_dir/server.crt" | awk '{print $1}')
final_server_key_sha256=$(sha256sum -- "$server_key" | awk '{print $1}')
final_source_commit=$(git_identity 'HEAD^{commit}')
final_source_tree=$(git_identity 'HEAD^{tree}')
readonly final_chrome_launcher_sha256 final_chrome_sha256 final_node_sha256
readonly final_certificate_sha256 final_server_key_sha256
readonly final_source_commit final_source_tree
if [[ $final_chrome_launcher_sha256 != "$chrome_launcher_sha256" ||
      $final_chrome_sha256 != "$chrome_sha256" ||
      $final_node_sha256 != "$node_sha256" ]]; then
    echo 'Chrome or Node executable changed during capture' >&2
    exit 1
fi
if [[ $final_certificate_sha256 != "$certificate_sha256" ||
      $final_server_key_sha256 != "$server_key_sha256" ]]; then
    echo 'TLS certificate or private key changed during capture' >&2
    exit 1
fi
if [[ $final_source_commit != "$source_commit" ||
      $final_source_tree != "$source_tree" ]] || ! require_clean_source; then
    echo 'capture source checkout changed during capture' >&2
    exit 1
fi
if ! (
    cd -- "$runtime_root"
    sha256sum --check --strict SHA256SUMS >/dev/null
); then
    echo 'capture runtime-source snapshot changed during capture' >&2
    exit 1
fi
(
    cd -- "$output_dir"
    top_level_checksums=(
        environment.json
        server.crt
        runtime-source/SHA256SUMS
    )
    for run_index in $(seq 1 "$run_count"); do
        top_level_checksums+=("$(printf 'run-%02d' "$run_index")/SHA256SUMS")
    done
    sha256sum -- "${top_level_checksums[@]}" >SHA256SUMS
)
python3 "$runtime_root/scripts/yume_capture_finalize.py" --root "$output_dir"

echo "Chrome 151 evidence captured in $output_dir"
