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
readonly DEFAULT_RUNS=5
readonly CAPTURE_IDLE_MS=42000
# The kit's client dials the relay on 127.0.0.1, which forwards to yumed on
# 127.0.0.2. Both use one port, because admission requires the :authority
# port to be the listener's.
readonly CAPTURE_PORT=39445
readonly SERVER_ADDRESS=127.0.0.2
readonly ECHO_PORT=39447
readonly SOCKS_PORT=39448
readonly GIT_TIMEOUT_SECONDS=10
readonly RUN_TIMEOUT_SECONDS=180
readonly KILL_AFTER_SECONDS=5
readonly LOG_BLOCKS=16384

usage() {
    cat <<'EOF'
usage: capture_yume151_runs.sh OUTPUT YUME YUMED RELEASE_BUNDLE KIT SNI CHROME_LAUNCHER CHROME_BINARY NODE_BINARY [RUNS]

Captures the live native YUME carrier through a per-run unprivileged TLS wire
relay while scripts/yume_carrier_workload.py drives the frozen cover-page
workload through yume's SOCKS5 port. KIT is a yume-setup kit for SNI that
`yume_carrier_workload.py configure-kit --port 39445` prepared. The browser arm must use the kit's server-tls.pem and
server-tls.key.pem as its capture certificate and key. OUTPUT must be a fresh
path outside every Git worktree. The kit's secret files stay where they are
and never enter the evidence bundle.
EOF
}

if [[ $# -lt 9 || $# -gt 10 ]]
then
    usage >&2
    exit 2
fi
if (( EUID == 0 ))
then
    echo 'YUME evidence capture must run as an unprivileged user' >&2
    exit 1
fi

readonly output_input=$1
readonly yume_input=$2
readonly yumed_input=$3
readonly release_bundle_input=$4
readonly kit_input=$5
readonly capture_sni=$6
readonly chrome_launcher_input=$7
readonly chrome_binary_input=$8
readonly node_input=$9
readonly run_count=${10:-$DEFAULT_RUNS}
readonly repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)

if [[ ! $run_count =~ ^[1-9][0-9]*$ || $run_count -gt 20 ]]
then
    echo 'runs must be an integer in 1..20' >&2
    exit 2
fi
if [[ ! $capture_sni =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]
then
    echo 'SNI must be a non-empty DNS name' >&2
    exit 2
fi

timeout_bin=$(command -v timeout || true)
git_bin=$(command -v git || true)
unshare_bin=$(command -v unshare || true)
ss_bin=$(command -v ss || true)
readonly timeout_bin git_bin unshare_bin ss_bin
for executable in "$timeout_bin" "$git_bin" "$unshare_bin" "$ss_bin" \
        "$yume_input" "$yumed_input" "$chrome_launcher_input" \
        "$chrome_binary_input" "$node_input"
do
    if [[ ! -x $executable ]]
    then
        echo "required executable is missing: $executable" >&2
        exit 1
    fi
done

# Capture runs must have no network egress, as in the browser arm, so both
# arms see only the loopback session they describe.
require_isolated_network() {
    local interfaces
    interfaces=$(ip -o link show | awk -F': ' '{print $2}')
    if [[ $interfaces != 'lo' ]] || [[ -n $(ip route show default) ]]
    then
        cat >&2 <<'ISOLATION'
capture requires the loopback-only network namespace

  sudo scripts/yume_capture_netns.sh setup
  sudo scripts/yume_capture_netns.sh exec -- <this command>

Only namespace creation needs privilege. The capture itself runs as the
invoking user.
ISOLATION
        return 1
    fi
}

for non_symlink_input in "$yume_input" "$yumed_input" "$release_bundle_input" \
        "$kit_input"
do
    if [[ -L $non_symlink_input ]]
    then
        echo "capture input must not be a symlink: $non_symlink_input" >&2
        exit 1
    fi
done

yume_bin=$(realpath -e -- "$yume_input")
yumed_bin=$(realpath -e -- "$yumed_input")
release_bundle=$(realpath -e -- "$release_bundle_input")
kit=$(realpath -e -- "$kit_input")
chrome_launcher=$(realpath -e -- "$chrome_launcher_input")
chrome_binary=$(realpath -e -- "$chrome_binary_input")
node_bin=$(realpath -e -- "$node_input")
readonly yume_bin yumed_bin release_bundle kit chrome_launcher chrome_binary node_bin
readonly client_config="$kit/client/yume.json"
readonly server_config="$kit/server/yumed.json"
readonly certificate="$kit/server/credentials/server-tls.pem"
for regular in "$client_config" "$server_config" "$certificate" "$release_bundle"
do
    if [[ ! -f $regular || ! -r $regular || -L $regular ]]
    then
        echo "input must be a readable, non-symlink regular file: $regular" >&2
        exit 1
    fi
done

chrome_launcher_sha256=$(sha256sum -- "$chrome_launcher" | awk '{print $1}')
chrome_binary_sha256=$(sha256sum -- "$chrome_binary" | awk '{print $1}')
node_sha256=$(sha256sum -- "$node_bin" | awk '{print $1}')
readonly chrome_launcher_sha256 chrome_binary_sha256 node_sha256
if [[ $chrome_launcher_sha256 != "$EXPECTED_CHROME_LAUNCHER_SHA256" ]]
then
    echo "Chrome launcher SHA-256 mismatch: got '$chrome_launcher_sha256'" >&2
    exit 1
fi
if [[ $chrome_binary_sha256 != "$EXPECTED_CHROME_BINARY_SHA256" ]]
then
    echo "Chrome binary SHA-256 mismatch: got '$chrome_binary_sha256'" >&2
    exit 1
fi
if [[ $(realpath -e -- "$(dirname -- "$chrome_launcher")/chrome") != "$chrome_binary" ]]
then
    echo 'Chrome launcher and binary are not one adjacent installation' >&2
    exit 1
fi
if [[ $node_sha256 != "$EXPECTED_NODE_BINARY_SHA256" ]]
then
    echo "Node binary SHA-256 mismatch: got '$node_sha256'" >&2
    exit 1
fi

chrome_version=$("$chrome_launcher" --version | sed -e 's/[[:space:]]*$//')
node_version=$("$node_bin" --version | sed -e 's/[[:space:]]*$//')
readonly chrome_version node_version
if [[ $chrome_version != "$EXPECTED_CHROME_VERSION" ]]
then
    echo "Chrome version mismatch: got '$chrome_version'" >&2
    exit 1
fi
if [[ $node_version != "$EXPECTED_NODE_VERSION" ]]
then
    echo "Node version mismatch: got '$node_version'" >&2
    exit 1
fi

if ! openssl x509 -in "$certificate" -noout -checkhost "$capture_sni" >/dev/null 2>&1
then
    echo 'the kit certificate does not cover the declared SNI' >&2
    exit 1
fi
if ! "$unshare_bin" --user --map-root-user true
then
    echo 'user-namespace sandbox support is unavailable' >&2
    exit 1
fi
for port in "$CAPTURE_PORT" "$ECHO_PORT" "$SOCKS_PORT"
do
    if "$ss_bin" -H -ltn "sport = :$port" | grep -q .
    then
        echo "capture port $port is already in use" >&2
        exit 1
    fi
done

git_identity() {
    "$timeout_bin" --signal=TERM --kill-after=1s "$GIT_TIMEOUT_SECONDS" \
        "$git_bin" -C "$repo_root" rev-parse --verify "$1"
}

require_clean_source() {
    if ! "$timeout_bin" --signal=TERM --kill-after=1s "$GIT_TIMEOUT_SECONDS" \
        "$git_bin" -C "$repo_root" diff --quiet --no-ext-diff --
    then
        return 1
    fi
    if ! "$timeout_bin" --signal=TERM --kill-after=1s "$GIT_TIMEOUT_SECONDS" \
        "$git_bin" -C "$repo_root" diff --cached --quiet --no-ext-diff --
    then
        return 1
    fi
    local untracked
    if ! untracked=$("$timeout_bin" --signal=TERM --kill-after=1s \
            "$GIT_TIMEOUT_SECONDS" "$BASH" -c '
                "$1" -C "$2" ls-files --others --exclude-standard \
                    -- ":/*" | head -c 1
                status=${PIPESTATUS[0]}
                (( status == 0 || status == 141 ))
            ' capture-untracked "$git_bin" "$repo_root")
    then
        return 1
    fi
    [[ -z $untracked ]]
}

source_commit=$(git_identity 'HEAD^{commit}')
source_tree=$(git_identity 'HEAD^{tree}')
yume_sha256=$(sha256sum -- "$yume_bin" | awk '{print $1}')
yumed_sha256=$(sha256sum -- "$yumed_bin" | awk '{print $1}')
release_bundle_sha256=$(sha256sum -- "$release_bundle" | awk '{print $1}')
client_config_sha256=$(sha256sum -- "$client_config" | awk '{print $1}')
server_config_sha256=$(sha256sum -- "$server_config" | awk '{print $1}')
certificate_sha256=$(sha256sum -- "$certificate" | awk '{print $1}')
tls_leaf_sha256=$(openssl x509 -in "$certificate" -outform DER |
    sha256sum | awk '{print $1}')
readonly source_commit source_tree yume_sha256 yumed_sha256
readonly release_bundle_sha256 client_config_sha256 server_config_sha256
readonly certificate_sha256 tls_leaf_sha256
if [[ ! $tls_leaf_sha256 =~ ^[0-9a-f]{64}$ ]]
then
    echo 'could not compute the certificate DER leaf SHA-256' >&2
    exit 1
fi
if ! require_clean_source
then
    echo 'capture source checkout is not clean' >&2
    exit 1
fi
if ! python3 "$repo_root/scripts/yume_capture_binary_provenance.py" \
        --bundle "$release_bundle" --yume "$yume_bin" --yumed "$yumed_bin" \
        --source-commit "$source_commit"
then
    echo 'the capture executables are not the exact release-bundle artifacts' >&2
    exit 1
fi

if [[ -e $output_input ]]
then
    echo "output path already exists: $output_input" >&2
    exit 1
fi
output_parent=$(realpath -e -- "$(dirname -- "$output_input")")
output_leaf=$(basename -- "$output_input")
readonly output_parent output_leaf
if [[ $output_leaf == '.' || $output_leaf == '..' ]]
then
    echo 'output path must name a fresh child directory' >&2
    exit 2
fi
readonly output_dir="$output_parent/$output_leaf"
if [[ $output_dir/ == "$repo_root/"* ]]
then
    echo 'capture output must be outside the source checkout' >&2
    exit 1
fi
git_ancestor=$output_parent
while :
do
    if [[ -e $git_ancestor/.git || -L $git_ancestor/.git ]]
    then
        echo 'capture output must be outside every Git worktree' >&2
        exit 1
    fi
    [[ $git_ancestor == / ]] && break
    git_ancestor=$(dirname -- "$git_ancestor")
done
mkdir -m 0700 -- "$output_dir"
install -m 0600 -- "$certificate" "$output_dir/server.crt"

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
    scripts/yume_carrier_workload.py
    scripts/yume_native_session.py
    scripts/release_preflight.py
    scripts/generate_transport_profiles.py
    scripts/yume_dependencies.py
    scripts/yume_bench_common.py
    scripts/yume_bench_resources.py
    scripts/yume_tls_wire.py
    tests/fixtures/chrome151-node24/manifest.json
)
mkdir -m 0700 -- "$runtime_root"
for relative in "${runtime_sources[@]}"
do
    install -D -m 0400 -- "$repo_root/$relative" "$runtime_root/$relative"
done
(
    cd -- "$runtime_root"
    sha256sum -- "${runtime_sources[@]}" >SHA256SUMS
)
chmod 0400 -- "$runtime_root/SHA256SUMS"

python3 "$runtime_root/scripts/yume_capture_manifest.py" \
    --output "$output_dir/environment.json" \
    --arm yume --repo "$repo_root" \
    --certificate "$output_dir/server.crt" --sni "$capture_sni" \
    --runs "$run_count" --idle-ms "$CAPTURE_IDLE_MS" \
    --chrome-version "$chrome_version" \
    --chrome-launcher "$chrome_launcher" \
    --chrome-launcher-sha256 "$chrome_launcher_sha256" \
    --chrome-binary "$chrome_binary" \
    --chrome-binary-sha256 "$chrome_binary_sha256" \
    --chrome-sandbox user-namespace \
    --node-version "$node_version" \
    --node-binary-sha256 "$node_sha256" \
    --display "${DISPLAY:-not-launched-in-yume-arm}" \
    --yume-binary-sha256 "$yume_sha256" \
    --yumed-binary-sha256 "$yumed_sha256" \
    --tls-backend openssl-chrome151 \
    --release-bundle-sha256 "$release_bundle_sha256" \
    --client-config-sha256 "$client_config_sha256" \
    --server-config-sha256 "$server_config_sha256" \
    --tls-leaf-sha256 "$tls_leaf_sha256" \
    --tls-wire-evidence 1

children=()
cleanup_children() {
    local pid
    for pid in "${children[@]}"
    do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    children=()
}
trap cleanup_children EXIT
trap 'exit 130' INT TERM

if ! require_isolated_network
then
    exit 1
fi

# Waits for a file a helper writes once it listens, while the helper lives.
wait_for_ready_file() {
    local path=$1
    local pid=$2
    for _ in $(seq 1 100)
    do
        if [[ -f $path ]]
        then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null
        then
            return 1
        fi
        sleep 0.05
    done
    return 1
}

wait_for_listener() {
    local address=$1
    local port=$2
    local pid=$3
    for _ in $(seq 1 200)
    do
        if ! kill -0 "$pid" 2>/dev/null
        then
            return 1
        fi
        if "$ss_bin" -H -ltn "src $address and sport = :$port" | grep -q .
        then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

# SIGTERM one process and require exit status 0.
stop_process() {
    local pid=$1
    local name=$2
    kill -TERM "$pid" 2>/dev/null || true
    local status=0
    wait "$pid" || status=$?
    if [[ $status != 0 ]]
    then
        echo "$name exited with status $status" >&2
        return 1
    fi
}

for run_index in $(seq 1 "$run_count")
do
    run_name=$(printf 'run-%02d' "$run_index")
    run_dir="$output_dir/$run_name"
    mkdir -m 0700 -- "$run_dir"
    children=()

    python3 "$runtime_root/scripts/yume_carrier_workload.py" echo \
        --listen "127.0.0.1:$ECHO_PORT" --ready-file "$run_dir/echo-ready.json" \
        --timeout "$RUN_TIMEOUT_SECONDS" >"$run_dir/echo.log" 2>&1 &
    echo_pid=$!
    children+=("$echo_pid")
    if ! wait_for_ready_file "$run_dir/echo-ready.json" "$echo_pid"
    then
        echo "$run_name: echo target did not become ready" >&2
        exit 1
    fi

    (
        ulimit -f "$LOG_BLOCKS"
        exec "$timeout_bin" --signal=TERM --kill-after="${KILL_AFTER_SECONDS}s" \
            "${RUN_TIMEOUT_SECONDS}s" "$yumed_bin" --config "$server_config"
    ) >"$run_dir/yumed.log" 2>&1 &
    yumed_pid=$!
    children+=("$yumed_pid")
    if ! wait_for_listener "$SERVER_ADDRESS" "$CAPTURE_PORT" "$yumed_pid"
    then
        echo "$run_name: yumed did not listen, see $run_dir/yumed.log" >&2
        exit 1
    fi

    python3 "$runtime_root/scripts/yume_tls_wire.py" relay \
        --listen "127.0.0.1:$CAPTURE_PORT" --target "$SERVER_ADDRESS:$CAPTURE_PORT" \
        --output "$run_dir/tls-wire.json" \
        --ready-file "$run_dir/tls-wire-ready.json" --timeout "$RUN_TIMEOUT_SECONDS" \
        >"$run_dir/tls-wire.log" 2>&1 &
    relay_pid=$!
    children+=("$relay_pid")
    if ! wait_for_ready_file "$run_dir/tls-wire-ready.json" "$relay_pid"
    then
        echo "$run_name: TLS relay did not become ready" >&2
        exit 1
    fi

    (
        ulimit -f "$LOG_BLOCKS"
        exec "$timeout_bin" --signal=TERM --kill-after="${KILL_AFTER_SECONDS}s" \
            "${RUN_TIMEOUT_SECONDS}s" "$yume_bin" --config "$client_config" \
            --connect 127.0.0.1 --socks-port "$SOCKS_PORT" \
            --outer-carrier-evidence "$run_dir/behavior.json"
    ) >"$run_dir/yume.log" 2>&1 &
    yume_pid=$!
    children+=("$yume_pid")
    if ! wait_for_listener 127.0.0.1 "$SOCKS_PORT" "$yume_pid"
    then
        echo "$run_name: yume did not listen, see $run_dir/yume.log" >&2
        exit 1
    fi

    if ! python3 "$runtime_root/scripts/yume_carrier_workload.py" drive \
            --socks "127.0.0.1:$SOCKS_PORT" --target "127.0.0.1:$ECHO_PORT" \
            --output "$run_dir/workload.json" >"$run_dir/workload.log" 2>&1
    then
        echo "$run_name: workload failed, see $run_dir/workload.log" >&2
        exit 1
    fi
    # yume exits 0 only when its evidence is complete: the WebSocket CLOSE
    # was echoed and the connection ended.
    if ! stop_process "$yume_pid" yume
    then
        echo "$run_name: see $run_dir/yume.log and behavior.json" >&2
        exit 1
    fi
    if ! wait "$relay_pid"
    then
        echo "$run_name: TLS wire relay failed" >&2
        exit 1
    fi
    if ! wait "$echo_pid"
    then
        echo "$run_name: echo target failed" >&2
        exit 1
    fi
    if ! stop_process "$yumed_pid" yumed
    then
        echo "$run_name: see $run_dir/yumed.log" >&2
        exit 1
    fi
    children=()
    rm -f -- "$run_dir/tls-wire-ready.json" "$run_dir/echo-ready.json"
    (
        cd -- "$run_dir"
        sha256sum -- behavior.json tls-wire.json workload.json >SHA256SUMS
    )
    echo "$run_name: complete"
done

if [[ $(git_identity 'HEAD^{commit}') != "$source_commit" ||
      $(git_identity 'HEAD^{tree}') != "$source_tree" ]] ||
   ! require_clean_source
then
    echo 'capture source checkout changed during capture' >&2
    exit 1
fi
for pair in "$yume_bin:$yume_sha256" "$yumed_bin:$yumed_sha256" \
        "$release_bundle:$release_bundle_sha256" \
        "$client_config:$client_config_sha256" \
        "$server_config:$server_config_sha256" \
        "$certificate:$certificate_sha256" \
        "$output_dir/server.crt:$certificate_sha256" \
        "$chrome_launcher:$chrome_launcher_sha256" \
        "$chrome_binary:$chrome_binary_sha256" "$node_bin:$node_sha256"
do
    if [[ $(sha256sum -- "${pair%:*}" | awk '{print $1}') != "${pair##*:}" ]]
    then
        echo "capture input changed during capture: ${pair%:*}" >&2
        exit 1
    fi
done
if ! (cd -- "$runtime_root" && sha256sum --check --strict SHA256SUMS >/dev/null)
then
    echo 'capture runtime-source snapshot changed during capture' >&2
    exit 1
fi
(
    cd -- "$output_dir"
    top=(environment.json server.crt runtime-source/SHA256SUMS)
    for run_index in $(seq 1 "$run_count")
    do
        top+=("$(printf 'run-%02d' "$run_index")/SHA256SUMS")
    done
    sha256sum -- "${top[@]}" >SHA256SUMS
)
python3 "$runtime_root/scripts/yume_capture_finalize.py" --root "$output_dir"
echo "YUME Chrome-151-profile evidence captured in $output_dir"
