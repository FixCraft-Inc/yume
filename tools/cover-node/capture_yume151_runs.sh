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
readonly EXPECTED_HELPER_SHA256='f0e2cf15f9f0f1984cf7b105ce6837537074d8b8b3d84343b37d47a9ec84f269'
readonly DEFAULT_RUNS=5
readonly CAPTURE_IDLE_MS=42000
readonly RELAY_PORT=39445
readonly GIT_TIMEOUT_SECONDS=10

usage() {
    cat <<'EOF'
usage: capture_yume151_runs.sh OUTPUT YUME RELEASE_BUNDLE CLIENT_CONFIG CERTIFICATE SNI TARGET CHROME_LAUNCHER CHROME_BINARY NODE_BINARY [RUNS]

Captures the live production YUME carrier through a per-run unprivileged TLS
wire relay. TARGET uses HOST:PORT syntax accepted by yume_tls_wire.py. OUTPUT
must be a fresh path outside the source checkout. CLIENT_CONFIG and its secret
files remain external and are never copied into the evidence bundle.
EOF
}

if [[ $# -lt 10 || $# -gt 11 ]]; then
    usage >&2
    exit 2
fi
if (( EUID == 0 )); then
    echo 'YUME evidence capture must run as an unprivileged user' >&2
    exit 1
fi

readonly output_input=$1
readonly yume_input=$2
readonly release_bundle_input=$3
readonly config_input=$4
readonly certificate_input=$5
readonly capture_sni=$6
readonly target_endpoint=$7
readonly chrome_launcher_input=$8
readonly chrome_binary_input=$9
readonly node_input=${10}
readonly run_count=${11:-$DEFAULT_RUNS}
readonly repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)

if [[ ! $run_count =~ ^[1-9][0-9]*$ || $run_count -gt 20 ]]; then
    echo 'runs must be an integer in 1..20' >&2
    exit 2
fi
if [[ ! $capture_sni =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; then
    echo 'SNI must be a non-empty DNS name' >&2
    exit 2
fi

timeout_bin=$(command -v timeout || true)
git_bin=$(command -v git || true)
unshare_bin=$(command -v unshare || true)
ss_bin=$(command -v ss || true)
rg_bin=$(command -v rg || true)
readonly timeout_bin git_bin unshare_bin ss_bin rg_bin
for executable in "$timeout_bin" "$git_bin" "$unshare_bin" "$ss_bin" \
        "$rg_bin" "$yume_input" "$chrome_launcher_input" "$chrome_binary_input" \
        "$node_input"; do
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

yume_bin=$(realpath -e -- "$yume_input")
client_config=$(realpath -e -- "$config_input")
certificate=$(realpath -e -- "$certificate_input")
release_bundle=$(realpath -e -- "$release_bundle_input")
chrome_launcher=$(realpath -e -- "$chrome_launcher_input")
chrome_binary=$(realpath -e -- "$chrome_binary_input")
node_bin=$(realpath -e -- "$node_input")
helper_bin=$(realpath -e -- "$(dirname -- "$yume_bin")/yume-chrome-tls-helper")
readonly yume_bin client_config certificate release_bundle chrome_launcher chrome_binary
readonly node_bin helper_bin
if [[ ! -x $helper_bin ]]; then
    echo "required executable is missing: $helper_bin" >&2
    exit 1
fi
for regular in "$client_config" "$certificate" "$release_bundle"; do
    if [[ ! -f $regular || ! -r $regular || -L $regular ]]; then
        echo "input must be a readable, non-symlink regular file: $regular" >&2
        exit 1
    fi
done

chrome_launcher_sha256=$(sha256sum -- "$chrome_launcher" | awk '{print $1}')
chrome_binary_sha256=$(sha256sum -- "$chrome_binary" | awk '{print $1}')
node_sha256=$(sha256sum -- "$node_bin" | awk '{print $1}')
readonly chrome_launcher_sha256 chrome_binary_sha256 node_sha256
if [[ $chrome_launcher_sha256 != "$EXPECTED_CHROME_LAUNCHER_SHA256" ]]; then
    echo "Chrome launcher SHA-256 mismatch: got '$chrome_launcher_sha256'" >&2
    exit 1
fi
if [[ $chrome_binary_sha256 != "$EXPECTED_CHROME_BINARY_SHA256" ]]; then
    echo "Chrome binary SHA-256 mismatch: got '$chrome_binary_sha256'" >&2
    exit 1
fi
if [[ $(realpath -e -- "$(dirname -- "$chrome_launcher")/chrome") != \
      "$chrome_binary" ]]; then
    echo 'Chrome launcher and binary are not one adjacent installation' >&2
    exit 1
fi
if [[ $node_sha256 != "$EXPECTED_NODE_BINARY_SHA256" ]]; then
    echo "Node binary SHA-256 mismatch: got '$node_sha256'" >&2
    exit 1
fi

chrome_version=$("$chrome_launcher" --version | sed -e 's/[[:space:]]*$//')
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

if ! openssl x509 -in "$certificate" -noout \
        -checkhost "$capture_sni" >/dev/null 2>&1; then
    echo 'certificate does not cover the declared SNI' >&2
    exit 1
fi
if ! "$unshare_bin" --user --map-root-user true; then
    echo 'user-namespace sandbox support is unavailable' >&2
    exit 1
fi
if "$ss_bin" -ltn | rg -q ":${RELAY_PORT}\\b"; then
    echo "capture relay port ${RELAY_PORT} is already in use" >&2
    exit 1
fi

git_identity() {
    "$timeout_bin" --signal=TERM --kill-after=1s "$GIT_TIMEOUT_SECONDS" \
        "$git_bin" -C "$repo_root" rev-parse --verify "$1"
}

require_clean_source() {
    if ! "$timeout_bin" --signal=TERM --kill-after=1s "$GIT_TIMEOUT_SECONDS" \
        "$git_bin" -C "$repo_root" diff --quiet --no-ext-diff -- &&
       "$timeout_bin" --signal=TERM --kill-after=1s "$GIT_TIMEOUT_SECONDS" \
        "$git_bin" -C "$repo_root" diff --cached --quiet --no-ext-diff --; then
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
        return 1
    fi
    [[ -z $untracked ]]
}

source_commit=$(git_identity 'HEAD^{commit}')
source_tree=$(git_identity 'HEAD^{tree}')
yume_sha256=$(sha256sum -- "$yume_bin" | awk '{print $1}')
helper_sha256=$(sha256sum -- "$helper_bin" | awk '{print $1}')
release_bundle_sha256=$(sha256sum -- "$release_bundle" | awk '{print $1}')
config_sha256=$(sha256sum -- "$client_config" | awk '{print $1}')
certificate_sha256=$(sha256sum -- "$certificate" | awk '{print $1}')
tls_leaf_sha256=$(openssl x509 -in "$certificate" -outform DER |
    sha256sum | awk '{print $1}')
readonly source_commit source_tree yume_sha256 helper_sha256 release_bundle_sha256
readonly config_sha256
readonly certificate_sha256 tls_leaf_sha256
if [[ ! $tls_leaf_sha256 =~ ^[0-9a-f]{64}$ ]]; then
    echo 'could not compute the certificate DER leaf SHA-256' >&2
    exit 1
fi
if [[ $helper_sha256 != "$EXPECTED_HELPER_SHA256" ]]; then
    echo 'YUME helper SHA-256 does not match this exact source checkpoint' >&2
    exit 1
fi
if ! require_clean_source; then
    echo 'capture source checkout is not clean' >&2
    exit 1
fi
if ! python3 "$repo_root/scripts/yume_capture_binary_provenance.py" \
        --bundle "$release_bundle" --yume "$yume_bin" \
        --helper "$helper_bin" --source-commit "$source_commit"; then
    echo 'YUME capture executables are not exact release-bundle artifacts' >&2
    exit 1
fi

if [[ -e $output_input ]]; then
    echo "output path already exists: $output_input" >&2
    exit 1
fi
output_parent=$(realpath -e -- "$(dirname -- "$output_input")")
output_leaf=$(basename -- "$output_input")
readonly output_parent output_leaf
if [[ $output_leaf == '.' || $output_leaf == '..' ]]; then
    echo 'output path must name a fresh child directory' >&2
    exit 2
fi
readonly output_dir="$output_parent/$output_leaf"
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
    --yume-helper-sha256 "$helper_sha256" \
    --release-bundle-sha256 "$release_bundle_sha256" \
    --tls-leaf-sha256 "$tls_leaf_sha256" \
    --tls-wire-evidence 1

relay_pid=''
cleanup_relay() {
    if [[ -n $relay_pid ]]; then
        kill "$relay_pid" 2>/dev/null || true
        wait "$relay_pid" 2>/dev/null || true
        relay_pid=''
    fi
}
trap cleanup_relay EXIT
trap 'exit 130' INT TERM

if ! require_isolated_network; then
    exit 1
fi

for run_index in $(seq 1 "$run_count"); do
    run_name=$(printf 'run-%02d' "$run_index")
    run_dir="$output_dir/$run_name"
    mkdir -m 0700 -- "$run_dir"
    python3 "$runtime_root/scripts/yume_tls_wire.py" relay \
        --listen "127.0.0.1:${RELAY_PORT}" --target "$target_endpoint" \
        --output "$run_dir/tls-wire.json" \
        --ready-file "$run_dir/tls-wire-ready.json" --timeout 180 \
        >"$run_dir/tls-wire.log" 2>&1 &
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
        echo "$run_name: TLS relay did not become ready" >&2
        exit 1
    fi

    if ! "$yume_bin" \
        --config "$client_config" \
        --server 127.0.0.1 --port "$RELAY_PORT" \
        --tls-name "$capture_sni" --tls-ca "$output_dir/server.crt" \
        --tls-pin "$tls_leaf_sha256" --tls-helper "$helper_bin" \
        --bench --bench-mib 1 --bench-chunk-kib 16 \
        --bench-streams 1 --bench-direction both \
        --tunnels 1 --obfs \
        --transport-profile chrome151-node24-v1 \
        --tls-backend chrome151 \
        --outer-carrier-evidence "$run_dir/behavior.json" \
        >"$run_dir/yume.log" 2>&1; then
        echo "$run_name: YUME capture failed; inspect $run_dir/yume.log" >&2
        exit 1
    fi
    if ! wait "$relay_pid"; then
        relay_pid=''
        echo "$run_name: TLS wire relay failed" >&2
        exit 1
    fi
    relay_pid=''
    rm -f -- "$run_dir/tls-wire-ready.json"
    (
        cd -- "$run_dir"
        sha256sum -- behavior.json tls-wire.json >SHA256SUMS
    )
    echo "$run_name: complete"
done

if [[ $(git_identity 'HEAD^{commit}') != "$source_commit" ||
      $(git_identity 'HEAD^{tree}') != "$source_tree" ]] ||
   ! require_clean_source; then
    echo 'capture source checkout changed during capture' >&2
    exit 1
fi
if [[ $(sha256sum -- "$yume_bin" | awk '{print $1}') != "$yume_sha256" ||
      $(sha256sum -- "$helper_bin" | awk '{print $1}') != "$helper_sha256" ||
      $(sha256sum -- "$release_bundle" | awk '{print $1}') != "$release_bundle_sha256" ||
      $(sha256sum -- "$client_config" | awk '{print $1}') != "$config_sha256" ||
      $(sha256sum -- "$certificate" | awk '{print $1}') != "$certificate_sha256" ||
      $(sha256sum -- "$output_dir/server.crt" | awk '{print $1}') != "$certificate_sha256" ]]; then
    echo 'capture executable, config, or certificate changed during capture' >&2
    exit 1
fi
if ! (cd -- "$runtime_root" &&
      sha256sum --check --strict SHA256SUMS >/dev/null); then
    echo 'capture runtime-source snapshot changed during capture' >&2
    exit 1
fi
(
    cd -- "$output_dir"
    top=(environment.json server.crt runtime-source/SHA256SUMS)
    for run_index in $(seq 1 "$run_count"); do
        top+=("$(printf 'run-%02d' "$run_index")/SHA256SUMS")
    done
    sha256sum -- "${top[@]}" >SHA256SUMS
)
python3 "$runtime_root/scripts/yume_capture_finalize.py" --root "$output_dir"
echo "YUME Chrome-151-profile evidence captured in $output_dir"
