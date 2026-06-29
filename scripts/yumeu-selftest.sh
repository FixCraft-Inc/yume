#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
YUME_BIN="${YUME_BIN:-$ROOT_DIR/build/bin/yume}"
YUMED_BIN="${YUMED_BIN:-$ROOT_DIR/build/bin/yumed}"
SERVER_PORT="${YUMEU_PORT:-19443}"
SOCKS_PORT="${YUMEU_SOCKS_PORT:-19090}"
ARGON_MEM="${YUMEU_ARGON2_MEM:-32768}"
ARGON_PAR="${YUMEU_ARGON2_PAR:-2}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/yumeu-selftest.XXXXXX")"
SERVER_PID=""
CLIENT_PID=""
STATUS=0

cleanup() {
    STATUS=$?
    if [[ -n "$CLIENT_PID" ]] && kill -0 "$CLIENT_PID" 2>/dev/null; then
        kill "$CLIENT_PID" 2>/dev/null || true
        wait "$CLIENT_PID" 2>/dev/null || true
    fi
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [[ "$STATUS" -eq 0 ]]; then
        rm -rf "$TMP_DIR"
    else
        echo "selftest failed; logs kept in $TMP_DIR" >&2
    fi
}
trap cleanup EXIT

wait_for_log() {
    local file="$1"
    local pattern="$2"
    local deadline=$((SECONDS + 20))
    while (( SECONDS < deadline )); do
        if [[ -f "$file" ]] && grep -q "$pattern" "$file"; then
            return 0
        fi
        sleep 0.2
    done
    echo "timed out waiting for '$pattern' in $file" >&2
    return 1
}

wait_for_file() {
    local file="$1"
    local deadline=$((SECONDS + 20))
    while (( SECONDS < deadline )); do
        if [[ -s "$file" ]]; then
            return 0
        fi
        sleep 0.2
    done
    echo "timed out waiting for file $file" >&2
    return 1
}

if [[ ! -x "$YUME_BIN" || ! -x "$YUMED_BIN" ]]; then
    echo "missing yume/yumed binaries; build first or set YUME_BIN/YUMED_BIN" >&2
    exit 1
fi

openssl genpkey -algorithm ED25519 -out "$TMP_DIR/auth.key" >/dev/null 2>&1
openssl pkey -in "$TMP_DIR/auth.key" -pubout -out "$TMP_DIR/auth.pub" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TMP_DIR/tls.key" \
    -out "$TMP_DIR/tls.crt" \
    -days 1 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1

(
    cd "$TMP_DIR"
    YUME_ARGON2_MEM_MAX="$ARGON_MEM" \
    YUME_ARGON2_PAR_MAX="$ARGON_PAR" \
    "$YUMED_BIN" \
        --listen "$SERVER_PORT" \
        --real \
        --cert "$TMP_DIR/tls.crt" \
        --key "$TMP_DIR/tls.key" \
        --auth-keys "$TMP_DIR/auth.pub" \
        --obfs \
        --inner-dual \
        --inner-required \
        --hop \
        --pq-auto-generate
) >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

wait_for_log "$TMP_DIR/server.log" "yumed listening"
wait_for_file "$TMP_DIR/.secrets/pq_public.key"

mkdir -p "$TMP_DIR/home"
HOME="$TMP_DIR/home" \
YUME_ARGON2_MEM=262144 \
YUME_ARGON2_PAR=10 \
"$YUME_BIN" \
    --server localhost \
    --port "$SERVER_PORT" \
    --inner-heavy \
    --pq-pub "$TMP_DIR/.secrets/pq_public.key" \
    --tls-ca "$TMP_DIR/tls.crt" \
    --auth "$TMP_DIR/auth.key" \
    --socks "$SOCKS_PORT" \
    --hop \
    --obfs \
    --accept-monitoring \
    --non-interactive \
    >"$TMP_DIR/client.log" 2>&1 &
CLIENT_PID=$!

wait_for_log "$TMP_DIR/client.log" "server Argon2 caps"
wait_for_log "$TMP_DIR/client.log" "inner crypto prepared: mode=heavy"
wait_for_log "$TMP_DIR/client.log" "SOCKS5 listening"

if command -v curl >/dev/null 2>&1; then
    curl --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
        --max-time 12 \
        --silent \
        --show-error \
        http://example.com/ >/dev/null 2>"$TMP_DIR/curl.log" || true
fi

sleep 1

if grep -q "decrypt failed" "$TMP_DIR/server.log"; then
    echo "server logged inner decrypt failure" >&2
    exit 1
fi
if ! grep -q "mem=$ARGON_MEM" "$TMP_DIR/client.log"; then
    echo "client did not apply server Argon2 memory cap" >&2
    exit 1
fi
if ! grep -q "par=$ARGON_PAR" "$TMP_DIR/client.log"; then
    echo "client did not apply server Argon2 parallelism cap" >&2
    exit 1
fi

echo "yumeu selftest passed"
