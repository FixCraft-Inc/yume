#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
YUME_BIN="${YUME_BIN:-$ROOT_DIR/build/bin/yume}"

if [[ ! -x "$YUME_BIN" ]]; then
    echo "missing yume binary: $YUME_BIN" >&2
    echo "build with ./ezbuild.sh --selftest --tests first" >&2
    exit 1
fi

exec "$YUME_BIN" --quick-bench "$@"
