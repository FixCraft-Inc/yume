#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
# Regenerate ASCII pipeline diagrams from docs/diagrams/*.spec.
# Usage: scripts/regen_diagrams.sh [spec ...]
# With no args, renders every .spec in docs/diagrams/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DRAW="$ROOT/scripts/draw_pipeline.py"
SPEC_DIR="$ROOT/docs/diagrams"

if [[ ! -x "$DRAW" && -f "$DRAW" ]]; then
  :
fi

specs=("$@")
if [[ ${#specs[@]} -eq 0 ]]; then
  mapfile -t specs < <(find "$SPEC_DIR" -maxdepth 1 -name '*.spec' -print | sort)
fi

for spec in "${specs[@]}"; do
  echo "=== $(basename "$spec") ==="
  python3 "$DRAW" "$spec"
  echo
done
