#!/usr/bin/env bash
set -euo pipefail
# Entry point used by Pages, CI and the public contributor workflow.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${repo_root}/scripts/yume_docs.py" website --all-languages "$@"
