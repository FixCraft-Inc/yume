#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(
  sed -nE 's/.*kVersion\[\] = "([^"]+)".*/\1/p' "${repo_root}/src/core/version.hpp" | head -n1
)"

if [[ -z "${version}" ]]; then
  echo "failed to read YUME version from src/core/version.hpp" >&2
  exit 1
fi

out="${repo_root}/../yume_${version}.orig.tar.xz"
prefix="yume-${version}"

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  if git -C "${repo_root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    SOURCE_DATE_EPOCH="$(git -C "${repo_root}" log -1 --format=%ct)"
  else
    SOURCE_DATE_EPOCH="$(date +%s)"
  fi
fi

cd "${repo_root}"

find . -mindepth 1 \
  \( -path './.git' \
     -o -path './.claude' \
     -o -path './.codex' \
     -o -path './.wrangler' \
     -o -path './basefwx' \
     -o -path './build' \
     -o -path './build-*' \
     -o -path './debian' \
     -o -path './DEV_services' \
     -o -path './obj-*' \
     -o -path './.private' \
     -o -path './third_party' \
     -o -path './vendor' \
     -o -path './website/.jekyll-cache' \
     -o -path './scripts/__pycache__' \) -prune \
  -o \( -name '*.pyc' \
        -o -name '*.log' \
        -o -name '*.trace' \
        -o -name '*.out' \
        -o -name '*.tar.xz' \
        -o -name '.DS_Store' \) -prune \
  -o -print0 \
  | LC_ALL=C sort -z \
  | tar --null --no-recursion --files-from - \
        --transform "s#^\\./#${prefix}/#" \
        --sort=name \
        --owner=0 --group=0 --numeric-owner \
        --mtime="@${SOURCE_DATE_EPOCH}" \
        -cJf "${out}"

echo "${out}"
