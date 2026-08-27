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

# Debian sorts a development snapshot before its eventual stable release by
# spelling upstream's "-devN" suffix as "~devN".
archive_version="${version/-dev/~dev}"
out="${repo_root}/../yume_${archive_version}.orig.tar.xz"
prefix="yume-${archive_version}"

if [[ -e "${out}" || -L "${out}" ]]; then
  echo "refusing to overwrite existing source archive: ${out}" >&2
  exit 2
fi

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  if git -C "${repo_root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    SOURCE_DATE_EPOCH="$(git -C "${repo_root}" log -1 --format=%ct)"
  else
    SOURCE_DATE_EPOCH="$(date +%s)"
  fi
fi

cd "${repo_root}"

archive_path_is_public() {
  local path="${1#./}"
  local root="${path%%/*}"

  if [[ -z "${path}" || "${path}" == /* ||
        "${path}" == *$'\n'* || "${path}" == *$'\r'* ]]; then
    return 1
  fi

  case "${root}" in
    .agents|.cache|.claude|.codex|.private|.pytest_cache|.secrets|.wrangler|\
    basefwx|bins|debian|DEV_services|third_party|vendor|yume-bench-results|\
    yume-lan-kit|build|build-?*|obj-?*)
      return 1
      ;;
  esac
  case "${path}" in
    AGENTS.md|AI_NOTES.md|opencode.json|website/_site|website/_site/*|\
    *.log|*.trace|*.out|*.pyc|*.tar.xz)
      return 1
      ;;
  esac
  case "/${path}/" in
    */.git/*|*/.agents/*|*/.cache/*|*/.claude/*|*/.codex/*|\
    */.private/*|*/.pytest_cache/*|*/.secrets/*|*/.wrangler/*|\
    */.jekyll-cache/*|*/__pycache__/*|*/.DS_Store/*)
      return 1
      ;;
  esac
  return 0
}

emit_archive_path() {
  local path="${1#./}"
  if archive_path_is_public "${path}" &&
     [[ -e "${path}" || -L "${path}" ]]; then
    printf './%s\0' "${path}"
  fi
}

archive_paths() {
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    # Package the live candidate rather than every filesystem entry. This
    # includes intentional untracked source files. Repository and checkout
    # excludes still protect local overlays, while a developer-global ignore
    # must not silently remove public candidate files. The explicit public-path
    # filter remains authoritative for tracked and untracked overlays.
    git -c core.excludesFile=/dev/null \
      ls-files --cached --others --exclude-standard -z -- . \
      | while IFS= read -r -d '' path; do
          emit_archive_path "${path}"
        done
    return
  fi

  # A repacked source tree may not carry .git. Retain an explicit fallback
  # with the same local/private/generated boundary.
  find . -mindepth 1 \
    \( -path './.git' \
       -o -path './.agents' \
       -o -path './.cache' \
       -o -path './.claude' \
       -o -path './.codex' \
       -o -path './.private' \
       -o -path './.pytest_cache' \
       -o -path './.secrets' \
       -o -path './.wrangler' \
       -o -path './AGENTS.md' \
       -o -path './AI_NOTES.md' \
       -o -path './opencode.json' \
       -o -path './basefwx' \
       -o -path './bins' \
       -o -path './build' \
       -o -path './build-*' \
       -o -path './debian' \
       -o -path './DEV_services' \
       -o -path './obj-*' \
       -o -path './third_party' \
       -o -path './vendor' \
       -o -path './yume-bench-results' \
       -o -path './yume-lan-kit' \
       -o -path './website/.jekyll-cache' \
       -o -path './website/_site' \
       -o -path './scripts/__pycache__' \) -prune \
    -o \( -name '*.pyc' \
          -o -name '*.log' \
          -o -name '*.trace' \
          -o -name '*.out' \
          -o -name '*.tar.xz' \
          -o -name '.DS_Store' \) -prune \
    -o -print0 \
    | while IFS= read -r -d '' path; do
        # Root pruning keeps large local trees cheap to skip. This second
        # filter also catches nested private/secret/cache directories.
        emit_archive_path "${path}"
      done
}

archive_tmp=""
listing=""
cleanup_temporary_files() {
  if [[ -n "${archive_tmp}" ]]; then
    rm -f -- "${archive_tmp}"
  fi
  if [[ -n "${listing}" ]]; then
    rm -f -- "${listing}"
  fi
}
trap cleanup_temporary_files EXIT
archive_tmp="$(mktemp "${out}.tmp.XXXXXX")"

if ! archive_paths \
    | LC_ALL=C sort -z \
    | tar --null --no-recursion --files-from - \
          --transform "s#^\\./#${prefix}/#" \
          --sort=name \
          --owner=0 --group=0 --numeric-owner \
          --mtime="@${SOURCE_DATE_EPOCH}" \
          -cJf "${archive_tmp}"; then
  exit 3
fi

# Creation itself is fail closed. The Debian wrapper repeats this validation,
# but calling this helper directly must never publish an archive that violates
# the same private/generated path boundary.
# Keep validation scratch space outside the repository even when TMPDIR points
# into it, so concurrent archive creators cannot enumerate one another's files.
listing="$(mktemp "${out}.listing.XXXXXX")"
if ! tar -tf "${archive_tmp}" >"${listing}" ||
   ! python3 "${repo_root}/scripts/check_source_archive_listing.py" \
       --listing "${listing}" --prefix "${prefix}"; then
  exit 4
fi

# Publish only a complete, validated archive. The same-directory hard link is
# atomic and refuses a concurrent creator instead of replacing its output.
chmod 0644 "${archive_tmp}"
if ! ln -T -- "${archive_tmp}" "${out}"; then
  echo "failed to publish source archive without overwriting: ${out}" >&2
  exit 5
fi
rm -f -- "${archive_tmp}"

echo "${out}"
