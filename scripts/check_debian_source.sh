#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
upstream_version="$(
  sed -nE 's/.*kVersion\[\] = "([^"]+)".*/\1/p' "${repo_root}/src/core/version.hpp" | head -n1
)"
debian_version="$(cd "${repo_root}" && dpkg-parsechangelog -S Version)"

if [[ -z "${upstream_version}" || -z "${debian_version}" ]]; then
  echo "failed to read YUME/Debian version" >&2
  exit 1
fi

prefix="yume-${upstream_version}"
artifacts=(
  "${repo_root}/../yume_${upstream_version}.orig.tar.xz"
  "${repo_root}/../yume_${debian_version}.debian.tar.xz"
  "${repo_root}/../yume_${debian_version}.dsc"
)

for artifact in "${artifacts[@]}"; do
  if [[ -e "${artifact}" ]]; then
    echo "refusing to overwrite existing source-package artifact: ${artifact}" >&2
    exit 2
  fi
done

cleanup() {
  rm -f "${artifacts[@]}"
}
trap cleanup EXIT

bash -n "${repo_root}/scripts/make_debian_orig.sh"
orig="$("${repo_root}/scripts/make_debian_orig.sh")"
if [[ "${orig}" != "${artifacts[0]}" ]]; then
  echo "unexpected orig path: ${orig}" >&2
  exit 3
fi

listing="$(mktemp)"
trap 'rm -f "${listing}"; cleanup' EXIT
tar -tf "${orig}" >"${listing}"

required=(
  "${prefix}/CMakeLists.txt"
  "${prefix}/README.md"
  "${prefix}/LICENSE"
  "${prefix}/src/main_client.cpp"
  "${prefix}/src/main_server.cpp"
  "${prefix}/docs/PACKAGING.md"
  "${prefix}/scripts/make_debian_orig.sh"
  "${prefix}/src/gui/third_party/nanosvg/nanosvg.h"
  "${prefix}/src/gui/third_party/stb/stb_image_write.h"
)

for path in "${required[@]}"; do
  if ! grep -qxF "${path}" "${listing}"; then
    echo "source package is missing expected file: ${path}" >&2
    exit 4
  fi
done

excluded_regex="^${prefix}/(AGENTS\\.md|AI_NOTES\\.md|DEV_services|basefwx|vendor|third_party|debian|\\.claude|\\.codex|\\.wrangler)(/|$)|^${prefix}/(build|build-[^/]+|obj-[^/]+)(/|$)|\\.(log|trace|out|pyc)$|\\.tar\\.xz$"
if grep -Eq "${excluded_regex}" "${listing}"; then
  echo "source package contains excluded files:" >&2
  grep -E "${excluded_regex}" "${listing}" >&2
  exit 5
fi

(cd "${repo_root}" && dpkg-source -b .)
echo "Debian source package check passed for ${debian_version}."
