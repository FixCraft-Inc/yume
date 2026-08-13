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
archive_version="${upstream_version/-dev/~dev}"
debian_upstream_version="${debian_version%-*}"

if [[ -z "${upstream_version}" || -z "${debian_version}" ]]; then
  echo "failed to read YUME/Debian version" >&2
  exit 1
fi

if [[ "${archive_version}" != "${debian_upstream_version}" ]]; then
  echo "YUME version ${upstream_version} does not match Debian upstream version ${debian_upstream_version}" >&2
  exit 1
fi

cmake \
  -DYUME_ABI_MAP="${repo_root}/src/abi/yume.map" \
  -DYUME_ABI_HEADER="${repo_root}/include/yume/yume.h" \
  -P "${repo_root}/cmake/check_yume_abi_header.cmake"
cmake \
  -DYUME_ABI_MAP="${repo_root}/src/abi/yume.map" \
  -DYUME_DEBIAN_SYMBOLS="${repo_root}/debian/libyume1.symbols" \
  -P "${repo_root}/cmake/check_yume_abi_debian_symbols.cmake"

prefix="yume-${archive_version}"
artifacts=(
  "${repo_root}/../yume_${archive_version}.orig.tar.xz"
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
  "${prefix}/scripts/check_source_archive_listing.py"
  "${prefix}/src/gui/third_party/nanosvg/nanosvg.h"
  "${prefix}/src/gui/third_party/stb/stb_image_write.h"
)

for path in "${required[@]}"; do
  if ! grep -qxF "${path}" "${listing}"; then
    echo "source package is missing expected file: ${path}" >&2
    exit 4
  fi
done

if ! python3 "${repo_root}/scripts/check_source_archive_listing.py" \
    --listing "${listing}" --prefix "${prefix}"; then
  exit 5
fi

(cd "${repo_root}" && dpkg-source -b .)
echo "Debian source package check passed for ${debian_version}."
