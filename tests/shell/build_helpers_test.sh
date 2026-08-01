#!/usr/bin/env bash
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/lib/library_detection.sh
source "${repo_root}/scripts/lib/library_detection.sh"
# shellcheck source=scripts/lib/safe_paths.sh
source "${repo_root}/scripts/lib/safe_paths.sh"
# shellcheck source=scripts/lib/user_context.sh
source "${repo_root}/scripts/lib/user_context.sh"
# shellcheck source=scripts/lib/macos_sdk.sh
source "${repo_root}/scripts/lib/macos_sdk.sh"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

expect_found() {
    yume_library_artifact_exists "$@" ||
        fail "expected library artifact for: $*"
}

expect_missing() {
    if yume_library_artifact_exists "$@"; then
        fail "unexpected library artifact for: $*"
    fi
}

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/yume-build-helpers-XXXXXX")"
cleanup_fixture() {
    case "${fixture_root}" in
        "${TMPDIR:-/tmp}"/yume-build-helpers-*)
            rm -rf -- "${fixture_root:?}"
            ;;
        *)
            fail "refusing to clean unexpected fixture path: ${fixture_root}"
            ;;
    esac
}
trap cleanup_fixture EXIT

library_dir="${fixture_root}/libraries with spaces"
mkdir -p "${library_dir}"

expect_missing libexample "${library_dir}"

: > "${library_dir}/libexample.so.*"
expect_missing libexample "${library_dir}"
rm -- "${library_dir}/libexample.so.*"

: > "${library_dir}/libexample.so.1"
expect_found libexample "${library_dir}"

: > "${library_dir}/libexample.so.2"
expect_found libexample "${library_dir}"

rm -- "${library_dir}/libexample.so.1" "${library_dir}/libexample.so.2"
: > "${library_dir}/libexample.so"
expect_found libexample "${library_dir}"

rm -- "${library_dir}/libexample.so"
: > "${library_dir}/libexample.a"
expect_found libexample "${library_dir}"

second_library_dir="${fixture_root}/second-library-dir"
mkdir -p "${second_library_dir}"
: > "${second_library_dir}/libfallback.so.7"
expect_found libfallback "${library_dir}" "${second_library_dir}"
expect_missing libmissing "${library_dir}" "${second_library_dir}"

removal_root="${fixture_root}/removal root"
mkdir -p "${removal_root}/first" "${removal_root}/second"
: > "${removal_root}/first/payload"
: > "${removal_root}/second/payload"
: > "${removal_root}/sentinel"

yume_remove_direct_children "${removal_root}" first second
[[ ! -e "${removal_root}/first" ]] || fail "first child was not removed"
[[ ! -e "${removal_root}/second" ]] || fail "second child was not removed"
[[ -f "${removal_root}/sentinel" ]] || fail "sibling sentinel was removed"

resolved="$(yume_direct_child_path "${removal_root}" replacement)"
expected_root="$(cd "${removal_root}" && pwd -P)"
[[ "${resolved}" == "${expected_root}/replacement" ]] ||
    fail "direct-child path was not canonicalized"

for unsafe_child in "" "." ".." "../escape" "nested/child" "/absolute"; do
    if yume_direct_child_path "${removal_root}" "${unsafe_child}" >/dev/null 2>&1; then
        fail "unsafe child was accepted: ${unsafe_child:-<empty>}"
    fi
done

if yume_direct_child_path / child >/dev/null 2>&1; then
    fail "filesystem root was accepted"
fi
if yume_remove_direct_children "" child >/dev/null 2>&1; then
    fail "empty removal root was accepted"
fi

[[ -n "$(yume_real_home)" ]] || fail "real home was empty"
[[ "$(yume_real_uid)" =~ ^[0-9]+$ ]] ||
    fail "real uid was not numeric"
[[ "$(yume_real_gid)" =~ ^[0-9]+$ ]] ||
    fail "real gid was not numeric"

sdk_home="${fixture_root}/sdk-home"
osxcross_root="${fixture_root}/osxcross"
mkdir -p "${sdk_home}/macos-sdk/MacOSX15.0.sdk"
: > "${sdk_home}/macos-sdk/MacOSX15.0.sdk/SDKSettings.json"
yume_ensure_macos_sdk_tarball "${sdk_home}" "${osxcross_root}"
[[ -f "${osxcross_root}/tarballs/MacOSX15.0.sdk.tar.xz" ]] ||
    fail "macOS SDK archive was not staged"

printf 'build helper tests passed\n'
