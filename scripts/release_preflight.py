#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

from yume_dependencies import DependencyError, load_dependencies
from generate_transport_profiles import ProfileError, active_profile_metadata


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = "linux-desktop-2.0"
BUNDLE_NAME = "yume-amd64-linux.tar.xz"
SERVER_NAME = "yumed-amd64-linux"
BUNDLE_DIRECTORY = "yume-amd64-linux"
HELPER_NAME = "yume-chrome-tls-helper"
EXPECTED_BUNDLE_FILES = {
    "LICENSE": 0o644,
    "QUICKSTART.md": 0o644,
    "THIRD_PARTY_NOTICES.md": 0o644,
    "manifest.json": 0o644,
    "yume": 0o755,
    HELPER_NAME: 0o755,
}
MAX_BUNDLE_FILE_BYTES = {
    "LICENSE": 1024 * 1024,
    "QUICKSTART.md": 1024 * 1024,
    "THIRD_PARTY_NOTICES.md": 1024 * 1024,
    "manifest.json": 1024 * 1024,
    "yume": 512 * 1024 * 1024,
    HELPER_NAME: 64 * 1024 * 1024,
}
MAX_SERVER_BYTES = 512 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def basefwx_dependency() -> dict[str, str]:
    try:
        return load_dependencies()["basefwx"]
    except (DependencyError, KeyError) as error:
        raise SystemExit(f"Invalid BaseFWX dependency metadata: {error}") from error


def transport_dependency() -> dict[str, object]:
    try:
        return active_profile_metadata()
    except (OSError, ProfileError) as error:
        raise SystemExit(f"Invalid transport profile metadata: {error}") from error


def validate_ref(ref: str, repository: str) -> None:
    tmpdir = tempfile.mkdtemp(prefix="yume-basefwx-ref-")
    try:
        subprocess.run(["git", "init", "-q", tmpdir], check=True)
        subprocess.run(["git", "-C", tmpdir, "remote", "add", "origin", repository], check=True)
        subprocess.run(["git", "-C", tmpdir, "fetch", "--depth", "1", "origin", ref], check=True)
        fetched = subprocess.check_output(
            ["git", "-C", tmpdir, "rev-parse", "FETCH_HEAD"], text=True).strip()
        require(fetched == ref, "Fetched BaseFWX commit does not match pinned ref")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def source_version() -> str:
    text = (ROOT / "src" / "core" / "version.hpp").read_text(encoding="utf-8")
    match = re.search(r'kVersion\[\]\s*=\s*"([^"]+)"', text)
    require(match is not None, "Cannot read YUME source version")
    return match.group(1)


def source_commit() -> str:
    commit = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    require(bool(re.fullmatch(r"[0-9a-f]{40}", commit)),
            "Cannot resolve the release source commit")
    return commit


def version_for_tag(tag: str) -> str:
    match = re.fullmatch(r"v2\.0(?:-(rc[1-9][0-9]*))?", tag)
    require(match is not None,
            "linux-desktop-2.0 accepts only v2.0-rcN or v2.0 tags")
    return f"2.0-{match.group(1)}" if match.group(1) else "2.0"


def validate_tag(tag: str | None, version: str, commit: str) -> None:
    if tag is None:
        return
    expected = version_for_tag(tag)
    require(version == expected,
            f"Release tag {tag} requires source version {expected}, found {version}")
    try:
        tagged_commit = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-list", "-n", "1", tag],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"Release tag does not exist in this checkout: {tag}") from exc
    require(tagged_commit == commit,
            f"Release tag {tag} does not resolve to checked-out commit {commit}")


def validate_expected_artifacts() -> None:
    expected = [BUNDLE_NAME, SERVER_NAME]
    require(len(expected) == len(set(expected)), "Duplicate release artifact names")


def validate_workflow_guards() -> None:
    release_yml = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    ci_yml = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    required_release = (
        "linux-desktop-2.0",
        'go-version: "1.26.5"',
        "check-latest: false",
        "-DYUME_BUILD_CHROME_TLS_HELPER=ON",
        "-DYUME_BUILD_GUI=OFF",
        "-DYUME_STATIC=OFF",
        "-DYUME_WARNINGS_AS_ERRORS=ON",
        "-DBASEFWX_REQUIRE_ARGON2=ON",
        "-DBASEFWX_REQUIRE_OQS=ON",
        "-DBASEFWX_REQUIRE_LZMA=ON",
        "GOPROXY=off",
        "package_linux_release.py",
        BUNDLE_NAME,
        SERVER_NAME,
        "linux-desktop-2.0-prepared.tar",
        "--same-permissions",
        "publish:",
        "default: false",
        "workflow_dispatch releases must be started from main.",
    )
    for needle in required_release:
        require(needle in release_yml, f"release.yml is missing required guard: {needle}")
    for needle in (
        "-DBASEFWX_REQUIRE_ARGON2=ON",
        "-DBASEFWX_REQUIRE_OQS=ON",
        "-DBASEFWX_REQUIRE_LZMA=ON",
    ):
        require(needle in ci_yml, f"ci.yml is missing required guard: {needle}")
    require("branches: [main, DEV]" in ci_yml, "ci.yml must cover main and DEV")
    require(release_yml.count("-B build-helper-") >= 2,
            "release.yml must configure two clean helper build directories")
    forbidden = (
        "build-macos", "openwrt", "windows-x86_64", "armv7", "armv8",
        "busybox", "yume-gui", "yume-amd64-linux-static", "debian archive",
    )
    lowered = release_yml.lower()
    for marker in forbidden:
        require(marker not in lowered,
                f"linux-desktop-2.0 workflow includes unsupported marker: {marker}")


def cache_value(cache: str, name: str) -> str | None:
    match = re.search(rf"^{re.escape(name)}:[^=]+=([^\r\n]+)$", cache, re.MULTILINE)
    return match.group(1).strip() if match else None


def validate_cmake_cache(path: pathlib.Path) -> None:
    require(path.is_file(), f"Missing CMake cache: {path}")
    cache = path.read_text(encoding="utf-8", errors="replace")
    required = {
        "YUME_USE_BASEFWX": "ON",
        "YUME_BUILD_CHROME_TLS_HELPER": "ON",
        "YUME_BUILD_GUI": "OFF",
        "YUME_STATIC": "OFF",
        "YUME_WARNINGS_AS_ERRORS": "ON",
        "BASEFWX_REQUIRE_ARGON2": "ON",
        "BASEFWX_REQUIRE_OQS": "ON",
        "BASEFWX_REQUIRE_LZMA": "ON",
    }
    for name, expected in required.items():
        actual = cache_value(cache, name)
        require(actual == expected,
                f"Release CMake cache requires {name}={expected}, found {actual}")


def validate_helper_rebuilds(first: pathlib.Path, second: pathlib.Path) -> str:
    for path in (first, second):
        require(path.is_file() and not path.is_symlink(),
                f"Missing regular Chrome TLS helper rebuild: {path}")
    first_hash = sha256_file(first)
    second_hash = sha256_file(second)
    require(first_hash == second_hash,
            "Chrome TLS helper clean rebuild SHA-256 mismatch")
    return first_hash


def require_elf_amd64(data: bytes, description: str) -> None:
    require(len(data) >= 20 and data[:4] == b"\x7fELF", f"{description} is not ELF")
    require(data[4] == 2 and data[5] == 1, f"{description} is not little-endian ELF64")
    require(int.from_bytes(data[18:20], "little") == 62, f"{description} is not x86-64")


def require_glibc_amd64(data: bytes, description: str) -> None:
    require_elf_amd64(data, description)
    require(len(data) >= 64, f"{description} has a truncated ELF header")
    program_offset = int.from_bytes(data[32:40], "little")
    entry_size = int.from_bytes(data[54:56], "little")
    entry_count = int.from_bytes(data[56:58], "little")
    require(entry_size >= 56 and entry_count <= 1024,
            f"{description} has invalid ELF program headers")
    interpreter = None
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        require(offset <= len(data) and entry_size <= len(data) - offset,
                f"{description} has truncated ELF program headers")
        if int.from_bytes(data[offset:offset + 4], "little") != 3:
            continue
        file_offset = int.from_bytes(data[offset + 8:offset + 16], "little")
        file_size = int.from_bytes(data[offset + 32:offset + 40], "little")
        require(file_size <= 4096 and file_offset <= len(data) and
                file_size <= len(data) - file_offset,
                f"{description} has invalid ELF interpreter metadata")
        interpreter = data[file_offset:file_offset + file_size].rstrip(b"\0")
        break
    require(interpreter == b"/lib64/ld-linux-x86-64.so.2",
            f"{description} is not a glibc x86-64 dynamic executable")


def validate_bundle(bundle: pathlib.Path, version: str, commit: str,
                    expected_helper_hash: str | None,
                    transport: dict[str, object]) -> dict[str, object]:
    require(bundle.is_file() and not bundle.is_symlink(), f"Missing release bundle: {bundle}")
    with tarfile.open(bundle, "r:xz") as archive:
        members = archive.getmembers()
        require(all(not member.issym() and not member.islnk() for member in members),
                "Release bundle must not contain links")
        names = {member.name.rstrip("/") for member in members}
        expected_names = {BUNDLE_DIRECTORY} | {
            f"{BUNDLE_DIRECTORY}/{name}" for name in EXPECTED_BUNDLE_FILES
        }
        require(names == expected_names,
                "Release bundle contents are incomplete or contain unexpected files")
        payloads: dict[str, bytes] = {}
        for name, mode in EXPECTED_BUNDLE_FILES.items():
            member = archive.getmember(f"{BUNDLE_DIRECTORY}/{name}")
            require(member.isfile(), f"Bundle member is not a regular file: {name}")
            require(member.mode == mode, f"Bundle member has unsafe mode: {name}")
            require(member.size <= MAX_BUNDLE_FILE_BYTES[name],
                    f"Bundle member exceeds size cap: {name}")
            handle = archive.extractfile(member)
            require(handle is not None, f"Cannot read bundle member: {name}")
            payloads[name] = handle.read()

    require_glibc_amd64(payloads["yume"], "bundled yume")
    require_elf_amd64(payloads[HELPER_NAME], "bundled Chrome TLS helper")
    manifest = json.loads(payloads["manifest.json"].decode("utf-8"))
    require(isinstance(manifest, dict), "Bundle manifest must be an object")
    require(manifest.get("schema") == 1, "Bundle manifest schema mismatch")
    require(manifest.get("release_profile") == PROFILE, "Bundle release profile mismatch")
    require(manifest.get("version") == version, "Bundle version mismatch")
    require(manifest.get("source_commit") == commit,
            "Bundle source commit does not match the checked-out release commit")
    require(manifest.get("platform") == "linux", "Bundle platform mismatch")
    require(manifest.get("architecture") == "x86_64", "Bundle architecture mismatch")
    require(manifest.get("libc") == "glibc", "Bundle libc mismatch")
    require(manifest.get("transport_profile") == transport["id"],
            "Bundle transport profile mismatch")
    helper = manifest.get("chrome_tls_helper", {})
    require(helper.get("build_id") == transport["helper_build_id"],
            "Bundle helper identity mismatch")
    require(helper.get("ipc_protocol") == 1, "Bundle helper IPC mismatch")
    require(helper.get("go_version") == "go1.26.5", "Bundle helper Go version mismatch")
    helper_hash = sha256_bytes(payloads[HELPER_NAME])
    require(helper.get("sha256") == helper_hash, "Bundle helper SHA-256 mismatch")
    require(helper.get("clean_rebuild_sha256") == helper_hash,
            "Bundle helper reproducibility evidence mismatch")
    if expected_helper_hash is not None:
        require(helper_hash == expected_helper_hash,
                "Bundled helper differs from clean rebuilds")
    features = manifest.get("required_features", {})
    require(features == {
        "argon2": True, "chrome_tls_helper": True, "post_quantum": True,
    }, "Bundle mandatory feature declarations are incomplete or relaxed")
    entries = manifest.get("files")
    require(isinstance(entries, list), "Bundle manifest file list is missing")
    by_name = {entry.get("file"): entry for entry in entries if isinstance(entry, dict)}
    expected_manifest_files = set(EXPECTED_BUNDLE_FILES) - {"manifest.json"}
    require(set(by_name) == expected_manifest_files,
            "Bundle manifest file list is incomplete or unexpected")
    for name in expected_manifest_files:
        entry = by_name[name]
        require(entry.get("sha256") == sha256_bytes(payloads[name]),
                f"Bundle manifest SHA-256 mismatch for {name}")
        require(entry.get("size") == len(payloads[name]),
                f"Bundle manifest size mismatch for {name}")
        require(entry.get("mode") == f"{EXPECTED_BUNDLE_FILES[name]:04o}",
                f"Bundle manifest mode mismatch for {name}")
    return manifest


def validate_artifacts(directory: pathlib.Path, version: str, commit: str,
                       expected_helper_hash: str | None,
                       transport: dict[str, object]) -> None:
    require(directory.is_dir(), f"Release artifact directory not found: {directory}")
    present = {path.name for path in directory.iterdir() if path.is_file()}
    require(present == {BUNDLE_NAME, SERVER_NAME},
            "Release artifacts are incomplete or include unexpected platforms/variants")
    manifest = validate_bundle(directory / BUNDLE_NAME, version, commit,
                               expected_helper_hash, transport)
    server = directory / SERVER_NAME
    require(server.is_file() and not server.is_symlink(),
            "Server artifact must be a regular file")
    server_stat = server.stat()
    require(server_stat.st_size <= MAX_SERVER_BYTES,
            "Server artifact exceeds size cap")
    require(stat.S_IMODE(server_stat.st_mode) == 0o755,
            "Server artifact mode must be 0755")
    server_bytes = server.read_bytes()
    require_glibc_amd64(server_bytes, "yumed server artifact")
    server_metadata = manifest.get("standalone_server", {})
    require(isinstance(server_metadata, dict),
            "Bundle manifest standalone server metadata is missing")
    require(server_metadata.get("file") == SERVER_NAME,
            "Bundle manifest server filename mismatch")
    require(server_metadata.get("mode") == "0755",
            "Bundle manifest server mode mismatch")
    require(server_metadata.get("size") == len(server_bytes),
            "Bundle manifest server size mismatch")
    require(server_metadata.get("sha256") == sha256_bytes(server_bytes),
            "Bundle manifest server SHA-256 mismatch")
    observed_version = subprocess.run(
        [str(server), "--version"], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
    ).stdout.strip()
    require(version in observed_version,
            "Server artifact version does not match source version")
    require(server_metadata.get("version_output") == observed_version,
            "Bundle manifest server version output mismatch")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the YUME 2.0 Linux release lane")
    parser.add_argument("--profile", default=PROFILE)
    parser.add_argument("--tag")
    parser.add_argument("--skip-ref-fetch", action="store_true")
    parser.add_argument("--cmake-cache", type=pathlib.Path)
    parser.add_argument("--helper-build-a", type=pathlib.Path)
    parser.add_argument("--helper-build-b", type=pathlib.Path)
    parser.add_argument("--artifacts", type=pathlib.Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    require(args.profile == PROFILE, f"Unsupported release profile: {args.profile}")
    dependency = basefwx_dependency()
    transport = transport_dependency()
    ref = dependency["revision"]
    if not args.skip_ref_fetch:
        validate_ref(ref, dependency["repository"])
    version = source_version()
    commit = source_commit()
    validate_tag(args.tag, version, commit)
    validate_expected_artifacts()
    validate_workflow_guards()
    if args.cmake_cache is not None:
        validate_cmake_cache(args.cmake_cache)
    require((args.helper_build_a is None) == (args.helper_build_b is None),
            "Both helper rebuild paths are required together")
    helper_hash = None
    if args.helper_build_a is not None:
        helper_hash = validate_helper_rebuilds(
            args.helper_build_a, args.helper_build_b)
    if args.artifacts is not None:
        validate_artifacts(args.artifacts, version, commit, helper_hash, transport)
    print(f"Preflight OK: profile={PROFILE} version={version} "
          f"transport={transport['id']} BaseFWX={ref}")


if __name__ == "__main__":
    main()
