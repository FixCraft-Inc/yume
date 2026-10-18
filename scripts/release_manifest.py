#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import tempfile
from datetime import datetime, timezone

from package_linux_release import BUNDLE_NAME, SERVER_NAME


SIDECAR_SUFFIXES = (".sha256", ".md5", ".sig")
CHECKSUM_FILES = {"SHA256SUMS.txt": "sha256", "MD5SUMS.txt": "md5"}
MANIFEST_NAME = "release-manifest.json"
EXPECTED_ARTIFACTS = (BUNDLE_NAME, SERVER_NAME)
MAX_METADATA_BYTES = 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def digest_file(path: pathlib.Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_metadata(path: pathlib.Path) -> str:
    require(path.stat().st_size <= MAX_METADATA_BYTES,
            f"Metadata file exceeds 1 MiB: {path.name}")
    return path.read_text(encoding="utf-8")


def read_checksum_file(path: pathlib.Path, algorithm: str) -> dict[str, str]:
    text = read_metadata(path)
    require(bool(text) and text.endswith("\n"),
            f"Checksum file must contain newline-terminated records: {path.name}")
    width = hashlib.new(algorithm).digest_size * 2
    records = {}
    for line in text[:-1].split("\n"):
        match = re.fullmatch(rf"([0-9a-fA-F]{{{width}}}) [ *]([A-Za-z0-9][A-Za-z0-9_.+-]*)", line)
        require(match is not None, f"Malformed checksum record: {path.name}")
        digest, name = match.groups()
        require(name not in records, f"Duplicate checksum record for {name}: {path.name}")
        records[name] = digest.lower()
    return records


def base_artifact_name(name: str) -> str:
    for suffix in SIDECAR_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def classify(name: str) -> dict[str, str]:
    stem = name[:-7] if name.endswith(".tar.xz") else name
    parts = stem.split("-")
    component = "yumed" if stem.startswith("yumed-") else "yume"
    arch = parts[1] if len(parts) >= 3 else "unknown"
    os_name = parts[2] if len(parts) >= 3 else "unknown"
    linkage = "dynamic"

    if "static" in parts:
        linkage = "static"
    if name.endswith(".tar.xz"):
        linkage = "bundle"

    return {
        "component": component,
        "arch": arch,
        "os": os_name,
        "linkage": linkage,
    }


def build_manifest(dist_dir: pathlib.Path, release_tag: str | None, *,
                   require_signatures: bool = False) -> dict[str, object]:
    require(dist_dir.is_dir(), f"Artifact directory not found: {dist_dir}")
    present = {}
    for path in dist_dir.iterdir():
        require(stat.S_ISREG(path.lstat().st_mode),
                f"Release entry is not a regular file: {path.name}")
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", path.name) is not None,
                f"Invalid release filename: {path.name}")
        present[path.name] = path
    artifacts = sorted(name for name in present
                       if name not in CHECKSUM_FILES and name != MANIFEST_NAME
                       and not name.endswith(SIDECAR_SUFFIXES))
    if require_signatures:
        require(set(artifacts) == set(EXPECTED_ARTIFACTS),
                "Release artifact set must contain exactly " + ", ".join(EXPECTED_ARTIFACTS))
        required = {"SHA256SUMS.txt", "SHA256SUMS.txt.sig"}
        required.update(name + suffix for name in artifacts for suffix in (".sha256", ".sig"))
        missing = sorted(required - present.keys())
        require(not missing, "Missing required release files: " + ", ".join(missing))

    for name, path in present.items():
        if not name.endswith(SIDECAR_SUFFIXES):
            continue
        base = base_artifact_name(name)
        require(base in artifacts or
                (name.endswith(".sig") and base in present and
                 (base in CHECKSUM_FILES or base == MANIFEST_NAME)),
                f"Sidecar without artifact: {name}")
        if name.endswith(".sig"):
            require(0 < path.stat().st_size <= MAX_METADATA_BYTES,
                    f"Signature file is empty or exceeds 1 MiB: {name}")

    binaries = []
    digests = {}
    for name in artifacts:
        path = present[name]
        sha256_value = digest_file(path, "sha256")
        md5_value = digest_file(path, "md5")
        digests[name] = {"sha256": sha256_value, "md5": md5_value}
        sha256_sidecar = present.get(f"{path.name}.sha256")
        md5_sidecar = present.get(f"{path.name}.md5")
        sig_sidecar = present.get(f"{path.name}.sig")

        if sha256_sidecar:
            require(read_checksum_file(sha256_sidecar, "sha256") == {name: sha256_value},
                    f"SHA256 checksum record mismatch for {name}")
        if md5_sidecar:
            require(read_checksum_file(md5_sidecar, "md5") == {name: md5_value},
                    f"MD5 checksum record mismatch for {name}")

        entry = {
            "file": path.name,
            "size": path.stat().st_size,
            "sha256": sha256_value,
            "md5": md5_value,
            "sha256_file": sha256_sidecar.name if sha256_sidecar else None,
            "md5_file": md5_sidecar.name if md5_sidecar else None,
            "signature": sig_sidecar.name if sig_sidecar else None,
        }
        entry.update(classify(path.name))
        binaries.append(entry)

    checksums = []
    for name, algorithm in sorted(CHECKSUM_FILES.items()):
        if name not in present:
            continue
        expected = {artifact: digests[artifact][algorithm] for artifact in artifacts}
        require(read_checksum_file(present[name], algorithm) == expected,
                f"Aggregate checksum records mismatch: {name}")
        checksums.append({
            "file": name,
            "algorithm": algorithm,
            "size": present[name].stat().st_size,
            "sha256": digest_file(present[name], "sha256"),
            "signature": f"{name}.sig" if f"{name}.sig" in present else None,
        })

    return {
        "project": "yume",
        "release_tag": release_tag,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": binaries,
        "checksums": checksums,
    }


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for name, value in pairs:
        require(name not in result, f"Duplicate manifest key: {name}")
        result[name] = value
    return result


def check_manifest(dist_dir: pathlib.Path, release_tag: str | None, *,
                   require_signatures: bool = False) -> dict[str, object]:
    expected = build_manifest(dist_dir, release_tag, require_signatures=require_signatures)
    path = dist_dir / MANIFEST_NAME
    require(path.is_file(), f"Missing release manifest: {MANIFEST_NAME}")
    actual = json.loads(read_metadata(path), object_pairs_hook=unique_json_object)
    require(isinstance(actual, dict), "Release manifest must be an object")
    generated_at = actual.get("generated_at")
    require(isinstance(generated_at, str) and
            re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", generated_at) is not None,
            "Invalid release manifest generation time")
    try:
        datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise SystemExit("Invalid release manifest generation time") from error
    expected["generated_at"] = generated_at
    require(actual == expected, "Release manifest differs from the release files or tag")
    if require_signatures:
        require((dist_dir / f"{MANIFEST_NAME}.sig").is_file(),
                f"Missing required release files: {MANIFEST_NAME}.sig")
    return actual


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Generate or check a release file inventory.")
    parser.add_argument("artifacts_dir", type=pathlib.Path)
    parser.add_argument("release_tag", nargs="?")
    parser.add_argument("--require-signatures", action="store_true",
                        help="require the exact Linux artifacts, SHA256 files and detached signatures")
    parser.add_argument("--check", action="store_true",
                        help="check the inventory without writing, including its signature in strict mode")
    args = parser.parse_args(argv)
    dist_dir = args.artifacts_dir.resolve()
    try:
        if args.check:
            check_manifest(dist_dir, args.release_tag, require_signatures=args.require_signatures)
        else:
            manifest = build_manifest(dist_dir, args.release_tag,
                                      require_signatures=args.require_signatures)
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=dist_dir,
                                                 prefix=".release-manifest-", delete=False) as handle:
                    temporary = pathlib.Path(handle.name)
                    handle.write(json.dumps(manifest, indent=2) + "\n")
                os.replace(temporary, dist_dir / MANIFEST_NAME)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
    except (OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"Release manifest failed: {error}") from error
    print(dist_dir / MANIFEST_NAME)


if __name__ == "__main__":
    main()
