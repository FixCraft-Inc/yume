#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone
from typing import Optional


SIDECAR_SUFFIXES = (".sha256", ".md5", ".sig")
IGNORED_FILES = {"SHA256SUMS.txt", "MD5SUMS.txt", "release-manifest.json"}


def digest_file(path: pathlib.Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_checksum_file(path: pathlib.Path) -> str:
    line = path.read_text(encoding="utf-8").strip()
    if not line:
        raise SystemExit(f"Empty checksum file: {path.name}")
    return line.split()[0].lower()


def base_artifact_name(name: str) -> str:
    for suffix in SIDECAR_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def classify(name: str) -> dict:
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
        "features": {
            "argon2": True,
            "oqs": True,
            "lzma": True,
        },
    }


def build_manifest(dist_dir: pathlib.Path, release_tag: Optional[str]) -> dict:
    present = {path.name: path for path in dist_dir.iterdir() if path.is_file()}
    binaries = []
    seen = set()

    for path in sorted(dist_dir.iterdir()):
        if not path.is_file() or path.name in IGNORED_FILES:
            continue
        if path.name.endswith(SIDECAR_SUFFIXES):
            continue
        if path.name in seen:
            raise SystemExit(f"Duplicate artifact name detected: {path.name}")
        seen.add(path.name)

        sha256_value = digest_file(path, "sha256")
        md5_value = digest_file(path, "md5")
        sha256_sidecar = present.get(f"{path.name}.sha256")
        md5_sidecar = present.get(f"{path.name}.md5")
        sig_sidecar = present.get(f"{path.name}.sig")

        if sha256_sidecar:
            sidecar_value = read_checksum_file(sha256_sidecar)
            if sidecar_value != sha256_value:
                raise SystemExit(f"SHA256 mismatch for {path.name}")
        if md5_sidecar:
            sidecar_value = read_checksum_file(md5_sidecar)
            if sidecar_value != md5_value:
                raise SystemExit(f"MD5 mismatch for {path.name}")

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

    sidecar_bases = {
        base_artifact_name(name)
        for name in present
        if name.endswith(SIDECAR_SUFFIXES)
    }
    missing_binaries = sorted(base for base in sidecar_bases if base not in seen)
    if missing_binaries:
        raise SystemExit("Sidecar without artifact: " + ", ".join(missing_binaries))

    return {
        "project": "yume",
        "release_tag": release_tag,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": binaries,
    }


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: release_manifest.py <artifacts-dir> [release-tag]")
    dist_dir = pathlib.Path(sys.argv[1]).resolve()
    if not dist_dir.is_dir():
        raise SystemExit(f"artifact directory not found: {dist_dir}")
    release_tag = sys.argv[2] if len(sys.argv) > 2 else None
    manifest = build_manifest(dist_dir, release_tag)
    output = dist_dir / "release-manifest.json"
    output.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
