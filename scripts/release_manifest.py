#!/usr/bin/env python3

import hashlib
import json
import pathlib
import sys
from typing import Optional


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify(name: str) -> dict:
    stem = name
    if stem.endswith(".tar.xz"):
        stem = stem[:-7]
    component = "yumed" if stem.startswith("yumed-") else "yume"
    parts = stem.split("-")
    arch = "unknown"
    os_name = "unknown"
    linkage = "dynamic"
    bundle = name.endswith(".tar.xz")

    if len(parts) >= 3:
        arch = parts[1]
        os_name = parts[2]
    if "static" in parts:
        linkage = "static"
    if bundle:
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
        "signature": None,
    }


def build_manifest(dist_dir: pathlib.Path, release_tag: Optional[str]) -> dict:
    files = []
    seen = set()
    for path in sorted(dist_dir.iterdir()):
        if not path.is_file():
            continue
        if path.name in {"SHA256SUMS.txt", "release-manifest.json"}:
            continue
        if path.name in seen:
            raise SystemExit(f"Duplicate artifact name detected: {path.name}")
        seen.add(path.name)
        entry = {
            "file": path.name,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        entry.update(classify(path.name))
        files.append(entry)
    return {
        "release_tag": release_tag,
        "generated_at": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": files,
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
