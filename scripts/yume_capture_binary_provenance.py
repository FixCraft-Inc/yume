#!/usr/bin/env python3
"""Bind YUME capture executables to one validated exact-commit Linux bundle."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import stat
import sys
import tarfile
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from release_preflight import (  # noqa: E402
    source_version,
    transport_dependency,
    validate_bundle,
)


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class ProvenanceError(ValueError):
    """The supplied runtime is not the exact validated bundle runtime."""


def _regular_executable(path: pathlib.Path, description: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ProvenanceError(f"cannot inspect {description}: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ProvenanceError(f"{description} must be a non-symlink regular file")
    if info.st_mode & 0o111 == 0:
        raise ProvenanceError(f"{description} must be executable")


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ProvenanceError(f"cannot hash capture executable: {path}") from exc
    return digest.hexdigest()


def validate_capture_binaries(
    bundle: pathlib.Path,
    yume: pathlib.Path,
    helper: pathlib.Path | None,
    commit: str,
) -> tuple[str, str | None]:
    if not COMMIT_RE.fullmatch(commit):
        raise ProvenanceError("source commit must be exact lowercase 40-hex")
    _regular_executable(yume, "YUME binary")
    yume_hash = _sha256(yume)
    helper_hash: str | None = None
    if helper is not None:
        _regular_executable(helper, "YUME helper")
        helper_hash = _sha256(helper)
    try:
        manifest = validate_bundle(
            bundle,
            source_version(),
            commit,
            helper_hash,
            transport_dependency(),
        )
    except (OSError, SystemExit, ValueError, tarfile.TarError) as exc:
        raise ProvenanceError(f"release bundle validation failed: {exc}") from exc
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise ProvenanceError("release bundle file manifest is missing")
    by_name: dict[str, dict[str, Any]] = {
        item.get("file"): item
        for item in entries
        if isinstance(item, dict) and isinstance(item.get("file"), str)
    }
    yume_entry = by_name.get("yume")
    if not isinstance(yume_entry, dict):
        raise ProvenanceError("release bundle YUME runtime entry is missing")
    if yume_entry.get("sha256") != yume_hash:
        raise ProvenanceError("YUME binary differs from the exact release bundle")
    for entry, path, description in ((yume_entry, yume, "YUME binary"),):
        if entry.get("size") != path.stat().st_size:
            raise ProvenanceError(f"{description} size differs from the release bundle")
        if not isinstance(entry.get("sha256"), str) or not SHA256_RE.fullmatch(
            entry["sha256"]
        ):
            raise ProvenanceError(f"{description} bundle hash is malformed")
    if helper is not None:
        helper_entry = by_name.get("yume-chrome-tls-helper")
        if not isinstance(helper_entry, dict):
            raise ProvenanceError("release bundle helper entry is missing")
        if helper_entry.get("sha256") != helper_hash:
            raise ProvenanceError("YUME helper differs from the exact release bundle")
        if helper_entry.get("size") != helper.stat().st_size:
            raise ProvenanceError("YUME helper size differs from the release bundle")
        if not isinstance(helper_entry.get("sha256"), str) or not SHA256_RE.fullmatch(
            helper_entry["sha256"]
        ):
            raise ProvenanceError("YUME helper bundle hash is malformed")
    return yume_hash, helper_hash


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=pathlib.Path)
    parser.add_argument("--yume", required=True, type=pathlib.Path)
    parser.add_argument(
        "--helper", type=pathlib.Path,
        help="optional helper path for an explicitly helper-backed capture")
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    try:
        yume_hash, helper_hash = validate_capture_binaries(
            args.bundle, args.yume, args.helper, args.source_commit
        )
    except ProvenanceError as exc:
        print(f"capture binary provenance rejected: {exc}", file=sys.stderr)
        return 1
    helper_text = f" helper={helper_hash}" if helper_hash is not None else ""
    print(f"Capture binary provenance OK: source={args.source_commit} "
          f"yume={yume_hash}{helper_text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
