#!/usr/bin/env python3
"""Immutable source provenance for YUME benchmark reports."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"runtime input is not a regular file: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise RuntimeError(f"runtime input changed while hashing: {path}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def git_source_snapshot(
    repository: Path,
    runtime_inputs: tuple[Path, ...],
) -> dict[str, object]:
    """Return commit, tree, dirty state, and exact runtime-input hashes."""
    root = repository.resolve(strict=True)

    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", "-c", "core.quotePath=true", "-C", str(root), *arguments],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        output = result.stdout.rstrip("\n")
        if len(output.encode("utf-8")) > 256 * 1024:
            raise RuntimeError("Git provenance output exceeds 256 KiB")
        return output

    resolved_inputs: dict[str, Path] = {}
    for relative in runtime_inputs:
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError(f"runtime input must be repository-relative: {relative}")
        resolved = (root / relative).resolve(strict=True)
        try:
            normalized = resolved.relative_to(root)
        except ValueError as exc:
            raise RuntimeError(f"runtime input escapes repository: {relative}") from exc
        if not resolved.is_file():
            raise RuntimeError(f"runtime input is not a regular file: {relative}")
        resolved_inputs[normalized.as_posix()] = resolved

    def git_identity() -> tuple[str, str, str]:
        commit = git("rev-parse", "--verify", "HEAD")
        tree = git("rev-parse", "--verify", "HEAD^{tree}")
        status = git("status", "--porcelain=v1", "--untracked-files=all")
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
            raise RuntimeError("Git provenance returned an invalid commit ID")
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", tree):
            raise RuntimeError("Git provenance returned an invalid tree ID")
        return commit, tree, status

    before_identity = git_identity()
    first_hashes = {
        name: sha256_file(path) for name, path in resolved_inputs.items()
    }
    file_hashes = {
        name: sha256_file(path) for name, path in resolved_inputs.items()
    }
    after_identity = git_identity()
    if before_identity != after_identity or first_hashes != file_hashes:
        raise RuntimeError("benchmark source changed while recording provenance")
    commit, tree, status = after_identity
    return {
        "commit": commit,
        "tree": tree,
        "dirty": bool(status),
        "status": status.splitlines(),
        "runtime_input_sha256": file_hashes,
    }
