#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Verify and seal one private matched-capture arm after every run succeeds."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_OPAQUE_BYTES = 512 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CHECKSUM_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([^\x00\r\n]+)$")
EXPECTED_RUNTIME_FILES = (
    "tools/cover-node/server.mjs",
    "tools/cover-node/workload.mjs",
    "tools/cover-node/workload-v1.json",
    "tools/cover-node/capture_chrome.mjs",
    "tools/cover-node/sanitize_netlog.mjs",
    "tools/cover-node/capture_yume151_runs.sh",
    "scripts/yume_capture_binary_provenance.py",
    "scripts/yume_capture_manifest.py",
    "scripts/yume_capture_finalize.py",
    "scripts/release_preflight.py",
    "scripts/generate_transport_profiles.py",
    "scripts/yume_dependencies.py",
    "scripts/yume_bench_common.py",
    "scripts/yume_bench_resources.py",
    "scripts/yume_tls_wire.py",
    "tests/fixtures/chrome151-node24/manifest.json",
)


class FinalizeError(ValueError):
    """The capture tree is incomplete, inconsistent, or unsafe."""


def _safe_manifest_name(value: str) -> str:
    if "\\" in value:
        raise FinalizeError(f"unsafe checksum path: {value!r}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or value.startswith("./")
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise FinalizeError(f"unsafe checksum path: {value!r}")
    return value


def parse_checksum_manifest(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FinalizeError("checksum manifest is not UTF-8") from exc
    if not text or not text.endswith("\n"):
        raise FinalizeError("checksum manifest must end with a newline")
    entries: dict[str, str] = {}
    for line in text.splitlines():
        match = CHECKSUM_LINE_RE.fullmatch(line)
        if match is None:
            raise FinalizeError("malformed checksum manifest line")
        digest, raw_name = match.groups()
        name = _safe_manifest_name(raw_name)
        if name in entries:
            raise FinalizeError(f"duplicate checksum path: {name}")
        entries[name] = digest
    return entries


class CaptureTree:
    """Open files relative to one no-follow directory anchor."""

    def __init__(self, root: Path) -> None:
        if root.is_symlink():
            raise FinalizeError(f"capture root must not be a symlink: {root}")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            self._root_fd = os.open(root, flags)
        except OSError as exc:
            raise FinalizeError(f"cannot anchor capture root: {root}") from exc
        metadata = os.fstat(self._root_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(self._root_fd)
            raise FinalizeError(f"capture root is not a directory: {root}")
        self.root = root.resolve(strict=True)

    def close(self) -> None:
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> "CaptureTree":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @staticmethod
    def _parts(relative: Path) -> tuple[str, ...]:
        value = relative.as_posix()
        _safe_manifest_name(value)
        return relative.parts

    def _open(self, relative: Path) -> int:
        parts = self._parts(relative)
        directory_fd = os.dup(self._root_fd)
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
            file_flags |= os.O_NOFOLLOW
        try:
            for component in parts[:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            descriptor = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        except OSError as exc:
            raise FinalizeError(f"cannot open capture input: {relative}") from exc
        finally:
            os.close(directory_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise FinalizeError(f"capture input is not regular: {relative}")
        return descriptor

    @staticmethod
    def _unchanged(before: os.stat_result, after: os.stat_result) -> bool:
        return (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )

    def bytes(self, relative: Path, *, maximum: int = MAX_MANIFEST_BYTES) -> bytes:
        descriptor = self._open(relative)
        try:
            before = os.fstat(descriptor)
            if before.st_size > maximum:
                raise FinalizeError(f"capture input is too large: {relative}")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(descriptor, min(128 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            if not self._unchanged(before, after):
                raise FinalizeError(f"capture input changed while reading: {relative}")
            value = b"".join(chunks)
            if len(value) > maximum:
                raise FinalizeError(f"capture input is too large: {relative}")
            return value
        finally:
            os.close(descriptor)

    def sha256(self, relative: Path, *, maximum: int = MAX_OPAQUE_BYTES) -> str:
        descriptor = self._open(relative)
        digest = hashlib.sha256()
        try:
            before = os.fstat(descriptor)
            if before.st_size > maximum:
                raise FinalizeError(f"capture input is too large: {relative}")
            total = 0
            while True:
                chunk = os.read(descriptor, 128 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise FinalizeError(f"capture input is too large: {relative}")
                digest.update(chunk)
            after = os.fstat(descriptor)
            if not self._unchanged(before, after):
                raise FinalizeError(f"capture input changed while hashing: {relative}")
            return digest.hexdigest()
        finally:
            os.close(descriptor)

    def write_private_json(self, name: str, value: dict[str, Any]) -> None:
        if "/" in name or name in {"", ".", ".."}:
            raise FinalizeError("completion output must be one safe filename")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(name, flags, 0o600, dir_fd=self._root_fd)
        try:
            os.fchmod(descriptor, 0o600)
            payload = (json.dumps(value, indent=2) + "\n").encode("utf-8")
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write while creating completion marker")
                view = view[written:]
        finally:
            os.close(descriptor)


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FinalizeError(f"invalid JSON: {label}") from exc
    if not isinstance(value, dict):
        raise FinalizeError(f"JSON must be an object: {label}")
    return value


def _require_names(
    entries: dict[str, str], expected: set[str], label: str
) -> None:
    if set(entries) != expected:
        raise FinalizeError(
            f"{label} paths differ: got {sorted(entries)!r}, "
            f"expected {sorted(expected)!r}"
        )


def _verify_entries(
    reader: CaptureTree,
    entries: dict[str, str],
    *,
    prefix: Path = Path(),
) -> None:
    for name, expected in entries.items():
        relative = prefix / Path(name)
        maximum = MAX_OPAQUE_BYTES if relative.name == "netlog.json" else MAX_MANIFEST_BYTES
        if reader.sha256(relative, maximum=maximum) != expected:
            raise FinalizeError(f"capture checksum mismatch: {relative}")


def finalize_capture(root: Path) -> dict[str, Any]:
    with CaptureTree(root) as reader:
        environment_raw = reader.bytes(Path("environment.json"))
        environment = _json_object(environment_raw, "environment.json")
        arm = environment.get("arm")
        if arm not in {"normal", "yume"}:
            raise FinalizeError("environment arm must be normal or yume")
        runs = environment.get("runs")
        if not isinstance(runs, int) or isinstance(runs, bool) or not 1 <= runs <= 20:
            raise FinalizeError("environment runs must be in 1..20")
        tls_wire = environment.get("tls_wire_evidence")
        if not isinstance(tls_wire, bool):
            raise FinalizeError("tls_wire_evidence must be Boolean")
        if arm == "yume":
            for field in (
                "yume_binary_sha256",
                "yume_helper_sha256",
                "release_bundle_sha256",
                "tls_leaf_sha256",
            ):
                value = environment.get(field)
                if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
                    raise FinalizeError(f"{field} must be lowercase SHA-256")

        top_raw = reader.bytes(Path("SHA256SUMS"))
        top_entries = parse_checksum_manifest(top_raw)
        expected_top = {
            "environment.json",
            "server.crt",
            "runtime-source/SHA256SUMS",
            *(f"run-{index:02d}/SHA256SUMS" for index in range(1, runs + 1)),
        }
        _require_names(top_entries, expected_top, "top-level checksum")
        _verify_entries(reader, top_entries)

        environment_sha256 = hashlib.sha256(environment_raw).hexdigest()
        certificate_sha256 = reader.sha256(Path("server.crt"))
        if environment.get("certificate_sha256") != certificate_sha256:
            raise FinalizeError("environment certificate SHA-256 mismatch")

        runtime_raw = reader.bytes(Path("runtime-source/SHA256SUMS"))
        runtime_entries = parse_checksum_manifest(runtime_raw)
        _require_names(
            runtime_entries, set(EXPECTED_RUNTIME_FILES), "runtime checksum"
        )
        _verify_entries(reader, runtime_entries, prefix=Path("runtime-source"))

        completed_runs: list[dict[str, Any]] = []
        for index in range(1, runs + 1):
            name = f"run-{index:02d}"
            checksums_path = Path(name) / "SHA256SUMS"
            checksums_raw = reader.bytes(checksums_path)
            entries = parse_checksum_manifest(checksums_raw)
            if arm == "normal":
                expected = {"netlog.json", "sanitized.json"}
                if tls_wire:
                    expected.add("tls-wire.json")
            else:
                expected = {"tls-wire.json"}
                if "behavior.json" in entries:
                    expected.add("behavior.json")
            _require_names(entries, expected, f"{name} checksum")
            _verify_entries(reader, entries, prefix=Path(name))
            completed_runs.append(
                {
                    "name": name,
                    "checksums_sha256": hashlib.sha256(checksums_raw).hexdigest(),
                    "files": entries,
                }
            )

        completion = {
            "schema": 1,
            "status": "complete",
            "arm": arm,
            "top_level_sha256": hashlib.sha256(top_raw).hexdigest(),
            "environment_sha256": environment_sha256,
            "certificate_sha256": certificate_sha256,
            "runtime_source": {
                "checksums_sha256": hashlib.sha256(runtime_raw).hexdigest(),
                "files": runtime_entries,
            },
            "runs": completed_runs,
        }
        reader.write_private_json("complete.json", completion)
        return completion


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--root", required=True, type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        finalize_capture(args.root)
    except (FinalizeError, OSError) as exc:
        print(f"capture finalization rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
