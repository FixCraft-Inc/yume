#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Write a private, source-bound manifest for one matched-capture arm."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from yume_bench_common import (  # noqa: E402
    PINNED_CHROME_BINARY_SHA256,
    PINNED_CHROME_LAUNCHER_SHA256,
    PINNED_CHROME_VERSION,
    PINNED_NODE_BINARY_SHA256,
    PINNED_NODE_VERSION,
)


ROOT = Path(__file__).resolve().parents[1]
WORKLOAD_PATH = ROOT / "tools/cover-node/workload-v1.json"
MAX_INPUT_BYTES = 1024 * 1024
OBJECT_ID_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SNI_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
)


class ManifestError(ValueError):
    """The capture environment is not safe or does not match its contract."""


def read_regular_nofollow(path: Path, *, maximum: int = MAX_INPUT_BYTES) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ManifestError(f"cannot open regular input: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ManifestError(f"input is not a regular file: {path}")
        if before.st_size > maximum:
            raise ManifestError(f"input exceeds {maximum} bytes: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(128 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ManifestError(f"input changed while reading: {path}")
        value = b"".join(chunks)
        if len(value) > maximum:
            raise ManifestError(f"input exceeds {maximum} bytes: {path}")
        return value
    finally:
        os.close(descriptor)


def load_workload(path: Path = WORKLOAD_PATH) -> tuple[dict[str, Any], str]:
    raw = read_regular_nofollow(path)
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError("workload manifest is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ManifestError("workload manifest must be an object")
    if document.get("schema") != 1:
        raise ManifestError("unsupported workload manifest schema")
    if document.get("id") != "cover-page-websocket-v1":
        raise ManifestError("unexpected workload manifest id")
    if document.get("transport_profile") != "chrome151-node24-v1":
        raise ManifestError("unexpected workload transport profile")
    contract = document.get("contract")
    if not isinstance(contract, dict) or contract.get("mode") != document["id"]:
        raise ManifestError("workload contract is absent or mismatched")
    assets = document.get("assets")
    if not isinstance(assets, list):
        raise ManifestError("workload assets must be an array")
    paths = [asset.get("path") for asset in assets if isinstance(asset, dict)]
    if paths != contract.get("asset_paths") or len(paths) != len(assets):
        raise ManifestError("workload asset order differs from its contract")
    expected_fields = {
        "mode",
        "asset_paths",
        "websocket_bytes_each_direction",
        "client_binary_messages",
        "server_binary_messages",
        "server_fragmented_binary_message",
        "ping_pong",
        "idle_ms",
        "close",
    }
    if set(contract) != expected_fields:
        raise ManifestError("workload contract fields do not match schema 1")
    client = contract.get("client_binary_messages")
    server = contract.get("server_binary_messages")
    fragments = contract.get("server_fragmented_binary_message")
    ping = contract.get("ping_pong")
    close = contract.get("close")
    if client != {"count": 64, "payload_bytes": 16384, "masked": True}:
        raise ManifestError("client WebSocket geometry is not workload v1")
    if server != {
        "unfragmented_count": 63,
        "payload_bytes": 16384,
        "masked": False,
    }:
        raise ManifestError("server WebSocket geometry is not workload v1")
    if fragments != [
        {"opcode": 2, "payload_bytes": 8192, "final": False, "masked": False},
        {"opcode": 0, "payload_bytes": 8192, "final": True, "masked": False},
    ]:
        raise ManifestError("server fragmentation is not workload v1")
    if ping != {
        "server_ping_payload_bytes": 12,
        "client_pong_payload_bytes": 12,
        "client_pong_masked": True,
    }:
        raise ManifestError("WebSocket controls are not workload v1")
    if close != {
        "kind": "graceful-websocket",
        "payload_bytes": 18,
        "client_masked": True,
        "server_masked": False,
        "h2_ping_immediately_before_close": True,
        "h2_ping_originator": "client",
    }:
        raise ManifestError("close behavior is not workload v1")
    if (
        contract.get("websocket_bytes_each_direction") != 1024 * 1024
        or contract.get("idle_ms") != 42000
        or client["count"] * client["payload_bytes"]
        != contract["websocket_bytes_each_direction"]
    ):
        raise ManifestError("workload v1 transfer or idle size drift")
    return document, hashlib.sha256(raw).hexdigest()


GIT_TIMEOUT_SECONDS = 10
MAX_GIT_OUTPUT_BYTES = 1024


def git_output(repo: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise ManifestError("Git identity command timed out") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or "git command failed"
        raise ManifestError(detail[:MAX_GIT_OUTPUT_BYTES])
    if len(result.stdout.encode("utf-8")) > MAX_GIT_OUTPUT_BYTES:
        raise ManifestError("Git identity output is unexpectedly large")
    return result.stdout.strip()


def git_checkout_is_dirty(repo: Path) -> bool:
    """Detect the first status record without buffering an unbounded listing."""
    process = subprocess.Popen(
        [
            "git", "-C", str(repo), "status", "--porcelain=v1",
            "--untracked-files=normal",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                process.kill()
                process.wait()
                raise ManifestError("Git cleanliness check timed out")
            first_byte = os.read(process.stdout.fileno(), 1)
            if first_byte:
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                return True
            return_code = process.wait(timeout=1)
            if return_code != 0:
                raise ManifestError("Git cleanliness check failed")
            return False
    finally:
        selector.close()
        process.stdout.close()


def source_identity(repo: Path) -> tuple[str, str]:
    resolved = repo.resolve(strict=True)
    commit = git_output(resolved, "rev-parse", "--verify", "HEAD^{commit}")
    tree = git_output(resolved, "rev-parse", "--verify", "HEAD^{tree}")
    if not OBJECT_ID_RE.fullmatch(commit) or not OBJECT_ID_RE.fullmatch(tree):
        raise ManifestError("Git returned an invalid commit or tree object ID")
    if git_checkout_is_dirty(resolved):
        raise ManifestError("capture source checkout is not clean")
    return commit, tree


def require_identity(actual: str, expected: str, label: str) -> None:
    if actual != expected:
        raise ManifestError(f"{label} mismatch: got {actual!r}")


def build_environment(args: argparse.Namespace) -> dict[str, Any]:
    if args.arm not in {"normal", "yume"}:
        raise ManifestError("capture arm must be normal or yume")
    if args.chrome_sandbox != "user-namespace":
        raise ManifestError("Chrome sandbox must be user-namespace")
    require_identity(
        args.chrome_version,
        f"Google Chrome {PINNED_CHROME_VERSION}",
        "Chrome version",
    )
    require_identity(
        args.chrome_launcher_sha256,
        PINNED_CHROME_LAUNCHER_SHA256,
        "Chrome launcher SHA-256",
    )
    require_identity(
        args.chrome_binary_sha256,
        PINNED_CHROME_BINARY_SHA256,
        "Chrome binary SHA-256",
    )
    require_identity(
        args.node_version, f"v{PINNED_NODE_VERSION}", "Node version"
    )
    require_identity(
        args.node_binary_sha256,
        PINNED_NODE_BINARY_SHA256,
        "Node binary SHA-256",
    )
    if not SNI_RE.fullmatch(args.sni):
        raise ManifestError("SNI is not a valid non-empty DNS name")
    if not 1 <= args.runs <= 20:
        raise ManifestError("runs must be in 1..20")
    if not 0 <= args.idle_ms <= 120_000:
        raise ManifestError("idle-ms must be in 0..120000")

    commit, tree = source_identity(args.repo)
    workload, workload_sha256 = load_workload()
    actual_contract = deepcopy(workload["contract"])
    actual_contract["idle_ms"] = args.idle_ms
    certificate_sha256 = hashlib.sha256(
        read_regular_nofollow(args.certificate)
    ).hexdigest()
    if args.arm == "yume":
        for field, value in (
            ("YUME binary SHA-256", args.yume_binary_sha256),
            ("YUME helper SHA-256", args.yume_helper_sha256),
            ("release bundle SHA-256", args.release_bundle_sha256),
            ("TLS leaf SHA-256", args.tls_leaf_sha256),
        ):
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ManifestError(f"{field} must be lowercase 64-hex")
    elif (
        args.yume_binary_sha256
        or args.yume_helper_sha256
        or args.release_bundle_sha256
        or args.tls_leaf_sha256
    ):
        raise ManifestError("normal arm must not declare YUME runtime hashes")
    environment = {
        "schema": 1,
        "arm": args.arm,
        "source_commit": commit,
        "source_tree": tree,
        "source_dirty": False,
        "chrome_version": args.chrome_version,
        "chrome_launcher": args.chrome_launcher,
        "chrome_launcher_sha256": args.chrome_launcher_sha256,
        "chrome_binary": args.chrome_binary,
        "chrome_binary_sha256": args.chrome_binary_sha256,
        "chrome_sandbox": args.chrome_sandbox,
        "node_version": args.node_version,
        "node_binary_sha256": args.node_binary_sha256,
        "display": args.display,
        "runs": args.runs,
        "idle_ms": args.idle_ms,
        "tls_wire_evidence": bool(args.tls_wire_evidence),
        "certificate_sha256": certificate_sha256,
        "sni": args.sni,
        "alpn": "h2",
        "transport_profile": workload["transport_profile"],
        "workload_manifest": {
            "schema": workload["schema"],
            "id": workload["id"],
            "sha256": workload_sha256,
        },
        "workload": actual_contract,
    }
    if args.arm == "yume":
        environment["yume_binary_sha256"] = args.yume_binary_sha256
        environment["yume_helper_sha256"] = args.yume_helper_sha256
        environment["release_bundle_sha256"] = args.release_bundle_sha256
        environment["tls_leaf_sha256"] = args.tls_leaf_sha256
    return environment


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        payload = (json.dumps(value, indent=2) + "\n").encode("utf-8")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while creating environment manifest")
            view = view[written:]
    finally:
        os.close(descriptor)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--output", required=True, type=Path)
    result.add_argument("--arm", required=True, choices=("normal", "yume"))
    result.add_argument("--repo", required=True, type=Path)
    result.add_argument("--certificate", required=True, type=Path)
    result.add_argument("--sni", required=True)
    result.add_argument("--runs", required=True, type=int)
    result.add_argument("--idle-ms", required=True, type=int)
    result.add_argument("--chrome-version", required=True)
    result.add_argument("--chrome-launcher", required=True)
    result.add_argument("--chrome-launcher-sha256", required=True)
    result.add_argument("--chrome-binary", required=True)
    result.add_argument("--chrome-binary-sha256", required=True)
    result.add_argument("--chrome-sandbox", required=True)
    result.add_argument("--node-version", required=True)
    result.add_argument("--node-binary-sha256", required=True)
    result.add_argument("--display", required=True)
    result.add_argument("--yume-binary-sha256", default="")
    result.add_argument("--yume-helper-sha256", default="")
    result.add_argument("--release-bundle-sha256", default="")
    result.add_argument("--tls-leaf-sha256", default="")
    result.add_argument(
        "--tls-wire-evidence", required=True, type=int, choices=(0, 1)
    )
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        write_private_json(args.output, build_environment(args))
    except (ManifestError, OSError) as exc:
        print(f"capture manifest rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
