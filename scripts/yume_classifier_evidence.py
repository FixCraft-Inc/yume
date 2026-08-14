#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Validate matched-session inputs for classifier and active-probe work.

This tool validates evidence provenance and workload equivalence. It does not
run a classifier or turn a matching input contract into a DPI-immunity claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import asdict, dataclass
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
from yume_chrome_evidence import validate_run  # noqa: E402
from yume_capture_finalize import (  # noqa: E402
    EXPECTED_RUNTIME_FILES,
    MAX_OPAQUE_BYTES,
    FinalizeError,
    parse_checksum_manifest,
)
from yume_capture_manifest import load_workload  # noqa: E402
from yume_tls_wire import (  # noqa: E402
    ParseError,
    validate_client_hello,
    validate_server_hello,
)


REQUIRED_RUNS = 5
MAX_JSON_BYTES = 4 * 1024 * 1024
OBJECT_ID_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERDICT_EXIT = {"PARITY": 0, "DRIFT": 1, "KNOWN_GAP": 2}
TLS_PROFILE = (
    Path(__file__).resolve().parents[1]
    / "tests/fixtures/chrome151-node24/chrome_tls_wire_profile.json"
)
WORKLOAD_MANIFEST = (
    Path(__file__).resolve().parents[1] / "tools/cover-node/workload-v1.json"
)
_WORKLOAD_DOCUMENT, _WORKLOAD_SHA256 = load_workload(WORKLOAD_MANIFEST)
EXPECTED_WORKLOAD = _WORKLOAD_DOCUMENT["contract"]
EXPECTED_WORKLOAD_MANIFEST = {
    "schema": _WORKLOAD_DOCUMENT["schema"],
    "id": _WORKLOAD_DOCUMENT["id"],
    "sha256": _WORKLOAD_SHA256,
}


class EvidenceError(ValueError):
    """The evidence tree is malformed or unsafe to read."""


@dataclass(frozen=True)
class Finding:
    verdict: str
    field: str
    normal: object
    yume: object
    detail: str


@dataclass(frozen=True)
class ArmEvidence:
    root: Path
    environment: dict[str, Any]
    behavior_runs: list[dict[str, Any]]
    tls_runs: list[dict[str, Any]]
    certificate_sha256: str | None


class EvidenceReader:
    """Read one evidence tree through an anchored no-follow directory fd."""

    def __init__(self, path: Path) -> None:
        if path.is_symlink():
            raise EvidenceError(f"evidence root must not be a symlink: {path}")
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            self._root_fd = os.open(path, flags)
        except OSError as exc:
            raise EvidenceError(f"cannot anchor evidence root: {path}") from exc
        metadata = os.fstat(self._root_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(self._root_fd)
            raise EvidenceError(f"evidence root is not a directory: {path}")
        self.path = path.resolve(strict=True)

    def close(self) -> None:
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> "EvidenceReader":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @staticmethod
    def _parts(relative: Path) -> tuple[str, ...]:
        if (
            relative.is_absolute()
            or not relative.parts
            or ".." in relative.parts
            or "." in relative.parts
        ):
            raise EvidenceError(f"unsafe evidence path: {relative}")
        return relative.parts

    def bytes(
        self, relative: Path, *, maximum: int = MAX_JSON_BYTES
    ) -> bytes:
        descriptor = self._open_regular(relative)
        try:
            before = os.fstat(descriptor)
            if before.st_size > maximum:
                raise EvidenceError(f"evidence input is too large: {relative}")
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
                raise EvidenceError(f"evidence changed while reading: {relative}")
            value = b"".join(chunks)
            if len(value) > maximum:
                raise EvidenceError(f"evidence input is too large: {relative}")
            return value
        finally:
            os.close(descriptor)

    def _open_regular(self, relative: Path) -> int:
        parts = self._parts(relative)
        directory_fd = os.dup(self._root_fd)
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
            file_flags |= os.O_NOFOLLOW
        try:
            for component in parts[:-1]:
                try:
                    next_fd = os.open(
                        component, directory_flags, dir_fd=directory_fd
                    )
                except FileNotFoundError:
                    raise
                except OSError as exc:
                    raise EvidenceError(
                        f"cannot traverse evidence directory: {relative}"
                    ) from exc
                os.close(directory_fd)
                directory_fd = next_fd
            try:
                descriptor = os.open(
                    parts[-1], file_flags, dir_fd=directory_fd
                )
            except FileNotFoundError:
                raise
            except OSError as exc:
                raise EvidenceError(
                    f"cannot open evidence file: {relative}"
                ) from exc
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                os.close(descriptor)
                raise EvidenceError(
                    f"evidence input is not a regular file: {relative}"
                )
            return descriptor
        finally:
            os.close(directory_fd)

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

    def json_object(self, relative: Path) -> dict[str, Any]:
        try:
            value = json.loads(self.bytes(relative))
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"invalid JSON evidence: {relative}") from exc
        if not isinstance(value, dict):
            raise EvidenceError(f"evidence JSON must be an object: {relative}")
        return value

    def optional_json_object(self, relative: Path) -> dict[str, Any] | None:
        try:
            return self.json_object(relative)
        except FileNotFoundError:
            return None

    def sha256(
        self, relative: Path, *, maximum: int = MAX_JSON_BYTES
    ) -> str:
        descriptor = self._open_regular(relative)
        digest = hashlib.sha256()
        try:
            before = os.fstat(descriptor)
            if before.st_size > maximum:
                raise EvidenceError(f"evidence input is too large: {relative}")
            total = 0
            while True:
                chunk = os.read(descriptor, 128 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise EvidenceError(f"evidence input is too large: {relative}")
                digest.update(chunk)
            after = os.fstat(descriptor)
            if not self._unchanged(before, after):
                raise EvidenceError(f"evidence changed while hashing: {relative}")
            return digest.hexdigest()
        finally:
            os.close(descriptor)


def _environment_runs(environment: dict[str, Any], label: str) -> int:
    runs = environment.get("runs")
    if not isinstance(runs, int) or isinstance(runs, bool) or runs != REQUIRED_RUNS:
        raise EvidenceError(
            f"{label} must declare exactly {REQUIRED_RUNS} runs"
        )
    return runs


def _checksum_entries(raw: bytes, label: str) -> dict[str, str]:
    try:
        return parse_checksum_manifest(raw)
    except FinalizeError as exc:
        raise EvidenceError(f"invalid {label}: {exc}") from exc


def _string_hash_mapping(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    result: dict[str, str] = {}
    for name, digest in value.items():
        if (
            not isinstance(name, str)
            or not isinstance(digest, str)
            or not SHA256_RE.fullmatch(digest)
        ):
            raise EvidenceError(f"{label} contains an invalid checksum entry")
        result[name] = digest
    return result


def _verify_hashes(
    reader: EvidenceReader,
    entries: dict[str, str],
    *,
    prefix: Path = Path(),
) -> None:
    for name, expected in entries.items():
        relative = prefix / Path(name)
        maximum = MAX_OPAQUE_BYTES if relative.name == "netlog.json" else MAX_JSON_BYTES
        try:
            actual = reader.sha256(relative, maximum=maximum)
        except FileNotFoundError as exc:
            raise EvidenceError(f"missing checksummed evidence: {relative}") from exc
        if actual != expected:
            raise EvidenceError(f"evidence checksum mismatch: {relative}")


def _verify_completion(
    reader: EvidenceReader,
    environment_raw: bytes,
    environment: dict[str, Any],
    expected_arm: str,
    runs: int,
) -> str:
    try:
        completion = reader.json_object(Path("complete.json"))
    except FileNotFoundError as exc:
        raise EvidenceError("capture completion marker is missing") from exc
    if (
        completion.get("schema") != 1
        or completion.get("status") != "complete"
        or completion.get("arm") != expected_arm
    ):
        raise EvidenceError("capture completion marker is invalid or mismatched")

    top_raw = reader.bytes(Path("SHA256SUMS"))
    if completion.get("top_level_sha256") != hashlib.sha256(top_raw).hexdigest():
        raise EvidenceError("top-level checksum manifest does not match completion")
    top_entries = _checksum_entries(top_raw, "top-level checksum manifest")
    expected_top = {
        "environment.json",
        "server.crt",
        "runtime-source/SHA256SUMS",
        *(f"run-{index:02d}/SHA256SUMS" for index in range(1, runs + 1)),
    }
    if set(top_entries) != expected_top:
        raise EvidenceError("top-level checksum paths are incomplete or unexpected")
    _verify_hashes(reader, top_entries)

    environment_sha256 = hashlib.sha256(environment_raw).hexdigest()
    if completion.get("environment_sha256") != environment_sha256:
        raise EvidenceError("environment manifest does not match completion")
    certificate_sha256 = reader.sha256(Path("server.crt"))
    if completion.get("certificate_sha256") != certificate_sha256:
        raise EvidenceError("certificate does not match completion")

    runtime = completion.get("runtime_source")
    if not isinstance(runtime, dict):
        raise EvidenceError("completion runtime_source must be an object")
    runtime_raw = reader.bytes(Path("runtime-source/SHA256SUMS"))
    if runtime.get("checksums_sha256") != hashlib.sha256(runtime_raw).hexdigest():
        raise EvidenceError("runtime checksum manifest does not match completion")
    runtime_entries = _checksum_entries(runtime_raw, "runtime checksum manifest")
    if set(runtime_entries) != set(EXPECTED_RUNTIME_FILES):
        raise EvidenceError("runtime checksum paths are incomplete or unexpected")
    if _string_hash_mapping(runtime.get("files"), "completion runtime files") != (
        runtime_entries
    ):
        raise EvidenceError("runtime checksums differ from completion")
    _verify_hashes(reader, runtime_entries, prefix=Path("runtime-source"))

    completed_runs = completion.get("runs")
    if not isinstance(completed_runs, list) or len(completed_runs) != runs:
        raise EvidenceError("completion does not contain every declared run")
    tls_wire = environment.get("tls_wire_evidence")
    if not isinstance(tls_wire, bool):
        raise EvidenceError("tls_wire_evidence must be Boolean")
    for index, completed in enumerate(completed_runs, start=1):
        name = f"run-{index:02d}"
        if not isinstance(completed, dict) or completed.get("name") != name:
            raise EvidenceError("completion run order or name is invalid")
        checksums_raw = reader.bytes(Path(name) / "SHA256SUMS")
        if completed.get("checksums_sha256") != hashlib.sha256(
            checksums_raw
        ).hexdigest():
            raise EvidenceError(f"{name} checksum manifest differs from completion")
        entries = _checksum_entries(checksums_raw, f"{name} checksum manifest")
        if expected_arm == "normal":
            expected = {"netlog.json", "sanitized.json"}
            if tls_wire:
                expected.add("tls-wire.json")
        else:
            expected = {"tls-wire.json"}
            if "behavior.json" in entries:
                expected.add("behavior.json")
        if set(entries) != expected:
            raise EvidenceError(f"{name} checksum paths are incomplete or unexpected")
        if _string_hash_mapping(
            completed.get("files"), f"completion {name} files"
        ) != entries:
            raise EvidenceError(f"{name} checksums differ from completion")
        _verify_hashes(reader, entries, prefix=Path(name))
    return certificate_sha256


def load_arm(path: Path, *, normal: bool) -> ArmEvidence:
    with EvidenceReader(path) as reader:
        environment_raw = reader.bytes(Path("environment.json"))
        try:
            environment = json.loads(environment_raw)
        except json.JSONDecodeError as exc:
            raise EvidenceError("invalid JSON evidence: environment.json") from exc
        if not isinstance(environment, dict):
            raise EvidenceError("evidence JSON must be an object: environment.json")
        expected_arm = "normal" if normal else "yume"
        if environment.get("arm") != expected_arm:
            raise EvidenceError(
                f"evidence arm must be {expected_arm!r}, got "
                f"{environment.get('arm')!r}"
            )
        if not normal:
            for field in (
                "yume_binary_sha256",
                "yume_helper_sha256",
                "release_bundle_sha256",
                "tls_leaf_sha256",
            ):
                value = environment.get(field)
                if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
                    raise EvidenceError(f"YUME {field} must be lowercase SHA-256")
        runs = _environment_runs(
            environment, "normal Chrome" if normal else "YUME"
        )
        certificate = _verify_completion(
            reader, environment_raw, environment, expected_arm, runs
        )
        behavior_name = "sanitized.json" if normal else "behavior.json"
        behavior_runs: list[dict[str, Any]] = []
        tls_runs: list[dict[str, Any]] = []
        for index in range(1, runs + 1):
            run = Path(f"run-{index:02d}")
            behavior = reader.optional_json_object(run / behavior_name)
            if behavior is None:
                if normal:
                    raise EvidenceError(
                        f"missing normal Chrome behavior: {run / behavior_name}"
                    )
            else:
                behavior_runs.append(behavior)
            tls_runs.append(reader.json_object(run / "tls-wire.json"))
        declared_certificate = environment.get("certificate_sha256")
        if declared_certificate is not None and (
            not isinstance(declared_certificate, str)
            or not SHA256_RE.fullmatch(declared_certificate)
        ):
            raise EvidenceError("certificate_sha256 must be a lowercase SHA-256")
        if declared_certificate != certificate:
            raise EvidenceError(
                "declared certificate SHA-256 does not match server.crt"
            )
        return ArmEvidence(
            reader.path, environment, behavior_runs, tls_runs, certificate
        )


def _value(environment: dict[str, Any], *names: str) -> object:
    for name in names:
        if name in environment:
            return environment[name]
    return None


def _header_pair_value(
    headers: object, name: str
) -> object:
    if not isinstance(headers, list):
        return None
    for pair in headers:
        if (
            isinstance(pair, list)
            and len(pair) == 2
            and pair[0] == name
            and isinstance(pair[1], str)
        ):
            return pair[1]
    return None


def _passive_lifecycle_projection(
    value: dict[str, Any]
) -> dict[str, Any] | None:
    """Project passive-visible request and WebSocket event order."""
    observations = value.get("observations")
    if not isinstance(observations, dict):
        return None

    requests: list[dict[str, Any]] = []
    websocket: list[dict[str, Any]] = []
    outer = observations.get("outer_events")
    if isinstance(outer, list):
        for event in outer:
            if not isinstance(event, dict):
                return None
            if (
                event.get("kind") == "h2-frame"
                and event.get("direction") == "sent"
                and event.get("h2_type") == 0x01
            ):
                method = _header_pair_value(
                    event.get("headers_in_order"), ":method"
                )
                path = _header_pair_value(
                    event.get("headers_in_order"), ":path"
                )
                stream_id = event.get("stream_id")
                if (
                    not isinstance(stream_id, int)
                    or isinstance(stream_id, bool)
                    or not isinstance(method, str)
                    or not isinstance(path, str)
                ):
                    return None
                if method == "CONNECT":
                    path = "<carrier-path>"
                requests.append({
                    "stream_id": stream_id,
                    "method": method,
                    "path": path,
                })
            elif event.get("kind") == "websocket-frame":
                item = {
                    "direction": event.get("direction"),
                    "opcode": event.get("opcode"),
                    "final": event.get("final"),
                    "payload_bytes": event.get("payload_bytes"),
                    "masked": event.get("masked"),
                }
                if websocket and all(
                    websocket[-1].get(key) == item[key] for key in item
                ):
                    websocket[-1]["count"] += 1
                else:
                    item["count"] = 1
                    websocket.append(item)
    else:
        headers = observations.get("headers")
        frames = observations.get("websocket_frames")
        if not isinstance(headers, list) or not isinstance(frames, list):
            return None
        for event in headers:
            if not isinstance(event, dict) or event.get("direction") != "sent":
                continue
            raw_headers = event.get("headers")
            if not isinstance(raw_headers, list) or not all(
                isinstance(item, str) for item in raw_headers
            ):
                return None
            method = next((
                item[len(":method: "):]
                for item in raw_headers if item.startswith(":method: ")
            ), None)
            path = next((
                item[len(":path: "):]
                for item in raw_headers if item.startswith(":path: ")
            ), None)
            stream_id = event.get("stream_id")
            if (
                not isinstance(stream_id, int)
                or isinstance(stream_id, bool)
                or not isinstance(method, str)
                or not isinstance(path, str)
            ):
                return None
            if method == "CONNECT":
                path = "<carrier-path>"
            requests.append({
                "stream_id": stream_id,
                "method": method,
                "path": path,
            })
        for entry in frames:
            if not isinstance(entry, dict):
                return None
            frame = entry.get("frame")
            count = entry.get("count")
            if (
                not isinstance(frame, dict)
                or not isinstance(count, int)
                or isinstance(count, bool)
                or count <= 0
            ):
                return None
            websocket.append({
                "direction": frame.get("direction"),
                "opcode": frame.get("opcode"),
                "final": frame.get("final"),
                "payload_bytes": frame.get("payload_length"),
                "masked": frame.get("masked"),
                "count": count,
            })

    if not requests or not websocket:
        return None
    return {
        "request_sequence": requests,
        "websocket_sequence": websocket,
    }


def _stable_behavior(value: dict[str, Any]) -> dict[str, Any]:
    flow_control = value.get("flow_control_fixture", {})
    idle = value.get("idle_and_close", {})
    return {
        "client_settings_in_order": value.get("client_settings_in_order"),
        "client_connection_window_update": value.get(
            "client_connection_window_update"
        ),
        "priming_get": value.get("priming_get"),
        "asset_sequence": value.get("asset_sequence"),
        "extended_connect": value.get("extended_connect"),
        "websocket_fixture": value.get("websocket_fixture"),
        "window_update_recovery_observed": flow_control.get(
            "window_update_recovery_observed"
        ),
        "graceful_websocket_close_observed": idle.get(
            "graceful_websocket_close_observed"
        ),
        "shaping_policy": value.get("shaping_policy"),
        "passive_lifecycle": _passive_lifecycle_projection(value),
    }


def _stable_projection(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    if len(runs) != REQUIRED_RUNS:
        return None
    projected = [_stable_behavior(run) for run in runs]
    if any(value != projected[0] for value in projected[1:]):
        return None
    return projected[0]


def _add_comparison(
    findings: list[Finding],
    field: str,
    normal: object,
    yume: object,
    *,
    detail: str,
) -> None:
    if normal is None or yume is None:
        findings.append(Finding("KNOWN_GAP", field, normal, yume, detail))
    elif normal != yume:
        findings.append(Finding("DRIFT", field, normal, yume, detail))


def _add_expected(
    findings: list[Finding],
    field: str,
    arm: str,
    actual: object,
    expected: object,
) -> None:
    if actual is None:
        findings.append(
            Finding("KNOWN_GAP", field, actual if arm == "normal" else expected,
                    expected if arm == "normal" else actual,
                    f"{arm} arm does not bind {field}")
        )
    elif actual != expected:
        findings.append(
            Finding("DRIFT", field, actual if arm == "normal" else expected,
                    expected if arm == "normal" else actual,
                    f"{arm} arm does not match the pinned profile")
        )


def _tls_profile_findings(arm: ArmEvidence, label: str) -> list[Finding]:
    findings: list[Finding] = []
    profile = json.loads(TLS_PROFILE.read_text(encoding="utf-8"))
    orders: set[tuple[str, ...]] = set()
    ech_lengths: set[int] = set()
    try:
        for report in arm.tls_runs:
            if report.get("schema") != 1:
                raise ParseError("unsupported TLS report schema")
            order, ech_length = validate_client_hello(
                report["client_hello"], profile["client_hello"]
            )
            validate_server_hello(
                report["server_hello"], profile["server_hello"]
            )
            orders.add(order)
            ech_lengths.add(ech_length)
        qualification = profile["qualification"]
        if len(orders) < qualification["minimum_distinct_middle_orders"]:
            raise ParseError("insufficient ClientHello extension-order diversity")
        if len(ech_lengths) < qualification["minimum_distinct_ech_lengths"]:
            raise ParseError("insufficient ECH-length diversity")
    except (KeyError, TypeError, ValueError, ParseError) as exc:
        findings.append(
            Finding(
                "DRIFT",
                f"tls_profile.{label}",
                "invalid" if label == "normal" else "chrome151-node24-v1",
                "chrome151-node24-v1" if label == "normal" else "invalid",
                str(exc),
            )
        )
    return findings


def _payload_distribution(events: list[dict[str, Any]]) -> object:
    counts: dict[int, int] = {}
    for event in events:
        size = event.get("payload_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("live WebSocket payload length is invalid")
        counts[size] = counts.get(size, 0) + 1
    if len(counts) == 1:
        return next(iter(counts))
    return [
        {"payload_bytes": size, "count": count}
        for size, count in sorted(counts.items())
    ]


def _live_binary_summary(
    events: list[dict[str, Any]], *, server: bool
) -> dict[str, Any]:
    masks = {event.get("masked") for event in events}
    return {
        "unfragmented_count" if server else "count": len(events),
        "payload_bytes": _payload_distribution(events),
        "masked": next(iter(masks)) if len(masks) == 1 else None,
    }


def _live_header_summary(event: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "stream_id": event.get("stream_id"),
        "headers_in_order": event.get("headers_in_order"),
    }
    priority = event.get("priority")
    if isinstance(priority, dict):
        summary.update(priority)
    return summary


def _validate_live_outer_events(run: dict[str, Any]) -> None:
    observations = run.get("observations")
    if not isinstance(observations, dict):
        raise ValueError("YUME live carrier observations are malformed")
    events = observations.get("outer_events")
    if not isinstance(events, list) or not 1 <= len(events) <= 4096:
        raise ValueError("YUME live carrier observations are missing or unbounded")
    allowed_kinds = {
        "h2-frame", "websocket-frame", "flow-window-stalled",
        "flow-window-recovered",
        "stream-close", "h2-headers-decoded", "idle-interval", "close-wire",
    }
    previous_ms = -1
    flow_window_stalled = False
    for event in events:
        if not isinstance(event, dict) or event.get("kind") not in allowed_kinds:
            raise ValueError("YUME live carrier event is malformed")
        if event.get("direction") not in {"sent", "received"}:
            raise ValueError("YUME live carrier direction is malformed")
        elapsed = event.get("milliseconds_after_session_start")
        if (
            not isinstance(elapsed, int)
            or isinstance(elapsed, bool)
            or elapsed < previous_ms
        ):
            raise ValueError("YUME live carrier timeline is malformed")
        previous_ms = elapsed
        kind = event["kind"]
        stream_class = event.get("stream_class")
        if stream_class not in {
            "connection", "priming", "asset-css", "asset-js", "carrier",
            "other",
        }:
            raise ValueError("YUME live carrier stream class is malformed")
        if kind == "h2-frame":
            for field, upper in (("h2_type", 0xFF), ("flags", 0xFF)):
                value = event.get(field)
                if (
                    not isinstance(value, int) or isinstance(value, bool)
                    or not 0 <= value <= upper
                ):
                    raise ValueError("YUME live H2 frame metadata is malformed")
            stream_id = event.get("stream_id")
            length = event.get("length")
            if (
                not isinstance(stream_id, int) or isinstance(stream_id, bool)
                or not 0 <= stream_id <= 0x7FFFFFFF
                or not isinstance(length, int) or isinstance(length, bool)
                or not 0 <= length <= 16 * 1024
            ):
                raise ValueError("YUME live H2 frame bounds are malformed")
            expected_class = {
                0: "connection", 1: "priming", 3: "asset-css",
                5: "asset-js", 7: "carrier", 9: "other",
            }.get(stream_id, "other")
            if stream_class != expected_class:
                raise ValueError("YUME live H2 stream classification is inconsistent")
            if stream_id not in {0, 1, 3, 5, 7, 9}:
                raise ValueError("YUME live H2 frame uses an unbound stream")
            frame_type = event["h2_type"]
            flags = event["flags"]
            settings = event.get("settings", [])
            if frame_type > 0x09:
                raise ValueError("YUME live H2 extension frame is not admitted")
            if frame_type in {0x02, 0x03, 0x05}:
                raise ValueError(
                    "YUME live H2 frame is outside the successful exact lifecycle"
                )
            if frame_type in {0x00, 0x01, 0x09} and length == 0:
                raise ValueError("YUME live H2 payload frame is empty")
            permitted_flags = {
                0x00: 0x09,  # END_STREAM | PADDED
                0x01: 0x2D,  # END_STREAM | END_HEADERS | PADDED | PRIORITY
                0x02: 0x00,
                0x03: 0x00,
                0x04: 0x01,
                0x05: 0x0C,  # END_HEADERS | PADDED
                0x06: 0x01,
                0x07: 0x00,
                0x08: 0x00,
                0x09: 0x04,
            }.get(frame_type)
            if permitted_flags is not None and flags & ~permitted_flags:
                raise ValueError("YUME live H2 frame flags are malformed")
            if frame_type in {0x00, 0x01, 0x02, 0x03, 0x05, 0x09} and stream_id == 0:
                raise ValueError("YUME live H2 stream-scoped frame uses stream zero")
            if frame_type in {0x04, 0x06, 0x07} and stream_id != 0:
                raise ValueError("YUME live H2 connection frame uses a stream")
            if frame_type == 0x04:
                if flags & 0x01:
                    if length != 0 or settings not in ([], None):
                        raise ValueError("YUME live H2 SETTINGS ACK is malformed")
                elif (
                    length % 6 != 0
                    or not isinstance(settings, list)
                    or length != 6 * len(settings)
                    or any(
                        not isinstance(item, list) or len(item) != 3
                        or not isinstance(item[0], int)
                        or isinstance(item[0], bool)
                        or not 0 <= item[0] <= 0xFFFF
                        or not isinstance(item[1], int)
                        or isinstance(item[1], bool)
                        or not 0 <= item[1] <= 0xFFFFFFFF
                        or not isinstance(item[2], str)
                        for item in settings
                    )
                ):
                    raise ValueError("YUME live H2 SETTINGS metadata is malformed")
            elif frame_type == 0x06 and (
                length != 8
                or not isinstance(event.get("is_ack"), bool)
                or event["is_ack"] is not bool(flags & 0x01)
                or not isinstance(event.get("unique_id"), int)
                or isinstance(event.get("unique_id"), bool)
                or event["unique_id"] < 0
            ):
                raise ValueError("YUME live H2 PING metadata is malformed")
            elif frame_type == 0x08 and (
                length != 4
                or not isinstance(event.get("delta"), int)
                or isinstance(event.get("delta"), bool)
                or not 1 <= event["delta"] <= 0x7FFFFFFF
            ):
                raise ValueError("YUME live H2 WINDOW_UPDATE metadata is malformed")
            elif frame_type == 0x07 and (
                length < 8
                or not isinstance(event.get("error_code"), int)
                or isinstance(event.get("error_code"), bool)
                or not 0 <= event["error_code"] <= 0xFFFFFFFF
            ):
                raise ValueError("YUME live H2 GOAWAY metadata is malformed")
            elif frame_type == 0x01:
                prefix_bytes = (1 if flags & 0x08 else 0) + (
                    5 if flags & 0x20 else 0
                )
                priority = event.get("priority")
                if length < prefix_bytes or (flags & 0x20) != (
                    0x20 if isinstance(priority, dict) else 0
                ):
                    raise ValueError("YUME live H2 HEADERS prefix is malformed")
                if isinstance(priority, dict) and (
                    set(priority) != {"parent_stream_id", "exclusive", "weight"}
                    or not isinstance(priority.get("parent_stream_id"), int)
                    or isinstance(priority.get("parent_stream_id"), bool)
                    or not 0 <= priority["parent_stream_id"] <= 0x7FFFFFFF
                    or not isinstance(priority.get("exclusive"), bool)
                    or not isinstance(priority.get("weight"), int)
                    or isinstance(priority.get("weight"), bool)
                    or not 1 <= priority["weight"] <= 256
                ):
                    raise ValueError("YUME live H2 HEADERS priority is malformed")
        elif kind == "h2-headers-decoded":
            if (
                not isinstance(event.get("stream_id"), int)
                or isinstance(event.get("stream_id"), bool)
                or event["stream_id"] <= 0
                or not isinstance(event.get("headers_in_order"), list)
            ):
                raise ValueError("YUME live decoded headers are malformed")
            expected_class = {
                1: "priming", 3: "asset-css", 5: "asset-js", 7: "carrier",
                9: "other",
            }.get(event["stream_id"])
            if event["direction"] != "received" or stream_class != expected_class:
                raise ValueError("YUME decoded headers have impossible provenance")
        elif kind == "websocket-frame":
            if (
                event.get("opcode") not in {0x00, 0x02, 0x08, 0x09, 0x0A}
                or not isinstance(event.get("final"), bool)
                or not isinstance(event.get("masked"), bool)
                or not isinstance(event.get("payload_bytes"), int)
                or isinstance(event.get("payload_bytes"), bool)
                or not 0 <= event["payload_bytes"] <= 16 * 1024 * 1024
            ):
                raise ValueError("YUME live WebSocket frame metadata is malformed")
            if stream_class != "carrier":
                raise ValueError("YUME live WebSocket stream class is malformed")
            expected_masked = event["direction"] == "sent"
            if event["masked"] is not expected_masked:
                raise ValueError("YUME live WebSocket masking role is inconsistent")
            if event["opcode"] in {0x08, 0x09, 0x0A} and (
                event["final"] is not True or event["payload_bytes"] > 125
            ):
                raise ValueError("YUME live WebSocket control frame is malformed")
            if (
                (event["opcode"] == 0x09 and event["direction"] != "received")
                or (event["opcode"] == 0x0A and event["direction"] != "sent")
            ):
                raise ValueError("YUME live WebSocket control role is inconsistent")
        elif kind in {"flow-window-stalled", "flow-window-recovered"}:
            if event["direction"] != "sent" or stream_class != "carrier":
                raise ValueError("YUME live flow event has impossible provenance")
            if kind == "flow-window-stalled":
                if flow_window_stalled:
                    raise ValueError("YUME live flow-window sequence is malformed")
                flow_window_stalled = True
            else:
                if not flow_window_stalled:
                    raise ValueError("YUME live flow-window sequence is malformed")
                flow_window_stalled = False
        elif kind == "stream-close":
            stream_id = event.get("stream_id")
            error_code = event.get("error_code")
            completed = event.get("completed")
            if (
                not isinstance(stream_id, int) or isinstance(stream_id, bool)
                or not 1 <= stream_id <= 0x7FFFFFFF
                or not isinstance(error_code, int) or isinstance(error_code, bool)
                or not 0 <= error_code <= 0xFFFFFFFF
                or not isinstance(completed, bool)
            ):
                raise ValueError("YUME stream-close metadata is malformed")
            expected_class = {
                1: "priming", 3: "asset-css", 5: "asset-js", 7: "carrier",
            }.get(stream_id, "other")
            if event["direction"] != "received" or stream_class != expected_class:
                raise ValueError("YUME stream-close event has impossible provenance")
        elif kind in {"idle-interval", "close-wire"}:
            if event["direction"] != "sent" or stream_class != "carrier":
                raise ValueError("YUME terminal event has impossible provenance")

    if flow_window_stalled:
        raise ValueError("YUME live flow-window recovery is incomplete")

    h2 = [event for event in events if event["kind"] == "h2-frame"]
    websocket = [
        event for event in events if event["kind"] == "websocket-frame"
    ]

    def first_h2(direction: str, frame_type: int, stream_id: int | None = None,
                 *, ack: bool | None = None) -> dict[str, Any] | None:
        matching = []
        for event in h2:
            if event.get("direction") != direction or event.get("h2_type") != frame_type:
                continue
            if stream_id is not None and event.get("stream_id") != stream_id:
                continue
            if ack is not None and bool(event.get("flags", 0) & 0x01) != ack:
                continue
            matching.append(event)
        return matching[0] if len(matching) == 1 else None

    client_settings = first_h2("sent", 0x04, 0, ack=False)
    server_settings = first_h2("received", 0x04, 0, ack=False)
    client_settings_ack = first_h2("sent", 0x04, 0, ack=True)
    server_settings_ack = first_h2("received", 0x04, 0, ack=True)
    connection_window = first_h2("sent", 0x08, 0)
    if (
        not client_settings
        or not server_settings
        or not client_settings_ack
        or not server_settings_ack
        or not connection_window
    ):
        raise ValueError("YUME live H2 opening observations are incomplete")
    if client_settings.get("settings") != run.get("client_settings_in_order"):
        raise ValueError("YUME live client SETTINGS summary is inconsistent")
    if server_settings.get("settings") != run.get("node_non_default_settings_in_order"):
        raise ValueError("YUME live server SETTINGS summary is inconsistent")
    window = run.get("client_connection_window_update")
    if not isinstance(window, dict):
        raise ValueError("YUME connection WINDOW_UPDATE summary is malformed")
    if (
        window.get("stream_id") != connection_window.get("stream_id")
        or window.get("delta") != connection_window.get("delta")
        or window.get("resulting_window") != 65535 + connection_window.get("delta", -65535)
    ):
        raise ValueError("YUME live connection WINDOW_UPDATE summary is inconsistent")

    def first_headers(direction: str, stream_id: int) -> dict[str, Any] | None:
        required_kind = "h2-frame" if direction == "sent" else "h2-headers-decoded"
        matching = [event for event in events if (
            event.get("direction") == direction
            and event.get("kind") == required_kind
            and (direction != "sent" or event.get("h2_type") == 0x01)
            and event.get("stream_id") == stream_id
            and isinstance(event.get("headers_in_order"), list)
        )]
        if len(matching) != 1:
            return None
        return matching[0]

    requests = [first_headers("sent", stream_id) for stream_id in (1, 3, 5, 7)]
    response = first_headers("received", 7)
    if any(event is None for event in requests) or response is None:
        raise ValueError("YUME live H2 request/response observations are incomplete")
    priming, css, js, connect = requests
    assert priming is not None and css is not None and js is not None and connect is not None

    known_streams = {1, 3, 5, 7}
    if any(event.get("stream_id") == 9 for event in h2):
        known_streams.add(9)
    for direction in ("sent", "received"):
        directional_h2 = [event for event in h2 if event.get("direction") == direction]
        consumed_continuations: set[int] = set()
        for stream_id in known_streams:
            raw_headers = [event for event in directional_h2 if (
                event.get("h2_type") == 0x01
                and event.get("stream_id") == stream_id
            )]
            if len(raw_headers) != 1:
                raise ValueError("YUME raw HEADERS cardinality is inconsistent")
            raw_position = directional_h2.index(raw_headers[0])
            if not raw_headers[0].get("flags", 0) & 0x04:
                continuation_position = raw_position + 1
                while continuation_position < len(directional_h2):
                    continuation = directional_h2[continuation_position]
                    if (
                        continuation.get("h2_type") != 0x09
                        or continuation.get("stream_id") != stream_id
                    ):
                        raise ValueError("YUME raw CONTINUATION chain is incomplete")
                    consumed_continuations.add(id(continuation))
                    if continuation.get("flags", 0) & 0x04:
                        break
                    continuation_position += 1
                else:
                    raise ValueError("YUME raw CONTINUATION chain is incomplete")
        if any(
            event.get("h2_type") == 0x09
            and event.get("stream_id") in known_streams
            and id(event) not in consumed_continuations
            for event in directional_h2
        ):
            raise ValueError("YUME raw CONTINUATION frame is orphaned")

    for stream_id in known_streams:
        decoded = first_headers("received", stream_id)
        if decoded is None:
            raise ValueError("YUME decoded response headers are incomplete")
        decoded_index = events.index(decoded)
        raw_indexes = [index for index, event in enumerate(events) if (
            event.get("kind") == "h2-frame"
            and event.get("direction") == "received"
            and event.get("h2_type") == 0x01
            and event.get("stream_id") == stream_id
        )]
        if len(raw_indexes) != 1 or raw_indexes[0] >= decoded_index:
            raise ValueError("YUME raw response HEADERS provenance is missing")
    stream_closes = [
        event for event in events if event.get("kind") == "stream-close"
    ]
    if (
        any(event["stream_id"] not in {1, 3, 5, 7, 9} for event in stream_closes)
        or len({event["stream_id"] for event in stream_closes})
        != len(stream_closes)
    ):
        raise ValueError("YUME live stream-close sequence is malformed")
    for stream_id in (1, 3, 5):
        decoded = first_headers("received", stream_id)
        stream_close = next((event for event in stream_closes if (
            event["stream_id"] == stream_id
        )), None)
        if (
            decoded is None or stream_close is None
            or stream_close["error_code"] != 0
            or stream_close["completed"] is not True
            or events.index(stream_close) <= events.index(decoded)
        ):
            raise ValueError("YUME live response stream-close is incomplete")
    if 9 in known_streams:
        favicon_response = first_headers("received", 9)
        favicon_close = next((event for event in stream_closes if (
            event["stream_id"] == 9
        )), None)
        if (
            favicon_response is None or favicon_close is None
            or favicon_close["error_code"] != 0
            or favicon_close["completed"] is not True
            or events.index(favicon_close) <= events.index(favicon_response)
        ):
            raise ValueError("YUME live favicon response lifecycle is incomplete")
    request_positions = {
        stream_id: events.index(event)
        for stream_id, event in zip((1, 3, 5, 7), requests)
        if event is not None
    }
    close_positions = {
        event["stream_id"]: events.index(event) for event in stream_closes
    }
    completed_priming_lifecycle = (
        request_positions[1] < close_positions[1]
        < request_positions[3]
        < request_positions[5]
        and request_positions[3] < close_positions[3]
        < request_positions[7]
        and request_positions[5] < close_positions[5]
        < request_positions[7]
    )
    if not completed_priming_lifecycle:
        raise ValueError("YUME live request lifecycle is producer-impossible")
    if 9 in known_streams:
        favicon_request = first_headers("sent", 9)
        if (
            favicon_request is None
            or events.index(favicon_request) <= request_positions[7]
        ):
            raise ValueError("YUME live favicon request order is inconsistent")
    if _live_header_summary(priming) != run.get("priming_get"):
        raise ValueError("YUME live priming headers are inconsistent")
    def header_value(event: dict[str, Any], name: str) -> Any:
        for pair in event.get("headers_in_order", []):
            if isinstance(pair, list) and len(pair) == 2 and pair[0] == name:
                return pair[1]
        return None

    expected_assets = []
    for event in (css, js):
        summary = _live_header_summary(event)
        summary["path"] = header_value(event, ":path")
        expected_assets.append(summary)
    if expected_assets != run.get("asset_sequence"):
        raise ValueError("YUME live asset headers are inconsistent")
    expected_connect = _live_header_summary(connect)
    expected_connect["requires_completed_priming_get"] = (
        completed_priming_lifecycle
    )
    expected_connect["node_response_headers_in_order"] = response.get("headers_in_order")
    if expected_connect != run.get("extended_connect"):
        raise ValueError("YUME live extended CONNECT summary is inconsistent")

    sent_binary = [event for event in websocket if (
        event.get("direction") == "sent" and event.get("opcode") == 0x02
    )]
    received_binary = [event for event in websocket if (
        event.get("direction") == "received" and event.get("opcode") == 0x02
        and event.get("final") is True
    )]
    received_fragments = [event for event in websocket if (
        event.get("direction") == "received"
        and event.get("opcode") in {0x00, 0x02}
        and not (event.get("opcode") == 0x02 and event.get("final") is True)
    )]
    fixture = run.get("websocket_fixture")
    if not isinstance(fixture, dict):
        raise ValueError("YUME WebSocket summary is malformed")
    if _live_binary_summary(sent_binary, server=False) != fixture.get("client_binary_messages"):
        raise ValueError("YUME live client WebSocket summary is inconsistent")
    if _live_binary_summary(received_binary, server=True) != fixture.get("server_binary_messages"):
        raise ValueError("YUME live server WebSocket summary is inconsistent")
    fragmented: list[dict[str, Any]] = []
    for first, second in zip(received_fragments, received_fragments[1:]):
        if (
            first.get("opcode") == 0x02 and first.get("final") is False
            and second.get("opcode") == 0x00 and second.get("final") is True
        ):
            fragmented = [
                {key: first.get(key) for key in ("opcode", "final", "payload_bytes", "masked")},
                {key: second.get(key) for key in ("opcode", "final", "payload_bytes", "masked")},
            ]
            break
    if fragmented != fixture.get("server_fragmented_binary_message"):
        raise ValueError("YUME live fragmented WebSocket summary is inconsistent")

    server_pings = [event for event in websocket if (
        event.get("direction") == "received" and event.get("opcode") == 0x09
    )]
    client_pongs = [event for event in websocket if (
        event.get("direction") == "sent" and event.get("opcode") == 0x0A
    )]
    sent_closes = [event for event in websocket if (
        event.get("direction") == "sent" and event.get("opcode") == 0x08
    )]
    received_closes = [event for event in websocket if (
        event.get("direction") == "received" and event.get("opcode") == 0x08
    )]
    if not all(len(group) == 1 for group in (
        server_pings, client_pongs, sent_closes, received_closes
    )):
        raise ValueError("YUME live WebSocket control counts are inconsistent")
    server_ping = server_pings[0]
    client_pong = client_pongs[0]
    expected_ping_pong = {
        "server_ping_payload_bytes": server_ping.get("payload_bytes") if server_ping else None,
        "client_pong_payload_bytes": client_pong.get("payload_bytes") if client_pong else None,
        "client_pong_masked": client_pong.get("masked") if client_pong else None,
    }
    if expected_ping_pong != fixture.get("ping_pong"):
        raise ValueError("YUME live WebSocket control summary is inconsistent")
    websocket_positions = {id(event): index for index, event in enumerate(websocket)}
    first_fragment = received_fragments[0] if received_fragments else None
    if (
        not sent_binary or first_fragment is None or not received_binary
        or websocket_positions[id(sent_binary[-1])]
        >= websocket_positions[id(server_ping)]
        or websocket_positions[id(server_ping)] + 1
        != websocket_positions[id(first_fragment)]
        or websocket_positions[id(client_pong)]
        <= websocket_positions[id(received_binary[-1])]
    ):
        raise ValueError("YUME live WebSocket PING/echo order is inconsistent")
    sent_close = sent_closes[0]
    received_close = received_closes[0]
    sent_close_index = events.index(sent_close)
    terminal_ping_index = next((index for index, event in enumerate(events) if (
        event.get("kind") == "h2-frame"
        and event.get("direction") == "sent"
        and event.get("h2_type") == 0x06
        and not event.get("flags", 0) & 0x01
    )), None)
    terminal_data_index = next((index for index, event in enumerate(events) if (
        terminal_ping_index is not None
        and terminal_ping_index < index < sent_close_index
        and event.get("kind") == "h2-frame"
        and event.get("direction") == "sent"
        and event.get("h2_type") == 0x00
        and event.get("stream_id") == 7
    )), None)
    terminal_goaway_index = next((index for index, event in enumerate(events) if (
        index > sent_close_index
        and event.get("kind") == "h2-frame"
        and event.get("direction") == "sent"
        and event.get("h2_type") == 0x07
        and event.get("stream_id") == 0
    )), None)
    if (
        terminal_ping_index is None or terminal_data_index is None
        or terminal_goaway_index is None
        or sent_close.get("h2_ping_immediately_before") is not True
    ):
        raise ValueError("YUME live terminal H2/WebSocket sequence is inconsistent")
    expected_close = {
        "payload_bytes": sent_close.get("payload_bytes"),
        "client_masked": sent_close.get("masked"),
        "server_masked": received_close.get("masked") if received_close else None,
        "h2_ping_immediately_before_close": sent_close.get(
            "h2_ping_immediately_before", False
        ),
        "h2_ping_originator": "client" if first_h2("sent", 0x06, 0, ack=False) else "unobserved",
    }
    if expected_close != fixture.get("close"):
        raise ValueError("YUME live WebSocket close summary is inconsistent")

    idle_events = [event for event in events if (
        event.get("kind") == "idle-interval"
    )]
    close_wires = [event for event in events if (
        event.get("kind") == "close-wire"
    )]
    if len(idle_events) != 1 or len(close_wires) != 1:
        raise ValueError("YUME live one-shot terminal events are inconsistent")
    idle_event = idle_events[0]
    close_wire = close_wires[0]
    sent_goaway = first_h2("sent", 0x07, 0)
    recovered = any(
        event.get("kind") == "h2-frame"
        and event.get("direction") == "received"
        and event.get("h2_type") == 0x08
        for event in events
    )
    if (
        idle_event is None or idle_event.get("completed") is not True
        or close_wire is None or close_wire.get("completed") is not True
        or sent_goaway is None
        or events.index(idle_event) >= terminal_ping_index
        or events.index(close_wire) <= terminal_goaway_index
    ):
        raise ValueError("YUME live idle/terminal observations are incomplete")
    flow = run.get("flow_control_fixture")
    if not isinstance(flow, dict):
        raise ValueError("YUME flow-control summary is malformed")
    if flow.get("client_stream_send_stalls") != sum(
        event.get("kind") == "flow-window-stalled" for event in events
    ) or flow.get("window_update_recovery_observed") is not recovered:
        raise ValueError("YUME live flow-control summary is inconsistent")
    idle = run.get("idle_and_close")
    if not isinstance(idle, dict):
        raise ValueError("YUME idle/close summary is malformed")
    expected_h2_pings = [
        {
            "milliseconds_after_session_start": event["milliseconds_after_session_start"],
            "is_ack": bool(event.get("flags", 0) & 0x01),
            "type": event["direction"],
            "unique_id": event.get("unique_id", 0),
        }
        for event in h2 if event.get("h2_type") == 0x06
    ]
    if (
        len(expected_h2_pings) != 2
        or expected_h2_pings[0]["type"] != "sent"
        or expected_h2_pings[0]["is_ack"] is not False
        or expected_h2_pings[1]["type"] != "received"
        or expected_h2_pings[1]["is_ack"] is not True
        or not isinstance(expected_h2_pings[0]["unique_id"], int)
        or isinstance(expected_h2_pings[0]["unique_id"], bool)
        or expected_h2_pings[0]["unique_id"] <= 0
        or expected_h2_pings[1]["unique_id"]
        != expected_h2_pings[0]["unique_id"]
    ):
        raise ValueError("YUME live H2 PING correlation is inconsistent")
    if (
        idle.get("requested_idle_ms") != idle_event.get("requested_ms")
        or idle.get("h2_pings") != expected_h2_pings
        or idle.get("graceful_websocket_close_observed") is not (
            received_close is not None and close_wire.get("completed") is True
        )
    ):
        raise ValueError("YUME live idle/close summary is inconsistent")


def _behavior_findings(arm: ArmEvidence, label: str) -> list[Finding]:
    findings: list[Finding] = []
    for index, run in enumerate(arm.behavior_runs, start=1):
        try:
            if label == "yume":
                if run.get("capture_status") != "complete":
                    raise ValueError("YUME live carrier capture is incomplete")
                if run.get("capture_source") != "live-production-carrier":
                    raise ValueError("YUME behavior is not from the live production carrier")
                _validate_live_outer_events(run)
            validate_run(
                run, f"{label}-run-{index:02d}",
                require_tls_observation=label != "yume",
            )
            websocket = run["websocket_fixture"]
            if websocket["client_binary_messages"] != (
                EXPECTED_WORKLOAD["client_binary_messages"]
            ):
                raise ValueError("client WebSocket message geometry drift")
            if websocket["server_binary_messages"] != (
                EXPECTED_WORKLOAD["server_binary_messages"]
            ):
                raise ValueError("server WebSocket message geometry drift")
            if websocket["server_fragmented_binary_message"] != (
                EXPECTED_WORKLOAD["server_fragmented_binary_message"]
            ):
                raise ValueError("fragmented WebSocket message geometry drift")
            if websocket["ping_pong"] != EXPECTED_WORKLOAD["ping_pong"]:
                raise ValueError("WebSocket ping/pong behavior drift")
            close = websocket["close"]
            expected_close = dict(EXPECTED_WORKLOAD["close"])
            expected_close.pop("kind")
            if close != expected_close:
                raise ValueError("WebSocket close behavior drift")
            idle = run["idle_and_close"]
            requested_idle = idle["requested_idle_ms"]
            if (
                not isinstance(requested_idle, int)
                or isinstance(requested_idle, bool)
                or not 42000 <= requested_idle <= 44000
            ):
                raise ValueError("observed idle interval is outside 42-44 seconds")
            pings = idle["h2_pings"]
            if (
                not isinstance(pings, list)
                or len(pings) != 2
                or not all(isinstance(item, dict) for item in pings)
                or pings[0].get("type") != "sent"
                or pings[0].get("is_ack") is not False
                or pings[1].get("type") != "received"
                or pings[1].get("is_ack") is not True
                or pings[0].get("unique_id") != pings[1].get("unique_id")
            ):
                raise ValueError("H2 idle ping/ack behavior drift")
            ping_times = [item.get("milliseconds_after_session_start") for item in pings]
            if any(
                not isinstance(value, int) or isinstance(value, bool)
                for value in ping_times
            ):
                raise ValueError("H2 idle ping timing is outside 42-44 seconds")
            if label == "yume":
                outer_events = run.get("observations", {}).get("outer_events", [])
                idle_index = next(
                    index for index, event in enumerate(outer_events)
                    if event.get("kind") == "idle-interval"
                )
                last_activity_ms = max(
                    event.get("milliseconds_after_session_start", -1)
                    for event in outer_events[:idle_index]
                )
                quiet_ms = ping_times[0] - last_activity_ms
                if not 42000 <= quiet_ms <= 44000:
                    raise ValueError("H2 quiet interval is outside 42-44 seconds")
            elif any(not 42000 <= value <= 44000 for value in ping_times):
                raise ValueError("H2 idle ping timing is outside 42-44 seconds")
            if run.get("shaping_policy") != {
                "synthetic_idle_keepalive": False,
                "random_padding": False,
                "random_timing_jitter": False,
                "bulk_websocket_message_bytes": 16384,
            }:
                raise ValueError("outer-carrier shaping policy is inconsistent")
            if _passive_lifecycle_projection(run) is None:
                raise ValueError("passive-visible lifecycle observations are malformed")
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            findings.append(
                Finding(
                    "DRIFT",
                    f"behavior.{label}.run-{index:02d}",
                    "invalid" if label == "normal" else "chrome151-node24-v1",
                    "chrome151-node24-v1" if label == "normal" else "invalid",
                    str(exc),
                )
            )
    return findings


def analyze(normal: ArmEvidence, yume: ArmEvidence) -> dict[str, Any]:
    findings: list[Finding] = []
    normal_env, yume_env = normal.environment, yume.environment

    identities = (
        ("chrome.version", ("chrome_version",),
         f"Google Chrome {PINNED_CHROME_VERSION}"),
        ("chrome.launcher_sha256", ("chrome_launcher_sha256",),
         PINNED_CHROME_LAUNCHER_SHA256),
        ("chrome.binary_sha256", ("chrome_binary_sha256",),
         PINNED_CHROME_BINARY_SHA256),
        ("node.version", ("node_version",), f"v{PINNED_NODE_VERSION}"),
        ("node.binary_sha256", ("node_binary_sha256", "node_sha256"),
         PINNED_NODE_BINARY_SHA256),
    )
    for field, aliases, expected in identities:
        left = _value(normal_env, *aliases)
        right = _value(yume_env, *aliases)
        _add_expected(findings, field, "normal", left, expected)
        _add_expected(findings, field, "yume", right, expected)
        _add_comparison(
            findings, field, left, right,
            detail="both arms must use the same pinned runtime identity",
        )

    for field, aliases in (
        ("source.commit", ("source_commit",)),
        ("source.tree", ("source_tree",)),
        ("source.dirty", ("source_dirty",)),
        ("session.sni", ("sni",)),
        ("session.alpn", ("alpn",)),
        ("session.transport_profile", ("transport_profile",)),
    ):
        left = _value(normal_env, *aliases)
        right = _value(yume_env, *aliases)
        _add_comparison(
            findings, field, left, right,
            detail="same-session evidence must bind this field in both arms",
        )
    for label, environment in (("normal", normal_env), ("yume", yume_env)):
        _add_expected(
            findings,
            "chrome.sandbox",
            label,
            environment.get("chrome_sandbox"),
            "user-namespace",
        )
        sni = environment.get("sni")
        if (
            not isinstance(sni, str)
            or not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?",
                sni,
            )
        ):
            findings.append(
                Finding("KNOWN_GAP", "session.sni",
                        sni if label == "normal" else "required",
                        "required" if label == "normal" else sni,
                        f"{label} arm does not bind a non-empty SNI")
            )
        _add_expected(
            findings, "session.alpn", label,
            environment.get("alpn"), "h2",
        )
        _add_expected(
            findings, "session.transport_profile", label,
            environment.get("transport_profile"), "chrome151-node24-v1",
        )
    for label, environment in (("normal", normal_env), ("yume", yume_env)):
        for field in ("source_commit", "source_tree"):
            value = environment.get(field)
            if value is not None and (
                not isinstance(value, str) or not OBJECT_ID_RE.fullmatch(value)
            ):
                raise EvidenceError(f"{label} {field} is not a Git object ID")
        dirty = environment.get("source_dirty")
        if dirty is not None and dirty is not False:
            findings.append(
                Finding("DRIFT", "source.dirty", dirty if label == "normal" else False,
                        False if label == "normal" else dirty,
                        f"{label} source checkout was not clean")
            )

    _add_comparison(
        findings,
        "session.certificate_sha256",
        normal.certificate_sha256,
        yume.certificate_sha256,
        detail="both arms must terminate with the same certificate",
    )

    normal_workload_manifest = normal_env.get("workload_manifest")
    yume_workload_manifest = yume_env.get("workload_manifest")
    for label, manifest in (
        ("normal", normal_workload_manifest),
        ("yume", yume_workload_manifest),
    ):
        _add_expected(
            findings,
            "workload.manifest",
            label,
            manifest,
            EXPECTED_WORKLOAD_MANIFEST,
        )
    _add_comparison(
        findings,
        "workload.manifest",
        normal_workload_manifest,
        yume_workload_manifest,
        detail="both arms must bind the same tracked workload manifest",
    )

    normal_workload = normal_env.get("workload")
    yume_workload = yume_env.get("workload")
    for label, workload in (("normal", normal_workload), ("yume", yume_workload)):
        if not isinstance(workload, dict):
            findings.append(
                Finding("KNOWN_GAP", f"workload.{label}", workload, EXPECTED_WORKLOAD,
                        f"{label} arm does not bind the frozen workload")
            )
            continue
        if set(workload) != set(EXPECTED_WORKLOAD):
            findings.append(
                Finding(
                    "DRIFT",
                    f"workload.{label}.fields",
                    sorted(workload),
                    sorted(EXPECTED_WORKLOAD),
                    f"{label} workload fields do not match the frozen schema",
                )
            )
        for field, expected in EXPECTED_WORKLOAD.items():
            _add_expected(
                findings, f"workload.{field}", label,
                workload.get(field), expected,
            )
    _add_comparison(
        findings,
        "workload",
        normal_workload,
        yume_workload,
        detail="browser and YUME arms must execute the same frozen workload",
    )

    normal_behavior = _stable_projection(normal.behavior_runs)
    yume_behavior = _stable_projection(yume.behavior_runs)
    findings.extend(_behavior_findings(normal, "normal"))
    findings.extend(_behavior_findings(yume, "yume"))
    if normal_behavior is None:
        findings.append(
            Finding("DRIFT", "behavior.normal", "unstable-or-missing", "stable",
                    "five normal-Chrome behavior reports must have one stable projection")
        )
    if not yume.behavior_runs:
        findings.append(
            Finding("KNOWN_GAP", "behavior.yume", "stable", "missing",
                    "YUME arm lacks sanitized H2/WebSocket behavior reports")
        )
    elif yume_behavior is None:
        findings.append(
            Finding("DRIFT", "behavior.yume", "stable", "unstable",
                    "five YUME behavior reports must have one stable projection")
        )
    if normal_behavior is not None and yume_behavior is not None:
        _add_comparison(
            findings,
            "behavior.stable_projection",
            normal_behavior,
            yume_behavior,
            detail="H2, asset, WebSocket, flow-control, and close behavior must match",
        )

    findings.extend(_tls_profile_findings(normal, "normal"))
    findings.extend(_tls_profile_findings(yume, "yume"))
    verdict = (
        "DRIFT" if any(item.verdict == "DRIFT" for item in findings)
        else "KNOWN_GAP" if findings else "PARITY"
    )
    return {
        "schema": 1,
        "scope": "matched-session-classifier-input-contract",
        "verdict": verdict,
        "runs_per_arm": REQUIRED_RUNS,
        "findings": [asdict(item) for item in findings],
        "boundaries": [
            "No passive classifier was trained or evaluated by this tool.",
            "No active probe or external hosting/IP metadata check was run.",
            "PARITY here means only that inputs are suitable for those later gates.",
        ],
    }


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        payload = (json.dumps(value, indent=2) + "\n").encode("utf-8")
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view):]
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normal", required=True, type=Path)
    parser.add_argument("--yume", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = analyze(
            load_arm(args.normal, normal=True),
            load_arm(args.yume, normal=False),
        )
        if args.output:
            write_private_json(args.output.resolve(), report)
        else:
            print(json.dumps(report, indent=2))
        return VERDICT_EXIT[report["verdict"]]
    except (EvidenceError, OSError) as exc:
        print(f"INVALID {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
