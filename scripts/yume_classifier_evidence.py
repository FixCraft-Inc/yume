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
EXPECTED_WORKLOAD = {
    "mode": "cover-page-websocket-v1",
    "asset_paths": ["/", "/assets/site.css", "/assets/site.js"],
    "websocket_bytes_each_direction": 1024 * 1024,
    "client_binary_messages": {
        "count": 64,
        "payload_bytes": 16384,
        "masked": True,
    },
    "server_binary_messages": {
        "unfragmented_count": 63,
        "payload_bytes": 16384,
        "masked": False,
    },
    "server_fragmented_binary_message": [
        {"opcode": 2, "payload_bytes": 8192, "final": False, "masked": False},
        {"opcode": 0, "payload_bytes": 8192, "final": True, "masked": False},
    ],
    "ping_pong": {
        "server_ping_payload_bytes": 12,
        "client_pong_payload_bytes": 12,
        "client_pong_masked": True,
    },
    "idle_ms": 42000,
    "close": {
        "kind": "graceful-websocket",
        "payload_bytes": 18,
        "client_masked": True,
        "server_masked": False,
        "h2_ping_immediately_before_close": True,
        "h2_ping_originator": "client",
    },
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

    def bytes(self, relative: Path) -> bytes:
        parts = self._parts(relative)
        directory_fd = os.dup(self._root_fd)
        descriptor = -1
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        file_flags = os.O_RDONLY | os.O_CLOEXEC
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
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise EvidenceError(
                    f"evidence input is not a regular file: {relative}"
                )
            if before.st_size > MAX_JSON_BYTES:
                raise EvidenceError(f"evidence input is too large: {relative}")
            chunks: list[bytes] = []
            remaining = MAX_JSON_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(128 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                raise EvidenceError(f"evidence changed while reading: {relative}")
            value = b"".join(chunks)
            if len(value) > MAX_JSON_BYTES:
                raise EvidenceError(f"evidence input is too large: {relative}")
            return value
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(directory_fd)

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

    def sha256(self, relative: Path) -> str:
        return hashlib.sha256(self.bytes(relative)).hexdigest()


def _environment_runs(environment: dict[str, Any], label: str) -> int:
    runs = environment.get("runs")
    if not isinstance(runs, int) or isinstance(runs, bool) or runs != REQUIRED_RUNS:
        raise EvidenceError(
            f"{label} must declare exactly {REQUIRED_RUNS} runs"
        )
    return runs


def load_arm(path: Path, *, normal: bool) -> ArmEvidence:
    with EvidenceReader(path) as reader:
        environment = reader.json_object(Path("environment.json"))
        runs = _environment_runs(
            environment, "normal Chrome" if normal else "YUME"
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
        try:
            certificate = reader.sha256(Path("server.crt"))
        except FileNotFoundError:
            certificate = None
        if (
            certificate is not None
            and declared_certificate is not None
            and declared_certificate != certificate
        ):
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


def _behavior_findings(arm: ArmEvidence, label: str) -> list[Finding]:
    findings: list[Finding] = []
    for index, run in enumerate(arm.behavior_runs, start=1):
        try:
            validate_run(run, f"{label}-run-{index:02d}")
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
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 42000 <= value <= 44000
                for value in ping_times
            ):
                raise ValueError("H2 idle ping timing is outside 42-44 seconds")
        except (KeyError, TypeError, ValueError) as exc:
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
