#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Validate the committed five-run Chrome 151 / Node 24 evidence fixture."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import sys
from typing import Any


PROFILE_ID = "chrome151-node24-v1"
EXPECTED_RUNS = 5


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_projection(run: dict[str, Any]) -> dict[str, Any]:
    projected = copy.deepcopy(run)
    projected.get("flow_control_fixture", {}).pop(
        "client_stream_send_stalls", None
    )
    idle = projected.get("idle_and_close", {})
    idle.pop("requested_idle_ms", None)
    idle.pop("h2_pings", None)
    projected.pop("observations", None)
    return projected


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_run(run: dict[str, Any], label: str) -> None:
    require(run.get("schema") == 2, f"{label}: unsupported schema")
    require(run.get("client", {}).get("version") == "151.0.7922.71",
            f"{label}: wrong Chrome version")
    tls = run.get("tls_observation", {})
    require(tls.get("version") == "TLS 1.3", f"{label}: TLS is not 1.3")
    require(tls.get("alpn") == "h2", f"{label}: ALPN is not h2")
    require(tls.get("resumed") is False, f"{label}: session unexpectedly resumed")
    require(run.get("client_settings_in_order") == [
        [1, 65536, "SETTINGS_HEADER_TABLE_SIZE"],
        [2, 0, "SETTINGS_ENABLE_PUSH"],
        [4, 6291456, "SETTINGS_INITIAL_WINDOW_SIZE"],
        [6, 262144, "SETTINGS_MAX_HEADER_LIST_SIZE"],
    ], f"{label}: Chrome SETTINGS drift")
    require(run.get("node_non_default_settings_in_order") == [
        [8, 1, "SETTINGS_ENABLE_CONNECT_PROTOCOL"]
    ], f"{label}: Node SETTINGS drift")
    require(
        [asset.get("path") for asset in run.get("asset_sequence", [])]
        == ["/assets/site.css", "/assets/site.js"],
        f"{label}: asset sequence drift",
    )
    connect_headers = run.get("extended_connect", {}).get(
        "headers_in_order", []
    )
    require([":protocol", "websocket"] in connect_headers,
            f"{label}: RFC 8441 header missing")
    websocket = run.get("websocket_fixture", {})
    require(websocket.get("application_bytes_each_direction") == 1024 * 1024,
            f"{label}: bulk transfer size drift")
    require(websocket.get("client_binary_messages", {}).get("count") == 64,
            f"{label}: client WebSocket message count drift")
    require(websocket.get("server_binary_messages", {}).get(
        "unfragmented_count") == 63,
        f"{label}: server WebSocket message count drift")
    require(run.get("flow_control_fixture", {}).get(
        "window_update_recovery_observed") is True,
        f"{label}: no flow-control recovery")
    require(run.get("idle_and_close", {}).get(
        "graceful_websocket_close_observed") is True,
        f"{label}: graceful close missing")


def validate_fixture(fixture: pathlib.Path) -> None:
    manifest_path = fixture / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("profile_id") == PROFILE_ID,
            "manifest profile identifier drift")
    entries = manifest.get("capture", {}).get("runs", [])
    require(len(entries) == EXPECTED_RUNS,
            f"expected {EXPECTED_RUNS} runs, found {len(entries)}")

    projections: list[dict[str, Any]] = []
    stalls: list[int] = []
    close_ms: list[int] = []
    for index, entry in enumerate(entries, start=1):
        label = f"run-{index:02d}"
        artifact = fixture / entry["artifact"]
        require(artifact.is_file(), f"{label}: artifact is missing")
        require(sha256_file(artifact) == entry["sanitized_sha256"],
                f"{label}: sanitized SHA-256 mismatch")
        run = json.loads(artifact.read_text(encoding="utf-8"))
        validate_run(run, label)
        projections.append(stable_projection(run))
        stalls.append(run["flow_control_fixture"]["client_stream_send_stalls"])
        close_ms.append(run["idle_and_close"]["requested_idle_ms"])

    first_projection = projections[0]
    require(all(value == first_projection for value in projections[1:]),
            "stable Chrome identity differs across runs")
    projection_digest = canonical_digest(first_projection)
    expected_projection_digest = manifest["capture"].get(
        "stable_identity_canonical_sha256"
    )
    require(projection_digest == expected_projection_digest,
            "stable identity canonical SHA-256 mismatch")

    print(f"PARITY profile={PROFILE_ID} runs={EXPECTED_RUNS}")
    print(f"stable_identity_sha256={projection_digest}")
    print(f"flow_control_stalls={','.join(map(str, stalls))}")
    print(f"close_ms={','.join(map(str, close_ms))}")
    print("KNOWN_GAP tls_clienthello=requires-wire-comparator")


def main() -> int:
    default_fixture = (
        pathlib.Path(__file__).resolve().parents[1]
        / "tests/fixtures/chrome151-node24"
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=pathlib.Path, default=default_fixture)
    args = parser.parse_args()
    try:
        validate_fixture(args.fixture.resolve())
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"DRIFT {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
