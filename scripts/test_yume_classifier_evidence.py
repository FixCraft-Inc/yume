#!/usr/bin/env python3
"""Focused tests for matched classifier-evidence contracts."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from yume_bench_common import (  # noqa: E402
    PINNED_CHROME_BINARY_SHA256,
    PINNED_CHROME_LAUNCHER_SHA256,
    PINNED_CHROME_VERSION,
    PINNED_NODE_BINARY_SHA256,
    PINNED_NODE_VERSION,
)
from yume_classifier_evidence import (  # noqa: E402
    EXPECTED_WORKLOAD_MANIFEST,
    EvidenceError,
    analyze,
    load_arm,
    write_private_json,
)
from yume_capture_finalize import (  # noqa: E402
    EXPECTED_RUNTIME_FILES,
    FinalizeError,
    finalize_capture,
)


FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "tests/fixtures/chrome151-node24"
)


class ClassifierEvidenceTest(unittest.TestCase):
    @staticmethod
    def _synthetic_live_outer_events(
        behavior: dict[str, object]
    ) -> list[dict[str, object]]:
        events: list[dict[str, object]] = []

        def add(kind: str, direction: str, stream_class: str,
                elapsed: int = 0, **metadata: object) -> None:
            events.append({
                "kind": kind,
                "direction": direction,
                "stream_class": stream_class,
                "milliseconds_after_session_start": elapsed,
                **metadata,
            })

        add("h2-frame", "sent", "connection", h2_type=4, flags=0,
            stream_id=0, length=24,
            settings=behavior["client_settings_in_order"])
        add("h2-frame", "received", "connection", h2_type=4, flags=0,
            stream_id=0, length=6,
            settings=behavior["node_non_default_settings_in_order"])
        add("h2-frame", "sent", "connection", h2_type=4, flags=1,
            stream_id=0, length=0, settings=[])
        add("h2-frame", "received", "connection", h2_type=4, flags=1,
            stream_id=0, length=0, settings=[])
        window = behavior["client_connection_window_update"]
        assert isinstance(window, dict)
        add("h2-frame", "sent", "connection", h2_type=8, flags=0,
            stream_id=0, length=4, delta=window["delta"])

        summaries = [
            behavior["priming_get"],
            *behavior["asset_sequence"],
            behavior["extended_connect"],
        ]
        extended = behavior["extended_connect"]
        assert isinstance(extended, dict)
        ordinary_response_headers = [
            [":status", "200"], ["date", "<runtime-date>"]
        ]

        def request(stream_class: str, summary: dict[str, object]) -> None:
            assert isinstance(summary, dict)
            add(
                "h2-frame", "sent", stream_class, h2_type=1, flags=0x25,
                stream_id=summary["stream_id"], length=5,
                headers_in_order=summary["headers_in_order"],
                priority={
                    "parent_stream_id": summary["parent_stream_id"],
                    "exclusive": summary["exclusive"],
                    "weight": summary["weight"],
                },
            )

        def response(stream_class: str, summary: dict[str, object]) -> None:
            assert isinstance(summary, dict)
            response_headers = (
                extended["node_response_headers_in_order"]
                if stream_class == "carrier"
                else ordinary_response_headers
            )
            add(
                "h2-frame", "received", stream_class, h2_type=1, flags=0x04,
                stream_id=summary["stream_id"], length=1,
            )
            add(
                "h2-headers-decoded", "received", stream_class,
                stream_id=summary["stream_id"],
                headers_in_order=response_headers,
            )
            if stream_class != "carrier":
                add(
                    "stream-close", "received", stream_class,
                    stream_id=summary["stream_id"], error_code=0,
                    completed=True,
                )

        priming, css, js, connect = summaries
        assert all(isinstance(summary, dict) for summary in summaries)
        request("priming", priming)
        response("priming", priming)
        request("asset-css", css)
        request("asset-js", js)
        response("asset-css", css)
        response("asset-js", js)
        request("carrier", connect)
        response("carrier", connect)
        favicon = {
            "stream_id": 9,
            "parent_stream_id": 0,
            "exclusive": True,
            "weight": 220,
            "headers_in_order": [
                [":method", "GET"],
                [":authority", "<cover-authority>"],
                [":scheme", "https"],
                [":path", "/favicon.ico"],
            ],
        }
        request("other", favicon)
        response("other", favicon)

        websocket = behavior["websocket_fixture"]
        assert isinstance(websocket, dict)
        client = websocket["client_binary_messages"]
        server = websocket["server_binary_messages"]
        assert isinstance(client, dict) and isinstance(server, dict)
        for _ in range(client["count"]):
            add("websocket-frame", "sent", "carrier", opcode=2, final=True,
                masked=client["masked"], payload_bytes=client["payload_bytes"])
        ping_pong = websocket["ping_pong"]
        assert isinstance(ping_pong, dict)
        add("websocket-frame", "received", "carrier", opcode=9, final=True,
            masked=False, payload_bytes=ping_pong["server_ping_payload_bytes"])
        for fragment in websocket["server_fragmented_binary_message"]:
            add("websocket-frame", "received", "carrier", **fragment)
        for _ in range(server["unfragmented_count"]):
            add("websocket-frame", "received", "carrier", opcode=2, final=True,
                masked=server["masked"], payload_bytes=server["payload_bytes"])
        add("websocket-frame", "sent", "carrier", opcode=10, final=True,
            masked=ping_pong["client_pong_masked"],
            payload_bytes=ping_pong["client_pong_payload_bytes"])

        flow = behavior["flow_control_fixture"]
        assert isinstance(flow, dict)
        for _ in range(flow["client_stream_send_stalls"]):
            add("flow-window-stalled", "sent", "carrier")
            add("flow-window-recovered", "sent", "carrier")
        add("h2-frame", "sent", "carrier", h2_type=0, flags=0,
            stream_id=7, length=16384)
        add("h2-frame", "received", "carrier", h2_type=8, flags=0,
            stream_id=7, length=4, delta=16384)

        idle = behavior["idle_and_close"]
        close = websocket["close"]
        assert isinstance(idle, dict) and isinstance(close, dict)
        elapsed = idle["requested_idle_ms"]
        add("idle-interval", "sent", "carrier", elapsed,
            requested_ms=elapsed, completed=True)
        add("h2-frame", "sent", "connection", elapsed, h2_type=6, flags=0,
            stream_id=0, length=8, is_ack=False, unique_id=1)
        add("h2-frame", "sent", "carrier", elapsed, h2_type=0, flags=0,
            stream_id=7, length=24)
        add("websocket-frame", "sent", "carrier", elapsed, opcode=8,
            final=True, masked=close["client_masked"],
            payload_bytes=close["payload_bytes"],
            h2_ping_immediately_before=True)
        add("h2-frame", "sent", "connection", elapsed, h2_type=7, flags=0,
            stream_id=0, length=8, error_code=0)
        add("close-wire", "sent", "carrier", elapsed, completed=True)
        add("h2-frame", "received", "connection", elapsed, h2_type=6, flags=1,
            stream_id=0, length=8, is_ack=True, unique_id=1)
        add("h2-frame", "received", "carrier", elapsed, h2_type=0, flags=0,
            stream_id=7, length=20)
        add("websocket-frame", "received", "carrier", elapsed, opcode=8,
            final=True, masked=close["server_masked"],
            payload_bytes=close["payload_bytes"])
        return events

    @staticmethod
    def _write_checksums(directory: Path, names: list[str]) -> None:
        lines = []
        for name in names:
            digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}\n")
        (directory / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")

    def _seal_arm(self, arm: Path) -> None:
        for path in (arm / "complete.json", arm / "SHA256SUMS"):
            path.unlink(missing_ok=True)
        runtime = arm / "runtime-source"
        runtime.mkdir(exist_ok=True)
        for name in EXPECTED_RUNTIME_FILES:
            path = runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text(f"fixture: {name}\n", encoding="utf-8")
        self._write_checksums(runtime, list(EXPECTED_RUNTIME_FILES))

        environment = json.loads((arm / "environment.json").read_text())
        for index in range(1, environment["runs"] + 1):
            run = arm / f"run-{index:02d}"
            names = [
                name
                for name in ("netlog.json", "sanitized.json", "behavior.json",
                             "tls-wire.json")
                if (run / name).is_file()
            ]
            self._write_checksums(run, names)
        top_names = [
            "environment.json",
            "server.crt",
            "runtime-source/SHA256SUMS",
            *(f"run-{index:02d}/SHA256SUMS"
              for index in range(1, environment["runs"] + 1)),
        ]
        self._write_checksums(arm, top_names)
        finalize_capture(arm)

    def _make_arm(
        self,
        root: Path,
        name: str,
        *,
        normal: bool,
        certificate: bytes,
        include_behavior: bool = True,
        workload_mode: str = "cover-page-websocket-v1",
        tls_backend: str = "openssl-chrome151",
    ) -> Path:
        arm = root / name
        arm.mkdir()
        certificate_sha256 = hashlib.sha256(certificate).hexdigest()
        environment = {
            "arm": "normal" if normal else "yume",
            "runs": 5,
            "chrome_version": f"Google Chrome {PINNED_CHROME_VERSION}",
            "chrome_launcher_sha256": PINNED_CHROME_LAUNCHER_SHA256,
            "chrome_binary_sha256": PINNED_CHROME_BINARY_SHA256,
            "chrome_sandbox": "user-namespace",
            "node_version": f"v{PINNED_NODE_VERSION}",
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "source_dirty": False,
            "sni": "cover.test",
            "alpn": "h2",
            "transport_profile": "chrome151-node24-v1",
            "certificate_sha256": certificate_sha256,
            "tls_wire_evidence": True,
            "workload_manifest": EXPECTED_WORKLOAD_MANIFEST,
            "workload": {
                "mode": workload_mode,
                "asset_paths": ["/", "/assets/site.css", "/assets/site.js"],
                "websocket_bytes_each_direction": 1048576,
                "client_binary_messages": {
                    "count": 64, "payload_bytes": 16384, "masked": True,
                },
                "server_binary_messages": {
                    "unfragmented_count": 63,
                    "payload_bytes": 16384,
                    "masked": False,
                },
                "server_fragmented_binary_message": [
                    {"opcode": 2, "payload_bytes": 8192,
                     "final": False, "masked": False},
                    {"opcode": 0, "payload_bytes": 8192,
                     "final": True, "masked": False},
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
            },
        }
        if normal:
            environment["node_binary_sha256"] = PINNED_NODE_BINARY_SHA256
        else:
            environment["node_sha256"] = PINNED_NODE_BINARY_SHA256
            environment["yume_binary_sha256"] = "c" * 64
            environment["tls_backend"] = tls_backend
            if tls_backend == "chrome151":
                environment["yume_helper_sha256"] = "d" * 64
            environment["release_bundle_sha256"] = "f" * 64
            environment["client_config_sha256"] = "0" * 64
            environment["tls_leaf_sha256"] = "e" * 64
        (arm / "server.crt").write_bytes(certificate)
        (arm / "environment.json").write_text(json.dumps(environment))
        behavior = json.loads(
            (FIXTURE / "runs/run-01.json").read_text(encoding="utf-8")
        )
        if not normal:
            behavior["capture_status"] = "complete"
            behavior["capture_source"] = "live-production-carrier"
            behavior.setdefault("observations", {})["outer_events"] = (
                self._synthetic_live_outer_events(behavior)
            )
        for index in range(1, 6):
            run = arm / f"run-{index:02d}"
            run.mkdir()
            tls = FIXTURE / f"helper_tls_wire_run_{index}.json"
            (run / "tls-wire.json").write_bytes(tls.read_bytes())
            if include_behavior:
                filename = "sanitized.json" if normal else "behavior.json"
                (run / filename).write_text(json.dumps(behavior))
            if normal:
                (run / "netlog.json").write_text("opaque fixture\n")
        self._seal_arm(arm)
        return arm

    def test_hypothetical_self_consistent_contract_is_parity_without_external_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            yume = self._make_arm(root, "yume", normal=False, certificate=b"cert")
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertEqual(report["verdict"], "PARITY")
        self.assertEqual(report["findings"], [])
        self.assertIn("No passive classifier", report["boundaries"][0])

    def test_truthful_yume_protocol_overhead_is_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            for index in range(1, 6):
                path = yume / f"run-{index:02d}/behavior.json"
                behavior = json.loads(path.read_text())
                events = behavior["observations"]["outer_events"]
                first_binary_index = next(
                    event_index for event_index, event in enumerate(events)
                    if event.get("kind") == "websocket-frame"
                    and event.get("direction") == "sent"
                    and event.get("opcode") == 0x02
                )
                overhead = dict(events[first_binary_index])
                overhead["payload_bytes"] = 40
                events.insert(first_binary_index, overhead)
                behavior["websocket_fixture"]["client_binary_messages"] = {
                    "count": 65,
                    "payload_bytes": [
                        {"payload_bytes": 40, "count": 1},
                        {"payload_bytes": 16384, "count": 64},
                    ],
                    "masked": True,
                }
                path.write_text(json.dumps(behavior))
            self._seal_arm(yume)
            report = analyze(
                load_arm(normal, normal=True), load_arm(yume, normal=False)
            )
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            "WebSocket message count drift" in item["detail"]
            for item in report["findings"]
        ))

    def test_missing_favicon_lifecycle_cannot_report_parity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            for index in range(1, 6):
                path = yume / f"run-{index:02d}/behavior.json"
                behavior = json.loads(path.read_text())
                events = behavior["observations"]["outer_events"]
                behavior["observations"]["outer_events"] = [
                    event for event in events if event.get("stream_id") != 9
                ]
                path.write_text(json.dumps(behavior))
            self._seal_arm(yume)
            report = analyze(
                load_arm(normal, normal=True), load_arm(yume, normal=False)
            )
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertIn(
            "behavior.stable_projection",
            {item["field"] for item in report["findings"]},
        )

    def test_early_server_ping_cannot_report_parity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            for index in range(1, 6):
                path = yume / f"run-{index:02d}/behavior.json"
                behavior = json.loads(path.read_text())
                events = behavior["observations"]["outer_events"]
                server_ping = next(
                    event for event in events
                    if event.get("kind") == "websocket-frame"
                    and event.get("direction") == "received"
                    and event.get("opcode") == 0x09
                )
                first_binary_index = next(
                    event_index for event_index, event in enumerate(events)
                    if event.get("kind") == "websocket-frame"
                    and event.get("direction") == "sent"
                    and event.get("opcode") == 0x02
                )
                events.remove(server_ping)
                events.insert(first_binary_index, server_ping)
                path.write_text(json.dumps(behavior))
            self._seal_arm(yume)
            report = analyze(
                load_arm(normal, normal=True), load_arm(yume, normal=False)
            )
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            "PING/echo order" in item["detail"]
            for item in report["findings"]
        ))

    def test_missing_yume_behavior_is_rejected_during_finalization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(FinalizeError, "run-01 checksum paths differ"):
                self._make_arm(
                    root, "yume", normal=False, certificate=b"cert",
                    include_behavior=False,
                )

    def test_helper_backed_yume_arm_accepts_bound_helper_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert",
                tls_backend="chrome151",
            )
            evidence = load_arm(yume, normal=False)
        self.assertEqual(evidence.environment["tls_backend"], "chrome151")
        self.assertEqual(evidence.environment["yume_helper_sha256"], "d" * 64)

    def test_arm_relabeling_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            environment = json.loads((normal / "environment.json").read_text())
            environment["arm"] = "yume"
            (normal / "environment.json").write_text(json.dumps(environment))
            with self.assertRaisesRegex(EvidenceError, "evidence arm"):
                load_arm(normal, normal=True)

    def test_sandbox_relabeling_is_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            for arm in (normal, yume):
                environment = json.loads((arm / "environment.json").read_text())
                environment["chrome_sandbox"] = "disabled"
                (arm / "environment.json").write_text(json.dumps(environment))
                self._seal_arm(arm)
            report = analyze(
                load_arm(normal, normal=True), load_arm(yume, normal=False)
            )
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertIn(
            "chrome.sandbox", {item["field"] for item in report["findings"]}
        )

    def test_certificate_and_workload_mismatch_are_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"normal")
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"yume",
                workload_mode="authenticated-endpoint-bench",
            )
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertEqual(report["verdict"], "DRIFT")
        fields = {item["field"] for item in report["findings"]}
        self.assertIn("session.certificate_sha256", fields)
        self.assertIn("workload", fields)

    def test_evidence_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            target = normal / "environment-target.json"
            target.write_text("{}")
            (normal / "environment.json").unlink()
            (normal / "environment.json").symlink_to(target)
            with self.assertRaisesRegex(EvidenceError, "cannot open evidence file"):
                load_arm(normal, normal=True)

    def test_environment_fifo_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            (normal / "environment.json").unlink()
            os.mkfifo(normal / "environment.json")
            with self.assertRaisesRegex(EvidenceError, "not a regular file"):
                load_arm(normal, normal=True)

    def test_yume_behavior_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            outside = root / "outside.json"
            outside.write_text("{}")
            (yume / "run-01/behavior.json").unlink()
            (yume / "run-01/behavior.json").symlink_to(outside)
            with self.assertRaisesRegex(EvidenceError, "cannot open evidence file"):
                load_arm(yume, normal=False)

    def test_empty_behavior_cannot_produce_false_parity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            yume = self._make_arm(root, "yume", normal=False, certificate=b"cert")
            for index in range(1, 6):
                (yume / f"run-{index:02d}/behavior.json").write_text("{}")
            self._seal_arm(yume)
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            item["field"].startswith("behavior.yume.run-")
            for item in report["findings"]
        ))

    def test_incomplete_yume_live_capture_is_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            for index in range(1, 6):
                path = yume / f"run-{index:02d}/behavior.json"
                behavior = json.loads(path.read_text())
                behavior["capture_status"] = "incomplete"
                path.write_text(json.dumps(behavior))
            self._seal_arm(yume)
            report = analyze(
                load_arm(normal, normal=True), load_arm(yume, normal=False)
            )
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            "capture is incomplete" in item["detail"]
            for item in report["findings"]
        ))

    def test_non_live_yume_behavior_source_is_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            for index in range(1, 6):
                path = yume / f"run-{index:02d}/behavior.json"
                behavior = json.loads(path.read_text())
                behavior["capture_source"] = "manual-summary"
                path.write_text(json.dumps(behavior))
            self._seal_arm(yume)
            report = analyze(
                load_arm(normal, normal=True), load_arm(yume, normal=False)
            )
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            "not from the live production carrier" in item["detail"]
            for item in report["findings"]
        ))

    def test_mismatched_live_h2_ping_ack_is_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            for index in range(1, 6):
                path = yume / f"run-{index:02d}/behavior.json"
                behavior = json.loads(path.read_text())
                ping_events = [
                    event
                    for event in behavior["observations"]["outer_events"]
                    if event.get("kind") == "h2-frame"
                    and event.get("h2_type") == 0x06
                    and event.get("direction") == "received"
                ]
                self.assertEqual(len(ping_events), 1)
                ping_events[0]["unique_id"] = 0
                path.write_text(json.dumps(behavior))
            self._seal_arm(yume)
            report = analyze(
                load_arm(normal, normal=True), load_arm(yume, normal=False)
            )
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            "PING correlation" in item["detail"]
            for item in report["findings"]
        ))

    def test_producer_impossible_live_headers_are_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            for index in range(1, 6):
                path = yume / f"run-{index:02d}/behavior.json"
                behavior = json.loads(path.read_text())
                events = behavior["observations"]["outer_events"]
                for event in events:
                    if (
                        event.get("kind") == "h2-frame"
                        and event.get("direction") == "sent"
                        and event.get("h2_type") == 0x01
                    ):
                        event["kind"] = "h2-headers-decoded"
                        event.pop("h2_type")
                        event.pop("flags")
                        event.pop("length")
                path.write_text(json.dumps(behavior))
            self._seal_arm(yume)
            report = analyze(
                load_arm(normal, normal=True), load_arm(yume, normal=False)
            )
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            "impossible provenance" in item["detail"]
            for item in report["findings"]
        ))

    def test_missing_live_continuation_chain_is_drift(self) -> None:
        for orphan in (False, True):
            with self.subTest(orphan=orphan), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                normal = self._make_arm(
                    root, "normal", normal=True, certificate=b"cert"
                )
                yume = self._make_arm(
                    root, "yume", normal=False, certificate=b"cert"
                )
                for index in range(1, 6):
                    path = yume / f"run-{index:02d}/behavior.json"
                    behavior = json.loads(path.read_text())
                    events = behavior["observations"]["outer_events"]
                    raw_response = next(
                        event for event in events
                        if event.get("kind") == "h2-frame"
                        and event.get("direction") == "received"
                        and event.get("h2_type") == 0x01
                        and event.get("stream_id") == 7
                    )
                    if orphan:
                        continuation = dict(raw_response)
                        continuation.update(h2_type=0x09, flags=0x04,
                                            length=1)
                        events.insert(events.index(raw_response), continuation)
                    else:
                        raw_response["flags"] &= ~0x04
                    path.write_text(json.dumps(behavior))
                self._seal_arm(yume)
                report = analyze(
                    load_arm(normal, normal=True), load_arm(yume, normal=False)
                )
                self.assertEqual(report["verdict"], "DRIFT")
                self.assertTrue(any(
                    "CONTINUATION" in item["detail"]
                    for item in report["findings"]
                ))

    def test_duplicate_live_settings_ack_is_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            for index in range(1, 6):
                path = yume / f"run-{index:02d}/behavior.json"
                behavior = json.loads(path.read_text())
                events = behavior["observations"]["outer_events"]
                ack = next(event for event in events if (
                    event.get("kind") == "h2-frame"
                    and event.get("h2_type") == 0x04
                    and event.get("flags") == 0x01
                    and event.get("direction") == "sent"
                ))
                events.insert(events.index(ack) + 1, dict(ack))
                path.write_text(json.dumps(behavior))
            self._seal_arm(yume)
            report = analyze(
                load_arm(normal, normal=True),
                load_arm(yume, normal=False),
            )
            self.assertEqual(report["verdict"], "DRIFT")

    def test_live_h2_data_geometry_is_fail_closed(self) -> None:
        for length in (0, 16 * 1024 + 1, 1024 * 1024):
            with self.subTest(length=length), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                normal = self._make_arm(
                    root, "normal", normal=True, certificate=b"cert"
                )
                yume = self._make_arm(
                    root, "yume", normal=False, certificate=b"cert"
                )
                for index in range(1, 6):
                    path = yume / f"run-{index:02d}/behavior.json"
                    behavior = json.loads(path.read_text())
                    events = behavior["observations"]["outer_events"]
                    extra = {
                        "kind": "h2-frame",
                        "direction": "received",
                        "stream_class": "carrier",
                        "stream_id": 7,
                        "h2_type": 0,
                        "flags": 0,
                        "length": length,
                        "milliseconds_after_session_start": 0,
                    }
                    events.insert(8, extra)
                    path.write_text(json.dumps(behavior))
                self._seal_arm(yume)
                report = analyze(
                    load_arm(normal, normal=True),
                    load_arm(yume, normal=False),
                )
                self.assertEqual(report["verdict"], "DRIFT")

    def test_yume_idle_timing_is_relative_to_completed_workload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            setup_ms = 9_000
            for index in range(1, 6):
                path = yume / f"run-{index:02d}/behavior.json"
                behavior = json.loads(path.read_text())
                events = behavior["observations"]["outer_events"]
                idle_index = next(
                    event_index for event_index, event in enumerate(events)
                    if event.get("kind") == "idle-interval"
                )
                for event in events[:idle_index]:
                    event["milliseconds_after_session_start"] = setup_ms
                for event in events[idle_index:]:
                    event["milliseconds_after_session_start"] += setup_ms
                for ping in behavior["idle_and_close"]["h2_pings"]:
                    ping["milliseconds_after_session_start"] += setup_ms
                path.write_text(json.dumps(behavior))
            self._seal_arm(yume)
            report = analyze(
                load_arm(normal, normal=True),
                load_arm(yume, normal=False),
            )
            self.assertEqual(report["verdict"], "PARITY")

    def test_unbound_live_terminal_sequence_is_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            for index in range(1, 6):
                path = yume / f"run-{index:02d}/behavior.json"
                behavior = json.loads(path.read_text())
                events = behavior["observations"]["outer_events"]
                terminal_ping = next(
                    event for event in events
                    if event.get("kind") == "h2-frame"
                    and event.get("direction") == "sent"
                    and event.get("h2_type") == 0x06
                )
                close = next(
                    event for event in events
                    if event.get("kind") == "websocket-frame"
                    and event.get("direction") == "sent"
                    and event.get("opcode") == 0x08
                )
                ping_index = events.index(terminal_ping)
                close_index = events.index(close)
                events[:] = [
                    event for event_index, event in enumerate(events)
                    if not (
                        ping_index < event_index < close_index
                        and event.get("kind") == "h2-frame"
                        and event.get("direction") == "sent"
                        and event.get("h2_type") == 0x00
                    )
                ]
                path.write_text(json.dumps(behavior))
            self._seal_arm(yume)
            report = analyze(
                load_arm(normal, normal=True), load_arm(yume, normal=False)
            )
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            "terminal H2/WebSocket sequence" in item["detail"]
            for item in report["findings"]
        ))

    def test_malformed_live_stream_close_is_drift(self) -> None:
        for mutation in ("missing", "wrong"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                normal = self._make_arm(
                    root, "normal", normal=True, certificate=b"cert"
                )
                yume = self._make_arm(
                    root, "yume", normal=False, certificate=b"cert"
                )
                for index in range(1, 6):
                    path = yume / f"run-{index:02d}/behavior.json"
                    behavior = json.loads(path.read_text())
                    stream_close = next(
                        event
                        for event in behavior["observations"]["outer_events"]
                        if event.get("kind") == "stream-close"
                    )
                    if mutation == "missing":
                        stream_close.pop("stream_id")
                    else:
                        stream_close["stream_id"] = 7
                    path.write_text(json.dumps(behavior))
                self._seal_arm(yume)
                report = analyze(
                    load_arm(normal, normal=True),
                    load_arm(yume, normal=False),
                )
                self.assertEqual(report["verdict"], "DRIFT")
                self.assertTrue(any(
                    "stream-close" in item["detail"]
                    for item in report["findings"]
                ))

    def test_producer_impossible_request_lifecycle_is_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            for index in range(1, 6):
                path = yume / f"run-{index:02d}/behavior.json"
                behavior = json.loads(path.read_text())
                events = behavior["observations"]["outer_events"]
                priming_close = next(
                    event for event in events
                    if event.get("kind") == "stream-close"
                    and event.get("stream_id") == 1
                )
                css_request = next(
                    event for event in events
                    if event.get("kind") == "h2-frame"
                    and event.get("direction") == "sent"
                    and event.get("stream_id") == 3
                    and event.get("h2_type") == 0x01
                )
                events.remove(priming_close)
                events.insert(events.index(css_request) + 1, priming_close)
                path.write_text(json.dumps(behavior))
            self._seal_arm(yume)
            report = analyze(
                load_arm(normal, normal=True), load_arm(yume, normal=False)
            )
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            "producer-impossible" in item["detail"]
            for item in report["findings"]
        ))

    def test_swapped_live_asset_requests_are_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert"
            )
            for index in range(1, 6):
                path = yume / f"run-{index:02d}/behavior.json"
                behavior = json.loads(path.read_text())
                events = behavior["observations"]["outer_events"]
                css_index = next(
                    event_index for event_index, event in enumerate(events)
                    if event.get("kind") == "h2-frame"
                    and event.get("direction") == "sent"
                    and event.get("stream_id") == 3
                    and event.get("h2_type") == 0x01
                )
                js_index = next(
                    event_index for event_index, event in enumerate(events)
                    if event.get("kind") == "h2-frame"
                    and event.get("direction") == "sent"
                    and event.get("stream_id") == 5
                    and event.get("h2_type") == 0x01
                )
                events[css_index], events[js_index] = (
                    events[js_index], events[css_index]
                )
                path.write_text(json.dumps(behavior))
            self._seal_arm(yume)
            report = analyze(
                load_arm(normal, normal=True), load_arm(yume, normal=False)
            )
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            "producer-impossible" in item["detail"]
            for item in report["findings"]
        ))

    def test_duplicate_live_header_provenance_is_drift(self) -> None:
        selectors = (
            ("sent", "h2-frame"),
            ("received", "h2-frame"),
            ("received", "h2-headers-decoded"),
        )
        for direction, kind in selectors:
            with (
                self.subTest(direction=direction, kind=kind),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                normal = self._make_arm(
                    root, "normal", normal=True, certificate=b"cert"
                )
                yume = self._make_arm(
                    root, "yume", normal=False, certificate=b"cert"
                )
                for index in range(1, 6):
                    path = yume / f"run-{index:02d}/behavior.json"
                    behavior = json.loads(path.read_text())
                    events = behavior["observations"]["outer_events"]
                    duplicate = next(
                        event for event in events
                        if event.get("kind") == kind
                        and event.get("direction") == direction
                        and event.get("stream_id") == 3
                        and (kind != "h2-frame" or
                             event.get("h2_type") == 0x01)
                    )
                    events.insert(events.index(duplicate) + 1, dict(duplicate))
                    path.write_text(json.dumps(behavior))
                self._seal_arm(yume)
                report = analyze(
                    load_arm(normal, normal=True),
                    load_arm(yume, normal=False),
                )
                self.assertEqual(report["verdict"], "DRIFT")

        mutations = (
            lambda event: event.__setitem__("length", 0),
            lambda event: event.__setitem__("flags", 0xFF),
            lambda event: event.pop("headers_in_order"),
        )
        for mutation_index, mutation in enumerate(mutations):
            with (
                self.subTest(mutation=mutation_index),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                normal = self._make_arm(
                    root, "normal", normal=True, certificate=b"cert"
                )
                yume = self._make_arm(
                    root, "yume", normal=False, certificate=b"cert"
                )
                for index in range(1, 6):
                    path = yume / f"run-{index:02d}/behavior.json"
                    behavior = json.loads(path.read_text())
                    request = next(
                        event for event in behavior["observations"]["outer_events"]
                        if event.get("kind") == "h2-frame"
                        and event.get("direction") == "sent"
                        and event.get("h2_type") == 0x01
                        and event.get("stream_id") == 3
                    )
                    mutation(request)
                    path.write_text(json.dumps(behavior))
                self._seal_arm(yume)
                report = analyze(
                    load_arm(normal, normal=True), load_arm(yume, normal=False)
                )
                self.assertEqual(report["verdict"], "DRIFT")

    def test_duplicate_live_one_shot_events_are_drift(self) -> None:
        selectors = (
            lambda event: event.get("kind") == "h2-frame"
            and event.get("direction") == "sent"
            and event.get("h2_type") == 0x04
            and not event.get("flags", 0) & 0x01,
            lambda event: event.get("kind") == "h2-frame"
            and event.get("direction") == "received"
            and event.get("h2_type") == 0x04
            and not event.get("flags", 0) & 0x01,
            lambda event: event.get("kind") == "h2-frame"
            and event.get("direction") == "sent"
            and event.get("h2_type") == 0x08
            and event.get("stream_id") == 0,
            lambda event: event.get("kind") == "h2-frame"
            and event.get("direction") == "sent"
            and event.get("h2_type") == 0x07,
            lambda event: event.get("kind") == "idle-interval",
            lambda event: event.get("kind") == "close-wire",
        )
        for selector_index, selector in enumerate(selectors):
            with (
                self.subTest(selector=selector_index),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                normal = self._make_arm(
                    root, "normal", normal=True, certificate=b"cert"
                )
                yume = self._make_arm(
                    root, "yume", normal=False, certificate=b"cert"
                )
                for index in range(1, 6):
                    path = yume / f"run-{index:02d}/behavior.json"
                    behavior = json.loads(path.read_text())
                    events = behavior["observations"]["outer_events"]
                    duplicate = next(event for event in events if selector(event))
                    events.insert(events.index(duplicate) + 1, dict(duplicate))
                    path.write_text(json.dumps(behavior))
                self._seal_arm(yume)
                report = analyze(
                    load_arm(normal, normal=True),
                    load_arm(yume, normal=False),
                )
                self.assertEqual(report["verdict"], "DRIFT")

        malformed_lengths = (
            lambda event: event.get("direction") == "sent"
            and event.get("h2_type") == 0x04
            and not event.get("flags", 0) & 0x01,
            lambda event: event.get("direction") == "sent"
            and event.get("h2_type") == 0x08
            and event.get("stream_id") == 0,
            lambda event: event.get("direction") == "sent"
            and event.get("h2_type") == 0x06
            and not event.get("flags", 0) & 0x01,
            lambda event: event.get("direction") == "sent"
            and event.get("h2_type") == 0x07,
        )
        for selector_index, selector in enumerate(malformed_lengths):
            with (
                self.subTest(malformed_length=selector_index),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                normal = self._make_arm(
                    root, "normal", normal=True, certificate=b"cert"
                )
                yume = self._make_arm(
                    root, "yume", normal=False, certificate=b"cert"
                )
                for index in range(1, 6):
                    path = yume / f"run-{index:02d}/behavior.json"
                    behavior = json.loads(path.read_text())
                    event = next(
                        item for item in behavior["observations"]["outer_events"]
                        if item.get("kind") == "h2-frame" and selector(item)
                    )
                    event["length"] = 0
                    path.write_text(json.dumps(behavior))
                self._seal_arm(yume)
                report = analyze(
                    load_arm(normal, normal=True), load_arm(yume, normal=False)
                )
                self.assertEqual(report["verdict"], "DRIFT")

        for frame_type, stream_id, stream_class in (
            (0x00, 9, "other"),
            (0x02, 7, "carrier"),
            (0x03, 7, "carrier"),
            (0x05, 7, "carrier"),
            (0x0B, 7, "carrier"),
        ):
            with (
                self.subTest(frame_type=frame_type),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                normal = self._make_arm(
                    root, "normal", normal=True, certificate=b"cert"
                )
                yume = self._make_arm(
                    root, "yume", normal=False, certificate=b"cert"
                )
                for index in range(1, 6):
                    path = yume / f"run-{index:02d}/behavior.json"
                    behavior = json.loads(path.read_text())
                    events = behavior["observations"]["outer_events"]
                    unknown = {
                        "kind": "h2-frame", "direction": "received",
                        "stream_class": stream_class,
                        "stream_id": stream_id,
                        "h2_type": frame_type, "flags": 0, "length": 0,
                        "milliseconds_after_session_start": 0,
                    }
                    events.insert(3, unknown)
                    path.write_text(json.dumps(behavior))
                self._seal_arm(yume)
                report = analyze(
                    load_arm(normal, normal=True),
                    load_arm(yume, normal=False),
                )
                self.assertEqual(report["verdict"], "DRIFT")

    def test_duplicate_live_websocket_controls_are_drift(self) -> None:
        for opcode, direction in ((0x09, "received"), (0x08, "received")):
            with (
                self.subTest(opcode=opcode),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                normal = self._make_arm(
                    root, "normal", normal=True, certificate=b"cert"
                )
                yume = self._make_arm(
                    root, "yume", normal=False, certificate=b"cert"
                )
                for index in range(1, 6):
                    path = yume / f"run-{index:02d}/behavior.json"
                    behavior = json.loads(path.read_text())
                    events = behavior["observations"]["outer_events"]
                    duplicate = next(
                        event for event in events
                        if event.get("kind") == "websocket-frame"
                        and event.get("opcode") == opcode
                        and event.get("direction") == direction
                    )
                    events.insert(events.index(duplicate) + 1, dict(duplicate))
                    path.write_text(json.dumps(behavior))
                self._seal_arm(yume)
                report = analyze(
                    load_arm(normal, normal=True),
                    load_arm(yume, normal=False),
                )
                self.assertEqual(report["verdict"], "DRIFT")
                self.assertTrue(any(
                    "control counts" in item["detail"]
                    for item in report["findings"]
                ))

    def test_malformed_live_observations_are_fail_closed(self) -> None:
        for malformed in (None, [], "bad"):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                normal = self._make_arm(
                    root, "normal", normal=True, certificate=b"cert"
                )
                yume = self._make_arm(
                    root, "yume", normal=False, certificate=b"cert"
                )
                for index in range(1, 6):
                    path = yume / f"run-{index:02d}/behavior.json"
                    behavior = json.loads(path.read_text())
                    behavior["observations"] = malformed
                    path.write_text(json.dumps(behavior))
                self._seal_arm(yume)
                report = analyze(
                    load_arm(normal, normal=True),
                    load_arm(yume, normal=False),
                )
                self.assertEqual(report["verdict"], "DRIFT")

    def test_identically_wrong_observed_geometry_is_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            yume = self._make_arm(root, "yume", normal=False, certificate=b"cert")
            for arm, filename in ((normal, "sanitized.json"), (yume, "behavior.json")):
                for index in range(1, 6):
                    path = arm / f"run-{index:02d}" / filename
                    behavior = json.loads(path.read_text())
                    behavior["websocket_fixture"]["client_binary_messages"][
                        "masked"
                    ] = False
                    path.write_text(json.dumps(behavior))
                self._seal_arm(arm)
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            item["field"].startswith("behavior.normal.run-")
            for item in report["findings"]
        ))

    def test_identically_incomplete_observed_controls_are_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            yume = self._make_arm(root, "yume", normal=False, certificate=b"cert")
            for arm, filename in ((normal, "sanitized.json"), (yume, "behavior.json")):
                for index in range(1, 6):
                    path = arm / f"run-{index:02d}" / filename
                    behavior = json.loads(path.read_text())
                    websocket = behavior["websocket_fixture"]
                    websocket.pop("server_fragmented_binary_message")
                    websocket.pop("ping_pong")
                    websocket.pop("close")
                    behavior["idle_and_close"].pop("requested_idle_ms")
                    behavior["idle_and_close"].pop("h2_pings")
                    path.write_text(json.dumps(behavior))
                self._seal_arm(arm)
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertEqual(report["verdict"], "DRIFT")

    def test_empty_session_fields_cannot_produce_false_parity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            yume = self._make_arm(root, "yume", normal=False, certificate=b"cert")
            for arm in (normal, yume):
                environment = json.loads((arm / "environment.json").read_text())
                environment["sni"] = ""
                environment["alpn"] = "http/1.1"
                environment["transport_profile"] = "unknown"
                (arm / "environment.json").write_text(json.dumps(environment))
                self._seal_arm(arm)
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertEqual(report["verdict"], "DRIFT")
        fields = {item["field"] for item in report["findings"]}
        self.assertIn("session.sni", fields)
        self.assertIn("session.alpn", fields)
        self.assertIn("session.transport_profile", fields)

    def test_empty_workloads_cannot_produce_false_parity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            yume = self._make_arm(root, "yume", normal=False, certificate=b"cert")
            for arm in (normal, yume):
                environment = json.loads((arm / "environment.json").read_text())
                environment["workload"] = {}
                (arm / "environment.json").write_text(json.dumps(environment))
                self._seal_arm(arm)
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertNotEqual(report["verdict"], "PARITY")
        self.assertIn(
            "workload.mode", {item["field"] for item in report["findings"]}
        )

    def test_unknown_workload_fields_cannot_produce_false_parity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            yume = self._make_arm(root, "yume", normal=False, certificate=b"cert")
            for arm in (normal, yume):
                environment = json.loads((arm / "environment.json").read_text())
                environment["workload"]["additional_phase"] = {
                    "requests": 1000, "idle_ms": 1,
                }
                (arm / "environment.json").write_text(json.dumps(environment))
                self._seal_arm(arm)
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            item["field"].endswith(".fields") for item in report["findings"]
        ))

    def test_runtime_version_requires_exact_manifest_string(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            yume = self._make_arm(root, "yume", normal=False, certificate=b"cert")
            for arm in (normal, yume):
                environment = json.loads((arm / "environment.json").read_text())
                environment["chrome_version"] = (
                    f"not-chrome {PINNED_CHROME_VERSION} contradictory"
                )
                (arm / "environment.json").write_text(json.dumps(environment))
                self._seal_arm(arm)
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertIn(
            "chrome.version", {item["field"] for item in report["findings"]}
        )

    def test_parent_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            yume = self._make_arm(root, "yume", normal=False, certificate=b"cert")
            outside = root / "outside-run"
            (yume / "run-01").rename(outside)
            (yume / "run-01").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(EvidenceError, "traverse evidence directory"):
                load_arm(yume, normal=False)

    def test_manifest_certificate_without_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            yume = self._make_arm(root, "yume", normal=False, certificate=b"cert")
            (yume / "server.crt").unlink()
            with self.assertRaisesRegex(EvidenceError, "missing checksummed evidence"):
                load_arm(yume, normal=False)

    def test_missing_completion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            normal = self._make_arm(
                Path(tmp), "normal", normal=True, certificate=b"cert"
            )
            (normal / "complete.json").unlink()
            with self.assertRaisesRegex(EvidenceError, "completion marker is missing"):
                load_arm(normal, normal=True)

    def test_payload_tamper_after_completion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            normal = self._make_arm(
                Path(tmp), "normal", normal=True, certificate=b"cert"
            )
            (normal / "run-01/sanitized.json").write_text("{}")
            with self.assertRaisesRegex(EvidenceError, "checksum mismatch"):
                load_arm(normal, normal=True)

    def test_completed_bundle_remains_verifiable_after_move(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(
                root, "normal", normal=True, certificate=b"cert"
            )
            moved = root / "moved-normal"
            normal.rename(moved)
            self.assertEqual(load_arm(moved, normal=True).environment["arm"], "normal")

    def test_private_report_is_exclusive_and_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            write_private_json(output, {"schema": 1})
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_private_json(output, {"schema": 1})


if __name__ == "__main__":
    unittest.main()
