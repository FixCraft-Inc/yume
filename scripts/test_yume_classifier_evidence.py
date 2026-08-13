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
    EvidenceError,
    analyze,
    load_arm,
    write_private_json,
)


FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "tests/fixtures/chrome151-node24"
)


class ClassifierEvidenceTest(unittest.TestCase):
    def _make_arm(
        self,
        root: Path,
        name: str,
        *,
        normal: bool,
        certificate: bytes,
        include_behavior: bool = True,
        workload_mode: str = "cover-page-websocket-v1",
    ) -> Path:
        arm = root / name
        arm.mkdir()
        certificate_sha256 = hashlib.sha256(certificate).hexdigest()
        environment = {
            "runs": 5,
            "chrome_version": f"Google Chrome {PINNED_CHROME_VERSION}",
            "chrome_launcher_sha256": PINNED_CHROME_LAUNCHER_SHA256,
            "chrome_binary_sha256": PINNED_CHROME_BINARY_SHA256,
            "node_version": f"v{PINNED_NODE_VERSION}",
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "source_dirty": False,
            "sni": "cover.test",
            "alpn": "h2",
            "transport_profile": "chrome151-node24-v1",
            "certificate_sha256": certificate_sha256,
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
        (arm / "server.crt").write_bytes(certificate)
        (arm / "environment.json").write_text(json.dumps(environment))
        behavior = json.loads(
            (FIXTURE / "runs/run-01.json").read_text(encoding="utf-8")
        )
        for index in range(1, 6):
            run = arm / f"run-{index:02d}"
            run.mkdir()
            tls = FIXTURE / f"helper_tls_wire_run_{index}.json"
            (run / "tls-wire.json").write_bytes(tls.read_bytes())
            if include_behavior:
                filename = "sanitized.json" if normal else "behavior.json"
                (run / filename).write_text(json.dumps(behavior))
        return arm

    def test_matched_contract_is_parity_without_external_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            yume = self._make_arm(root, "yume", normal=False, certificate=b"cert")
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertEqual(report["verdict"], "PARITY")
        self.assertEqual(report["findings"], [])
        self.assertIn("No passive classifier", report["boundaries"][0])

    def test_missing_yume_behavior_is_known_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert",
                include_behavior=False,
            )
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertEqual(report["verdict"], "KNOWN_GAP")
        self.assertIn("behavior.yume", {item["field"] for item in report["findings"]})

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

    def test_optional_yume_behavior_symlink_is_not_treated_as_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            yume = self._make_arm(
                root, "yume", normal=False, certificate=b"cert",
                include_behavior=False,
            )
            outside = root / "outside.json"
            outside.write_text("{}")
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
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertEqual(report["verdict"], "DRIFT")
        self.assertTrue(any(
            item["field"].startswith("behavior.yume.run-")
            for item in report["findings"]
        ))

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

    def test_manifest_certificate_without_file_is_known_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            normal = self._make_arm(root, "normal", normal=True, certificate=b"cert")
            yume = self._make_arm(root, "yume", normal=False, certificate=b"cert")
            (yume / "server.crt").unlink()
            report = analyze(load_arm(normal, normal=True), load_arm(yume, normal=False))
        self.assertEqual(report["verdict"], "KNOWN_GAP")
        self.assertIn(
            "session.certificate_sha256",
            {item["field"] for item in report["findings"]},
        )

    def test_private_report_is_exclusive_and_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            write_private_json(output, {"schema": 1})
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_private_json(output, {"schema": 1})


if __name__ == "__main__":
    unittest.main()
