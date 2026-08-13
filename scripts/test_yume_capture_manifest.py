#!/usr/bin/env python3
"""Focused tests for source-bound matched-capture environment manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from yume_bench_common import (
    PINNED_CHROME_BINARY_SHA256,
    PINNED_CHROME_LAUNCHER_SHA256,
    PINNED_CHROME_VERSION,
    PINNED_NODE_BINARY_SHA256,
    PINNED_NODE_VERSION,
)
from yume_capture_manifest import (
    ManifestError,
    WORKLOAD_PATH,
    build_environment,
    load_workload,
    write_private_json,
)


class CaptureManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "config", "user.name", "Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        (self.repo / "tracked").write_text("clean\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "tracked"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-q", "-m", "fixture"],
            check=True,
        )
        self.certificate = self.root / "server.crt"
        self.certificate.write_bytes(b"public certificate")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def args(self, **overrides: object) -> argparse.Namespace:
        values: dict[str, object] = {
            "arm": "normal",
            "repo": self.repo,
            "certificate": self.certificate,
            "sni": "cover.test",
            "runs": 5,
            "idle_ms": 42000,
            "chrome_version": f"Google Chrome {PINNED_CHROME_VERSION}",
            "chrome_launcher": "/exact/google-chrome",
            "chrome_launcher_sha256": PINNED_CHROME_LAUNCHER_SHA256,
            "chrome_binary": "/exact/chrome",
            "chrome_binary_sha256": PINNED_CHROME_BINARY_SHA256,
            "chrome_sandbox": "user-namespace",
            "node_version": f"v{PINNED_NODE_VERSION}",
            "node_binary_sha256": PINNED_NODE_BINARY_SHA256,
            "display": ":99",
            "tls_wire_evidence": 1,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_clean_source_binds_exact_shared_contract(self) -> None:
        environment = build_environment(self.args())
        workload_bytes = WORKLOAD_PATH.read_bytes()
        self.assertEqual(environment["arm"], "normal")
        self.assertFalse(environment["source_dirty"])
        self.assertEqual(len(environment["source_commit"]), 40)
        self.assertEqual(len(environment["source_tree"]), 40)
        self.assertEqual(
            environment["certificate_sha256"],
            hashlib.sha256(self.certificate.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            environment["workload_manifest"]["sha256"],
            hashlib.sha256(workload_bytes).hexdigest(),
        )
        self.assertEqual(environment["workload"]["idle_ms"], 42000)

    def test_actual_idle_is_not_misrepresented(self) -> None:
        environment = build_environment(self.args(idle_ms=0))
        self.assertEqual(environment["workload"]["idle_ms"], 0)

    def test_dirty_source_is_rejected(self) -> None:
        (self.repo / "untracked").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "not clean"):
            build_environment(self.args())

    def test_certificate_symlink_is_rejected(self) -> None:
        link = self.root / "certificate-link"
        link.symlink_to(self.certificate)
        with self.assertRaisesRegex(ManifestError, "cannot open regular input"):
            build_environment(self.args(certificate=link))

    def test_certificate_fifo_is_rejected_without_blocking(self) -> None:
        fifo = self.root / "certificate-fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ManifestError, "not a regular file"):
            build_environment(self.args(certificate=fifo))

    def test_runtime_identity_drift_is_rejected(self) -> None:
        with self.assertRaisesRegex(ManifestError, "Node binary SHA-256 mismatch"):
            build_environment(self.args(node_binary_sha256="0" * 64))

    def test_arm_and_sandbox_labels_are_fail_closed(self) -> None:
        with self.assertRaisesRegex(ManifestError, "capture arm"):
            build_environment(self.args(arm="baseline"))
        with self.assertRaisesRegex(ManifestError, "Chrome sandbox"):
            build_environment(self.args(chrome_sandbox="disabled"))

    def test_workload_asset_order_is_validated(self) -> None:
        document, _digest = load_workload()
        document["contract"]["asset_paths"].reverse()
        altered = self.root / "altered.json"
        altered.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "asset order"):
            load_workload(altered)

    def test_private_output_is_exclusive_and_mode_0600(self) -> None:
        output = self.root / "environment.json"
        write_private_json(output, {"schema": 1})
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(json.loads(output.read_text()), {"schema": 1})
        with self.assertRaises(FileExistsError):
            write_private_json(output, {"schema": 2})

    def test_output_symlink_is_rejected(self) -> None:
        target = self.root / "target"
        target.write_text("unchanged", encoding="utf-8")
        output = self.root / "output"
        output.symlink_to(target)
        with self.assertRaises(OSError):
            write_private_json(output, {"schema": 1})
        self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()
