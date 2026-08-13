#!/usr/bin/env python3
"""Focused tests for portable, fail-closed capture finalization."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from yume_capture_finalize import (
    EXPECTED_RUNTIME_FILES,
    FinalizeError,
    finalize_capture,
)


class CaptureFinalizeTest(unittest.TestCase):
    @staticmethod
    def _write_checksums(directory: Path, names: list[str]) -> None:
        lines = []
        for name in names:
            digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}\n")
        (directory / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")

    def _prepare(self, root: Path) -> None:
        certificate = b"public certificate"
        (root / "server.crt").write_bytes(certificate)
        environment = {
            "schema": 1,
            "arm": "normal",
            "runs": 1,
            "tls_wire_evidence": False,
            "certificate_sha256": hashlib.sha256(certificate).hexdigest(),
        }
        (root / "environment.json").write_text(json.dumps(environment))

        runtime = root / "runtime-source"
        runtime.mkdir()
        for name in EXPECTED_RUNTIME_FILES:
            path = runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"fixture: {name}\n", encoding="utf-8")
        self._write_checksums(runtime, list(EXPECTED_RUNTIME_FILES))

        run = root / "run-01"
        run.mkdir()
        (run / "netlog.json").write_text("opaque fixture\n")
        (run / "sanitized.json").write_text("{}\n")
        self._write_checksums(run, ["netlog.json", "sanitized.json"])
        self._write_checksums(
            root,
            [
                "environment.json",
                "server.crt",
                "runtime-source/SHA256SUMS",
                "run-01/SHA256SUMS",
            ],
        )

    def test_complete_marker_is_last_exclusive_and_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._prepare(root)
            result = finalize_capture(root)
            complete = root / "complete.json"
            self.assertEqual(result["status"], "complete")
            self.assertEqual(stat.S_IMODE(complete.stat().st_mode), 0o600)
            self.assertFalse(any(str(root) in name for name in result["runs"][0]["files"]))
            with self.assertRaises(FileExistsError):
                finalize_capture(root)

    def test_absolute_checksum_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._prepare(root)
            digest = hashlib.sha256((root / "run-01/netlog.json").read_bytes()).hexdigest()
            (root / "run-01/SHA256SUMS").write_text(
                f"{digest}  {root}/run-01/netlog.json\n", encoding="utf-8"
            )
            self._write_checksums(
                root,
                [
                    "environment.json",
                    "server.crt",
                    "runtime-source/SHA256SUMS",
                    "run-01/SHA256SUMS",
                ],
            )
            with self.assertRaisesRegex(FinalizeError, "unsafe checksum path"):
                finalize_capture(root)
            self.assertFalse((root / "complete.json").exists())

    def test_payload_tamper_is_rejected_before_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._prepare(root)
            (root / "run-01/sanitized.json").write_text('{"changed": true}\n')
            with self.assertRaisesRegex(FinalizeError, "checksum mismatch"):
                finalize_capture(root)
            self.assertFalse((root / "complete.json").exists())

    def test_missing_runtime_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._prepare(root)
            (root / "runtime-source/scripts/yume_tls_wire.py").unlink()
            with self.assertRaisesRegex(FinalizeError, "cannot open capture input"):
                finalize_capture(root)
            self.assertFalse((root / "complete.json").exists())

    def test_environment_fifo_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "environment.json").unlink(missing_ok=True)
            os.mkfifo(root / "environment.json")
            with self.assertRaisesRegex(FinalizeError, "not regular"):
                finalize_capture(root)


if __name__ == "__main__":
    unittest.main()
