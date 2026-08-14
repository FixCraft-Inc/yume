#!/usr/bin/env python3
"""Focused tests for exact-bundle YUME capture runtime binding."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yume_capture_binary_provenance as provenance


class CaptureBinaryProvenanceTest(unittest.TestCase):
    @staticmethod
    def _executable(path: Path, payload: bytes) -> None:
        path.write_bytes(payload)
        path.chmod(0o755)

    def test_exact_bundle_binaries_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "yume-amd64-linux.tar.xz"
            bundle.write_bytes(b"bundle")
            yume = root / "yume"
            helper = root / "yume-chrome-tls-helper"
            self._executable(yume, b"exact-yume")
            self._executable(helper, b"exact-helper")
            manifest = {"files": [
                {"file": "yume", "size": yume.stat().st_size,
                 "sha256": hashlib.sha256(yume.read_bytes()).hexdigest()},
                {"file": "yume-chrome-tls-helper",
                 "size": helper.stat().st_size,
                 "sha256": hashlib.sha256(helper.read_bytes()).hexdigest()},
            ]}
            with (
                mock.patch.object(provenance, "source_version", return_value="2.0-dev6"),
                mock.patch.object(provenance, "transport_dependency", return_value={}),
                mock.patch.object(provenance, "validate_bundle", return_value=manifest),
            ):
                hashes = provenance.validate_capture_binaries(
                    bundle, yume, helper, "a" * 40
                )
            self.assertEqual(hashes[0], manifest["files"][0]["sha256"])
            self.assertEqual(hashes[1], manifest["files"][1]["sha256"])

    def test_stale_yume_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "yume-amd64-linux.tar.xz"
            bundle.write_bytes(b"bundle")
            yume = root / "yume"
            helper = root / "yume-chrome-tls-helper"
            self._executable(yume, b"stale-yume")
            self._executable(helper, b"exact-helper")
            manifest = {"files": [
                {"file": "yume", "size": len(b"expected-yume"),
                 "sha256": hashlib.sha256(b"expected-yume").hexdigest()},
                {"file": "yume-chrome-tls-helper",
                 "size": helper.stat().st_size,
                 "sha256": hashlib.sha256(helper.read_bytes()).hexdigest()},
            ]}
            with (
                mock.patch.object(provenance, "source_version", return_value="2.0-dev6"),
                mock.patch.object(provenance, "transport_dependency", return_value={}),
                mock.patch.object(provenance, "validate_bundle", return_value=manifest),
            ):
                with self.assertRaisesRegex(
                    provenance.ProvenanceError, "differs from the exact release bundle"
                ):
                    provenance.validate_capture_binaries(
                        bundle, yume, helper, "a" * 40
                    )

    def test_non_executable_or_malformed_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            yume = root / "yume"
            helper = root / "helper"
            yume.write_bytes(b"not executable")
            self._executable(helper, b"helper")
            with self.assertRaisesRegex(provenance.ProvenanceError, "40-hex"):
                provenance.validate_capture_binaries(
                    root / "bundle", yume, helper, "BAD"
                )
            with self.assertRaisesRegex(provenance.ProvenanceError, "executable"):
                provenance.validate_capture_binaries(
                    root / "bundle", yume, helper, "a" * 40
                )


if __name__ == "__main__":
    unittest.main()
