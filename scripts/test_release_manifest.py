#!/usr/bin/env python3
"""Exercise release inventory classification and fail-closed validation."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import release_manifest as manifest


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = tempfile.TemporaryDirectory(prefix="yume-release-manifest-")
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        self.dist = self.root / "artifacts"
        self.dist.mkdir()
        self.tag = "v0.3.0-rc1"
        for name in manifest.EXPECTED_ARTIFACTS:
            (self.dist / name).write_bytes(f"Fixture {name}\n".encode())
            self.write_checksum(name)
            (self.dist / f"{name}.sig").write_bytes(b"signature fixture\n")
        self.write_aggregate()
        (self.dist / "SHA256SUMS.txt.sig").write_bytes(b"aggregate signature fixture\n")

    def checksum_record(self, name: str, algorithm: str = "sha256") -> str:
        digest = hashlib.new(algorithm, (self.dist / name).read_bytes()).hexdigest()
        return f"{digest}  {name}\n"

    def write_checksum(self, name: str) -> None:
        (self.dist / f"{name}.sha256").write_text(self.checksum_record(name), encoding="utf-8")

    def write_aggregate(self) -> None:
        (self.dist / "SHA256SUMS.txt").write_text(
            "".join(self.checksum_record(name) for name in manifest.EXPECTED_ARTIFACTS),
            encoding="utf-8")

    def build(self) -> dict[str, object]:
        return manifest.build_manifest(self.dist, self.tag, require_signatures=True)

    def write_manifest(self) -> dict[str, object]:
        document = self.build()
        self.save_manifest(document)
        (self.dist / f"{manifest.MANIFEST_NAME}.sig").write_bytes(b"manifest signature fixture\n")
        return document

    def save_manifest(self, document: dict[str, object]) -> None:
        (self.dist / manifest.MANIFEST_NAME).write_text(
            json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def check(self) -> dict[str, object]:
        return manifest.check_manifest(self.dist, self.tag, require_signatures=True)

    def test_aggregate_and_manifest_signatures_survive_generation(self) -> None:
        args = [str(self.dist), self.tag, "--require-signatures"]
        with contextlib.redirect_stdout(io.StringIO()):
            manifest.main(args)
        (self.dist / f"{manifest.MANIFEST_NAME}.sig").write_bytes(b"manifest signature fixture\n")
        with contextlib.redirect_stdout(io.StringIO()):
            manifest.main(args)
            manifest.main(args + ["--check"])
        document = self.check()
        entries = {entry["file"]: entry for entry in document["files"]}
        self.assertEqual(set(entries), set(manifest.EXPECTED_ARTIFACTS))
        for name, entry in entries.items():
            self.assertEqual(entry["signature"], f"{name}.sig")
        self.assertEqual(document["checksums"], [{
            "file": "SHA256SUMS.txt", "algorithm": "sha256",
            "size": (self.dist / "SHA256SUMS.txt").stat().st_size,
            "sha256": hashlib.sha256((self.dist / "SHA256SUMS.txt").read_bytes()).hexdigest(),
            "signature": "SHA256SUMS.txt.sig",
        }])

    def test_strict_missing_publication_files_are_rejected(self) -> None:
        required = ["SHA256SUMS.txt", "SHA256SUMS.txt.sig"]
        required.extend(name + suffix for name in manifest.EXPECTED_ARTIFACTS
                        for suffix in (".sha256", ".sig"))
        for name in required:
            with self.subTest(file=name):
                path = self.dist / name
                payload = path.read_bytes()
                path.unlink()
                companion = self.dist / f"{name}.sig" if name == "SHA256SUMS.txt" else None
                companion_payload = companion.read_bytes() if companion else None
                if companion:
                    companion.unlink()
                try:
                    with self.assertRaisesRegex(SystemExit, "Missing required release files"):
                        self.build()
                finally:
                    path.write_bytes(payload)
                    if companion:
                        companion.write_bytes(companion_payload)

    def test_empty_signatures_are_rejected(self) -> None:
        self.write_manifest()
        for name in (*manifest.EXPECTED_ARTIFACTS, "SHA256SUMS.txt", manifest.MANIFEST_NAME):
            with self.subTest(file=name):
                path = self.dist / f"{name}.sig"
                payload = path.read_bytes()
                path.write_bytes(b"")
                try:
                    with self.assertRaisesRegex(SystemExit, "Signature file is empty"):
                        self.check()
                finally:
                    path.write_bytes(payload)

    def test_orphan_aggregate_and_manifest_signatures_are_rejected(self) -> None:
        self.write_manifest()
        for name in ("SHA256SUMS.txt", manifest.MANIFEST_NAME):
            with self.subTest(file=name):
                path = self.dist / name
                payload = path.read_bytes()
                path.unlink()
                try:
                    with self.assertRaisesRegex(SystemExit, "Sidecar without artifact"):
                        manifest.build_manifest(self.dist, self.tag)
                finally:
                    path.write_bytes(payload)

    def test_unknown_artifact_is_rejected_even_with_valid_sidecars(self) -> None:
        name = "unexpected-amd64-linux"
        (self.dist / name).write_bytes(b"unexpected artifact\n")
        self.write_checksum(name)
        (self.dist / f"{name}.sig").write_bytes(b"signature fixture\n")
        with (self.dist / "SHA256SUMS.txt").open("a", encoding="utf-8") as handle:
            handle.write(self.checksum_record(name))
        with self.assertRaisesRegex(SystemExit, "Release artifact set must contain exactly"):
            self.build()

    def test_nonregular_entries_are_rejected_before_hashing(self) -> None:
        path = self.dist / manifest.EXPECTED_ARTIFACTS[0]
        payload = path.read_bytes()
        target = self.root / "outside-artifacts"
        target.write_bytes(payload)
        for kind in ("symlink", "directory", "fifo"):
            with self.subTest(kind=kind):
                path.unlink()
                if kind == "symlink":
                    path.symlink_to(target)
                elif kind == "directory":
                    path.mkdir()
                else:
                    os.mkfifo(path)
                try:
                    with mock.patch.object(manifest, "digest_file", side_effect=AssertionError(
                            "nonregular entry reached hashing")):
                        with self.assertRaisesRegex(SystemExit, "not a regular file"):
                            self.build()
                finally:
                    if kind == "directory":
                        path.rmdir()
                    else:
                        path.unlink()
                    path.write_bytes(payload)

    def test_primary_checksum_requires_one_record_naming_its_artifact(self) -> None:
        name = manifest.EXPECTED_ARTIFACTS[0]
        path = self.dist / f"{name}.sha256"
        record = self.checksum_record(name)
        digest = record.split()[0]
        for payload in (f"{digest}\n", f"{digest}  different-artifact\n",
                        record + record, record.rstrip("\n")):
            with self.subTest(payload=payload):
                path.write_text(payload, encoding="utf-8")
                with self.assertRaisesRegex(SystemExit, "checksum|Checksum"):
                    self.build()

    def test_primary_checksum_digest_mismatch_is_rejected(self) -> None:
        name = manifest.EXPECTED_ARTIFACTS[0]
        (self.dist / f"{name}.sha256").write_text(f"{'0' * 64}  {name}\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "SHA256 checksum record mismatch"):
            self.build()

    def test_aggregate_requires_exact_artifact_coverage_and_digests(self) -> None:
        first, second = (self.checksum_record(name) for name in manifest.EXPECTED_ARTIFACTS)
        corrupt = "0" * 64 + first[64:]
        for payload in (first, first + second + first, corrupt + second,
                        first + second + "0" * 64 + "  absent-artifact\n"):
            with self.subTest(payload=payload):
                (self.dist / "SHA256SUMS.txt").write_text(payload, encoding="utf-8")
                with self.assertRaisesRegex(SystemExit, "Aggregate checksum|Duplicate checksum"):
                    self.build()

    def test_check_rejects_stale_or_forged_inventory(self) -> None:
        original = self.write_manifest()
        for location, field, replacement in (
                ("files", "signature", None), ("files", "size", 0),
                ("files", "sha256", "0" * 64), ("checksums", "signature", None),
                ("checksums", "sha256", "0" * 64), (None, "release_tag", "v0.3.0-rc2"),
                (None, "unexpected", True)):
            with self.subTest(location=location, field=field):
                changed = json.loads(json.dumps(original))
                target = changed[location][0] if location else changed
                target[field] = replacement
                self.save_manifest(changed)
                with self.assertRaisesRegex(SystemExit, "differs from the release files or tag"):
                    self.check()

    def test_check_requires_manifest_signature(self) -> None:
        self.write_manifest()
        (self.dist / f"{manifest.MANIFEST_NAME}.sig").unlink()
        with self.assertRaisesRegex(SystemExit, "Missing required release files: release-manifest.json.sig"):
            self.check()

    def test_duplicate_manifest_keys_are_rejected(self) -> None:
        self.write_manifest()
        path = self.dist / manifest.MANIFEST_NAME
        path.write_text('{"project":"different",' + path.read_text(encoding="utf-8")[1:],
                        encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "Duplicate manifest key"):
            self.check()

    def test_invalid_manifest_generation_times_are_rejected(self) -> None:
        document = self.write_manifest()
        for value in (None, "2026-10-17", "2026-99-99T99:99:99Z"):
            with self.subTest(value=value):
                document["generated_at"] = value
                self.save_manifest(document)
                with self.assertRaisesRegex(SystemExit, "Invalid release manifest generation time"):
                    self.check()

    def test_check_does_not_overwrite_a_rejected_manifest(self) -> None:
        document = self.write_manifest()
        document["release_tag"] = "different-tag"
        self.save_manifest(document)
        path = self.dist / manifest.MANIFEST_NAME
        before = path.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(SystemExit, "differs from the release files or tag"):
                manifest.main([str(self.dist), self.tag, "--require-signatures", "--check"])
        self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
