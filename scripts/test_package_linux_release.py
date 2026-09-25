#!/usr/bin/env python3
"""Exercise native release archives using compiled ELF contract fixtures."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import package_linux_release as package
import release_manifest
import release_preflight as preflight
import yume_capture_binary_provenance as provenance


class NativeReleasePackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workspace = tempfile.TemporaryDirectory(prefix="yume-package-test-")
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.root = Path(cls.workspace.name)
        cls.version = "0.3.0-dev1"
        cls.commit = "a" * 40
        cls.transport = package.active_profile_metadata()
        source = cls.root / "fixture.c"
        source.write_text(
            '#include <stdio.h>\n'
            'int main(void) {\n'
            '  puts(PROGRAM " 0.3.0-dev1");\n'
            '  puts("transport YTP/1, config schema 1, suite ytp1-tls13-h2");\n'
            '  return 0;\n}\n', encoding="utf-8")
        for name in ("yume", "yumed"):
            subprocess.run(
                ["cc", str(source), f'-DPROGRAM="{name}"', "-o", str(cls.root / name)],
                check=True, capture_output=True, text=True, timeout=30)
        for name in ("LICENSE", "NOTICES", "QUICKSTART"):
            (cls.root / name).write_text(f"Fixture {name}\n", encoding="utf-8")

    def setUp(self) -> None:
        self.output = tempfile.TemporaryDirectory(prefix="yume-package-output-")
        self.addCleanup(self.output.cleanup)
        self.output_dir = Path(self.output.name)
        self.args = argparse.Namespace(
            yume=self.root / "yume", yumed=self.root / "yumed",
            setup=preflight.ROOT / "tools/yume_setup.py",
            doctor=preflight.ROOT / "tools/yume_doctor.py",
            license=self.root / "LICENSE", notices=self.root / "NOTICES",
            quick_start=self.root / "QUICKSTART", output_dir=self.output_dir,
            version=self.version, source_commit=self.commit)

    def package(self) -> None:
        with mock.patch.object(package, "parse_args", return_value=self.args):
            with contextlib.redirect_stdout(io.StringIO()):
                package.main()

    def validate(self) -> dict[str, object]:
        preflight.validate_artifacts(
            self.output_dir, self.version, self.commit, self.transport)
        return preflight.validate_bundle(
            self.output_dir / package.BUNDLE_NAME,
            self.version, self.commit, self.transport)

    def rewrite_bundle(self, *, duplicate: bool = False,
                       wrong_identity: bool = False,
                       root_mode: int | None = None,
                       root_is_file: bool = False) -> None:
        bundle = self.output_dir / package.BUNDLE_NAME
        with tarfile.open(bundle, "r:xz") as original:
            entries = [(member, original.extractfile(member).read()
                        if member.isfile() else None)
                       for member in original.getmembers()]
        with tarfile.open(bundle, "w:xz", format=tarfile.PAX_FORMAT) as changed:
            for member, payload in entries:
                if member.name == package.BUNDLE_DIRECTORY:
                    if root_mode is not None:
                        member.mode = root_mode
                    if root_is_file:
                        member.type = tarfile.REGTYPE
                        member.size = 0
                        payload = b""
                if wrong_identity and member.name.endswith("/manifest.json"):
                    manifest = json.loads(payload)
                    manifest["transport"] = "transport-v2"
                    payload = json.dumps(manifest).encode()
                    member.size = len(payload)
                changed.addfile(member, io.BytesIO(payload) if payload is not None else None)
                if duplicate and member.name.endswith("/yume"):
                    changed.addfile(member, io.BytesIO(payload))

    def test_native_package_roundtrip_and_reproducible_archive(self) -> None:
        self.package()
        first = (self.output_dir / package.BUNDLE_NAME).read_bytes()
        manifest = self.validate()
        self.assertEqual(manifest["transport"], "YTP/1")
        names = {entry["file"] for entry in manifest["files"]}
        self.assertIn("yume-setup", names)
        self.assertIn("yume-doctor", names)
        self.assertNotIn("yume-chrome-tls-helper", names)
        self.assertNotIn("argon2", manifest["required_features"])
        self.package()
        self.assertEqual(first, (self.output_dir / package.BUNDLE_NAME).read_bytes())

    def test_reference_binary_identity_is_rejected(self) -> None:
        with mock.patch.object(package, "version_output", return_value=(
                f"yume {self.version}\ntransport-v2 wire 0.2.0-dev6")):
            with self.assertRaisesRegex(SystemExit, "not the native"):
                self.package()
        self.assertEqual(list(self.output_dir.iterdir()), [])

    def test_missing_provisioner_is_rejected(self) -> None:
        self.args.setup = self.root / "absent-tool"
        with self.assertRaisesRegex(SystemExit, "Missing regular schema-1 setup"):
            self.package()

    def test_duplicate_archive_member_is_rejected(self) -> None:
        self.package()
        self.rewrite_bundle(duplicate=True)
        with self.assertRaisesRegex(SystemExit, "unexpected files"):
            self.validate()

    def test_unsafe_archive_root_is_rejected(self) -> None:
        for changes in ({"root_mode": 0o777}, {"root_is_file": True}):
            with self.subTest(changes=changes):
                self.package()
                self.rewrite_bundle(**changes)
                with self.assertRaisesRegex(SystemExit, "root"):
                    self.validate()

    def test_reference_manifest_identity_is_rejected(self) -> None:
        self.package()
        self.rewrite_bundle(wrong_identity=True)
        with self.assertRaisesRegex(SystemExit, "native schema-1"):
            self.validate()

    def test_changed_server_is_rejected(self) -> None:
        self.package()
        with (self.output_dir / package.SERVER_NAME).open("ab") as handle:
            handle.write(b"tampered")
        with self.assertRaisesRegex(SystemExit, "SHA-256 mismatch|size mismatch"):
            self.validate()

    def test_capture_provenance_uses_native_bundle_contract(self) -> None:
        self.package()
        with mock.patch.object(provenance, "source_version", return_value=self.version):
            digest = provenance.validate_capture_binaries(
                self.output_dir / package.BUNDLE_NAME, self.args.yume, self.commit)
        self.assertEqual(digest, package.sha256_file(self.args.yume))

    def test_release_index_does_not_invent_library_features(self) -> None:
        self.package()
        bundle_manifest = self.validate()
        manifest = release_manifest.build_manifest(self.output_dir, None)
        entries = {entry["file"]: entry for entry in manifest["files"]}
        self.assertEqual(set(entries), {package.BUNDLE_NAME, package.SERVER_NAME})
        for name, component, linkage in (
                (package.BUNDLE_NAME, "yume", "bundle"),
                (package.SERVER_NAME, "yumed", "dynamic")):
            with self.subTest(artifact=name):
                entry = entries[name]
                self.assertEqual(entry["component"], component)
                self.assertEqual(entry["arch"], "amd64")
                self.assertEqual(entry["os"], "linux")
                self.assertEqual(entry["linkage"], linkage)
                self.assertEqual(entry["sha256"],
                                 package.sha256_file(self.output_dir / name))
                self.assertNotIn("features", entry)
        # The validated package contract owns primitive support. Native PQ
        # support does not establish an Argon2, liboqs or liblzma dependency.
        self.assertTrue(bundle_manifest["required_features"]["post_quantum"])


if __name__ == "__main__":
    unittest.main()
