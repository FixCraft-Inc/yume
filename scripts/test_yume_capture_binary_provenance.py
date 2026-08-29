#!/usr/bin/env python3
"""Focused tests for exact-bundle YUME capture runtime binding."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yume_capture_binary_provenance as provenance
from release_preflight import require_no_runtime_search_path


class CaptureBinaryProvenanceTest(unittest.TestCase):
    @staticmethod
    def _executable(path: Path, payload: bytes) -> None:
        path.write_bytes(payload)
        path.chmod(0o755)

    @staticmethod
    def _elf_with_needed(*libraries: bytes) -> bytes:
        data = bytearray(1024)
        data[:6] = b"\x7fELF\x02\x01"
        data[18:20] = (62).to_bytes(2, "little")
        data[32:40] = (64).to_bytes(8, "little")
        data[54:56] = (56).to_bytes(2, "little")
        data[56:58] = (2).to_bytes(2, "little")

        load = 64
        data[load:load + 4] = (1).to_bytes(4, "little")
        data[load + 8:load + 16] = (256).to_bytes(8, "little")
        data[load + 16:load + 24] = (0x400000).to_bytes(8, "little")
        data[load + 32:load + 40] = (512).to_bytes(8, "little")

        dynamic = load + 56
        dynamic_offset = 384
        string_offset = 512
        string_address = 0x400000 + string_offset - 256
        strings = bytearray(b"\0")
        needed_offsets: list[int] = []
        for library in libraries:
            needed_offsets.append(len(strings))
            strings.extend(library + b"\0")
        entries = [(5, string_address), (10, len(strings))]
        entries.extend((1, offset) for offset in needed_offsets)
        entries.append((0, 0))
        dynamic_size = len(entries) * 16
        data[dynamic:dynamic + 4] = (2).to_bytes(4, "little")
        data[dynamic + 8:dynamic + 16] = dynamic_offset.to_bytes(8, "little")
        data[dynamic + 32:dynamic + 40] = dynamic_size.to_bytes(8, "little")
        for index, (tag, value) in enumerate(entries):
            offset = dynamic_offset + index * 16
            data[offset:offset + 8] = tag.to_bytes(8, "little")
            data[offset + 8:offset + 16] = value.to_bytes(8, "little")
        data[string_offset:string_offset + len(strings)] = strings
        return bytes(data)

    def test_bundle_elf_rejects_runtime_openssl_dependencies(self) -> None:
        require_no_runtime_search_path(
            self._elf_with_needed(b"libc.so.6", b"libstdc++.so.6"),
            "fixture",
        )
        for library in (b"libssl.so.3", b"libcrypto.so.3", b"libssl-custom.so"):
            with self.subTest(library=library), self.assertRaisesRegex(
                SystemExit, "dynamically links OpenSSL"
            ):
                require_no_runtime_search_path(
                    self._elf_with_needed(b"libc.so.6", library), "fixture"
                )
        for library in (b"/tmp/libssl.so.3", b"../libcrypto.so.3"):
            with self.subTest(library=library), self.assertRaisesRegex(
                SystemExit, "unsafe DT_NEEDED path"
            ):
                require_no_runtime_search_path(
                    self._elf_with_needed(b"libc.so.6", library), "fixture"
                )

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
                mock.patch.object(provenance, "source_version", return_value="0.2.0-dev6"),
                mock.patch.object(provenance, "transport_dependency", return_value={}),
                mock.patch.object(provenance, "validate_bundle", return_value=manifest),
            ):
                hashes = provenance.validate_capture_binaries(
                    bundle, yume, helper, "a" * 40
                )
            self.assertEqual(hashes[0], manifest["files"][0]["sha256"])
            self.assertEqual(hashes[1], manifest["files"][1]["sha256"])

    def test_native_capture_requires_only_the_yume_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / "yume-amd64-linux.tar.xz"
            bundle.write_bytes(b"bundle")
            yume = root / "yume"
            self._executable(yume, b"exact-native-yume")
            manifest = {"files": [{
                "file": "yume",
                "size": yume.stat().st_size,
                "sha256": hashlib.sha256(yume.read_bytes()).hexdigest(),
            }]}
            with (
                mock.patch.object(provenance, "source_version", return_value="0.2.0-dev6"),
                mock.patch.object(provenance, "transport_dependency", return_value={}),
                mock.patch.object(provenance, "validate_bundle", return_value=manifest),
            ):
                hashes = provenance.validate_capture_binaries(
                    bundle, yume, None, "a" * 40
                )
            self.assertEqual(hashes, (manifest["files"][0]["sha256"], None))

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
                mock.patch.object(provenance, "source_version", return_value="0.2.0-dev6"),
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
