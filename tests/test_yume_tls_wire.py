#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts/yume_tls_wire.py"
PROFILE_PATH = (
    REPO_ROOT / "tests/fixtures/chrome151-node24/chrome_tls_wire_profile.json"
)
SPEC = importlib.util.spec_from_file_location("yume_tls_wire", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
WIRE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WIRE
SPEC.loader.exec_module(WIRE)


def vector8(value: bytes) -> bytes:
    return bytes([len(value)]) + value


def vector16(value: bytes) -> bytes:
    return len(value).to_bytes(2, "big") + value


def extension(kind: int, value: bytes) -> bytes:
    return kind.to_bytes(2, "big") + vector16(value)


def handshake_record(kind: int, body: bytes, record_version: int = 0x0301) -> bytes:
    message = bytes([kind]) + len(body).to_bytes(3, "big") + body
    return b"\x16" + record_version.to_bytes(2, "big") + vector16(message)


class WireParserTests(unittest.TestCase):
    def test_normalizes_client_hello_without_discarding_geometry(self) -> None:
        extensions = b"".join([
            extension(0x0A0A, b""),
            extension(0, vector16(b"\x00" + vector16(b"localhost"))),
            extension(16, vector16(vector8(b"h2") + vector8(b"http/1.1"))),
            extension(10, vector16(b"\x00\x1d\x00\x17")),
            extension(51, vector16(b"\x00\x1d" + vector16(b"x" * 32))),
            extension(0x1A1A, b"x"),
        ])
        body = b"".join([
            b"\x03\x03",
            b"r" * 32,
            vector8(b"s" * 32),
            vector16(b"\x13\x01\x13\x02"),
            vector8(b"\x00"),
            vector16(extensions),
        ])

        hello = WIRE.normalize_client_hello(handshake_record(1, body))

        self.assertEqual(hello["random"], "<entropy>")
        self.assertEqual(hello["session_id_length"], 32)
        self.assertEqual(hello["cipher_suites"], ["0x1301", "0x1302"])
        self.assertEqual(hello["extensions"][0]["type"], "GREASE")
        self.assertEqual(hello["extensions"][-1]["length"], 1)
        key_share = WIRE.extension_by_type(hello, "0x0033")
        self.assertEqual(key_share["shares"][0]["key_exchange_length"], 32)
        self.assertEqual(key_share["shares"][0]["key_exchange"], "<entropy>")

    def test_rejects_odd_cipher_vector(self) -> None:
        body = b"".join([
            b"\x03\x03",
            b"r" * 32,
            vector8(b""),
            vector16(b"\x13"),
            vector8(b"\x00"),
            vector16(b""),
        ])
        with self.assertRaisesRegex(WIRE.ParseError, "odd u16 vector"):
            WIRE.normalize_client_hello(handshake_record(1, body))

    def test_rejects_truncated_handshake(self) -> None:
        with self.assertRaisesRegex(WIRE.ParseError, "not found"):
            WIRE.normalize_client_hello(b"\x16\x03\x01\x00\x10short")


def candidate_report(profile: dict, order_shift: int, ech_length: int) -> dict:
    client = profile["client_hello"]
    middle_types = list(client["middle_extension_types"])
    shift = order_shift % len(middle_types)
    middle_types = middle_types[shift:] + middle_types[:shift]
    middle = []
    for kind in middle_types:
        item = {
            "type": kind,
            "length": client["exact_extension_lengths"].get(kind, ech_length),
        }
        item.update(client["structured_extensions"].get(kind, {}))
        middle.append(item)
    hello = {
        field: client[field]
        for field in ("kind", "legacy_version", "session_id_length",
                      "cipher_suites", "compression_methods")
    }
    hello["extensions"] = [
        {"type": "GREASE", "length": client["first_grease_length"]},
        *middle,
        {"type": "GREASE", "length": client["last_grease_length"]},
    ]
    hello["tls_records"] = [{
        "content_type": 22,
        "legacy_version": client["record_legacy_version"],
        "length": client["record_length_base"] + ech_length,
    }]
    return {"schema": 1, "client_hello": hello,
            "server_hello": profile["server_hello"]}


class WireProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))

    def write_candidates(self, directory: pathlib.Path,
                         shifts: list[int], lengths: list[int]) -> list[pathlib.Path]:
        paths = []
        for index, (shift, length) in enumerate(zip(shifts, lengths, strict=True)):
            path = directory / f"run-{index}.json"
            path.write_text(
                json.dumps(candidate_report(self.profile, shift, length)),
                encoding="utf-8",
            )
            paths.append(path)
        return paths

    def test_accepts_five_structurally_matching_variable_hellos(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidates = self.write_candidates(
                pathlib.Path(temporary), [0, 1, 2, 3, 4], [186, 218, 250, 282, 186]
            )
            self.assertEqual(WIRE.validate_profile(PROFILE_PATH, candidates), 0)

    def test_rejects_stable_extension_order_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidates = self.write_candidates(
                pathlib.Path(temporary), [0, 0, 0, 0, 0], [186, 218, 250, 282, 186]
            )
            with self.assertRaisesRegex(WIRE.ParseError, "stable extension-order"):
                WIRE.validate_profile(PROFILE_PATH, candidates)

    def test_rejects_record_geometry_drift(self) -> None:
        report = candidate_report(self.profile, 0, 186)
        report["client_hello"]["tls_records"][0]["length"] += 1
        with self.assertRaisesRegex(WIRE.ParseError, "TLS record length"):
            WIRE.validate_client_hello(
                report["client_hello"], self.profile["client_hello"]
            )


if __name__ == "__main__":
    unittest.main()
