#!/usr/bin/env python3
"""Gate the native OpenSSL ClientHello against the committed browser capture.

The claim this file defends is deliberately narrow and machine-checked: the
openssl-diagnostic backend, driven from config/transport_profiles.json, emits
the same JA4 fingerprint as the captured browser. JA4 is the right target
because it sorts extensions and ignores GREASE, and Chrome has permuted its own
extension order on every connection since v110 -- so extension order is not a
stable property of "looking like Chrome", while the cipher list, the extension
set and the signature algorithm list are.

What this does NOT claim is byte parity. Stock OpenSSL cannot place GREASE in
the cipher list, supported_groups, supported_versions or key_share, and cannot
be told where to put an extension. Rather than leave that gap as prose, the
final test re-derives it from the emitted bytes and pins it against
known_tls_divergence in the registry, so it cannot widen unnoticed.
"""

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from yume_tls_wire import is_grease, normalize_client_hello  # noqa: E402

FIXTURE = REPO_ROOT / "tests/fixtures/chrome151-node24/chrome_tls_wire_profile.json"
REGISTRY = REPO_ROOT / "config/transport_profiles.json"

# JA4 hashes the extension list with SNI and ALPN removed: both are attacker- or
# destination-controlled rather than client properties.
JA4_EXCLUDED_EXTENSIONS = {0x0000, 0x0010}


def dump_tool() -> pathlib.Path:
    """Locate the ClientHello dump binary, or skip if this build lacks it."""
    override = os.environ.get("YUME_CLIENTHELLO_DUMP")
    if override:
        return pathlib.Path(override)
    raise unittest.SkipTest(
        "YUME_CLIENTHELLO_DUMP not set; native wire gate needs the built tool")


def as_int(value: str) -> int:
    return int(value, 16)


def ja4_parts(ciphers: list[int], extensions: list[int],
              sigalgs: list[int]) -> tuple[str, str]:
    """The two JA4 hash components: ja4_b (ciphers) and ja4_c (extensions)."""
    real_ciphers = sorted(c for c in ciphers if not is_grease(c))
    cipher_str = ",".join(f"{c:04x}" for c in real_ciphers)
    ja4_b = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]

    real_exts = sorted(e for e in extensions
                       if not is_grease(e) and e not in JA4_EXCLUDED_EXTENSIONS)
    ext_str = ",".join(f"{e:04x}" for e in real_exts)
    sig_str = ",".join(f"{s:04x}" for s in sigalgs)
    ja4_c = hashlib.sha256(f"{ext_str}_{sig_str}".encode()).hexdigest()[:12]
    return ja4_b, ja4_c


def from_capture() -> tuple[list[int], list[int], list[int]]:
    hello = json.loads(FIXTURE.read_text())["client_hello"]
    ciphers = [as_int(c) for c in hello["cipher_suites"] if c != "GREASE"]
    # The capture records the two GREASE extensions separately from the
    # permuted middle block, and JA4 drops GREASE anyway.
    exts = [as_int(e) for e in hello["middle_extension_types"]]
    sigalgs = [as_int(s)
               for s in hello["structured_extensions"]["0x000d"]["values"]
               if s != "GREASE"]
    return ciphers, exts, sigalgs


def raw_extension_types(data: bytes) -> list[int]:
    """Extension types straight off the wire, GREASE values intact.

    normalize_client_hello() renders every GREASE code point as the literal
    string "GREASE", which is right for structural comparison but loses the
    actual values -- and RFC 8701 §3.3 requires the two GREASE extensions in one
    ClientHello to differ, so that check needs the raw bytes.
    """
    body = data[5:]                       # TLS record header
    cursor = 4 + 2 + 32                   # handshake header, version, random
    cursor += 1 + body[cursor]            # session id
    cursor += 2 + int.from_bytes(body[cursor:cursor + 2], "big")  # ciphers
    cursor += 1 + body[cursor]            # compression methods
    cursor += 2                           # extensions block length
    types: list[int] = []
    while cursor + 4 <= len(body):
        types.append(int.from_bytes(body[cursor:cursor + 2], "big"))
        cursor += 4 + int.from_bytes(body[cursor + 2:cursor + 4], "big")
    return types


def from_native() -> tuple[list[int], list[int], list[int], dict, list[int]]:
    tool = dump_tool()
    with tempfile.TemporaryDirectory() as work:
        target = pathlib.Path(work) / "clienthello.bin"
        subprocess.run([str(tool), "--output", str(target)],
                       check=True, capture_output=True, timeout=60)
        raw = target.read_bytes()
        hello = normalize_client_hello(raw)
    ciphers = [as_int(c) for c in hello["cipher_suites"] if c != "GREASE"]
    exts = [as_int(e["type"]) for e in hello["extensions"]
            if e["type"] != "GREASE"]
    sigalgs: list[int] = []
    for extension in hello["extensions"]:
        if extension["type"] == "0x000d":
            sigalgs = [as_int(v) for v in extension["values"] if v != "GREASE"]
    return ciphers, exts, sigalgs, hello, raw_extension_types(raw)


class NativeWireTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cap_ciphers, self.cap_exts, self.cap_sigalgs = from_capture()
        (self.nat_ciphers, self.nat_exts, self.nat_sigalgs,
         self.native_hello, self.nat_raw_exts) = from_native()

    def test_cipher_list_matches_capture_exactly(self) -> None:
        # Order matters here and OpenSSL preserves it, so this is an exact
        # sequence comparison, not a set comparison.
        self.assertEqual(self.nat_ciphers, self.cap_ciphers)

    def test_signature_algorithms_match_capture_exactly(self) -> None:
        # JA4 hashes sigalgs in order, and OpenSSL 3.5 emits ML-DSA, so this
        # must match as a sequence.
        self.assertEqual(self.nat_sigalgs, self.cap_sigalgs)

    def test_extension_set_matches_capture(self) -> None:
        self.assertEqual(set(self.nat_exts), set(self.cap_exts))

    def test_ja4_hash_components_match_capture(self) -> None:
        self.assertEqual(
            ja4_parts(self.nat_ciphers, self.nat_exts, self.nat_sigalgs),
            ja4_parts(self.cap_ciphers, self.cap_exts, self.cap_sigalgs))

    def test_ja4_extension_count_matches_capture(self) -> None:
        # ja4_a encodes the extension count; a mismatch changes the fingerprint
        # even when both hash components agree.
        self.assertEqual(len(self.nat_exts), len(self.cap_exts))

    def test_grease_extensions_are_present_and_distinct(self) -> None:
        greased = [t for t in self.nat_raw_exts if is_grease(t)]
        self.assertEqual(len(greased), 2,
                         f"expected two GREASE extensions, got {greased}")
        self.assertEqual(len(set(greased)), 2,
                         "GREASE values must differ (RFC 8701 §3.3)")

    def test_ech_grease_length_is_one_the_browser_uses(self) -> None:
        allowed = json.loads(FIXTURE.read_text())["client_hello"]["allowed_ech_lengths"]
        ech = [e for e in self.native_hello["extensions"] if e["type"] == "0xfe0d"]
        self.assertEqual(len(ech), 1, "no ECH extension was emitted")
        self.assertIn(ech[0]["length"], allowed)

    def test_declared_divergence_still_matches_reality(self) -> None:
        """Re-derive the accepted gap from emitted bytes and pin it."""
        declared = json.loads(REGISTRY.read_text())["profiles"][0]["known_tls_divergence"]
        actual = {
            "cipher_suites": (
                [f"0x{c:04x}" for c in self.cap_ciphers if c not in self.nat_ciphers],
                [f"0x{c:04x}" for c in self.nat_ciphers if c not in self.cap_ciphers]),
            "signature_algorithms": (
                [f"0x{s:04x}" for s in self.cap_sigalgs if s not in self.nat_sigalgs],
                [f"0x{s:04x}" for s in self.nat_sigalgs if s not in self.cap_sigalgs]),
            "extensions": (
                [f"0x{e:04x}" for e in self.cap_exts if e not in self.nat_exts],
                [f"0x{e:04x}" for e in self.nat_exts if e not in self.cap_exts]),
        }
        for field, (missing, extra) in actual.items():
            self.assertEqual(declared[field]["missing"], missing,
                             f"{field}.missing drifted from emitted bytes")
            self.assertEqual(declared[field]["extra"], extra,
                             f"{field}.extra drifted from emitted bytes")


if __name__ == "__main__":
    unittest.main()
