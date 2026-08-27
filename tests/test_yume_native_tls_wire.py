#!/usr/bin/env python3
"""Gate both native OpenSSL ClientHello modes against the browser capture.

The claim this file defends is deliberately narrow and machine-checked: the
openssl-diagnostic backend, driven from config/transport_profiles.json, emits
the same JA4 fingerprint as the captured browser. JA4 is the right target
because it sorts extensions and ignores GREASE, and Chrome has permuted its own
extension order on every connection since v110 -- so extension order is not a
stable property of "looking like Chrome", while the cipher list, the extension
set and the signature algorithm list are.

What this does NOT claim is byte parity, and the gap is wider than GREASE.
Stock OpenSSL cannot place GREASE in the cipher list, supported_groups,
supported_versions or key_share, cannot be told where to put an extension, and
additionally offers three ec_point_formats where the browser offers one. JA3
hashes the extension list in wire order and does not match at all; the final
tests re-derive every one of those residuals from the emitted bytes and pin
them against known_tls_divergence in the registry, so none can widen unnoticed.

A separate positive gate drives the default `openssl-chrome151` backend through
12 fresh SSL objects on one context and checks all six pinned structure rows,
GREASE relationships, edge placement, custom-extension interleaving, changing
JA3 order, and exact JA4. That remains a ClientHello structure claim rather
than whole-session indistinguishability.

One residual that used to live here is closed: the browser's second key_share
entry is reachable through the `*` prefix in SSL_CTX_set1_groups_list, and the
registry now asks for it. The GREASE share beside it is not reachable.
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
EXPECTED_CAPTURE_JA4 = "t13d1516h2_8daaf6152771_806a8c22fdea"

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


def ja4_a(supported_versions: list[int], has_domain_sni: bool,
          ciphers: list[int], extensions: list[int],
          alpn_protocols: list[str]) -> str:
    """JA4's unhashed A component for a TCP ClientHello."""
    versions = {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
    }
    real_versions = [v for v in supported_versions if not is_grease(v)]
    if not real_versions or max(real_versions) not in versions:
        raise AssertionError(f"unsupported JA4 TLS versions: {real_versions}")
    alpn = alpn_protocols[0] if alpn_protocols else ""
    alpn_code = f"{alpn[0]}{alpn[-1]}" if alpn else "00"
    return (f"t{versions[max(real_versions)]}"
            f"{'d' if has_domain_sni else 'i'}"
            f"{len(ciphers):02d}{len(extensions):02d}{alpn_code}")


def ja4_fingerprint(supported_versions: list[int], has_domain_sni: bool,
                    ciphers: list[int], extensions: list[int],
                    sigalgs: list[int], alpn_protocols: list[str]) -> str:
    ja4_b, ja4_c = ja4_parts(ciphers, extensions, sigalgs)
    return (f"{ja4_a(supported_versions, has_domain_sni, ciphers, extensions, alpn_protocols)}"
            f"_{ja4_b}_{ja4_c}")


def from_capture() -> tuple[list[int], list[int], list[int], list[int],
                            list[int], list[str], bool]:
    hello = json.loads(FIXTURE.read_text())["client_hello"]
    structured = hello["structured_extensions"]
    ciphers = [as_int(c) for c in hello["cipher_suites"] if c != "GREASE"]
    # The capture records the two GREASE extensions separately from the
    # permuted middle block, and JA4 drops GREASE anyway.
    exts = [as_int(e) for e in hello["middle_extension_types"]]
    groups = [as_int(group) for group in structured["0x000a"]["values"]
              if group != "GREASE"]
    sigalgs = [as_int(s)
               for s in structured["0x000d"]["values"]
               if s != "GREASE"]
    versions = [as_int(version) for version in structured["0x002b"]["versions"]
                if version != "GREASE"]
    alpns = list(structured["0x0010"]["protocols"])
    has_domain_sni = bool(structured["0x0000"]["server_names"])
    return ciphers, exts, groups, sigalgs, versions, alpns, has_domain_sni


def extension_entries(data: bytes) -> list[tuple[int, bytes]]:
    """Ordered (type, body) entries straight off the wire."""
    body = data[5:]
    cursor = 4 + 2 + 32
    cursor += 1 + body[cursor]
    cursor += 2 + int.from_bytes(body[cursor:cursor + 2], "big")
    cursor += 1 + body[cursor]
    cursor += 2
    entries: list[tuple[int, bytes]] = []
    while cursor + 4 <= len(body):
        kind = int.from_bytes(body[cursor:cursor + 2], "big")
        length = int.from_bytes(body[cursor + 2:cursor + 4], "big")
        entries.append((kind, body[cursor + 4:cursor + 4 + length]))
        cursor += 4 + length
    return entries


def extension_bodies(data: bytes) -> dict[int, bytes]:
    """Extension type -> body, straight off the wire.

    normalize_client_hello() is shaped for structural comparison and does not
    surface ec_point_formats or the key_share geometry, both of which JA4
    ignores and a raw-ClientHello classifier does not.
    """
    return dict(extension_entries(data))


def raw_cipher_suites(data: bytes) -> list[int]:
    body = data[5:]
    cursor = 4 + 2 + 32
    cursor += 1 + body[cursor]
    length = int.from_bytes(body[cursor:cursor + 2], "big")
    cursor += 2
    return [int.from_bytes(body[i:i + 2], "big")
            for i in range(cursor, cursor + length, 2)]


def raw_u16_vector(body: bytes, prefix_bytes: int) -> list[int]:
    length = int.from_bytes(body[:prefix_bytes], "big")
    start = prefix_bytes
    return [int.from_bytes(body[i:i + 2], "big")
            for i in range(start, start + length, 2)]


def raw_key_shares(body: bytes) -> list[tuple[int, int]]:
    total = int.from_bytes(body[:2], "big")
    cursor = 2
    shares: list[tuple[int, int]] = []
    while cursor + 4 <= 2 + total:
        group = int.from_bytes(body[cursor:cursor + 2], "big")
        length = int.from_bytes(body[cursor + 2:cursor + 4], "big")
        shares.append((group, length))
        cursor += 4 + length
    return shares


def ec_point_formats(bodies: dict[int, bytes]) -> list[int]:
    """The 0x000b list: one length byte, then one byte per format."""
    raw = bodies.get(0x000b)
    if raw is None:
        return []
    return list(raw[1:1 + raw[0]])


def key_share_geometry(bodies: dict[int, bytes]) -> list[tuple[str, int]]:
    """(group, key_exchange_length) per share, GREASE rendered as the capture does."""
    raw = bodies.get(0x0033)
    if raw is None:
        return []
    total = int.from_bytes(raw[:2], "big")
    cursor = 2
    shares: list[tuple[str, int]] = []
    while cursor + 4 <= 2 + total:
        group = int.from_bytes(raw[cursor:cursor + 2], "big")
        length = int.from_bytes(raw[cursor + 2:cursor + 4], "big")
        shares.append(("GREASE" if is_grease(group) else f"0x{group:04x}", length))
        cursor += 4 + length
    return shares


def cert_compression(bodies: dict[int, bytes]) -> list[str]:
    """The 0x001b algorithm list, by RFC 8879 name."""
    raw = bodies.get(0x001b)
    if raw is None:
        return []
    names = {1: "zlib", 2: "brotli", 3: "zstd"}
    count = raw[0]
    return [names.get(int.from_bytes(raw[1 + i:1 + i + 2], "big"), "?")
            for i in range(0, count, 2)]


def ja3(tls_version: int, ciphers: list[int], extensions: list[int],
        groups: list[int], formats: list[int]) -> tuple[str, str]:
    """Canonical JA3: GREASE filtered, but extension order preserved.

    That order is the whole reason JA3 is reported separately here. JA4 sorts
    the extension list; JA3 does not, so JA3 is the component that exposes
    emission order.
    """
    text = ",".join((
        str(tls_version),
        "-".join(str(c) for c in ciphers if not is_grease(c)),
        "-".join(str(e) for e in extensions if not is_grease(e)),
        "-".join(str(g) for g in groups if not is_grease(g)),
        "-".join(str(f) for f in formats),
    ))
    return text, hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()


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


def parse_native(raw: bytes) -> tuple[list[int], list[int], list[int], list[int],
                           list[int], list[str], bool, dict, list[int], bytes]:
    hello = normalize_client_hello(raw)
    ciphers = [as_int(c) for c in hello["cipher_suites"] if c != "GREASE"]
    exts = [as_int(e["type"]) for e in hello["extensions"]
            if e["type"] != "GREASE"]
    groups: list[int] = []
    sigalgs: list[int] = []
    versions: list[int] = []
    alpns: list[str] = []
    has_domain_sni = False
    for extension in hello["extensions"]:
        if extension["type"] == "0x0000":
            has_domain_sni = bool(extension["server_names"])
        elif extension["type"] == "0x000a":
            groups = [as_int(v) for v in extension["values"] if v != "GREASE"]
        elif extension["type"] == "0x000d":
            sigalgs = [as_int(v) for v in extension["values"] if v != "GREASE"]
        elif extension["type"] == "0x0010":
            alpns = list(extension["protocols"])
        elif extension["type"] == "0x002b":
            versions = [as_int(v) for v in extension["versions"] if v != "GREASE"]
    return (ciphers, exts, groups, sigalgs, versions, alpns, has_domain_sni,
            hello, raw_extension_types(raw), raw)


def from_native(backend: str = "openssl-diagnostic") -> tuple[
        list[int], list[int], list[int], list[int], list[int], list[str],
        bool, dict, list[int], bytes]:
    tool = dump_tool()
    with tempfile.TemporaryDirectory() as work:
        target = pathlib.Path(work) / "clienthello.bin"
        subprocess.run([str(tool), "--backend", backend,
                        "--output", str(target)],
                       check=True, capture_output=True, timeout=60)
        return parse_native(target.read_bytes())


def from_native_many(backend: str, count: int) -> list[tuple]:
    """Render several SSL objects from one long-lived SSL_CTX/process."""
    tool = dump_tool()
    with tempfile.TemporaryDirectory() as work:
        target = pathlib.Path(work) / "clienthello.bin"
        subprocess.run([str(tool), "--backend", backend,
                        "--count", str(count), "--output", str(target)],
                       check=True, capture_output=True, timeout=60)
        return [parse_native(pathlib.Path(f"{target}.{index}").read_bytes())
                for index in range(count)]


class DiagnosticNativeWireTests(unittest.TestCase):
    def setUp(self) -> None:
        (self.cap_ciphers, self.cap_exts, self.cap_groups, self.cap_sigalgs,
         self.cap_versions, self.cap_alpns,
         self.cap_has_domain_sni) = from_capture()
        (self.nat_ciphers, self.nat_exts, self.nat_groups, self.nat_sigalgs,
         self.nat_versions, self.nat_alpns, self.nat_has_domain_sni,
         self.native_hello, self.nat_raw_exts, self.nat_raw) = from_native()
        self.nat_bodies = extension_bodies(self.nat_raw)

    def test_cipher_list_matches_capture_exactly(self) -> None:
        # Order matters here and OpenSSL preserves it, so this is an exact
        # sequence comparison, not a set comparison.
        self.assertEqual(self.nat_ciphers, self.cap_ciphers)

    def test_signature_algorithms_match_capture_exactly(self) -> None:
        # JA4 hashes sigalgs in order, and OpenSSL 3.5 emits ML-DSA, so this
        # must match as a sequence.
        self.assertEqual(self.nat_sigalgs, self.cap_sigalgs)

    def test_supported_groups_match_capture_exactly(self) -> None:
        self.assertEqual(self.nat_groups, self.cap_groups)

    def test_extension_set_matches_capture(self) -> None:
        self.assertEqual(set(self.nat_exts), set(self.cap_exts))

    def test_complete_ja4_matches_capture(self) -> None:
        captured = ja4_fingerprint(
            self.cap_versions, self.cap_has_domain_sni,
            self.cap_ciphers, self.cap_exts, self.cap_sigalgs,
            self.cap_alpns)
        self.assertEqual(captured, EXPECTED_CAPTURE_JA4)
        self.assertEqual(
            ja4_fingerprint(
                self.nat_versions, self.nat_has_domain_sni,
                self.nat_ciphers, self.nat_exts, self.nat_sigalgs,
                self.nat_alpns),
            captured)

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

    def test_ec_point_formats_divergence_is_pinned(self) -> None:
        """OpenSSL offers three EC point formats; the browser offers one.

        JA4 does not hash this extension, so the JA4 match above hides it
        entirely. JA3 does hash it, and so does anything reading the raw
        ClientHello. There is no OpenSSL setter for the list -- only
        SSL_get0_ec_point_formats, a getter -- so this cannot be closed
        without patching OpenSSL.
        """
        declared = json.loads(REGISTRY.read_text())["profiles"][0]["known_tls_divergence"]
        capture = json.loads(FIXTURE.read_text())["client_hello"]
        self.assertEqual(ec_point_formats(self.nat_bodies),
                         declared["ec_point_formats"]["offered"],
                         "emitted ec_point_formats drifted from the registry")
        self.assertEqual(capture["structured_extensions"]["0x000b"]["values"],
                         declared["ec_point_formats"]["capture"],
                         "registry ec_point_formats capture drifted from the fixture")
        self.assertNotEqual(declared["ec_point_formats"]["offered"],
                            declared["ec_point_formats"]["capture"],
                            "if this ever matches, retire the residual instead")

    def test_key_share_geometry_divergence_is_pinned(self) -> None:
        """The browser sends GREASE + hybrid + classical; OpenSSL sends two.

        openssl_selection.key_share_groups marks both real groups with the `*`
        prefix SSL_CTX_set1_groups_list needs to generate a share, so the
        browser's classical (0x001d) share is now offered too. Only the GREASE
        share is left, and stock OpenSSL cannot express it -- the emitted body
        is 1258 bytes against the capture's 1263, which is exactly those five.
        """
        declared = json.loads(REGISTRY.read_text())["profiles"][0]["known_tls_divergence"]
        capture = json.loads(FIXTURE.read_text())["client_hello"]
        cap_shares = [[s["group"], s["key_exchange_length"]]
                      for s in capture["structured_extensions"]["0x0033"]["shares"]]
        nat_shares = [[group, length]
                      for group, length in key_share_geometry(self.nat_bodies)]
        self.assertEqual(nat_shares, declared["key_share"]["offered"],
                         "emitted key_share geometry drifted from the registry")
        self.assertEqual(cap_shares, declared["key_share"]["capture"],
                         "registry key_share capture drifted from the fixture")

    def test_cert_compression_is_requested_or_visibly_degraded(self) -> None:
        """OpenSSL can only offer an algorithm it was compiled with.

        So this is build-dependent and both states are pinned: an
        enable-brotli build must emit exactly what the profile asks for, and
        any other build must emit exactly the recorded degradation. A third
        answer means something changed that nobody declared.

        Note this asserts the emitted *value*, which the committed fixture does
        not record -- it pins only the 3-byte length. The brotli expectation
        comes from Chrome's documented behaviour, so a recapture is still owed
        before this row counts as matched.
        """
        declared = json.loads(REGISTRY.read_text())["profiles"][0]["known_tls_divergence"]
        capture = json.loads(FIXTURE.read_text())["client_hello"]
        entry = declared["cert_compression"]
        self.assertEqual(capture["exact_extension_lengths"]["0x001b"],
                         entry["capture_length"],
                         "registry cert_compression length drifted from the fixture")

        emitted = cert_compression(self.nat_bodies)
        if emitted == entry["requested"]:
            # A one-algorithm offer is a 1-byte count plus one u16.
            self.assertEqual(len(self.nat_bodies[0x001b]),
                             entry["capture_length"],
                             "single-algorithm body should match the capture length")
        else:
            self.assertEqual(emitted, entry["degraded"],
                             "emitted certificate compression is neither the "
                             "requested list nor the declared degradation")

    def test_ja3_does_not_match_and_is_static(self) -> None:
        """Pin the JA3 claim boundary in both directions.

        JA3 preserves extension emission order, so it cannot match a browser
        that permutes that order per connection -- and the second assertion is
        the one that matters for a classifier: this backend's JA3 is constant,
        where real Chrome's is a fresh value on every connection. A stable
        Chrome-labelled JA3 is a signal, not parity. Any claim that the
        OpenSSL backend reaches a browser JA3 fails here.
        """
        capture = json.loads(FIXTURE.read_text())["client_hello"]
        _, cap_ja3 = ja3(0x0303, self.cap_ciphers, self.cap_exts,
                         self.cap_groups,
                         capture["structured_extensions"]["0x000b"]["values"])
        _, nat_ja3 = ja3(0x0303, self.nat_ciphers,
                         [e for e in self.nat_raw_exts if not is_grease(e)],
                         self.nat_groups, ec_point_formats(self.nat_bodies))
        self.assertNotEqual(nat_ja3, cap_ja3,
                            "JA3 parity is not claimed; if it holds, requalify "
                            "the claim rather than relaxing this test")

        # A second render from a fresh process: different GREASE draw, different
        # ECH body length, identical JA3.
        (again_ciphers, _, again_groups, _, _, _, _, _,
         again_raw_exts, again_raw) = from_native()
        _, repeat_ja3 = ja3(0x0303, again_ciphers,
                            [e for e in again_raw_exts if not is_grease(e)],
                            again_groups,
                            ec_point_formats(extension_bodies(again_raw)))
        self.assertEqual(nat_ja3, repeat_ja3,
                         "native JA3 is expected to be static; a varying one "
                         "would mean extension order became per-connection")

    def test_declared_divergence_still_matches_reality(self) -> None:
        """Re-derive the accepted gap from emitted bytes and pin it."""
        declared = json.loads(REGISTRY.read_text())["profiles"][0]["known_tls_divergence"]
        actual = {
            "cipher_suites": (
                [f"0x{c:04x}" for c in self.cap_ciphers if c not in self.nat_ciphers],
                [f"0x{c:04x}" for c in self.nat_ciphers if c not in self.cap_ciphers]),
            "supported_groups": (
                [f"0x{g:04x}" for g in self.cap_groups if g not in self.nat_groups],
                [f"0x{g:04x}" for g in self.nat_groups if g not in self.cap_groups]),
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


class ChromeNativeWireTests(unittest.TestCase):
    """Positive 6/6 gate for the native patched OpenSSL backend."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.capture = json.loads(FIXTURE.read_text())["client_hello"]
        (cls.cap_ciphers, cls.cap_exts, cls.cap_groups, cls.cap_sigalgs,
         cls.cap_versions, cls.cap_alpns,
         cls.cap_has_domain_sni) = from_capture()
        # One process and one SSL_CTX, but a fresh SSL object for every hello.
        cls.renders = from_native_many("openssl-chrome151", 12)

    def test_exact_non_grease_profile_and_chrome_edge_slots(self) -> None:
        for render in self.renders:
            (ciphers, extensions, groups, sigalgs, versions, alpns, has_sni,
             _hello, _raw_exts, raw) = render
            entries = extension_entries(raw)

            self.assertEqual(ciphers, self.cap_ciphers)
            self.assertEqual(set(extensions), set(self.cap_exts))
            self.assertEqual(len(extensions), len(self.cap_exts))
            self.assertEqual(groups, self.cap_groups)
            self.assertEqual(sigalgs, self.cap_sigalgs)
            self.assertEqual(versions, self.cap_versions)
            self.assertEqual(alpns, self.cap_alpns)
            self.assertEqual(has_sni, self.cap_has_domain_sni)

            self.assertTrue(is_grease(entries[0][0]))
            self.assertEqual(entries[0][1], b"")
            self.assertTrue(is_grease(entries[-1][0]))
            self.assertEqual(entries[-1][1], b"\x00")
            self.assertNotEqual(entries[0][0], entries[-1][0])

    def test_grease_categories_and_key_share_relationships(self) -> None:
        observations: set[tuple[int, ...]] = set()
        for render in self.renders:
            raw = render[-1]
            bodies = extension_bodies(raw)
            ciphers = raw_cipher_suites(raw)
            groups = raw_u16_vector(bodies[0x000A], 2)
            versions = raw_u16_vector(bodies[0x002B], 1)
            shares = raw_key_shares(bodies[0x0033])
            grease_exts = [kind for kind, _ in extension_entries(raw)
                           if is_grease(kind)]

            self.assertTrue(is_grease(ciphers[0]))
            self.assertEqual(ciphers[1:], self.cap_ciphers)
            self.assertTrue(is_grease(groups[0]))
            self.assertEqual(groups[1:], self.cap_groups)
            self.assertTrue(is_grease(versions[0]))
            self.assertEqual(versions[1:], self.cap_versions)
            self.assertEqual(len(grease_exts), 2)
            self.assertEqual(len(set(grease_exts)), 2)

            self.assertTrue(is_grease(shares[0][0]))
            self.assertEqual(shares[0][0], groups[0],
                             "supported_groups and key_share must share GREASE")
            self.assertEqual(shares[0][1], 1)
            self.assertEqual(shares[1:], [(0x11EC, 1216), (0x001D, 32)])
            observations.add((ciphers[0], groups[0], versions[0],
                              grease_exts[0], grease_exts[1]))

        self.assertGreater(len(observations), 1,
                           "GREASE must be redrawn for SSL objects sharing a context")

    def test_closed_point_format_and_certificate_compression_rows(self) -> None:
        for render in self.renders:
            bodies = extension_bodies(render[-1])
            self.assertEqual(ec_point_formats(bodies), [0])
            self.assertEqual(cert_compression(bodies), ["brotli"])
            self.assertEqual(bodies[0x001B], b"\x02\x00\x02")

    def test_middle_order_varies_and_custom_extensions_interleave(self) -> None:
        orders: set[tuple[int, ...]] = set()
        custom_types = {0x0012, 0x44CD, 0xFE0D}
        saw_interleaved_custom_extensions = False
        for render in self.renders:
            middle = tuple(kind for kind, _ in extension_entries(render[-1])
                           if not is_grease(kind))
            orders.add(middle)
            self.assertEqual(set(middle), set(self.cap_exts))
            positions = sorted(i for i, kind in enumerate(middle)
                               if kind in custom_types)
            if positions != list(range(positions[0], positions[0] + len(positions))):
                saw_interleaved_custom_extensions = True

        self.assertGreater(len(orders), 1,
                           "extension order must vary per connection")
        self.assertTrue(saw_interleaved_custom_extensions,
                        "SCT, ALPS, and ECH must shuffle as individual blocks")

    def test_ja3_varies_per_connection_while_ja4_stays_exact(self) -> None:
        ja3_hashes: set[str] = set()
        for render in self.renders:
            (ciphers, extensions, groups, sigalgs, versions, alpns, has_sni,
             _hello, raw_exts, raw) = render
            self.assertEqual(
                ja4_fingerprint(versions, has_sni, ciphers, extensions,
                                sigalgs, alpns),
                EXPECTED_CAPTURE_JA4)
            _, digest = ja3(0x0303, ciphers,
                            [kind for kind in raw_exts if not is_grease(kind)],
                            groups, ec_point_formats(extension_bodies(raw)))
            ja3_hashes.add(digest)
        self.assertGreater(len(ja3_hashes), 1)


if __name__ == "__main__":
    unittest.main()
