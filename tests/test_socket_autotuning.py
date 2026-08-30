#!/usr/bin/env python3
"""Guard TCP window autotuning at each pin definition and call site.

Any explicit SO_RCVBUF/SO_SNDBUF value disables Linux TCP window autotuning for
that socket. A file-wide allowlist is unsafe: one source can own both a
loopback/AF_UNIX endpoint and a remote connection, as the proxy sources do.
This test therefore permits only named function bodies and separately audits
every call to the helpers that contain the permitted pins.

See docs/IMPLEMENTATION_STATUS.md, "Performance and network qualification".
"""

from __future__ import annotations

import re
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT / "src"

DIRECT_PIN = re.compile(
    r"\b(?:receive_buffer_size|send_buffer_size)\s*\(|SO_(?:RCV|SND)BUF"
)
HELPER_CALL = re.compile(
    r"(?:(?:\.|->)\s*(?P<member>set_socket_buffers)|"
    r"\b(?P<free>set_socket_buffers|tune_socket|ConfigureSocketpairBuffers))\s*\("
)
HELPER_DECLARATION = re.compile(
    r"\bvoid\s+set_socket_buffers\s*\([^{};]*\)\s*;"
)


@dataclass(frozen=True)
class Scope:
    path: str
    symbol: str
    signature: re.Pattern[str]
    expected_matches: int
    reason: str
    helper: str | None = None


# These scopes contain the only direct buffer pins. The scope, count, and
# reason are all checked so an unrelated socket added to the same file cannot
# inherit an exemption.
DIRECT_PIN_SCOPES = (
    Scope(
        "outbound/stream.cpp",
        "ClientTransportStream::set_socket_buffers",
        re.compile(
            r"\bvoid\s+ClientTransportStream::set_socket_buffers\s*"
            r"\([^;{}]*\)\s*\{"
        ),
        2,
        "helper definition retained without any production call sites",
    ),
    Scope(
        "client/codec/monero_rpc.cpp",
        "tune_socket",
        re.compile(r"\bvoid\s+tune_socket\s*\([^;{}]*\)\s*\{"),
        2,
        "accepted Monero RPC socket from an enforced loopback-only listener",
    ),
    Scope(
        "client/transport/chrome_tls_helper.cpp",
        "ConfigureSocketpairBuffers",
        re.compile(
            r"\bvoid\s+ConfigureSocketpairBuffers\s*\([^;{}]*\)\s*\{"
        ),
        2,
        "AF_UNIX helper socketpair, not a TCP connection",
    ),
)

# A safe definition is not enough: each invocation is checked in its own
# enclosing function. `set_socket_buffers` intentionally has no allowed calls.
HELPER_CALL_SCOPES = (
    Scope(
        "client/codec/monero_rpc.cpp",
        "MoneroRpcCodecSession::MoneroRpcCodecSession",
        re.compile(
            r"\bMoneroRpcCodecSession\s*\([^;{}]*\)\s*"
            r":\s*[^{}]*\{"
        ),
        1,
        "the server constructor rejects every non-loopback listener",
        helper="tune_socket",
    ),
    Scope(
        "client/transport/chrome_tls_helper.cpp",
        "LaunchChromeTlsHelper",
        re.compile(
            r"\bClientTransportStream\s+LaunchChromeTlsHelper\s*"
            r"\([^;{}]*\)\s*\{"
        ),
        1,
        "passes only the AF_UNIX socketpair created in this function",
        helper="ConfigureSocketpairBuffers",
    ),
)


def code_only(text: str) -> str:
    """Strip comments while preserving code positions well enough for scopes."""
    text = re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group(0).count("\n"),
        text,
        flags=re.DOTALL,
    )
    return re.sub(r"//[^\n]*", "", text)


def function_range(code: str, scope: Scope) -> tuple[int, int]:
    matches = list(scope.signature.finditer(code))
    if len(matches) != 1:
        raise AssertionError(
            f"src/{scope.path}: expected one {scope.symbol} definition, "
            f"found {len(matches)}"
        )
    opening = code.find("{", matches[0].start(), matches[0].end())
    if opening < 0:
        raise AssertionError(f"src/{scope.path}: {scope.symbol} has no body")

    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return matches[0].start(), index + 1
    raise AssertionError(f"src/{scope.path}: unterminated {scope.symbol} body")


def line_number(code: str, position: int) -> int:
    return code.count("\n", 0, position) + 1


def helper_name(match: re.Match[str]) -> str:
    return match.group("member") or match.group("free")


class SocketAutotuningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = {
            path.relative_to(SCAN_ROOT).as_posix(): code_only(
                path.read_text(encoding="utf-8")
            )
            for path in sorted(SCAN_ROOT.rglob("*"))
            if path.suffix in (".cpp", ".hpp", ".cc", ".h")
            and not path.name.endswith("_test.cpp")
        }

    def resolved_ranges(
        self, scopes: tuple[Scope, ...]
    ) -> dict[str, list[tuple[Scope, int, int]]]:
        resolved: dict[str, list[tuple[Scope, int, int]]] = {}
        for scope in scopes:
            self.assertIn(scope.path, self.sources, f"stale scope: {scope.path}")
            start, end = function_range(self.sources[scope.path], scope)
            resolved.setdefault(scope.path, []).append((scope, start, end))
        return resolved

    def test_only_named_scopes_pin_socket_buffers(self) -> None:
        allowed = self.resolved_ranges(DIRECT_PIN_SCOPES)
        offenders = []
        for path, code in self.sources.items():
            ranges = allowed.get(path, [])
            for match in DIRECT_PIN.finditer(code):
                if not any(start <= match.start() < end for _, start, end in ranges):
                    offenders.append(
                        f"src/{path}:{line_number(code, match.start())} pins a "
                        "socket buffer outside a named safe scope"
                    )
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_direct_pin_scopes_have_exact_expected_contents(self) -> None:
        for scope in DIRECT_PIN_SCOPES:
            code = self.sources[scope.path]
            start, end = function_range(code, scope)
            count = len(DIRECT_PIN.findall(code[start:end]))
            self.assertEqual(
                count,
                scope.expected_matches,
                f"src/{scope.path}: {scope.symbol} pin count changed; "
                f"re-audit this scope ({scope.reason})",
            )

    def test_pinning_helper_calls_are_allowed_by_callsite(self) -> None:
        definitions = self.resolved_ranges(DIRECT_PIN_SCOPES)
        callsites = self.resolved_ranges(HELPER_CALL_SCOPES)
        offenders = []
        for path, code in self.sources.items():
            for match in HELPER_CALL.finditer(code):
                if any(
                    declaration.start() <= match.start() < declaration.end()
                    for declaration in HELPER_DECLARATION.finditer(code)
                ):
                    continue
                if any(
                    start <= match.start() < end
                    for _, start, end in definitions.get(path, [])
                ):
                    continue
                if any(
                    scope.helper == helper_name(match)
                    and start <= match.start() < end
                    for scope, start, end in callsites.get(path, [])
                ):
                    continue
                offenders.append(
                    f"src/{path}:{line_number(code, match.start())} calls "
                    f"pinning helper {helper_name(match)} outside a named "
                    "loopback/AF_UNIX callsite"
                )
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_helper_call_scopes_have_exact_expected_calls(self) -> None:
        definitions = self.resolved_ranges(DIRECT_PIN_SCOPES)
        for scope in HELPER_CALL_SCOPES:
            code = self.sources[scope.path]
            start, end = function_range(code, scope)
            count = sum(
                1
                for match in HELPER_CALL.finditer(code, start, end)
                if helper_name(match) == scope.helper
                if not any(
                    def_start <= match.start() < def_end
                    for _, def_start, def_end in definitions.get(scope.path, [])
                )
            )
            self.assertEqual(
                count,
                scope.expected_matches,
                f"src/{scope.path}: {scope.symbol} helper-call count changed; "
                f"re-audit this callsite ({scope.reason})",
            )

    def test_proxy_connection_sources_do_not_pin_buffers(self) -> None:
        for path in ("client/proxy/socks.cpp", "outbound/forward.cpp"):
            code = self.sources[path]
            self.assertIsNone(DIRECT_PIN.search(code), f"src/{path} pins buffers")
            self.assertIsNone(HELPER_CALL.search(code), f"src/{path} calls a pinning helper")

    def test_helper_declaration_documents_the_hazard(self) -> None:
        header = (SCAN_ROOT / "outbound/stream.hpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("set_socket_buffers", header)
        self.assertIn("autotuning", header)

    def test_unqualified_member_calls_are_detected(self) -> None:
        match = HELPER_CALL.search("set_socket_buffers(socket);")
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(helper_name(match), "set_socket_buffers")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
