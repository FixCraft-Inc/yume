#!/usr/bin/env python3
"""Guard TCP window autotuning at each pin definition.

Any explicit SO_RCVBUF/SO_SNDBUF value disables Linux TCP window autotuning for
that socket. A file-wide allowlist is unsafe: one source can own both a
loopback/AF_UNIX endpoint and a remote connection. This test therefore permits
only named function bodies, and no production source needs one today.
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


@dataclass(frozen=True)
class Scope:
    path: str
    symbol: str
    signature: re.Pattern[str]
    expected_matches: int
    reason: str


# The only function bodies allowed to pin a buffer, each for a loopback or
# AF_UNIX socket. The scope, count, and reason are all checked so an unrelated
# socket added to the same file cannot inherit an exemption. A scope that is a
# helper also needs each of its call sites audited, because the helper cannot
# see which socket it is given.
DIRECT_PIN_SCOPES: tuple[Scope, ...] = ()


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

    def resolved_ranges(self) -> dict[str, list[tuple[Scope, int, int]]]:
        resolved: dict[str, list[tuple[Scope, int, int]]] = {}
        for scope in DIRECT_PIN_SCOPES:
            self.assertIn(scope.path, self.sources, f"stale scope: {scope.path}")
            start, end = function_range(self.sources[scope.path], scope)
            resolved.setdefault(scope.path, []).append((scope, start, end))
        return resolved

    def test_the_scan_reaches_the_socket_sources(self) -> None:
        for path in ("providers/asio_tcp_byte_channel_provider.cpp",
                     "runtime/native_socks5.cpp"):
            self.assertIn(path, self.sources)

    def test_only_named_scopes_pin_socket_buffers(self) -> None:
        allowed = self.resolved_ranges()
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

    def test_every_pin_spelling_is_detected(self) -> None:
        for text in (
                "socket.set_option(tcp::socket::receive_buffer_size(4096));",
                "socket.set_option(tcp::socket::send_buffer_size (4096));",
                "::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));",
                "::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));"):
            with self.subTest(text=text):
                self.assertIsNotNone(DIRECT_PIN.search(text))

    def test_comments_do_not_count_as_pins(self) -> None:
        code = code_only("// SO_RCVBUF\n/* send_buffer_size(1) */\nint x;\n")
        self.assertIsNone(DIRECT_PIN.search(code))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
