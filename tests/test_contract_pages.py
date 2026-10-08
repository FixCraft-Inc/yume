#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""An interface cannot grow a name its contract page does not state.

A feature reaches users through a contract page first. For the interfaces
whose names can be read from the source, this check holds the code to that
order: every request and error code the control socket answers, and every
member name its replies carry, must appear in control protocol 1, and every
function the C ABI exports must be named in the ABI page. The programs that
read those replies, the status text and the GUI's C++ and QML, may take only
members the socket writes, so a misspelled field fails here rather than
showing nothing. Configuration keys, command-line options and wire labels
have their own checks (test_config_reference.py, test_yume_cli.py and
test_wire_labels.py).
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGES = ROOT / "docs" / "src" / "en_US" / "pages"
SPAN = re.compile(r"`([^`\n]+)`")
CONTROL = ROOT / "src" / "runtime" / "control_socket.cpp"
STATUS_TEXT = ROOT / "src" / "runtime" / "control_status_text.cpp"
GUI = ROOT / "src" / "gui"
# The GUI files that read control replies. The kit store and the preset table
# read documents of their own.
GUI_READERS = ("app_state.cpp", "capture.cpp", "control_client.cpp", "headless.cpp",
               "message_model.cpp", "tray.cpp", "tunnel.cpp")
# The names QML gives the reply objects it reads. QML's own properties are
# camelCase, and reply members are lowercase with underscores.
QML_MEMBER = re.compile(
    r"\b(?:status|circuits|proposal|posture|limits|traffic|server|failure|route|link|reply)"
    r"\??\.([a-z][a-z0-9_]*)\b(?!\s*\()")


def spans(page: str) -> set[str]:
    return {span.strip() for span in SPAN.findall((PAGES / page).read_text(encoding="utf-8"))}


def words(page: str) -> set[str]:
    return {word for span in spans(page) for word in re.findall(r"[A-Za-z0-9_-]+", span)}


def documented_members(page: str) -> set[str]:
    """The page's code-span words and the JSON member names of its examples."""
    text = (PAGES / page).read_text(encoding="utf-8")
    names = words(page)
    for block in re.findall(r"^@code[^\n]*\n(.*?)^@end", text, re.S | re.M):
        names.update(re.findall(r'"([a-z][a-z0-9_]*)"\s*:', block))
    return names


def reply_members() -> set[str]:
    """Every member name control_socket.cpp writes into a JSON object."""
    source = CONTROL.read_text(encoding="utf-8")
    return (set(re.findall(r'\{"([a-z][a-z0-9_]*)",', source))
            | set(re.findall(r'\["([a-z][a-z0-9_]*)"\]\s*=', source))
            | set(re.findall(r'"([a-z][a-z0-9_]*)":', source)))


def members_read() -> dict[str, set[str]]:
    """Each reply member a reader takes, with the files that take it."""
    found: dict[str, set[str]] = {}

    def add(where: str, names: list[str]) -> None:
        for name in names:
            found.setdefault(name, set()).add(where)

    text = STATUS_TEXT.read_text(encoding="utf-8")
    add(STATUS_TEXT.name, re.findall(r'\.(?:at|find|contains)\("([a-z][a-z0-9_]*)"\)', text))
    # Its formatting helpers take an object and a member name.
    add(STATUS_TEXT.name, re.findall(r'\b\w+\(\w+, "([a-z][a-z0-9_]*)"\)', text))
    for name in GUI_READERS:
        source = (GUI / name).read_text(encoding="utf-8")
        # Settings keys and request names are not reply members.
        source = re.sub(r'settings_\.value\(QStringLiteral\("[a-z_]*"\)', "", source)
        source = re.sub(r'requests\(\)\.contains\(QStringLiteral\("[a-z_-]*"\)\)', "", source)
        add(name, re.findall(r'\.(?:value|contains)\(QStringLiteral\("([a-z][a-z0-9_]*)"\)\)', source))
        # The headless report copies a fixed list of status members.
        for listed in re.findall(r"for \(const char\* key :\s*\{([^}]*)\}", source):
            add(name, re.findall(r'"([a-z][a-z0-9_]*)"', listed))
    for qml in sorted((GUI / "qml").glob("*.qml")):
        add(qml.name, QML_MEMBER.findall(qml.read_text(encoding="utf-8")))
    return found


class ContractPages(unittest.TestCase):
    def test_every_control_request_is_in_control_1(self) -> None:
        source = (ROOT / "src" / "runtime" / "control_socket.cpp").read_text(encoding="utf-8")
        requests = set(re.findall(r'requested [!=]= "([a-z-]+)"', source))
        self.assertIn("status", requests)
        self.assertEqual(sorted(requests - words("control_1.doc")), [])

    def test_every_control_error_code_is_in_control_1(self) -> None:
        source = (ROOT / "src" / "runtime" / "control_socket.cpp").read_text(encoding="utf-8")
        codes = set(re.findall(r'error_reply\(\s*"([a-z-]+)"', source))
        self.assertIn("malformed", codes)
        self.assertEqual(sorted(codes - words("control_1.doc")), [])

    def test_every_reply_member_is_in_control_1(self) -> None:
        members = reply_members()
        for expected in ("server_identity", "payload_bytes_sent", "exit_streams", "missed"):
            self.assertIn(expected, members)
        self.assertEqual(sorted(members - documented_members("control_1.doc")), [])

    def test_readers_take_only_members_the_socket_writes(self) -> None:
        read = members_read()
        for expected in ("last_failure", "min_hops", "max_epoch_bytes", "instance"):
            self.assertIn(expected, read)
        unknown = {name: sorted(files) for name, files in read.items()
                   if name not in reply_members()}
        self.assertEqual(unknown, {})

    def test_every_abi_export_is_named_in_the_abi_page(self) -> None:
        exports = set(re.findall(r"\b(yume_[a-z0-9_]+)\s*;",
                                 (ROOT / "src" / "abi" / "yume.map").read_text(encoding="utf-8")))
        self.assertGreater(len(exports), 20)
        # The page names functions in prose and in its example code alike.
        text = (PAGES / "abi.doc").read_text(encoding="utf-8")
        named = set(re.findall(r"\byume_[a-z0-9_]+\b", text))
        self.assertEqual(sorted(exports - named), [])


if __name__ == "__main__":
    unittest.main()
