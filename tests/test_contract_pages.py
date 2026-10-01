#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""An interface cannot grow a name its contract page does not state.

A feature reaches users through a contract page first. For the interfaces
whose names can be read from the source, this check holds the code to that
order: every request and error code the control socket answers must appear
in control protocol 1, and every function the C ABI exports must be named in
the ABI page. Configuration keys, command-line options and wire labels have
their own checks (test_config_reference.py, test_yume_cli.py and
test_wire_labels.py).
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGES = ROOT / "docs" / "src" / "en_US" / "pages"
SPAN = re.compile(r"`([^`\n]+)`")


def spans(page: str) -> set[str]:
    return {span.strip() for span in SPAN.findall((PAGES / page).read_text(encoding="utf-8"))}


def words(page: str) -> set[str]:
    return {word for span in spans(page) for word in re.findall(r"[A-Za-z0-9_-]+", span)}


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
