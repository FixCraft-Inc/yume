#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Every configuration key the parser accepts is documented and exercised.

The schema-1 parser closes each object with one helper, CheckClosedObject,
which lists the keys that object accepts. A key there must appear in the
configuration reference, the page an operator reads, and in one of the
complete documents under tests/fixtures/config, which
`yume_config_v1_test --closure` parses and then probes with an unknown key
in every object. A new key therefore needs its documentation and a fixture
before the tests pass, and a new object that forgets its closure fails the
probe.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / "src" / "config" / "v1" / "config.cpp"
REFERENCE = ROOT / "docs" / "src" / "en_US" / "pages" / "configuration.doc"
FIXTURES = ROOT / "tests" / "fixtures" / "config"


def parser_keys(text: str) -> set[str]:
    """Every key named in the accepted list of a CheckClosedObject call."""
    keys: set[str] = set()
    for call in re.finditer(r"CheckClosedObject\((.*?)\);", text, re.S):
        braces = re.findall(r"\{([^{}]*)\}", call.group(1))
        if braces:
            keys.update(re.findall(r'"([a-z0-9_]+)"', braces[0]))
    # ParseLimits names its eight required keys through an array.
    limits = re.search(r"constexpr std::array<std::string_view, \d+> keys\{\{(.*?)\}\};", text, re.S)
    if limits:
        keys.update(re.findall(r'"([a-z0-9_]+)"', limits.group(1)))
    return keys


def documented_words(text: str) -> set[str]:
    words: set[str] = set()
    for span in re.findall(r"`([^`\n]+)`", text):
        words.update(re.findall(r"[a-z0-9_]+", span))
    return words


def fixture_keys() -> set[str]:
    keys: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, dict):
            keys.update(value)
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    for path in sorted(FIXTURES.glob("*.json")):
        walk(json.loads(path.read_text(encoding="utf-8")))
    return keys


class ConfigurationReference(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = parser_keys(PARSER.read_text(encoding="utf-8"))

    def test_the_parser_keys_are_found(self) -> None:
        # A broken extraction would pass everything below, so it is pinned
        # to keys every section of the schema has.
        for key in ("schema", "role", "endpoint", "file", "listen_path", "reverse_proxy",
                    "max_frame_bytes", "idle_epoch_rotation", "routes_signature", "domains"):
            self.assertIn(key, self.keys)
        self.assertGreater(len(self.keys), 80)

    def test_every_key_is_in_the_reference(self) -> None:
        documented = documented_words(REFERENCE.read_text(encoding="utf-8"))
        missing = sorted(self.keys - documented)
        self.assertEqual(missing, [], "keys missing from docs/src/en_US/pages/configuration.doc")

    def test_every_key_is_in_a_complete_fixture(self) -> None:
        missing = sorted(self.keys - fixture_keys())
        self.assertEqual(missing, [], "keys missing from tests/fixtures/config")

    def test_fixtures_hold_no_key_the_parser_lacks(self) -> None:
        self.assertEqual(sorted(fixture_keys() - self.keys), [])

    def test_each_role_has_a_fixture(self) -> None:
        roles = {json.loads(path.read_text(encoding="utf-8"))["role"]
                 for path in FIXTURES.glob("*.json")}
        self.assertEqual(roles, {"client", "server"})


if __name__ == "__main__":
    unittest.main()
