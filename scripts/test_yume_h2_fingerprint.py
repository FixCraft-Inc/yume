#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""The opening gate compares ordered SETTINGS, including repeated IDs."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(__file__).resolve().with_name("yume_h2_fingerprint.py")
FIXTURE = ROOT / "tests/fixtures/chrome151-node24/chrome_h2_profile.json"


class H2FingerprintTest(unittest.TestCase):
    def setUp(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.settings = [row[:2] for row in fixture["client_settings_in_order"]]
        self.observed = {
            "settings_in_order": self.settings,
            "connection_window_updates": [fixture["client_connection_window_update"]["delta"]],
            "priority_frames": [],
            "priming_get": fixture["priming_get"],
        }
        temporary = tempfile.TemporaryDirectory(prefix="yume-h2-fingerprint-")
        self.addCleanup(temporary.cleanup)
        self.emitter = Path(temporary.name) / "emitter"

    def check(self, settings: list[list[int]], *, report: bool = False
              ) -> subprocess.CompletedProcess[str]:
        observed = dict(self.observed, settings_in_order=settings)
        self.emitter.write_text(
            f"#!{sys.executable}\nprint({json.dumps(observed)!r})\n", encoding="utf-8")
        self.emitter.chmod(0o700)
        arguments = [sys.executable, str(SCRIPT), "--emitter", str(self.emitter)]
        arguments += ["--json"] if report else ["--check", "chrome"]
        return subprocess.run(arguments, capture_output=True, text=True, timeout=10)

    def test_exact_fixture_passes(self) -> None:
        result = self.check(self.settings)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("opening matches", result.stdout)

    def test_reordered_settings_fail(self) -> None:
        result = self.check(list(reversed(self.settings)))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("SETTINGS in order", result.stderr)

    def test_duplicate_settings_fail_even_if_final_values_match(self) -> None:
        setting_id, value = self.settings[0]
        for duplicate in ([setting_id, value], [setting_id, value + 1]):
            with self.subTest(duplicate=duplicate):
                result = self.check([duplicate, *self.settings])
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("SETTINGS in order", result.stderr)

    def test_json_report_preserves_the_differing_sequence(self) -> None:
        settings = [self.settings[0], *reversed(self.settings)]
        result = self.check(settings, report=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        comparison = report["comparisons"]["chrome"]
        self.assertIn("SETTINGS in order", comparison["differing_fields"])
        delta = next(item for item in comparison["deltas"] if item["field"] == "SETTINGS in order")
        self.assertEqual(json.loads(delta["yume"]), settings)
        self.assertEqual(json.loads(delta["ref"]), self.settings)


if __name__ == "__main__":
    unittest.main()
