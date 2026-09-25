#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Check built native CLI output and rejection paths without opening a network.

Run with --yume /path/to/yume --yumed /path/to/yumed.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))

import yume_cli  # noqa: E402

PROGRAMS: dict[str, Path] = {}


class NativeCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.expected_help = {}
        for layout in yume_cli.load_layouts():
            if layout.binary in PROGRAMS:
                ordered, _ = yume_cli.resolve(layout)
                cls.expected_help[layout.binary] = "\n".join(yume_cli.render_help(layout, ordered)) + "\n"

    def invoke(self, name: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(PROGRAMS[name]), *arguments], capture_output=True, text=True,
            timeout=5, check=False,
        )

    def assert_usage_failure(self, name: str, arguments: list[str], diagnostic: str) -> None:
        result = self.invoke(name, *arguments)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, f"{name}: {diagnostic}\n" + self.expected_help[name])

    def test_help_matches_the_canonical_manual(self) -> None:
        for name in PROGRAMS:
            for flag in ("--help", "-h"):
                with self.subTest(binary=name, flag=flag):
                    result = self.invoke(name, flag)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(result.stdout, self.expected_help[name])

    def test_version_reports_the_native_composition(self) -> None:
        for name in PROGRAMS:
            with self.subTest(binary=name):
                result = self.invoke(name, "--version")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertTrue(result.stdout.startswith(f"{name} "))
                self.assertIn("transport YTP/1, config schema 1, suite ytp1-tls13-h2\n", result.stdout)
                self.assertIn("session security ", result.stdout)
                self.assertIn(", crypto backend ", result.stdout)
                self.assertIn("evidence profile ", result.stdout)
                self.assertNotIn("unwired", result.stdout)

    def test_config_is_required_for_run_and_validation(self) -> None:
        for name in PROGRAMS:
            for arguments in ([], ["--validate"]):
                with self.subTest(binary=name, arguments=arguments):
                    self.assert_usage_failure(name, arguments, "--config is required")

    def test_config_requires_exactly_one_path(self) -> None:
        for name in PROGRAMS:
            for arguments in (["--config"], ["--config", "first", "--config", "second"]):
                with self.subTest(binary=name, arguments=arguments):
                    self.assert_usage_failure(name, arguments, "--config needs exactly one path")

    def test_reference_and_unimplemented_options_are_rejected(self) -> None:
        arguments = [
            ["--diagnostic-level", "debug"], ["setup"], ["doctor"],
            ["completion", "bash"], ["--completion", "bash"], ["--credits"],
            ["--server", "localhost"], ["--listen", "443"], ["--socks", "1080"],
        ]
        for name in PROGRAMS:
            for values in arguments:
                with self.subTest(binary=name, arguments=values):
                    self.assert_usage_failure(name, values, f"unknown argument: {values[0]}")

    def test_metadata_flags_do_not_hide_unknown_arguments(self) -> None:
        for name in PROGRAMS:
            for flag in ("--help", "--version"):
                with self.subTest(binary=name, flag=flag):
                    self.assert_usage_failure(name, [flag, "--unknown"], "unknown argument: --unknown")

    def test_metadata_does_not_read_the_configuration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yume-cli-") as temporary:
            missing = str(Path(temporary) / "absent.json")
            for name in PROGRAMS:
                for flag in ("--help", "--version"):
                    with self.subTest(binary=name, flag=flag):
                        result = self.invoke(name, "--config", missing, flag)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stderr, "")

    def test_validation_rejects_a_nonobject_configuration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yume-cli-") as temporary:
            path = Path(temporary) / "invalid.json"
            path.write_text("[]\n", encoding="utf-8")
            for name in PROGRAMS:
                with self.subTest(binary=name):
                    result = self.invoke(name, "--config", str(path), "--validate")
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("configuration error at JSON pointer", result.stderr)
                    self.assertIn("must be an object", result.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yume", type=Path, required=True)
    parser.add_argument("--yumed", type=Path, required=True)
    args = parser.parse_args()
    for name in ("yume", "yumed"):
        path = getattr(args, name).resolve(strict=True)
        if not path.is_file():
            parser.error(f"{name} must name a regular executable file")
        PROGRAMS[name] = path
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeCli))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
