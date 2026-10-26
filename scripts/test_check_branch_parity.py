#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Branch parity must fail when its comparison cannot be completed."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name("check_branch_parity.sh")


class BranchParityTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="yume-parity-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.executable("git", '''
case "$1" in
  rev-parse) exit 0 ;;
  diff)
    printf '%s' "$YUME_TEST_CHANGED"
    if [[ "$YUME_TEST_DIFF_STATUS" != 0 ]]; then
      echo 'fixture git diff failed' >&2
    fi
    exit "$YUME_TEST_DIFF_STATUS"
    ;;
  *) exit 99 ;;
esac
''')
        self.allowlist = self.root / "allowlist"
        self.allowlist.write_text("# Fixture-only allowance\nallowed/**\n", encoding="utf-8")

    def executable(self, name: str, source: str) -> None:
        path = self.bin / name
        path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + source,
                        encoding="utf-8")
        path.chmod(0o700)

    def compare(self, changes: str, status: int = 0) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                           ALLOWLIST_FILE=str(self.allowlist), YUME_TEST_CHANGED=changes,
                           YUME_TEST_DIFF_STATUS=str(status))
        return subprocess.run(["bash", str(SCRIPT), "main", "DEV"], cwd=self.root,
                              env=environment, capture_output=True, text=True, timeout=10)

    def test_failed_diff_never_reports_parity(self) -> None:
        for output in ("", "allowed/partial.txt\n"):
            with self.subTest(output=output):
                result = self.compare(output, status=128)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("Unable to compare branches", result.stderr)
                self.assertNotIn("parity OK", result.stdout)

    def test_failed_sort_never_reports_parity(self) -> None:
        self.executable("sort", "cat\nexit 2\n")
        result = self.compare("allowed/partial.txt\n")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("parity OK", result.stdout)

    def test_empty_successful_diff_is_identical(self) -> None:
        result = self.compare("")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("are identical", result.stdout)

    def test_allowlisted_differences_are_sorted_and_deduplicated(self) -> None:
        result = self.compare("allowed/z\nallowed/a\nallowed/z\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("parity OK with allowlist", result.stdout)
        self.assertTrue(result.stdout.endswith("  - allowed/a\n  - allowed/z\n"))

    def test_disallowed_difference_fails(self) -> None:
        result = self.compare("allowed/a\nsrc/unexpected.cpp\n")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("  - src/unexpected.cpp\n", result.stdout)
        self.assertNotIn("parity OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
