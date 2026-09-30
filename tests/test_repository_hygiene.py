#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Each rule of scripts/check_repository_hygiene.py rejects what it names."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_repository_hygiene", ROOT / "scripts" / "check_repository_hygiene.py")
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)

SIGNED = "tree 0\ngpgsig -----BEGIN SSH SIGNATURE-----\n -----END SSH SIGNATURE-----\n\nx"
GOOD = (
    "Stop the dependency fallbacks at their first failed step\n"
    "\n"
    "Each step is now checked, a failed download is named, and a failed\n"
    "build removes its prefix.\n"
    "\n"
    "Validation: three new fallback tests pass and fail with each fix\n"
    "removed, as the run records:\n"
    "https://github.com/example/a-very-long-link-that-cannot-be-wrapped-at-all\n"
)


class MessageRules(unittest.TestCase):
    def test_the_project_format_passes(self) -> None:
        self.assertEqual(hygiene.message_problems(GOOD, SIGNED), [])

    def assert_rejected(self, message: str, raw: str, expected: str) -> None:
        problems = hygiene.message_problems(message, raw)
        self.assertTrue(any(expected in problem for problem in problems), problems)

    def test_a_long_subject_fails(self) -> None:
        self.assert_rejected("S" * 73 + GOOD[GOOD.index("\n"):], SIGNED, "subject is 73")

    def test_a_subject_period_fails(self) -> None:
        self.assert_rejected(GOOD.replace("step\n", "step.\n", 1), SIGNED, "period")

    def test_a_missing_blank_line_fails(self) -> None:
        self.assert_rejected(GOOD.replace("step\n\n", "step\n", 1), SIGNED, "blank line")

    def test_an_unwrapped_body_line_fails(self) -> None:
        self.assert_rejected(GOOD.replace("prefix.", "prefix and says so " + "x" * 50),
                             SIGNED, "wrap at 72")

    def test_a_missing_validation_paragraph_fails(self) -> None:
        self.assert_rejected(GOOD.replace("Validation:", "Tests:"), SIGNED, "Validation")

    def test_an_attribution_trailer_fails(self) -> None:
        self.assert_rejected(GOOD + "\nCo-Authored-By: Someone <a@b>\n", SIGNED, "trailer")

    def test_an_unsigned_commit_fails(self) -> None:
        self.assert_rejected(GOOD, "tree 0\nauthor a\n\nx", "not signed")


class WhitespaceAndRanges(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.repo = Path(self.scratch.name)
        self.environment = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null",
                                GIT_CONFIG_NOSYSTEM="1")
        self.git("init", "-q", "-b", "main")
        self.saved_root = hygiene.REPO_ROOT
        hygiene.REPO_ROOT = self.repo

    def tearDown(self) -> None:
        hygiene.REPO_ROOT = self.saved_root
        self.scratch.cleanup()

    def git(self, *arguments: str, stdin: str | None = None) -> str:
        return subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
             "-c", "commit.gpgsign=false", *arguments],
            cwd=self.repo, env=self.environment, input=stdin, capture_output=True,
            text=True, check=True).stdout.strip()

    def commit(self, name: str, content: str) -> str:
        (self.repo / name).write_text(content, encoding="utf-8")
        self.git("add", name)
        self.git("commit", "-q", "-m", GOOD)
        return self.git("rev-parse", "HEAD")

    def test_a_new_committed_file_with_trailing_space_fails(self) -> None:
        self.commit("clean.txt", "clean\n")
        self.assertEqual(hygiene.whitespace_problems(staged=False), [])
        self.commit("new.txt", "trailing \n")
        problems = hygiene.whitespace_problems(staged=False)
        self.assertTrue(any("new.txt" in line for line in problems), problems)

    def test_a_staged_new_file_with_trailing_space_fails(self) -> None:
        self.commit("clean.txt", "clean\n")
        (self.repo / "staged.txt").write_text("trailing\t\n", encoding="utf-8")
        self.git("add", "staged.txt")
        problems = hygiene.whitespace_problems(staged=True)
        self.assertTrue(any("staged.txt" in line for line in problems), problems)

    def test_a_range_checks_every_commit_and_needs_signatures(self) -> None:
        base = self.commit("a.txt", "a\n")
        self.commit("b.txt", "b\n")
        problems = hygiene.commit_problems(f"{base}..HEAD")
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("not signed", problems[0])

    def test_a_signed_commit_in_the_range_passes(self) -> None:
        base = self.commit("a.txt", "a\n")
        tree = self.git("write-tree")
        raw = (f"tree {tree}\nparent {base}\n"
               "author t <t@example.invalid> 1 +0000\n"
               "committer t <t@example.invalid> 1 +0000\n"
               "gpgsig -----BEGIN SSH SIGNATURE-----\n -----END SSH SIGNATURE-----\n"
               f"\n{GOOD}")
        signed = self.git("hash-object", "-t", "commit", "-w", "--stdin", stdin=raw)
        self.assertEqual(hygiene.commit_problems(f"{base}..{signed}"), [])

    def test_an_unknown_start_checks_the_tip_alone(self) -> None:
        self.commit("a.txt", "a\n")
        problems = hygiene.commit_problems("0000000000000000000000000000000000000000..HEAD")
        self.assertEqual(len(problems), 1, problems)


if __name__ == "__main__":
    unittest.main()
