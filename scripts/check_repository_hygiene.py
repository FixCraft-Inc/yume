#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Check whitespace in every committed file and the format of new commits.

`git diff --check` compares the index or a commit with its parent, so a new
file that was never staged escapes it. Comparing the empty tree with HEAD
checks every committed file, new ones included.

`--commits A..B` checks each non-merge commit in the range against the
project's commit format: a subject of at most 72 columns without a closing
period, a blank line, a body wrapped at 72 columns (a single long token such
as a URL may exceed it), a paragraph that starts with "Validation:", no
attribution trailers, and a signature. Whether the signature verifies needs
the signer's public key, which only a maintainer's checkout has.

Before a commit, stage the change and run with `--staged`, which checks the
index instead of HEAD.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_COLUMNS = 72
TRAILER = re.compile(r"^(co-authored-by|signed-off-by|generated-by|reviewed-by)\s*:", re.I | re.M)
ZERO_SHA = re.compile(r"^0+$")


class HygieneError(Exception):
    pass


def _git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(["git", *arguments], cwd=REPO_ROOT, capture_output=True,
                                text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HygieneError(f"git {arguments[0]} failed: {error}") from error
    if check and result.returncode != 0:
        raise HygieneError(f"git {' '.join(arguments)}: {result.stderr.strip()}")
    return result


def whitespace_problems(staged: bool) -> list[str]:
    if staged:
        result = _git("diff", "--cached", "--check", check=False)
    else:
        empty = _git("hash-object", "-t", "tree", "/dev/null").stdout.strip()
        result = _git("diff", "--check", empty, "HEAD", check=False)
    if result.returncode not in (0, 2):
        raise HygieneError(f"git diff --check failed: {result.stderr.strip()}")
    return [line for line in result.stdout.splitlines() if line.strip()]


def message_problems(message: str, raw_commit: str) -> list[str]:
    """What is wrong with one commit's message and signature."""
    problems = []
    lines = message.rstrip("\n").split("\n")
    subject = lines[0]
    if not subject.strip():
        problems.append("empty subject")
    if len(subject) > MAX_COLUMNS:
        problems.append(f"subject is {len(subject)} columns, the limit is {MAX_COLUMNS}")
    if subject.rstrip().endswith("."):
        problems.append("subject ends with a period")
    if len(lines) < 3 or lines[1] != "":
        problems.append("no blank line and body after the subject")
    for number, line in enumerate(lines[2:], start=3):
        if len(line) > MAX_COLUMNS and " " in line.strip():
            problems.append(f"line {number} is {len(line)} columns, wrap at {MAX_COLUMNS}")
    if not re.search(r"(?:^|\n\n)Validation:", message):
        problems.append("no paragraph starting with \"Validation:\"")
    if TRAILER.search(message):
        problems.append("attribution trailer present")
    header = raw_commit.split("\n\n", 1)[0]
    if not re.search(r"^gpgsig(-sha256)? ", header, re.M):
        problems.append("commit is not signed")
    return problems


def commits_in(revision_range: str) -> list[str]:
    start, _, end = revision_range.partition("..")
    if not end:
        raise HygieneError(f"expected a range A..B, got {revision_range!r}")
    if ZERO_SHA.match(start) or _git("cat-file", "-e", f"{start}^{{commit}}",
                                     check=False).returncode != 0:
        # A new branch, or history the checkout does not hold: the pushed
        # tip is what can be checked.
        print(f"hygiene: {start or 'start'} is not available, checking {end} alone")
        return [_git("rev-parse", "--verify", f"{end}^{{commit}}").stdout.strip()]
    listed = _git("rev-list", "--no-merges", "--reverse", f"{start}..{end}").stdout.split()
    return listed


def commit_problems(revision_range: str) -> list[str]:
    problems = []
    for sha in commits_in(revision_range):
        message = _git("log", "-1", "--format=%B", sha).stdout
        raw = _git("cat-file", "commit", sha).stdout
        for problem in message_problems(message, raw):
            problems.append(f"{sha[:12]} {message.splitlines()[0][:50]!r}: {problem}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--staged", action="store_true",
                        help="check the index instead of every committed file")
    parser.add_argument("--commits", metavar="A..B",
                        help="check the format of each commit in this range")
    options = parser.parse_args(argv)
    try:
        problems = [f"whitespace: {line}" for line in whitespace_problems(options.staged)]
        if options.commits:
            problems += [f"commit {line}" for line in commit_problems(options.commits)]
    except HygieneError as error:
        print(f"hygiene: {error}", file=sys.stderr)
        return 2
    for problem in problems:
        print(f"hygiene: {problem}", file=sys.stderr)
    if problems:
        return 1
    print("hygiene: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
