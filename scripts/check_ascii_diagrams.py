#!/usr/bin/env python3
"""Validate fixed-width ASCII boxes in YUME docs and man pages."""

from __future__ import annotations

import sys
from pathlib import Path


def iter_literal_lines(path: Path):
    in_markdown_fence = False
    in_roff_literal = False
    suffix = path.suffix
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if suffix == ".md":
            if raw.startswith("```text"):
                in_markdown_fence = True
                continue
            if raw.startswith("```") and in_markdown_fence:
                in_markdown_fence = False
                continue
            if in_markdown_fence:
                yield lineno, raw
        else:
            if raw == ".nf":
                in_roff_literal = True
                continue
            if raw == ".fi" and in_roff_literal:
                in_roff_literal = False
                continue
            if in_roff_literal:
                yield lineno, raw


def check(path: Path) -> list[str]:
    errors: list[str] = []
    for lineno, line in iter_literal_lines(path):
        if "+----------------+" in line:
            errors.append(f"{path}:{lineno}: old small box style: {line}")

        if line.startswith("+") and line.endswith("+"):
            width = len(line)
            if set(line[1:-1]) != {"-"}:
                continue
            if width not in (34, 72):
                errors.append(f"{path}:{lineno}: unexpected box width {width}: {line}")

        if line.startswith("|") and line.endswith("|"):
            width = len(line)
            if width not in (34, 72):
                errors.append(f"{path}:{lineno}: unexpected boxed row width {width}: {line}")
            if len(line) >= 2 and line[1] != " ":
                errors.append(f"{path}:{lineno}: missing left padding: {line}")
            if len(line) >= 2 and line[-2] != " ":
                errors.append(f"{path}:{lineno}: missing right padding: {line}")
    return errors


def main(argv: list[str]) -> int:
    paths = [Path(arg) for arg in argv[1:]]
    if not paths:
        # basefwx/* paths are only present in the meta-repo checkout, not
        # the standalone yume checkout. Skip them silently when missing
        # so this script can be wired into CI for the standalone repo.
        paths = [
            Path("README.md"),
            Path("docs/EXPLAINED.md"),
            Path("basefwx/docs/EXPLAINED.md"),
            Path("basefwx/docs/man/basefwx.1"),
            Path("basefwx/docs/man/basefwx.7"),
            Path("docs/man/yume.1"),
            Path("docs/man/yumed.8"),
        ]
        paths = [p for p in paths if p.exists()]

    errors: list[str] = []
    for path in paths:
        if not path.exists():
            errors.append(f"{path}: does not exist")
            continue
        errors.extend(check(path))

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
