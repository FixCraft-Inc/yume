#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Validate the ASCII figures in YUME and BaseFWX docs and man pages.

YUME's route figures are generated, and `scripts/yume_diagrams.py check`
already proves each one matches the specification that produced it. What
this script owns is the property no specification can state: that a literal
region renders as a figure on a terminal at all.

The rules are structural rather than a list of permitted widths. A figure
used to be built from boxes of exactly 34 or 72 columns, which the generator
no longer needs now that it sizes a box to its own longest label, and which
BaseFWX's hand-drawn figures still follow. Both satisfy the rules below, so
one gate covers generated and hand-drawn figures alike.

  * every line of one box has the same width and indent,
  * a boxed row is padded on both sides,
  * no line in a literal region is wide enough for a terminal to fold it,
  * no literal line carries a tab or trailing whitespace.
"""

from __future__ import annotations

import sys
from pathlib import Path

# A manual indents a literal region, so a figure has to leave room for that
# indent inside the eighty columns a terminal traditionally offers.
MAX_LITERAL_WIDTH = 76

DEFAULT_PATHS = (
    "README.md",
    "docs/EXPLAINED.md",
    "docs/man/yume.1",
    "docs/man/yumed.8",
    "docs/man/yume-gui.1",
    "basefwx/docs/EXPLAINED.md",
    "basefwx/docs/man/basefwx.1",
    "basefwx/docs/man/basefwx.7",
)


def iter_literal_blocks(path: Path):
    """Each Markdown text fence or roff literal region, as its own block.

    Blocks are kept apart because the last box of one figure and the first
    box of the next are adjacent lines, and comparing them to each other
    would report a disagreement that no reader ever sees.
    """
    block: list[tuple[int, str]] = []
    inside = False
    suffix = path.suffix
    opening, closing = ("```text", "```") if suffix == ".md" else (".nf", ".fi")

    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not inside:
            if raw.startswith(opening) if suffix == ".md" else raw == opening:
                inside = True
            continue
        if raw.startswith(closing) if suffix == ".md" else raw == closing:
            inside = False
            if block:
                yield block
            block = []
            continue
        block.append((lineno, raw))
    if block:
        yield block


def is_border(line: str) -> bool:
    body = line.strip()
    return (
        len(body) >= 3
        and body.startswith("+")
        and body.endswith("+")
        and set(body[1:-1]) <= {"-", "+"}
    )


def is_row(line: str) -> bool:
    body = line.strip()
    return len(body) >= 3 and body.startswith("|") and body.endswith("|")


def check(path: Path) -> list[str]:
    errors: list[str] = []
    for block in iter_literal_blocks(path):
        for lineno, line in block:
            if "\t" in line:
                errors.append(f"{path}:{lineno}: tab in a literal line")
            if line != line.rstrip():
                errors.append(f"{path}:{lineno}: trailing whitespace in a literal line")
        # A literal region that draws no box is a command example or a
        # configuration excerpt. Those have their own line lengths and no
        # figure to be ragged, so only the figure rules are skipped here.
        if any(is_border(line) for _, line in block):
            errors.extend(_check_figure(path, block))
    return errors


def _check_figure(path: Path, block: list[tuple[int, str]]) -> list[str]:
    errors: list[str] = []
    # One box is a run of adjacent border and row lines. Comparing inside the
    # run is what lets a staircase indent each box differently while still
    # proving that no single box is ragged.
    run: list[tuple[int, str]] = []

    def close_run() -> None:
        if len(run) >= 2:
            shapes = {(len(line) - len(line.lstrip(" ")), len(line)) for _, line in run}
            if len(shapes) > 1:
                errors.append(
                    f"{path}:{run[0][0]}: box lines disagree on indent or width: "
                    + ", ".join(f"{indent}+{width}" for indent, width in sorted(shapes))
                )
        run.clear()

    for lineno, line in block:
        if len(line) > MAX_LITERAL_WIDTH:
            errors.append(
                f"{path}:{lineno}: figure line is {len(line)} columns, "
                f"more than {MAX_LITERAL_WIDTH}"
            )
        if is_border(line) or is_row(line):
            run.append((lineno, line))
        else:
            close_run()
        if is_row(line):
            body = line.strip()
            if body[1] != " ":
                errors.append(f"{path}:{lineno}: missing left padding: {line}")
            if body[-2] != " ":
                errors.append(f"{path}:{lineno}: missing right padding: {line}")

    close_run()
    return errors


def main(argv: list[str]) -> int:
    paths = [Path(arg) for arg in argv[1:]]
    if not paths:
        # basefwx/* paths are only present in the meta-repo checkout, not
        # the standalone yume checkout. Skip them silently when missing
        # so this script can be wired into CI for the standalone repo.
        paths = [path for path in map(Path, DEFAULT_PATHS) if path.exists()]

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
    print(f"ascii figures: {len(paths)} files checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
