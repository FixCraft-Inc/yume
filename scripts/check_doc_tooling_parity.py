#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Prove the documentation tooling is identical in YUME and BaseFWX.

The two projects are separate repositories with separate release cycles, and
BaseFWX is a dependency of YUME rather than the other way round, so neither
can import the other's scripts. They therefore each carry a copy.

Two copies of one contract is a defect unless something proves they are the
same, which is what this script is. A change to the tooling is made in YUME
and copied across in the same change, and this comparison fails until it is.

The BaseFWX checkout is ignored by YUME and absent from a fresh clone, so a
missing `basefwx/` is reported as skipped rather than as a failure.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BASEFWX_ROOT = REPO_ROOT / "basefwx"

# The files that must be byte-identical in both checkouts. A renderer or a
# grammar rule that existed in one and not the other would let the same source
# publish different documents depending on which repository rendered it.
SHARED = (
    "scripts/yume_doc_spec.py",
    "scripts/yume_doc_inline.py",
    "scripts/yume_doc_markdown.py",
    "scripts/yume_doc_man.py",
    "scripts/yume_doc_web.py",
    "scripts/yume_docs.py",
    "scripts/test_yume_docs.py",
    "scripts/test_yume_doc_pipeline.py",
    "docs/src/README.md",
    "scripts/yume_diagram_spec.py",
    "scripts/yume_diagram_ascii.py",
    "scripts/yume_diagram_svg.py",
    "scripts/yume_diagram_theme.py",
    "scripts/yume_diagram_preview.py",
    "scripts/yume_diagrams.py",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if not BASEFWX_ROOT.is_dir():
        print("doc tooling parity: no basefwx/ checkout, skipped")
        return 0

    problems: list[str] = []
    for relative in SHARED:
        ours = REPO_ROOT / relative
        theirs = BASEFWX_ROOT / relative
        if not ours.is_file():
            problems.append(f"{relative}: missing from this repository")
            continue
        if not theirs.is_file():
            problems.append(f"basefwx/{relative}: missing, so copy it from {relative}")
            continue
        if digest(ours) != digest(theirs):
            problems.append(
                f"basefwx/{relative} differs from {relative}, so copy the YUME "
                "copy across in this same change"
            )

    if problems:
        for problem in problems:
            print(f"doc tooling parity: {problem}", file=sys.stderr)
        print(
            "doc tooling parity: copy each reported YUME file to its matching "
            "path under basefwx/, then rerun this check",
            file=sys.stderr,
        )
        return 1

    print(f"doc tooling parity: {len(SHARED)} shared files match basefwx/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
