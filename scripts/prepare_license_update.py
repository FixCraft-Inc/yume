#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

"""Dry-run/apply license header updates for YUME and bundled BaseFWX.

Default mode is dry-run. Use --apply only after reviewing the planned changes.
This script intentionally edits only source-file header lines, not LICENSE,
LICENCE, README, Debian metadata, or longer licensing docs.
"""

from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

YUME_OLD = "Licensed under the GNU General Public License v3.0."
YUME_NEW = "Licensed under the GNU Affero General Public License v3.0 or later."

BASEFWX_GPL_NEW = "Licensed under the GNU General Public License v3.0 or later."
BASEFWX_LGPL_NEW = "Licensed under the GNU Lesser General Public License v3.0 or later."
BASEFWX_EXAMPLE_NEW = "SPDX-License-Identifier: MIT OR Apache-2.0"
BASEFWX_MIXED_NEW = "SPDX-License-Identifier: LGPL-3.0-or-later AND GPL-3.0-or-later"

TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".java",
    ".mm",
    ".py",
    ".sh",
    ".txt",
}

SKIP_DIR_NAMES = {
    ".git",
    ".gradle",
    ".pytest_cache",
    "__pycache__",
    "build",
    "build-fix",
    "build-rf",
    "vendor",
}


def is_skipped(path: Path) -> bool:
    parts = set(path.relative_to(ROOT).parts)
    if parts & SKIP_DIR_NAMES:
        return True
    return any(part.startswith("build-") for part in parts)


def source_files_under(base: Path):
    for path in base.rglob("*"):
        if not path.is_file() or is_skipped(path):
            continue
        if path.suffix in TEXT_EXTENSIONS or path.name == "CMakeLists.txt":
            yield path


def basefwx_license_for(path: Path) -> str | None:
    rel = path.relative_to(ROOT).as_posix()

    if rel.startswith("basefwx/examples/plugins/"):
        return BASEFWX_EXAMPLE_NEW

    if rel.startswith("basefwx/cpp/src/cli/"):
        return BASEFWX_GPL_NEW
    if rel.startswith("basefwx/cpp/include/basefwx/cli/"):
        return BASEFWX_GPL_NEW
    if rel in {
        "basefwx/cpp/include/basefwx/cli_colors.hpp",
        "basefwx/cpp/src/main.cpp",
        "basefwx/cpp/src/cli_colors.cpp",
        "basefwx/python/basefwx/_cli.py",
        "basefwx/python/basefwx/__main__.py",
        "basefwx/java/src/main/java/com/fixcraft/basefwx/cli/BaseFwxCli.java",
        "basefwx/java/src/main/java/com/fixcraft/basefwx/cli/BenchCommands.java",
        "basefwx/java/src/main/java/com/fixcraft/basefwx/cli/CodecCommands.java",
        "basefwx/java/src/main/java/com/fixcraft/basefwx/cli/CliOptions.java",
        "basefwx/java/src/main/java/com/fixcraft/basefwx/cli/FileCommands.java",
        "basefwx/java/src/main/java/com/fixcraft/basefwx/cli/MediaCommands.java",
        "basefwx/java/src/main/java/com/fixcraft/basefwx/FwxAESBenchmark.java",
    }:
        return BASEFWX_GPL_NEW
    if rel in {
        "basefwx/cpp/CMakeLists.txt",
        "basefwx/python/basefwx/main.py",
        "basefwx/python/pyproject.toml",
        "basefwx/python/setup.py",
    }:
        return BASEFWX_MIXED_NEW
    if rel.startswith("basefwx/tools/"):
        return BASEFWX_GPL_NEW
    if rel.startswith("basefwx/scripts/") or rel.startswith("basefwx/python/scripts/"):
        return BASEFWX_GPL_NEW

    if rel.startswith("basefwx/cpp/"):
        return BASEFWX_LGPL_NEW
    if rel.startswith("basefwx/java/src/main/java/com/fixcraft/basefwx/"):
        return BASEFWX_LGPL_NEW
    if rel.startswith("basefwx/python/basefwx/"):
        return BASEFWX_LGPL_NEW

    return None


def update_license_line(text: str, replacement: str) -> tuple[str, int]:
    old_variants = [
        YUME_OLD,
        "SPDX-License-Identifier: GPL-3.0-or-later",
    ]
    changed = 0
    out = text
    for old in old_variants:
        if old in out:
            out = out.replace(old, replacement)
            changed += text.count(old)
    return out, changed


def update_example_plugin_header(text: str, path: Path) -> tuple[str, int]:
    if "BaseFWX example" not in text[:512]:
        return text, 0
    if BASEFWX_EXAMPLE_NEW in text[:512]:
        return text, 0

    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines[:24]):
        if "Licensed under the GNU General Public License v3.0" not in line:
            continue
        prefix = line.split("Licensed under", 1)[0]
        j = i + 1
        while j < len(lines) and (
            "BaseFWX Plugin-Template Exception" in lines[j]
            or "You may use this file" in lines[j]
            or "Plugin under any license" in lines[j]
        ):
            j += 1
        if path.suffix == ".txt" or path.name == "CMakeLists.txt" or line.lstrip().startswith("#"):
            note = f"{prefix}This file is intentionally permissive so plugin authors can use it as a starting template.\n"
        else:
            note = f"{prefix}This file is intentionally permissive so plugin authors can use it as a starting template.\n"
        updated_lines = lines[:i] + [f"{prefix}{BASEFWX_EXAMPLE_NEW}\n", note] + lines[j:]
        updated = "".join(updated_lines)
        return (updated, 1) if updated != text else (text, 0)

    return text, 0


def process_file(path: Path, replacement: str, apply: bool) -> int:
    text = path.read_text(encoding="utf-8")
    if replacement == BASEFWX_EXAMPLE_NEW:
        updated, count = update_example_plugin_header(text, path)
    else:
        updated, count = update_license_line(text, replacement)
    if count and apply:
        path.write_text(updated, encoding="utf-8")
    return count


def run_yume(apply: bool) -> tuple[int, int]:
    roots = [ROOT / "include", ROOT / "src"]
    files = 0
    edits = 0
    for base in roots:
        for path in source_files_under(base):
            count = process_file(path, YUME_NEW, apply)
            if count:
                files += 1
                edits += count
                print(f"yume     {path.relative_to(ROOT)} -> AGPL-3.0-or-later")
    return files, edits


def run_basefwx(apply: bool) -> tuple[int, int]:
    files = 0
    edits = 0
    for path in source_files_under(ROOT / "basefwx"):
        replacement = basefwx_license_for(path)
        if replacement is None:
            continue
        count = process_file(path, replacement, apply)
        if count:
            files += 1
            edits += count
            rel = path.relative_to(ROOT)
            if replacement == BASEFWX_LGPL_NEW:
                tag = "LGPL-3.0-or-later"
            elif replacement == BASEFWX_MIXED_NEW:
                tag = "LGPL-3.0-or-later AND GPL-3.0-or-later"
            elif replacement == BASEFWX_EXAMPLE_NEW:
                tag = "MIT OR Apache-2.0"
            else:
                tag = "GPL-3.0-or-later"
            print(f"basefwx  {rel} -> {tag}")
    return files, edits


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "target",
        choices=("yume", "basefwx", "all"),
        help="which tree to scan",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write changes; default is dry-run only",
    )
    args = parser.parse_args()

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"{mode}: license header update for {args.target}")

    total_files = 0
    total_edits = 0
    if args.target in ("yume", "all"):
        files, edits = run_yume(args.apply)
        total_files += files
        total_edits += edits
    if args.target in ("basefwx", "all"):
        files, edits = run_basefwx(args.apply)
        total_files += files
        total_edits += edits

    print(f"{mode}: {total_edits} header line(s) in {total_files} file(s)")
    if not args.apply:
        print("No files changed. Re-run with --apply to write updates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
