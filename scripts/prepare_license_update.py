#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

"""Dry-run/apply license header updates for YUME and bundled BaseFWX.

Default mode is dry-run. Use --apply only after reviewing the planned changes.
This script updates source-file header lines and prepends missing headers.
It does not rewrite LICENSE, LICENCE, README, Debian metadata, or long docs.
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

YUME_HEADER = [
    "YUME - Yume Universal Multiprotocol Engine",
    "Copyright (C) 2020-2026  FixCraft Inc.",
    YUME_NEW,
]

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
    "third_party",
    "basefwx",
    "website",
    ".claude",
    ".codex",
    ".wrangler",
}

YUME_EXTRA_FILES = (
    ROOT / "CMakeLists.txt",
    ROOT / "ezbuild.sh",
    ROOT / "fullau.sh",
)

YUME_SCAN_DIRS = (
    ROOT / "include",
    ROOT / "src",
    ROOT / "scripts",
    ROOT / "tools",
)


def is_skipped(path: Path, base: Path = ROOT) -> bool:
    rel_parts = path.relative_to(base).parts
    name = path.name
    if name.startswith("LICENSE") or name.startswith("LICENCE"):
        return True
    for index, part in enumerate(rel_parts):
        if part in SKIP_DIR_NAMES:
            return True
        if index < len(rel_parts) - 1 and part.startswith("build-"):
            return True
    return False


def comment_prefix(path: Path) -> str:
    if path.suffix == ".py" or path.suffix == ".sh" or path.name.endswith(".sh"):
        return "# "
    return "# "


def format_header(path: Path, lines: list[str]) -> str:
    prefix = comment_prefix(path)
    return "".join(f"{prefix}{line}\n" for line in lines)


def has_license_marker(text: str, replacement: str) -> bool:
    head = text[:1200]
    if replacement in head:
        return True
    if replacement == YUME_NEW:
        return "GNU Affero General Public License v3.0 or later" in head
    if replacement == BASEFWX_LGPL_NEW:
        return "GNU Lesser General Public License v3.0 or later" in head
    if replacement == BASEFWX_GPL_NEW:
        return "GNU General Public License v3.0 or later" in head and "Lesser" not in head
    if replacement == BASEFWX_EXAMPLE_NEW:
        return BASEFWX_EXAMPLE_NEW in head
    if replacement == BASEFWX_MIXED_NEW:
        return BASEFWX_MIXED_NEW in head
    return False


def prepend_header(text: str, path: Path, header_lines: list[str]) -> tuple[str, int]:
    block = format_header(path, header_lines)
    if text.startswith("#!"):
        first_newline = text.find("\n")
        if first_newline == -1:
            return block + text, 1
        return text[: first_newline + 1] + block + text[first_newline + 1 :], 1
    if text.startswith("\ufeff"):
        return text[:1] + block + text[1:], 1
    return block + text, 1


def source_files_under(base: Path):
    for path in base.rglob("*"):
        if not path.is_file() or is_skipped(path, base=base):
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
    if rel.startswith("basefwx/python/tools/") or rel.startswith("basefwx/python/tests/"):
        return BASEFWX_GPL_NEW
    if rel.startswith("basefwx/.github/scripts/"):
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
        note = (
            f"{prefix}This file is intentionally permissive so plugin authors "
            "can use it as a starting template.\n"
        )
        updated_lines = lines[:i] + [f"{prefix}{BASEFWX_EXAMPLE_NEW}\n", note] + lines[j:]
        updated = "".join(updated_lines)
        return (updated, 1) if updated != text else (text, 0)

    return text, 0


def process_file(path: Path, replacement: str, apply: bool, header_lines: list[str] | None = None) -> int:
    text = path.read_text(encoding="utf-8")
    updated = text
    count = 0

    if replacement == BASEFWX_EXAMPLE_NEW:
        updated, count = update_example_plugin_header(text, path)
    else:
        updated, count = update_license_line(text, replacement)

    if count == 0 and header_lines is not None and not has_license_marker(updated, replacement):
        updated, count = prepend_header(updated, path, header_lines)

    if count and apply:
        path.write_text(updated, encoding="utf-8")
    return count


def yume_files():
    seen: set[Path] = set()
    for extra in YUME_EXTRA_FILES:
        if extra.is_file():
            seen.add(extra.resolve())
            yield extra
    for base in YUME_SCAN_DIRS:
        if not base.is_dir():
            continue
        for path in source_files_under(base):
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            if path.name == "prepare_license_update.py":
                continue
            yield path


def run_yume(apply: bool) -> tuple[int, int]:
    files = 0
    edits = 0
    for path in yume_files():
        count = process_file(path, YUME_NEW, apply, header_lines=YUME_HEADER)
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
        header_lines = None
        if replacement == BASEFWX_GPL_NEW:
            header_lines = [
                "BaseFWX - Cryptography Engine",
                "Copyright (C) 2020-2026  FixCraft Inc.",
                BASEFWX_GPL_NEW,
            ]
        elif replacement == BASEFWX_LGPL_NEW:
            header_lines = [
                "BaseFWX - Cryptography Engine",
                "Copyright (C) 2020-2026  FixCraft Inc.",
                BASEFWX_LGPL_NEW,
            ]
        elif replacement == BASEFWX_MIXED_NEW:
            header_lines = [
                "BaseFWX - Cryptography Engine",
                "Copyright (C) 2020-2026  FixCraft Inc.",
                BASEFWX_MIXED_NEW,
            ]
        count = process_file(path, replacement, apply, header_lines=header_lines)
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
