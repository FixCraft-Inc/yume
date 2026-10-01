#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Every repository path the documentation names in code exists.

A document that points at `src/runtime/native_cli.cpp` or
`providers/h2_web_front_door.*` goes stale silently when the file moves.
This reads the documentation sources and the hand-written guides, takes each
code span that names a path under a repository root (or, as the source map
writes them, under `src/`), and requires a file or directory to match it.
`*` matches any run of characters. Only files a fresh clone would hold count:
the Git-visible files (tracked, or new and not ignored), or every file when
there is no Git checkout, as in a synced build workspace. A generated file
counts only when it is listed below. The changelog is exempt, because it
records files that were removed on purpose, and so is the authoring guide
BaseFWX shares, whose examples name BaseFWX files and translations yet to
exist.
"""

from __future__ import annotations

import fnmatch
import functools
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = sorted(
    [path for path in (ROOT / "docs" / "src" / "en_US").rglob("*.doc")
     if path.name != "changelog.doc"]
    + list((ROOT / "docs" / "src" / "en_US").rglob("*.part"))
    + [ROOT / "docs" / "diagrams" / "README.md"])
ROOTS = ("src/", "scripts/", "tools/", "tests/", "config/", "docs/", "include/",
         "cmake/", "debian/", "website/", "patches/", ".github/")
# The directories under src/ that the source map names without the prefix.
LAYERS = ("engine/", "ytp/", "circuit/", "providers/", "runtime/", "abi/", "common/",
          "admission/", "stealth/", "fs/", "config/v1/", "modules/", "gui/",
          "test_support/")
# Generated paths a document names, as it spells them: a build output as it
# appears in the build tree, and the website copies and diagram includes the
# website build and `yume_diagrams.py preview` write.
GENERATED = {"src/libyume.so", "website/docs/*.md", "website/_includes/diagrams/",
             "website/_includes/diagrams/preview.html"}
SPAN = re.compile(r"`([^`\n]+)`")
PATH = re.compile(r"[A-Za-z0-9_.*{}/-]+")


def named_paths(text: str) -> list[tuple[int, str]]:
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        for span in SPAN.findall(line):
            span = span.strip()
            if PATH.fullmatch(span) and span.startswith(ROOTS + LAYERS):
                found.append((number, span))
    return found


def with_directories(files: set[str]) -> frozenset[str]:
    directories = {parent.as_posix() for name in files
                   for parent in Path(name).parents if parent != Path(".")}
    return frozenset(files | directories)


@functools.cache
def repository_paths() -> frozenset[str]:
    """Every file a fresh clone would hold, and every directory above one.

    Without Git, as in a synced build workspace, the files under the roots a
    document may name stand in for them.
    """
    try:
        listing = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others",
             "--exclude-standard"], capture_output=True, check=True, timeout=60).stdout
        files = {name for name in listing.decode("utf-8").split("\0") if name}
    except (OSError, subprocess.SubprocessError):
        files = {path.relative_to(ROOT).as_posix()
                 for root in ROOTS if (ROOT / root).is_dir()
                 for path in (ROOT / root).rglob("*") if path.is_file()}
    return with_directories(files)


def exists(path: str, paths: frozenset[str] | None = None) -> bool:
    if path in GENERATED:
        return True
    if paths is None:
        paths = repository_paths()
    for candidate in (path, "src/" + path):
        candidate = candidate.rstrip("/").replace("{", "").replace("}", "")
        if "*" in candidate:
            if fnmatch.filter(paths, candidate):
                return True
        elif candidate in paths:
            return True
    return False


class DocumentationPaths(unittest.TestCase):
    def test_every_named_path_exists(self) -> None:
        missing = []
        for source in SOURCES:
            for number, path in named_paths(source.read_text(encoding="utf-8")):
                if not exists(path):
                    missing.append(f"{source.relative_to(ROOT)}:{number}: {path}")
        self.assertEqual(missing, [], "\n".join(missing))

    def test_paths_are_recognized(self) -> None:
        text = ("`src/runtime/native_cli.cpp` `providers/h2_web_front_door.*` "
                "`config/reachability.json` `yume --status` `YUME_BUILD_GUI`")
        self.assertEqual([path for _, path in named_paths(text)],
                         ["src/runtime/native_cli.cpp", "providers/h2_web_front_door.*",
                          "config/reachability.json"])
        paths = with_directories({"src/providers/h2_web_front_door.cpp",
                                  "src/runtime/native_cli.cpp"})
        self.assertTrue(exists("providers/h2_web_front_door.*", paths))
        self.assertTrue(exists("src/runtime/", paths))
        self.assertTrue(exists("website/_includes/diagrams/", paths))
        self.assertFalse(exists("src/runtime/removed_long_ago.cpp", paths))
        self.assertFalse(exists("src/providers/", frozenset()))


if __name__ == "__main__":
    unittest.main()
