#!/usr/bin/env python3
"""Reject private, generated, and malformed paths in a source archive."""

from __future__ import annotations

import argparse
import pathlib
import re


FORBIDDEN_ROOTS = {
    ".agents", ".cache", ".claude", ".codex", ".private",
    ".pytest_cache", ".secrets", ".wrangler", "basefwx", "bins", "debian",
    "DEV_services", "third_party", "vendor", "yume-bench-results",
    "yume-lan-kit",
}
FORBIDDEN_ANYWHERE = {
    ".git", ".agents", ".cache", ".claude", ".codex", ".jekyll-cache",
    ".private", ".pytest_cache", ".secrets", ".wrangler", "__pycache__",
}
FORBIDDEN_BASENAMES = {".DS_Store"}
FORBIDDEN_ROOT_FILES = {"AGENTS.md", "AI_NOTES.md", "opencode.json"}
FORBIDDEN_SUFFIXES = (".log", ".trace", ".out", ".pyc", ".tar.xz")
GENERATED_ROOT_RE = re.compile(r"(?:build(?:-[^/]+)?|obj-[^/]+)")


def rejected_paths(names: list[str], prefix: str) -> list[str]:
    rejected: list[str] = []
    for original in names:
        name = original.rstrip("/")
        if not name or name.startswith("/") or "\0" in name:
            rejected.append(original)
            continue
        parts = name.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            rejected.append(original)
            continue
        if parts[0] != prefix:
            rejected.append(original)
            continue
        relative = parts[1:]
        if not relative:
            continue
        root = relative[0]
        if (root in FORBIDDEN_ROOTS or root in FORBIDDEN_ROOT_FILES or
                GENERATED_ROOT_RE.fullmatch(root) is not None or
                any(part in FORBIDDEN_ANYWHERE for part in relative) or
                any(part in FORBIDDEN_BASENAMES for part in relative) or
                relative[:2] == ["website", "_site"] or
                name.endswith(FORBIDDEN_SUFFIXES)):
            rejected.append(original)
    return rejected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listing", required=True, type=pathlib.Path)
    parser.add_argument("--prefix", required=True)
    args = parser.parse_args()
    names = args.listing.read_text(encoding="utf-8").splitlines()
    rejected = rejected_paths(names, args.prefix)
    if rejected:
        print("source package contains excluded or malformed paths:")
        print("\n".join(rejected))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
