#!/usr/bin/env python3
"""Compatibility wrapper for the canonical YUME 2.0 local benchmark."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def parse_args() -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        description=(
            "Run the in-process YUME 2.0 local benchmark. The old 1.x "
            "no-inner/light/heavy/hop matrix has been retired."
        )
    )
    parser.add_argument(
        "--yume",
        type=Path,
        default=REPO_ROOT / "build" / "bin" / "yume",
        help="yume executable (default: build/bin/yume)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="run --full-bench instead of the quick smoke profile",
    )
    args, benchmark_args = parser.parse_known_args()
    if benchmark_args[:1] == ["--"]:
        benchmark_args = benchmark_args[1:]
    return args, benchmark_args


def main() -> int:
    args, passthrough = parse_args()
    binary = args.yume.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit(f"yume executable not found: {binary}")
    mode = "--full-bench" if args.full else "--quick-bench"
    os.execv(str(binary), [str(binary), mode, *passthrough])
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
