#!/usr/bin/env python3
"""Compatibility wrapper for the canonical YUME 2.0 local benchmark."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from yume_bench_common import run_streamed_command  # noqa: E402
from yume_bench_resources import (  # noqa: E402
    host_resource_info,
    print_host_resources,
    print_process_resources,
)


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
    parser.add_argument(
        "--resource-sample-ms",
        type=int,
        default=250,
        help="external /proc sampling interval (default: 250 ms)",
    )
    parser.add_argument(
        "--no-resource-sampling",
        action="store_true",
        help="disable external CPU/RAM recording",
    )
    parser.add_argument(
        "--resource-json",
        type=Path,
        help="resource report path (default: yume-bench-results/local-<UTC>/resources.json)",
    )
    parser.add_argument(
        "--timeout-sec",
        type=int,
        default=7200,
        help="hard wrapper timeout; zero disables it (default: 7200)",
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
    if not 100 <= args.resource_sample_ms <= 5000:
        raise SystemExit("--resource-sample-ms must be 100..5000")
    if not 0 <= args.timeout_sec <= 86400:
        raise SystemExit("--timeout-sec must be 0..86400")
    mode = "--full-bench" if args.full else "--quick-bench"
    command = [str(binary), mode, *passthrough]
    result = run_streamed_command(
        command,
        timeout=float(args.timeout_sec) if args.timeout_sec else None,
        resource_sampling=not args.no_resource_sampling,
        resource_sample_ms=args.resource_sample_ms,
        interrupt_message="[local] interrupted; stopping the benchmark",
    )
    if result.resources:
        host = host_resource_info()
        print_host_resources("[local]", host)
        print_process_resources("[local] yume/selftest", result.resources)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report_path = (
            args.resource_json.expanduser().resolve()
            if args.resource_json
            else REPO_ROOT
            / "yume-bench-results"
            / f"local-{timestamp}"
            / "resources.json"
        )
        report_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        report = {
            "schema": 1,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "command": command,
            "exit_code": result.returncode,
            "host": host,
            "process": result.resources,
        }
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"[local] resource report: {report_path}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
