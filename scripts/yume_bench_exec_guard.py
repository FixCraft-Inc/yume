#!/usr/bin/env python3
"""Fail closed unless a benchmark workload has no caps and no-new-privs."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


STATUS_FIELDS = (
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
    "NoNewPrivs",
)
ZERO_CAPS = "0000000000000000"


def security_state(status: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in status.splitlines():
        name, separator, value = line.partition(":")
        if separator and name in STATUS_FIELDS:
            values[name] = value.strip()
    return values


def validate_security_state(state: dict[str, str]) -> None:
    missing = [name for name in STATUS_FIELDS if name not in state]
    if missing:
        raise RuntimeError(f"missing process security fields: {', '.join(missing)}")
    caps = STATUS_FIELDS[:-1]
    if any(state[name] != ZERO_CAPS for name in caps):
        raise RuntimeError("benchmark workload retained Linux capabilities")
    if state["NoNewPrivs"] != "1":
        raise RuntimeError("benchmark workload did not set no-new-privs")


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] != "--":
        print("usage: yume_bench_exec_guard.py -- COMMAND [ARG ...]", file=sys.stderr)
        return 2
    try:
        state = security_state(
            Path("/proc/self/status").read_text(encoding="ascii", errors="strict")
        )
        validate_security_state(state)
    except (OSError, RuntimeError) as exc:
        print(f"benchmark workload security check failed: {exc}", file=sys.stderr)
        return 126
    print(
        "YUME_BENCH_SECURITY_STATE="
        + json.dumps(state, sort_keys=True, separators=(",", ":")),
        file=sys.stderr,
        flush=True,
    )
    try:
        os.execvp(argv[1], argv[1:])
    except OSError as exc:
        print(f"could not exec benchmark workload: {exc}", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
