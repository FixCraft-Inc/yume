"""Preload fault shims without displacing a built binary's ASan runtime."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess


def preload_for(binary: Path, shim: Path, inherited: str = "") -> str:
    """Keep dynamic ASan first, then the shim and any inherited preloads.

    Only use with trusted test binaries. Resolve the runtime from the binary
    rather than the default compiler, which may use a different ASan version.
    """
    linked = subprocess.run(
        ["ldd", str(binary.resolve())], capture_output=True, text=True,
        check=True, timeout=10,
    )
    runtimes = []
    for line in linked.stdout.splitlines():
        fields = line.split()
        if fields and (fields[0].startswith("libasan.so")
                       or fields[0].startswith("libclang_rt.asan")):
            if len(fields) < 3 or fields[1] != "=>" or not Path(fields[2]).is_file():
                raise RuntimeError("cannot resolve the test binary's ASan runtime")
            runtimes.append(fields[2])
    return ":".join(dict.fromkeys([
        *runtimes, str(shim), *filter(None, re.split(r"[:\s]+", inherited)),
    ]))
