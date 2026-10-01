#!/usr/bin/env python3
"""Open a kit that yume sealed through the public C ABI."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import yume_native_session as session  # noqa: E402

CHILD_ASAN_OPTIONS_ENV = "YUME_TEST_CHILD_ASAN_OPTIONS"


def run(probe: Path, yume: Path, openssl: Path) -> None:
    probe, yume, openssl = (path.resolve(strict=True) for path in (probe, yume, openssl))
    environment = session.openssl_environment(openssl)
    child_asan_options = environment.pop(CHILD_ASAN_OPTIONS_ENV, None)
    if child_asan_options is not None:
        # The ASan-preloaded Python host disables only leak detection. The
        # instrumented programs keep the strict leak policy.
        environment["ASAN_OPTIONS"] = child_asan_options
    with tempfile.TemporaryDirectory(prefix="yume-abi-kit-") as temporary:
        kit = Path(temporary) / "kit"
        session.provision_kit(kit, "localhost", 443, environment)
        client = kit / "client"
        sealed = Path(temporary) / "client.kit"
        sealing = subprocess.run(
            [str(yume), "--seal-kit", str(client), "--output", str(sealed)],
            env=environment, capture_output=True, text=True, timeout=60, check=False)
        code = sealing.stdout.strip()
        if sealing.returncode or len(code) != 29:
            raise RuntimeError("yume --seal-kit failed: " + sealing.stderr.strip())
        files = sum(1 for path in client.rglob("*") if path.is_file())
        result = subprocess.run(
            [str(probe), str(sealed), code, str(client), str(files)],
            env=environment, timeout=240, check=False)
        if result.returncode:
            raise RuntimeError(f"sealed kit probe failed with exit {result.returncode}")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--yume", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.probe, args.yume, args.openssl)
    except (OSError, ValueError, RuntimeError, session.SessionFailure,
            subprocess.TimeoutExpired) as error:
        print(f"sealed kit ABI gate: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
