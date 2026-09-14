#!/usr/bin/env python3
"""Run yumed-ytp1 and yume-ytp1 as processes and move bytes through SOCKS5."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))

import yume_native_session as session  # noqa: E402

PAYLOAD_BYTES = 1024 * 1024


def validate(program: Path, config: Path, environment: dict[str, str]) -> None:
    result = subprocess.run([str(program), "--config", str(config), "--validate"],
                            env=environment, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise session.SessionFailure(f"{program.name} --validate failed: {result.stderr.strip()}")


def run(yumed: Path, yume: Path, openssl: Path) -> None:
    environment = session.openssl_environment(openssl)
    with tempfile.TemporaryDirectory(prefix="yume-native-runtime-") as temporary:
        root = Path(temporary)
        kit = root / "kit"
        server_port, socks_port, target_port, closed_port = (session.free_port() for _ in range(4))
        session.provision_kit(kit, "localhost", server_port, environment)
        session.configure_kit(kit, listen_address="127.0.0.1", networks=["127.0.0.1/32"],
                              connect_address="127.0.0.1", socks_port=socks_port)
        validate(yumed, kit / "server/yumed.json", environment)
        validate(yume, kit / "client/yume.json", environment)

        target = session.serve_payload("127.0.0.1", target_port, PAYLOAD_BYTES)
        logs = {name: (root / f"{name}.log").open("wb") for name in ("yumed", "yume")}
        server = subprocess.Popen([str(yumed), "--config", str(kit / "server/yumed.json")],
                                  env=environment, stdout=logs["yumed"], stderr=subprocess.STDOUT)
        client = None
        try:
            deadline = time.monotonic() + 30
            session.wait_for_port("127.0.0.1", server_port, server, deadline)
            client = subprocess.Popen([str(yume), "--config", str(kit / "client/yume.json")],
                                      env=environment, stdout=logs["yume"], stderr=subprocess.STDOUT)
            session.wait_for_port("127.0.0.1", socks_port, client, deadline)

            length, digest, _ = session.get_through_socks(socks_port, "127.0.0.1", target_port,
                                                          time.monotonic() + 30)
            if length != PAYLOAD_BYTES or digest != session.payload_digest(PAYLOAD_BYTES):
                raise session.SessionFailure(f"tunnelled payload differs: {length} of {PAYLOAD_BYTES} bytes")

            # Outside 127.0.0.1/32: configured destinations refuse it.
            code, connection = session.socks_connect(socks_port, "127.0.0.2", target_port)
            connection.close()
            if code != session.REPLY_NOT_ALLOWED:
                raise session.SessionFailure(f"refused destination returned SOCKS reply {code}")
            # Permitted, but nothing listens: the server cannot set up the route.
            code, connection = session.socks_connect(socks_port, "127.0.0.1", closed_port)
            connection.close()
            if code != session.REPLY_HOST_UNREACHABLE:
                raise session.SessionFailure(f"closed destination returned SOCKS reply {code}")

            session.stop_process(client, "yume-ytp1")
            client = None
            session.stop_process(server, "yumed-ytp1")
        finally:
            for process in (client, server):
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            target.shutdown()
            for handle in logs.values():
                handle.close()
            for name in logs:
                text = (root / f"{name}.log").read_text(encoding="utf-8", errors="replace")
                session.reject_secret_output(name, text)
                sys.stdout.write(f"--- {name} log\n{text}")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yumed", type=Path, required=True)
    parser.add_argument("--yume", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        run(arguments.yumed, arguments.yume, arguments.openssl)
    except (session.SessionFailure, OSError, subprocess.SubprocessError) as error:
        print(f"native runtime test: {error}", file=sys.stderr)
        return 1
    print("native runtime processes carried SOCKS5 traffic and stopped cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
