#!/usr/bin/env python3
"""Route public-ABI streams through a native daemon to bounded loopback targets."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import yume_native_session as session  # noqa: E402


class Echo(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(15)
        received = bytearray()
        while chunk := self.request.recv(65536):
            received.extend(chunk)
            if len(received) > 20 * 65536:
                raise RuntimeError("probe exceeded target input bound")
        self.request.sendall(received)


class Target(socketserver.ThreadingTCPServer):
    daemon_threads = False
    block_on_close = True


class TargetV6(Target):
    address_family = socket.AF_INET6


def run(probe: Path, daemon: Path, openssl: Path) -> None:
    probe = probe.resolve(strict=True)
    daemon = daemon.resolve(strict=True)
    environment = session.openssl_environment(openssl)
    child_options = environment.pop("YUME_TEST_CHILD_ASAN_OPTIONS", None)
    if child_options is not None:
        environment["ASAN_OPTIONS"] = child_options
    with tempfile.TemporaryDirectory(prefix="yume-abi-route-") as temporary, ExitStack() as stack:
        root = Path(temporary)
        target4 = stack.enter_context(Target(("127.0.0.1", 0), Echo))
        target6 = stack.enter_context(TargetV6(("::1", 0), Echo))
        threads: list[threading.Thread] = []
        for target in (target4, target6):
            thread = threading.Thread(target=target.serve_forever)
            thread.start()
            threads.append(thread)
        server: subprocess.Popen | None = None
        try:
            kit = root / "kit"
            server_port = session.free_port()
            session.provision_kit(kit, "localhost", server_port, environment)
            session.configure_kit(kit, listen_address="127.0.0.1",
                                  networks=("127.0.0.1/32", "::1/128"),
                                  connect_address="127.0.0.1", socks_port=session.free_port())
            client_path = kit / "client/yume.json"
            client = json.loads(client_path.read_text(encoding="utf-8"))
            # The public caller owns application I/O. No local SOCKS adapter
            # is requested or silently discarded by endpoint start.
            client["adapters"] = []
            client_path.write_text(json.dumps(client), encoding="utf-8")
            log = stack.enter_context((root / "daemon.log").open("w+", encoding="utf-8"))
            server = subprocess.Popen([str(daemon), "--config", str(kit / "server/yumed.json")],
                                      env=environment, stdout=log, stderr=subprocess.STDOUT)
            session.wait_for_port("127.0.0.1", server_port, server, time.monotonic() + 20)
            result = subprocess.run([str(probe), str(kit / "client"),
                                     str(target4.server_address[1]), str(target6.server_address[1])],
                                    env=environment, timeout=90, check=False)
            if result.returncode:
                raise session.SessionFailure(f"ABI route probe exited {result.returncode}")
            session.stop_process(server, "ABI route daemon")
            log.seek(0)
            session.reject_secret_output("daemon", log.read())
        finally:
            if server is not None and server.poll() is None:
                server.kill()
                server.wait(timeout=5)
            for target in (target4, target6):
                target.shutdown()
            for thread in threads:
                thread.join(timeout=5)
                if thread.is_alive():
                    raise session.SessionFailure("echo target did not stop")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--yumed", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.probe, args.yumed, args.openssl)
    except (session.SessionFailure, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"ABI route integration: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
