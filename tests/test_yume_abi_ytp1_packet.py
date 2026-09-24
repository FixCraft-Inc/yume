#!/usr/bin/env python3
"""Exercise named packet services and native UDP routes through the public ABI."""

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
from test_yume_abi_ytp1_stream import composite_fingerprint  # noqa: E402

SERVICES = (("echo", "stream"), ("echo", "packet"), ("unregistered", "packet"),
            ("denied", "packet"), ("stream-only", "stream"))
GRANTED = (("echo", "stream"), ("echo", "packet"), ("unregistered", "packet"))


class Echo(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        payload, connection = self.request
        target = self.server
        target.received += 1
        target.total_bytes += len(payload)
        if not payload or target.received > 256 or target.total_bytes > 1024 * 1024:
            raise RuntimeError("UDP probe exceeded the target bounds")
        if connection.sendto(payload, self.client_address) != len(payload):
            raise RuntimeError("UDP echo write was incomplete")


class Target(socketserver.UDPServer):
    max_packet_size = 65535

    def __init__(self, address: tuple[str, int]) -> None:
        self.received = 0
        self.total_bytes = 0
        self.failed = False
        super().__init__(address, Echo)

    def handle_error(self, request: object, client_address: object) -> None:
        # The main thread reports failure after every worker has joined.
        self.failed = True


class TargetV6(Target):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def named(probe: Path, openssl: Path, kit: Path, environment: dict[str, str]) -> None:
    session.provision_kit(kit, "localhost", session.free_port(), environment)
    for relative in ("server/yumed.json", "client/yume.json"):
        path = kit / relative
        config = json.loads(path.read_text(encoding="utf-8"))
        config["services"] = [
            {"name": name, "kind": kind, "max_concurrent_streams": 8}
            for name, kind in SERVICES
        ]
        config["adapters"] = []
        config["limits"]["max_packet_batch"] = 4
        if config["role"] == "server":
            config["endpoint"]["listen_addresses"] = ["127.0.0.1"]
        else:
            # A numeric dial needs no resolver helper. TLS still authenticates
            # the kit's host name. The stream probe covers named dialing.
            config["endpoint"]["connect_address"] = "127.0.0.1"
        path.write_text(json.dumps(config), encoding="utf-8")
    authorization = kit / "server/credentials/authorized-keys.json"
    store = json.loads(authorization.read_text(encoding="utf-8"))
    if len(store["keys"]) != 1:
        raise session.SessionFailure("packet fixture requires one authorized client")
    store["keys"][0]["capabilities"] = [
        {"service": name, "kind": kind} for name, kind in GRANTED
    ]
    authorization.write_text(json.dumps(store), encoding="utf-8")
    client_fingerprint = composite_fingerprint(
        openssl, kit / "client/credentials/client-composite.pub.pem")
    if client_fingerprint != store["keys"][0]["identity"]["sha256"]:
        raise session.SessionFailure("client identity fingerprint disagrees with the kit")
    server_fingerprint = composite_fingerprint(
        openssl, kit / "server/credentials/server-composite.pub.pem")
    result = subprocess.run(
        [str(probe), "named", str(kit / "server"), str(kit / "client"),
         client_fingerprint, server_fingerprint],
        env=environment, timeout=90, check=False)
    if result.returncode:
        raise session.SessionFailure(f"named packet ABI probe exited {result.returncode}")


def routed(probe: Path, daemon: Path, root: Path, environment: dict[str, str]) -> None:
    with ExitStack() as stack:
        target4 = stack.enter_context(Target(("127.0.0.1", 0)))
        # UDP connect cannot detect an absent receiver. Both localhost address
        # families use the same port so DNS order cannot select a dead target.
        target6 = stack.enter_context(TargetV6(("::1", target4.server_address[1])))
        targets = (target4, target6)
        threads: list[threading.Thread] = []
        server: subprocess.Popen | None = None
        try:
            for target in targets:
                thread = threading.Thread(target=target.serve_forever)
                thread.start()
                threads.append(thread)
            kit = root / "route-kit"
            server_port = session.free_port()
            session.provision_kit(kit, "localhost", server_port, environment)
            session.configure_kit(kit, listen_address="127.0.0.1",
                                  networks=("127.0.0.1/32", "::1/128"),
                                  connect_address="127.0.0.1", socks_port=session.free_port())
            path = kit / "client/yume.json"
            config = json.loads(path.read_text(encoding="utf-8"))
            config["adapters"] = []
            path.write_text(json.dumps(config), encoding="utf-8")
            log = stack.enter_context((root / "daemon.log").open("w+", encoding="utf-8"))
            server = subprocess.Popen([str(daemon), "--config", str(kit / "server/yumed.json")],
                                      env=environment, stdout=log, stderr=subprocess.STDOUT)
            session.wait_for_port("127.0.0.1", server_port, server, time.monotonic() + 20)
            result = subprocess.run(
                [str(probe), "route", str(kit / "client"), str(target4.server_address[1]),
                 str(target6.server_address[1])],
                env=environment, timeout=90, check=False)
            if result.returncode:
                raise session.SessionFailure(f"routed packet ABI probe exited {result.returncode}")
            session.stop_process(server, "packet ABI daemon")
            log.seek(0)
            session.reject_secret_output("packet daemon", log.read())
        finally:
            if server is not None and server.poll() is None:
                server.kill()
                server.wait(timeout=5)
            # Only started workers may be shut down: socketserver.shutdown()
            # waits for serve_forever(), which never ran if thread.start failed.
            for target in targets[:len(threads)]:
                target.shutdown()
            for thread in threads:
                thread.join(timeout=5)
                if thread.is_alive():
                    raise session.SessionFailure("UDP echo target did not stop")
        if any(target.failed for target in targets):
            raise session.SessionFailure("UDP echo target failed")
        if sum(target.received for target in targets) != 96:
            raise session.SessionFailure("UDP echo targets received an unexpected datagram count")


def run(probe: Path, daemon: Path, openssl: Path) -> None:
    probe = probe.resolve(strict=True)
    daemon = daemon.resolve(strict=True)
    openssl = openssl.resolve(strict=True)
    if not all(path.is_file() for path in (probe, daemon, openssl)):
        raise ValueError("probe, daemon and OpenSSL must be regular files")
    environment = session.openssl_environment(openssl)
    child_options = environment.pop("YUME_TEST_CHILD_ASAN_OPTIONS", None)
    if child_options is not None:
        environment["ASAN_OPTIONS"] = child_options
    with tempfile.TemporaryDirectory(prefix="yume-abi-packet-") as temporary:
        root = Path(temporary)
        named(probe, openssl, root / "named-kit", environment)
        routed(probe, daemon, root, environment)


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
        print(f"packet ABI integration: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
