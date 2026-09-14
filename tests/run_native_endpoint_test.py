#!/usr/bin/env python3
"""Exercise the native endpoint with real setup-kit credentials and sockets."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def run(binary: Path, openssl: Path) -> None:
    binary = binary.resolve(strict=True)
    openssl = openssl.resolve(strict=True)
    if not binary.is_file() or not openssl.is_file():
        raise ValueError("test binary and OpenSSL must be regular files")
    environment = os.environ.copy()
    environment["PATH"] = str(openssl.parent) + os.pathsep + environment.get("PATH", "")
    # Setup selects openssl by PATH. Keep generation on the selected library's
    # installation; unsupported PQ algorithms must fail, never skip this gate.
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="yume-native-endpoint-") as temporary:
        kit = Path(temporary) / "kit"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        # Closing the reservation is unavoidable before the native listener
        # binds; a competing bind fails this test instead of selecting a peer.
        setup = subprocess.run(
            [sys.executable, str(root / "tools/yume_setup_ytp1.py"), "init",
             "--host", "localhost", "--port", str(port), "--output", str(kit)],
            env=environment, capture_output=True, text=True, timeout=75, check=False,
        )
        if setup.returncode:
            raise RuntimeError("native test credential provisioning failed: " + setup.stderr.strip())
        for relative in ("server/yumed.json", "client/yume.json"):
            path = kit / relative
            config = json.loads(path.read_text(encoding="utf-8"))
            config["services"] = [
                {"name": name, "kind": "stream", "max_concurrent_streams": 8}
                for name in ("echo", "denied")
            ]
            config["adapters"] = []
            if config["role"] == "server":
                config["endpoint"]["listen_addresses"] = ["127.0.0.1"]
            path.write_text(json.dumps(config), encoding="utf-8")
            if config["role"] == "server":
                direct = dict(config, adapters=[
                    {"kind": "direct_tcp", "service": name} for name in ("echo", "denied")
                ])
                path.with_name("direct-tcp.json").write_text(json.dumps(direct), encoding="utf-8")
            packets = dict(config, services=[
                dict(service, kind="packet") for service in config["services"]
            ], adapters=([
                {"kind": "direct_udp", "service": name} for name in ("echo", "denied")
            ] if config["role"] == "server" else []))
            if config["role"] == "server":
                packets["credentials"] = dict(config["credentials"], authorized_keys={
                    "file": "credentials/authorized-packets.json"
                })
            packet_name = "direct-udp.json" if config["role"] == "server" else "routes-udp.json"
            path.with_name(packet_name).write_text(json.dumps(packets), encoding="utf-8")
            if config["role"] == "server":
                unsupported = dict(packets, adapters=[
                    {"kind": "packet", "service": "echo", "interface_name": "ytptest0", "mtu": 1400}
                ])
            else:
                unsupported = dict(config, adapters=[
                    {"kind": "socks5", "service": "echo", "listen_address": "127.0.0.1", "listen_port": 1080}
                ])
            path.with_name("unsupported-adapter.json").write_text(json.dumps(unsupported), encoding="utf-8")
            if config["role"] == "server":
                config["limits"]["max_queued_bytes"] = 64 * 1024 * 1024
                variant = path.with_name("invalid-queue.json")
            else:
                config["services"][1] = {"name": "echo", "kind": "packet",
                                          "max_concurrent_streams": 8}
                variant = path.with_name("dual-kind.json")
            variant.write_text(json.dumps(config), encoding="utf-8")
        authorization = kit / "server/credentials/authorized-keys.json"
        store = json.loads(authorization.read_text(encoding="utf-8"))
        for entry in store["keys"]:
            entry["capabilities"] = [{"service": "echo", "kind": "stream"}]
        authorization.write_text(json.dumps(store), encoding="utf-8")
        for entry in store["keys"]:
            entry["capabilities"] = [{"service": "echo", "kind": "packet"}]
        authorization.with_name("authorized-packets.json").write_text(json.dumps(store), encoding="utf-8")
        result = subprocess.run([str(binary), str(kit)], env=environment,
                                timeout=35, check=False)
        if result.returncode:
            raise RuntimeError(f"native endpoint test failed with exit {result.returncode}")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.binary, args.openssl)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"native endpoint gate: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
