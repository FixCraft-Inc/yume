#!/usr/bin/env python3
"""Provision a real stack and drive named streams through the public C ABI v1."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
from collections.abc import Iterator


SERVICE = "abi-stream-v1"
CHILD_ASAN_OPTIONS_ENV = "YUME_TEST_CHILD_ASAN_OPTIONS"


class CoverHandler(BaseHTTPRequestHandler):
    """Small deterministic origin for the H2 priming requests."""

    protocol_version = "HTTP/1.1"

    def _respond(self, *, head_only: bool) -> None:
        body = b"<!doctype html><title>Yume ABI test cover</title>\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._respond(head_only=False)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._respond(head_only=True)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


@contextmanager
def cover_backend() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), CoverHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--yumed", type=Path, required=True)
    return parser.parse_args()


def run_checked(argv: list[str], cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=60,
    )
    output = result.stdout.decode(errors="replace")
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(argv)}\n{output}"
        )
    return output


def pick_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def write_secret(path: Path) -> None:
    path.write_text(secrets.token_bytes(32).hex())
    path.chmod(0o600)


def main() -> int:
    args = parse_args()
    with (
        tempfile.TemporaryDirectory(prefix="yume-abi-stream-") as temporary,
        cover_backend() as cover_port,
    ):
        root = Path(temporary)
        home = root / "home"
        runtime = root / "runtime"
        home.mkdir(mode=0o700)
        runtime.mkdir(mode=0o700)
        environment = os.environ.copy()
        child_asan_options = environment.pop(CHILD_ASAN_OPTIONS_ENV, None)
        if child_asan_options is not None:
            # The ASan-preloaded Python host disables only leak detection to
            # avoid reporting CPython's process-lifetime allocations. Each
            # spawned instrumented executable must retain the strict CI leak
            # policy.
            environment["ASAN_OPTIONS"] = child_asan_options
        environment.update(
            {
                "HOME": str(home),
                "XDG_RUNTIME_DIR": str(runtime),
            }
        )

        cert = root / "server.crt"
        tls_key = root / "server.key"
        run_checked(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(tls_key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ],
            root,
            environment,
        )

        client_prefix = root / "client"
        run_checked(
            [str(args.yumed), "--keys-gen", str(client_prefix)],
            root,
            environment,
        )
        client_key = client_prefix.with_suffix(".key")
        client_public = client_prefix.with_suffix(".pub")
        authorized_keys = root / "authorized_keys"
        shutil.copyfile(client_public, authorized_keys)
        listing = run_checked(
            [
                str(args.yumed),
                "--auth-keys",
                str(client_public),
                "--keys-list",
            ],
            root,
            environment,
        )
        fingerprints = re.findall(r"(?m)^[0-9a-f]{64}$", listing)
        if len(fingerprints) != 1:
            raise RuntimeError(
                f"expected one composite fingerprint, got {fingerprints}\n{listing}"
            )

        auth_meta = root / "auth_keys.meta"
        auth_meta.write_text(
            json.dumps(
                {
                    fingerprints[0]: {
                        "permissions": {"allow_services": [SERVICE]},
                    }
                },
                indent=2,
            )
        )
        obfs_secret = root / "obfs.hex"
        inner_psk = root / "inner-psk.hex"
        write_secret(obfs_secret)
        write_secret(inner_psk)

        port = pick_port()
        server_config = root / "server.json"
        server_config.write_text(
            json.dumps(
                {
                    "role": "server",
                    "listen_address": "127.0.0.1",
                    "listen_port": port,
                    "tls_cert": str(cert),
                    "tls_key": str(tls_key),
                    "auth_keys": str(authorized_keys),
                    "auth_keys_meta": str(auth_meta),
                    "threads": 2,
                    "obfuscation": True,
                    "obfs_secret_file": str(obfs_secret),
                    "inner_psk_file": str(inner_psk),
                    "inner_crypto": True,
                    "real_backend": f"loopback://127.0.0.1:{cover_port}",
                    "allow_services": [SERVICE],
                    "ipc_enable": False,
                    "boring": True,
                },
                indent=2,
            )
        )
        client_config = root / "client.json"
        client_config.write_text(
            json.dumps(
                {
                    # Carrier admission intentionally requires the HTTP/2
                    # authority and TLS SNI to name the same host.
                    "role": "client",
                    "server": "localhost",
                    "port": port,
                    "identity": str(client_key),
                    "socks_port": 0,
                    "tunnels": 1,
                    "service_streams_only": True,
                    "tls_ca_cert": str(cert),
                    "tls_server_name": "localhost",
                    "accept_monitoring": True,
                    "auto_attach_local": False,
                    "obfuscation": True,
                    "obfs_secret_file": str(obfs_secret),
                    "inner_psk_file": str(inner_psk),
                    "inner_crypto": True,
                    "tls_backend": "openssl-diagnostic",
                    "non_interactive": True,
                    "boring": True,
                },
                indent=2,
            )
        )

        output = run_checked(
            [str(args.probe), str(server_config), str(client_config)],
            root,
            environment,
        )
        if output:
            print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
