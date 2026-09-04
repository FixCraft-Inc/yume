#!/usr/bin/env python3
"""Positive half of the ``yume-gui --headless`` contract.

``test_yume_gui_headless.py`` proves the command fails when it should. This
proves it succeeds when it should, which is the half that actually demonstrates
the GUI's facade drives real core: it stands up a genuine dev6 ``yumed`` --
composite AUTH v2 identity, admission secret, inner PSK, loopback cover
backend -- and then requires ``yume-gui --headless`` to run its full
connect -> stop -> reconnect -> stop lifecycle against it and exit 0.

A GUI that compiles, renders and refuses bad input still proves nothing about
whether it can talk to a server. This is that gate.

The server recipe deliberately mirrors the daemon fixtures used elsewhere, which is
the already-qualified way to bring a dev6 server up in-tree.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

SERVICE = "gui-live-check"
STARTUP_TIMEOUT = 90


class CoverHandler(BaseHTTPRequestHandler):
    """Plain HTTP origin behind the carrier's unauthenticated cover path."""

    protocol_version = "HTTP/1.1"

    def _respond(self, *, head_only: bool) -> None:
        body = b"<!doctype html><title>Yume GUI live cover</title>\n"
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


def pick_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def write_secret(path: Path) -> None:
    path.write_text(secrets.token_bytes(32).hex())
    path.chmod(0o600)


def run_checked(argv: list[str], cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(
        argv, cwd=cwd, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        check=False, timeout=120,
    )
    output = result.stdout.decode(errors="replace")
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(argv)}\n{output}"
        )
    return output


def wait_for_listener(port: int, proc: subprocess.Popen, timeout: float) -> None:
    """Block until the server accepts TCP, or it dies first."""
    deadline = threading.Event()
    waited = 0.0
    step = 0.25
    while waited < timeout:
        if proc.poll() is not None:
            raise RuntimeError(f"yumed exited early with {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            deadline.wait(step)
            waited += step
    raise RuntimeError(f"yumed did not listen on {port} within {timeout}s")


def build_environment(root: Path) -> dict[str, str]:
    env = dict(os.environ)
    # Keep the run off the developer's real ~/.yume.
    env["HOME"] = str(root)
    env["XDG_CONFIG_HOME"] = str(root / ".config")
    env["XDG_DATA_HOME"] = str(root / ".local" / "share")
    return env


def provision(root: Path, yumed: Path, cover_port: int,
              env: dict[str, str]) -> tuple[Path, Path, int]:
    """Create certs, a composite identity, secrets, and both config files."""
    cert = root / "server.crt"
    tls_key = root / "server.key"
    run_checked(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(tls_key), "-out", str(cert),
            "-days", "1", "-nodes", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        root, env,
    )

    client_prefix = root / "client"
    run_checked([str(yumed), "--keys-gen", str(client_prefix)], root, env)
    client_key = client_prefix.with_suffix(".key")
    client_public = client_prefix.with_suffix(".pub")

    authorized_keys = root / "authorized_keys"
    shutil.copyfile(client_public, authorized_keys)

    listing = run_checked(
        [str(yumed), "--auth-keys", str(client_public), "--keys-list"], root, env
    )
    fingerprints = re.findall(r"(?m)^[0-9a-f]{64}$", listing)
    if len(fingerprints) != 1:
        raise RuntimeError(
            f"expected exactly one composite fingerprint, got {fingerprints}\n"
            f"{listing}"
        )

    auth_meta = root / "auth_keys.meta"
    auth_meta.write_text(
        json.dumps(
            {fingerprints[0]: {"permissions": {"allow_services": [SERVICE]}}},
            indent=2,
        )
    )

    obfs_secret = root / "obfs.hex"
    inner_psk = root / "inner-psk.hex"
    write_secret(obfs_secret)
    write_secret(inner_psk)
    # yumed refuses to start without a cover source: with none, the HTTP/2
    # decoy would serve a page identical on every deployment.
    cover_index = root / "cover-index.html"
    cover_index.write_text(
        "<!doctype html><title>example</title><p>It works.</p>\n",
        encoding="utf-8",
    )

    port = pick_port()
    server_config = root / "server.json"
    server_config.write_text(
        json.dumps(
            {
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
                "real_index_path": str(cover_index),
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
                # Carrier admission requires the HTTP/2 authority and the TLS
                # SNI to name the same host.
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
    return server_config, client_config, port


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui", type=Path, required=True)
    parser.add_argument("--yumed", type=Path, required=True)
    args = parser.parse_args()

    for name, path in (("yume-gui", args.gui), ("yumed", args.yumed)):
        if not path.is_file():
            print(f"{name} not found at {path}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory(prefix="yume-gui-live-") as tmp:
        root = Path(tmp)
        (root / ".config").mkdir()
        env = build_environment(root)

        with cover_backend() as cover_port:
            server_config, client_config, port = provision(
                root, args.yumed, cover_port, env
            )

            server_log = root / "yumed.log"
            with server_log.open("wb") as log:
                server = subprocess.Popen(
                    [str(args.yumed), "--config", str(server_config)],
                    cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT,
                )
                try:
                    wait_for_listener(port, server, STARTUP_TIMEOUT)

                    # The GUI drives only the client here. The server half of
                    # the contract is exercised separately; pointing the GUI's
                    # server lifecycle at this same port would collide with the
                    # yumed we just started.
                    result = subprocess.run(
                        [
                            str(args.gui), "--headless",
                            "--client-config", str(client_config),
                        ],
                        cwd=root, env=env,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        check=False, timeout=STARTUP_TIMEOUT + 120,
                    )
                    output = result.stdout.decode(errors="replace")
                    print(output, end="")

                    if result.returncode != 0:
                        print(
                            "\n--- yumed log ---\n"
                            + server_log.read_text(errors="replace")[-4000:],
                            file=sys.stderr,
                        )
                        print(
                            f"FAIL: headless returned {result.returncode}; "
                            "expected 0 against a live dev6 server",
                            file=sys.stderr,
                        )
                        return 1

                    # Exit 0 alone is not enough: require the evidence that
                    # both the first connect and the reconnect actually
                    # reached Connected, which is what distinguishes this from
                    # the old always-zero smoke.
                    required = [
                        "client connect reached Connected",
                        "client connect stop clean",
                        "client reconnect reached Connected",
                        "client reconnect stop clean",
                        "all exercised lifecycles passed",
                    ]
                    missing = [n for n in required if n not in output]
                    if missing:
                        print(
                            "FAIL: headless exited 0 but never reported: "
                            + ", ".join(missing),
                            file=sys.stderr,
                        )
                        return 1
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=15)

    print("yume-gui live connect/stop/reconnect contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
