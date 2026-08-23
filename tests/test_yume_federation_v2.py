#!/usr/bin/env python3
"""End-to-end AUTH v2 federation test using two real yumed processes."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO, Callable


TIMEOUT_SECONDS = 30.0
MAX_RUNTIME_RESPONSE = 1024 * 1024
ALICE_ID = "a" * 32
BOB_ID = "b" * 32


class FixtureError(RuntimeError):
    """Raised when the integration fixture fails an acceptance assertion."""


class CoverHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self) -> None:
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _respond
    do_HEAD = _respond
    do_POST = _respond

    def log_message(self, _format: str, *_args: object) -> None:
        return


@dataclass
class ManagedProcess:
    name: str
    process: subprocess.Popen[bytes]
    log_path: Path
    log_file: BinaryIO

    def stop(self) -> None:
        if self.process.poll() is not None:
            self.log_file.close()
            return
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=3)
        finally:
            self.log_file.close()

    def log_text(self) -> str:
        try:
            return self.log_path.read_text(errors="replace")
        except OSError:
            return ""


@dataclass(frozen=True)
class NodeFiles:
    root: Path
    cert: Path
    tls_key: Path
    federation_key: Path
    federation_pub: Path
    client_key: Path
    client_pub: Path
    authorized_keys: Path
    auth_meta: Path
    obfs_secret: Path
    history_dir: Path
    relay_receive_dir: Path
    home: Path
    runtime_dir: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--yume", type=Path, required=True)
    parser.add_argument("--yumed", type=Path, required=True)
    return parser.parse_args()


def run_checked(argv: list[str], cwd: Path, log_path: Path) -> str:
    result = subprocess.run(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = result.stdout.decode(errors="replace")
    log_path.write_text(output)
    if result.returncode != 0:
        raise FixtureError(
            f"command failed ({result.returncode}): {' '.join(argv)}\n{output}"
        )
    return output


def start_process(
    name: str,
    argv: list[str],
    cwd: Path,
    environment: dict[str, str],
) -> ManagedProcess:
    log_path = cwd / f"{name}.log"
    log_file = log_path.open("wb")
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=environment,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return ManagedProcess(name, process, log_path, log_file)


def wait_until(
    description: str,
    predicate: Callable[[], bool],
    processes: list[ManagedProcess],
    timeout: float = TIMEOUT_SECONDS,
    poll_interval: float = 0.05,
) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        for managed in processes:
            returncode = managed.process.poll()
            if returncode is not None:
                raise FixtureError(
                    f"{managed.name} exited with {returncode} while waiting for "
                    f"{description}\n{managed.log_text()}"
                )
        try:
            if predicate():
                return
        except (ConnectionError, FileNotFoundError, OSError, ValueError) as exc:
            last_error = str(exc)
        time.sleep(poll_interval)
    suffix = f": {last_error}" if last_error else ""
    raise FixtureError(f"timed out waiting for {description}{suffix}")


def pick_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def tcp_ready(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def write_secret(path: Path, value: bytes | None = None) -> None:
    path.write_text((value or secrets.token_bytes(32)).hex())
    path.chmod(0o600)


def generate_identity(yumed: Path, prefix: Path) -> tuple[Path, Path]:
    run_checked(
        [str(yumed), "--keys-gen", str(prefix)],
        prefix.parent,
        prefix.parent / f"{prefix.name}-keys-gen.log",
    )
    private_key = prefix.with_suffix(".key")
    public_key = prefix.with_suffix(".pub")
    if not private_key.is_file() or not public_key.is_file():
        raise FixtureError(f"yumed --keys-gen did not create {prefix}")
    return private_key, public_key


def identity_fingerprint(yumed: Path, public_key: Path) -> str:
    output = run_checked(
        [str(yumed), "--auth-keys", str(public_key), "--keys-list"],
        public_key.parent,
        public_key.parent / f"{public_key.stem}-keys-list.log",
    )
    fingerprints = re.findall(r"(?m)^[0-9a-f]{64}$", output)
    if len(fingerprints) != 1:
        raise FixtureError(
            f"expected one composite fingerprint for {public_key}, got {fingerprints}"
        )
    return fingerprints[0]


def generate_certificate(root: Path) -> tuple[Path, Path]:
    cert = root / "server.crt"
    key = root / "server.key"
    run_checked(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
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
        root / "openssl-cert.log",
    )
    return cert, key


def make_node(yumed: Path, root: Path) -> NodeFiles:
    root.mkdir(mode=0o700)
    cert, tls_key = generate_certificate(root)
    federation_key, federation_pub = generate_identity(yumed, root / "federation")
    client_key, client_pub = generate_identity(yumed, root / "client")
    obfs_secret = root / "obfs.hex"
    write_secret(obfs_secret)
    history_dir = root / "history"
    relay_receive_dir = root / "received"
    home = root / "home"
    runtime_dir = root / "runtime"
    for directory in (history_dir, relay_receive_dir, home, runtime_dir):
        directory.mkdir(mode=0o700)
    return NodeFiles(
        root=root,
        cert=cert,
        tls_key=tls_key,
        federation_key=federation_key,
        federation_pub=federation_pub,
        client_key=client_key,
        client_pub=client_pub,
        authorized_keys=root / "authorized_keys",
        auth_meta=root / "auth_keys.meta",
        obfs_secret=obfs_secret,
        history_dir=history_dir,
        relay_receive_dir=relay_receive_dir,
        home=home,
        runtime_dir=runtime_dir,
    )


def enroll_node(
    yumed: Path,
    node: NodeFiles,
    remote_federation_pub: Path,
    remote_peer_id: str,
) -> None:
    node.authorized_keys.write_bytes(
        remote_federation_pub.read_bytes() + b"\n" + node.client_pub.read_bytes()
    )
    node.authorized_keys.chmod(0o600)
    federation_fingerprint = identity_fingerprint(yumed, remote_federation_pub)
    client_fingerprint = identity_fingerprint(yumed, node.client_pub)
    node.auth_meta.write_text(
        json.dumps(
            {
                federation_fingerprint: {
                    "alias": f"federation-{remote_peer_id}",
                    "federation_peer_id": remote_peer_id,
                },
                client_fingerprint: {"alias": f"client-{remote_peer_id}"},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    node.auth_meta.chmod(0o600)


def server_argv(
    yumed: Path,
    node: NodeFiles,
    node_id: str,
    node_name: str,
    listen_port: int,
    cover_port: int,
    peer_id: str,
    peer_port: int,
    peer_cert: Path,
    peer_carrier_secret: Path,
    pairwise_psk: Path,
) -> list[str]:
    peer = json.dumps(
        {
            "id": peer_id,
            "url": f"yume://localhost:{peer_port}",
            "psk_file": str(pairwise_psk),
            "carrier_secret_file": str(peer_carrier_secret),
        },
        separators=(",", ":"),
    )
    return [
        str(yumed),
        "--listen",
        f"127.0.0.1:{listen_port}",
        "--cert",
        str(node.cert),
        "--key",
        str(node.tls_key),
        "--auth-keys",
        str(node.authorized_keys),
        "--auth-keys-meta",
        str(node.auth_meta),
        "--obfs-secret-file",
        str(node.obfs_secret),
        "--inner-psk-file",
        str(pairwise_psk),
        "--real-backend",
        f"loopback://127.0.0.1:{cover_port}",
        "--server-id",
        node_id,
        "--server-name",
        node_name,
        "--threads",
        "2",
        "--relay-enable",
        "--directory-enable",
        "--federation-enable",
        "--federation-identity",
        str(node.federation_key),
        "--federation-operator-ca",
        str(peer_cert),
        "--peer",
        peer,
        "--boring",
    ]


def node_environment(node: NodeFiles) -> dict[str, str]:
    environment = os.environ.copy()
    environment["HOME"] = str(node.home)
    environment["XDG_RUNTIME_DIR"] = str(node.runtime_dir)
    return environment


def client_argv(
    yume: Path,
    node: NodeFiles,
    port: int,
    socks_port: int,
    instance: str,
    preferred_id: str,
    preferred_name: str,
    pairwise_psk: Path,
) -> list[str]:
    return [
        str(yume),
        "--server",
        "localhost",
        "--port",
        str(port),
        "--socks",
        str(socks_port),
        "--auth",
        str(node.client_key),
        "--tls-ca",
        str(node.cert),
        "--obfs-secret-file",
        str(node.obfs_secret),
        "--inner-psk-file",
        str(pairwise_psk),
        "--profile",
        "chrome",
        "--instance",
        instance,
        "--client-id",
        preferred_id,
        "--name",
        preferred_name,
        "--history-dir",
        str(node.history_dir),
        "--relay-receive-dir",
        str(node.relay_receive_dir),
        "--non-interactive",
        "--accept-monitoring",
        "--boring",
    ]


def runtime_socket(node: NodeFiles, instance: str) -> Path:
    return node.runtime_dir / "yume" / f"client-{instance}.sock"


def runtime_request(path: Path, operation: str, arguments: dict[str, object]) -> dict:
    request = json.dumps({"op": operation, "args": arguments}).encode() + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(str(path))
        connection.sendall(request)
        response = bytearray()
        while len(response) <= MAX_RUNTIME_RESPONSE:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            if b"\n" in chunk:
                break
    if len(response) > MAX_RUNTIME_RESPONSE or b"\n" not in response:
        raise ConnectionError("invalid local runtime response framing")
    decoded = json.loads(bytes(response).split(b"\n", 1)[0])
    if not isinstance(decoded, dict):
        raise ValueError("local runtime response is not an object")
    return decoded


def require_ok(response: dict, operation: str) -> object:
    if response.get("ok") is not True:
        raise FixtureError(f"{operation} failed: {response}")
    return response.get("result")


def dump_logs(processes: list[ManagedProcess]) -> None:
    for managed in processes:
        print(f"\n===== {managed.name}: {managed.log_path} =====", file=sys.stderr)
        print(managed.log_text(), file=sys.stderr)


def run_fixture(yume: Path, yumed: Path) -> None:
    if not yume.is_file() or not os.access(yume, os.X_OK):
        raise FixtureError(f"yume binary is not executable: {yume}")
    if not yumed.is_file() or not os.access(yumed, os.X_OK):
        raise FixtureError(f"yumed binary is not executable: {yumed}")

    processes: list[ManagedProcess] = []
    cover_servers: list[ThreadingHTTPServer] = []
    cover_threads: list[threading.Thread] = []
    temporary = tempfile.mkdtemp(prefix="yume-federation-v2-")
    try:
        # Cleanup is deliberately deferred until after failure logs are dumped
        # and every child is stopped.
        with nullcontext(temporary):
            root = Path(temporary)
            root.chmod(0o700)
            node_a = make_node(yumed, root / "node-a")
            node_b = make_node(yumed, root / "node-b")
            enroll_node(yumed, node_a, node_b.federation_pub, "node-b")
            enroll_node(yumed, node_b, node_a.federation_pub, "node-a")

            pairwise_psk = root / "pairwise-psk.hex"
            write_secret(pairwise_psk)

            for _ in range(2):
                server = ThreadingHTTPServer(("127.0.0.1", 0), CoverHandler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                cover_servers.append(server)
                cover_threads.append(thread)

            port_a = pick_port()
            port_b = pick_port()
            daemon_b = start_process(
                "node-b-yumed",
                server_argv(
                    yumed,
                    node_b,
                    "2" * 32,
                    "node-b",
                    port_b,
                    int(cover_servers[1].server_port),
                    "node-a",
                    port_a,
                    node_a.cert,
                    node_a.obfs_secret,
                    pairwise_psk,
                ),
                node_b.root,
                node_environment(node_b),
            )
            processes.append(daemon_b)
            wait_until("node-b listener", lambda: tcp_ready(port_b), processes)

            daemon_a = start_process(
                "node-a-yumed",
                server_argv(
                    yumed,
                    node_a,
                    "1" * 32,
                    "node-a",
                    port_a,
                    int(cover_servers[0].server_port),
                    "node-b",
                    port_b,
                    node_b.cert,
                    node_b.obfs_secret,
                    pairwise_psk,
                ),
                node_a.root,
                node_environment(node_a),
            )
            processes.append(daemon_a)
            wait_until("node-a listener", lambda: tcp_ready(port_a), processes)
            wait_until(
                "reciprocal federation links to reach ready",
                lambda: (
                    "federation peer ready: node-b" in daemon_a.log_text()
                    and "federation peer ready: node-a" in daemon_b.log_text()
                ),
                processes,
            )

            instance_a = "federation-v2-a"
            instance_b = "federation-v2-b"
            socks_a = pick_port()
            socks_b = pick_port()
            client_b = start_process(
                "node-b-yume",
                client_argv(
                    yume,
                    node_b,
                    port_b,
                    socks_b,
                    instance_b,
                    BOB_ID,
                    "bob",
                    pairwise_psk,
                ),
                node_b.root,
                node_environment(node_b),
            )
            processes.append(client_b)
            client_a = start_process(
                "node-a-yume",
                client_argv(
                    yume,
                    node_a,
                    port_a,
                    socks_a,
                    instance_a,
                    ALICE_ID,
                    "alice",
                    pairwise_psk,
                ),
                node_a.root,
                node_environment(node_a),
            )
            processes.append(client_a)

            socket_a = runtime_socket(node_a, instance_a)
            socket_b = runtime_socket(node_b, instance_b)
            wait_until(
                "both client runtime sockets",
                lambda: socket_a.exists() and socket_b.exists(),
                processes,
            )

            remote_b = f"node-b:{BOB_ID}"
            remote_a = f"node-a:{ALICE_ID}"

            def reciprocal_directory_visible() -> bool:
                directory_a = require_ok(
                    runtime_request(socket_a, "directory.list", {}),
                    "node-a directory.list",
                )
                directory_b = require_ok(
                    runtime_request(socket_b, "directory.list", {}),
                    "node-b directory.list",
                )
                ids_a = {entry.get("endpoint_id") for entry in directory_a}
                ids_b = {entry.get("endpoint_id") for entry in directory_b}
                return remote_b in ids_a and remote_a in ids_b

            wait_until(
                "federation.directory to exchange both endpoints",
                reciprocal_directory_visible,
                processes,
                poll_interval=0.5,
            )

            payload = root / "federation-roundtrip.bin"
            payload_bytes = (
                b"YUME federation AUTH v2 DATA/CLOSE integration\x00"
                + secrets.token_bytes(4096)
            )
            payload.write_bytes(payload_bytes)
            relay_password = "federation-v2-integration-password"
            require_ok(
                runtime_request(
                    socket_a,
                    "bytes.send",
                    {
                        "peer": remote_b,
                        "path": str(payload),
                        "password": relay_password,
                    },
                ),
                "bytes.send",
            )

            invite: dict[str, object] = {}

            def invite_arrived() -> bool:
                nonlocal invite
                result = require_ok(
                    runtime_request(socket_b, "invite.list", {}),
                    "invite.list",
                )
                matching = [
                    item
                    for item in result
                    if item.get("channel_kind") == "bytes"
                ]
                if not matching:
                    return False
                invite = matching[0]
                return True

            wait_until("federated bytes invite", invite_arrived, processes)
            invite_id = invite.get("invite_id")
            if not isinstance(invite_id, str) or not invite_id:
                raise FixtureError(f"invalid invite id: {invite}")
            require_ok(
                runtime_request(
                    socket_b,
                    "invite.accept",
                    {"invite_id": invite_id, "password": relay_password},
                ),
                "invite.accept",
            )

            received = node_b.relay_receive_dir / payload.name
            wait_until(
                "federated DATA payload",
                lambda: received.is_file() and received.read_bytes() == payload_bytes,
                processes,
            )
            wait_until(
                "federated channel CLOSE",
                lambda: (
                    "channel with alice closed: transfer complete"
                    in client_b.log_text()
                    and require_ok(
                        runtime_request(socket_b, "runtime.status", {}),
                        "node-b runtime.status",
                    ).get("active_channels")
                    == 0
                ),
                processes,
            )

            print(
                "PASS: reciprocal AUTH v2 federation ready; directory exchanged; "
                "one federated channel delivered DATA and CLOSE"
            )
    except Exception:
        dump_logs(processes)
        raise
    finally:
        for managed in reversed(processes):
            managed.stop()
        for server in cover_servers:
            server.shutdown()
            server.server_close()
        for thread in cover_threads:
            thread.join(timeout=2)
        shutil.rmtree(temporary, ignore_errors=True)


def main() -> int:
    args = parse_args()
    try:
        run_fixture(args.yume.resolve(), args.yumed.resolve())
    except (FixtureError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
