#!/usr/bin/env python3
"""Shared harness for federation integration tests.

Launches real `yumed` and `yume` processes on loopback. Two tests build on it:
a two-node AUTH v2 acceptance run, and a three-node cluster run that pins the
single-hop directory boundary. Keeping one harness means a change to how a node
is enrolled or started cannot make the two disagree about what a cluster is.
"""

from __future__ import annotations

import json
import os
import re
import secrets
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
from typing import BinaryIO, Callable, Iterable, Sequence

TIMEOUT_SECONDS = 30.0
MAX_RUNTIME_RESPONSE = 1024 * 1024


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
    peer_ca_bundle: Path
    obfs_secret: Path
    inner_psk: Path
    history_dir: Path
    relay_receive_dir: Path
    home: Path
    runtime_dir: Path


@dataclass(frozen=True)
class PeerLink:
    """One node's view of a federation peer it dials."""

    peer_id: str
    node: NodeFiles
    port: int
    pairwise_psk: Path


class CoverServers:
    """Loopback HTTP origins standing in for each node's real backend."""

    def __init__(self) -> None:
        self._servers: list[ThreadingHTTPServer] = []
        self._threads: list[threading.Thread] = []

    def start(self) -> int:
        server = ThreadingHTTPServer(("127.0.0.1", 0), CoverHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._servers.append(server)
        self._threads.append(thread)
        return int(server.server_port)

    def stop(self) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=2)


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
    inner_psk = root / "inner-psk.hex"
    write_secret(inner_psk)
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
        peer_ca_bundle=root / "peer-ca-bundle.pem",
        obfs_secret=obfs_secret,
        inner_psk=inner_psk,
        history_dir=history_dir,
        relay_receive_dir=relay_receive_dir,
        home=home,
        runtime_dir=runtime_dir,
    )


def enroll_node(
    yumed: Path,
    node: NodeFiles,
    peers: Sequence[PeerLink],
) -> None:
    """Authorizes every peer that dials this node, plus its own client.

    An accepting node needs no federation-specific inbound code: a peer link
    presents as an ordinary AUTH v2 client and is distinguished only by the
    `federation_peer_id` and identity-bound `federation_psk_file` metadata on
    its enrolled composite key. Enrolling several peers is therefore several
    independently authorized keys, not a reason to share the ordinary client
    inner PSK.
    """
    authorized = b"".join(
        peer.node.federation_pub.read_bytes() + b"\n" for peer in peers
    )
    node.authorized_keys.write_bytes(authorized + node.client_pub.read_bytes())
    node.authorized_keys.chmod(0o600)

    meta: dict[str, dict[str, str]] = {
        identity_fingerprint(yumed, node.client_pub): {
            "alias": f"client-{node.root.name}"
        }
    }
    for peer in peers:
        meta[identity_fingerprint(yumed, peer.node.federation_pub)] = {
            "alias": f"federation-{peer.peer_id}",
            "federation_peer_id": peer.peer_id,
            "federation_psk_file": str(peer.pairwise_psk),
        }
    node.auth_meta.write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n"
    )
    node.auth_meta.chmod(0o600)

    # One CA file verifies every peer this node dials. load_verify_file maps to
    # SSL_CTX_load_verify_locations, which reads a concatenated PEM bundle, so a
    # node with several peers does not need a shared certificate authority.
    node.peer_ca_bundle.write_bytes(
        b"".join(peer.node.cert.read_bytes() for peer in peers)
    )


def server_argv(
    yumed: Path,
    node: NodeFiles,
    node_id: str,
    node_name: str,
    listen_port: int,
    cover_port: int,
    peers: Sequence[PeerLink],
    *,
    cluster_bootstrap: bool = False,
) -> list[str]:
    argv = [
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
        str(node.inner_psk),
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
        str(node.peer_ca_bundle),
        "--boring",
    ]
    for peer in peers:
        argv += [
            "--peer",
            json.dumps(
                {
                    "id": peer.peer_id,
                    "url": f"yume://localhost:{peer.port}",
                    "psk_file": str(peer.pairwise_psk),
                    "carrier_secret_file": str(peer.node.obfs_secret),
                },
                separators=(",", ":"),
            ),
        ]
    if cluster_bootstrap:
        argv.append("--cluster-bootstrap")
    return argv


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
        str(node.inner_psk),
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


def server_runtime_socket(node: NodeFiles) -> Path:
    """The single yumed admin socket under this node's private runtime dir."""
    directory = node.runtime_dir / "yume"
    candidates = sorted(directory.glob("server-*.sock"))
    if len(candidates) != 1:
        raise FixtureError(
            f"expected exactly one server socket in {directory}, got {candidates}"
        )
    return candidates[0]


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


def dump_logs(processes: Iterable[ManagedProcess]) -> None:
    for managed in processes:
        print(f"\n===== {managed.name}: {managed.log_path} =====", file=sys.stderr)
        print(managed.log_text(), file=sys.stderr)


def make_temporary_root(prefix: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix=prefix))
    root.chmod(0o700)
    return root
