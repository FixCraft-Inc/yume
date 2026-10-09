#!/usr/bin/env python3
"""Run yumed and yume as processes and move bytes through SOCKS5."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))

import yume_native_session as session  # noqa: E402

PAYLOAD_BYTES = 1024 * 1024


def validate(program: Path, config: Path, environment: dict[str, str], *flags: str) -> None:
    result = subprocess.run([str(program), "--config", str(config), "--validate", *flags],
                            env=environment, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise session.SessionFailure(f"{program.name} --validate failed: {result.stderr.strip()}")


def check_payload(socks_port: int, host: str, target_port: int) -> None:
    code, connection = session.socks_connect(socks_port, host, target_port)
    with connection:
        if code != session.REPLY_SUCCEEDED:
            raise session.SessionFailure(f"permitted destination returned SOCKS reply {code}")
        connection.sendall(b"GET /payload HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
        length, digest = session.read_http_body(connection)
    if length != PAYLOAD_BYTES or digest != session.payload_digest(PAYLOAD_BYTES):
        raise session.SessionFailure("destination payload differs")


def check_first_payload(socks_port: int, target_port: int) -> None:
    """A new client's first request, retried until its session is up.

    The SOCKS5 port opens before the session authenticates, and a request
    without a session is refused rather than queued.
    """
    length, digest, _ = session.get_through_socks(socks_port, "127.0.0.1", target_port,
                                                  time.monotonic() + 30)
    if length != PAYLOAD_BYTES or digest != session.payload_digest(PAYLOAD_BYTES):
        raise session.SessionFailure(f"tunnelled payload differs: {length} of {PAYLOAD_BYTES} bytes")


def check_dns_destinations(socks_port: int, target_port: int) -> None:
    # A successful named route proves that resolution and configured policy are
    # composed. Each mixed set must fail even when its first answer is allowed.
    check_payload(socks_port, "allowed.yume.test", target_port)
    for host in ("denied.yume.test", "allowed-first.yume.test", "denied-first.yume.test"):
        code, connection = session.socks_connect(socks_port, host, target_port)
        with connection:
            if code != session.REPLY_NOT_ALLOWED:
                raise session.SessionFailure(f"{host} returned SOCKS reply {code}")
    # Refusing one OPEN must leave the authenticated session usable.
    check_payload(socks_port, "allowed.yume.test", target_port)


def receive_until_eof(listener: socket.socket, expected: bytes) -> None:
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(10)
        received = bytearray()
        while block := connection.recv(4096):
            received.extend(block)
            if len(received) > len(expected):
                raise session.SessionFailure("optimistic data was duplicated")
        if received != expected:
            raise session.SessionFailure("optimistic data was lost or reordered")
        # Reply only after EOF: closing the client's write side must still let
        # the established RouteBridge carry the response back.
        connection.sendall(received)


def connect_request(address: bytes, port: int) -> bytes:
    return b"\x05\x01\x00" + address + port.to_bytes(2, "big")


def require_reply(connection: socket.socket, code: int) -> None:
    reply = session.recv_exact(connection, 10)
    if reply != bytes((5, code, 0, 1, 0, 0, 0, 0, 0, 0)):
        raise session.SessionFailure(f"expected SOCKS reply {code}, got {reply.hex()}")


def check_optimistic_data(socks_port: int) -> None:
    # Larger than either handshake bound, with NUL and high bytes. A success
    # reply alone would miss payload loss, duplication, or premature EOF.
    payload = bytes(range(256)) * 256
    addresses = (b"\x01\x7f\x00\x00\x01", b"\x03\x09127.0.0.1")
    with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as worker:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)
        for address in addresses:
            request = connect_request(address, listener.getsockname()[1])
            for mode in ("connect-and-data", "greeting-connect-and-data", "split-request"):
                with socket.create_connection(("127.0.0.1", socks_port), timeout=10) as connection:
                    if mode == "greeting-connect-and-data":
                        connection.sendall(b"\x05\x01\x00" + request + payload)
                    else:
                        connection.sendall(b"\x05\x01\x00")
                    if session.recv_exact(connection, 2) != b"\x05\x00":
                        raise session.SessionFailure(f"{mode}: method selection failed")
                    if mode == "connect-and-data":
                        connection.sendall(request + payload)
                    elif mode == "split-request":
                        for byte in request[:-1]:
                            connection.sendall(bytes((byte,)))
                        connection.sendall(request[-1:] + payload)
                    connection.shutdown(socket.SHUT_WR)
                    require_reply(connection, session.REPLY_SUCCEEDED)
                    response = worker.submit(receive_until_eof, listener, payload)
                    if session.recv_exact(connection, len(payload)) != payload or connection.recv(1):
                        raise session.SessionFailure(f"{mode}: response differs or lacks EOF")
                    response.result(timeout=15)


def check_optimistic_refusal(socks_port: int) -> None:
    # Keep a target listening on the denied address so a policy bypass cannot
    # pass this check merely because the kernel refused the connection.
    with socket.socket() as listener:
        listener.bind(("127.0.0.2", 0))
        listener.listen(1)
        addresses = (b"\x01\x7f\x00\x00\x02", b"\x03\x09127.0.0.2")
        for address in addresses:
            with socket.create_connection(("127.0.0.1", socks_port), timeout=10) as connection:
                request = connect_request(address, listener.getsockname()[1])
                connection.sendall(b"\x05\x01\x00" + request + b"must not reach the target")
                if session.recv_exact(connection, 2) != b"\x05\x00":
                    raise session.SessionFailure("refused request: method selection failed")
                require_reply(connection, session.REPLY_NOT_ALLOWED)
        listener.setblocking(False)
        try:
            unexpected, _ = listener.accept()
        except BlockingIOError:
            return
        unexpected.close()
        raise session.SessionFailure("optimistic data bypassed destination policy")


def udp_request(host: str, port: int, payload: bytes) -> bytes:
    """A SOCKS5 UDP datagram for an IPv4 destination."""
    return b"\x00\x00\x00\x01" + socket.inet_aton(host) + port.to_bytes(2, "big") + payload


def udp_associate(socks_port: int) -> tuple[socket.socket, tuple[str, int]]:
    """Returns the control connection and the relay address the reply names."""
    control = socket.create_connection(("127.0.0.1", socks_port), timeout=10)
    try:
        control.sendall(b"\x05\x01\x00")
        if session.recv_exact(control, 2) != b"\x05\x00":
            raise session.SessionFailure("UDP ASSOCIATE: method selection failed")
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = session.recv_exact(control, 10)
        if reply[:4] != b"\x05\x00\x00\x01" or reply[4:8] != socket.inet_aton("127.0.0.1"):
            raise session.SessionFailure(f"UDP ASSOCIATE reply {reply.hex()}")
        return control, ("127.0.0.1", int.from_bytes(reply[8:10], "big"))
    except BaseException:
        control.close()
        raise


def expect_silence(receiver: socket.socket, what: str) -> None:
    receiver.settimeout(0.5)
    try:
        receiver.recvfrom(65536)
    except socket.timeout:
        return
    finally:
        receiver.settimeout(10)
    raise session.SessionFailure(what)


def check_udp_associate(socks_port: int) -> None:
    # An echo target inside 127.0.0.1/32 and a live listener outside it, so a
    # policy bypass would be seen rather than refused by the kernel.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as outside, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as app, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        target.bind(("127.0.0.1", 0))
        outside.bind(("127.0.0.2", 0))
        app.bind(("127.0.0.1", 0))
        for sock in (target, outside, app):
            sock.settimeout(10)
        target_port = target.getsockname()[1]
        control, relay = udp_associate(socks_port)
        with control:
            payload = bytes(range(256)) * 16
            app.sendto(udp_request("127.0.0.1", target_port, payload), relay)
            data, exit_address = target.recvfrom(65536)
            if data != payload:
                raise session.SessionFailure("UDP payload changed on its way out")
            # UDP allows an empty datagram. YTP cannot carry it, and it must
            # not end the flow that the next reply uses.
            target.sendto(b"", exit_address)
            target.sendto(payload[::-1], exit_address)
            reply, source = app.recvfrom(65536)
            if source != relay or reply != udp_request("127.0.0.1", target_port, payload[::-1]):
                raise session.SessionFailure("UDP reply differs or came from elsewhere")

            outside_port = outside.getsockname()[1]
            app.sendto(udp_request("127.0.0.2", outside_port, b"must not arrive"), relay)
            app.sendto(udp_request("127.0.0.1", target_port, b"after refusal"), relay)
            data, _ = target.recvfrom(65536)
            if data != b"after refusal":
                raise session.SessionFailure("UDP traffic stopped after a refused destination")
            expect_silence(outside, "UDP ASSOCIATE bypassed configured destinations")
            probe.connect(relay)

        # The relay closes with its TCP connection. A connected probe then
        # sees the closed port as a refused connection.
        deadline = time.monotonic() + 10
        probe.settimeout(0.05)
        while True:
            if time.monotonic() > deadline:
                raise session.SessionFailure("UDP relay stayed open after its TCP connection closed")
            try:
                probe.send(b"x")
                probe.recv(1)
            except ConnectionRefusedError:
                break
            except socket.timeout:
                continue
    print("UDP ASSOCIATE verified: datagrams both ways, destination refusal, relay closed with its TCP connection")


def add_module(kit: Path, program: Path) -> tuple[Path, str]:
    """Serves stream service "echo" with the module and forwards to it.

    Returns the client's forward socket and the identity the module should see.
    """
    service = {"name": "echo", "kind": "stream", "max_concurrent_streams": 8}
    server_path = kit / "server/yumed.json"
    server = json.loads(server_path.read_text(encoding="utf-8"))
    server["services"].append(service)
    server["adapters"].append({"kind": "module", "service": "echo", "program": str(program)})
    server_path.write_text(json.dumps(server, indent=2), encoding="utf-8")

    forward = kit / "client/echo.sock"
    client_path = kit / "client/yume.json"
    client = json.loads(client_path.read_text(encoding="utf-8"))
    client["services"].append(service)
    client["adapters"].append({"kind": "forward", "service": "echo", "listen_path": str(forward)})
    client_path.write_text(json.dumps(client, indent=2), encoding="utf-8")

    keys_path = kit / "server/credentials/authorized-keys.json"
    keys = json.loads(keys_path.read_text(encoding="utf-8"))
    if len(keys["keys"]) != 1:
        raise session.SessionFailure("the kit must authorize exactly one client")
    keys["keys"][0]["capabilities"].append({"service": "echo", "kind": "stream"})
    keys_path.write_text(json.dumps(keys, indent=2), encoding="utf-8")
    return forward, keys["keys"][0]["identity"]["sha256"]


def add_egress_lists(kit: Path) -> None:
    """Moves part of the direct adapters' policy into egress lists.

    The adapters permit 127.0.0.0/16, a deny list takes that range back and an
    allow list exempts 127.0.0.1. The adapter alone would permit 127.0.0.2, so
    a refusal there shows that the list decided.
    """
    lists = kit / "server/lists"
    lists.mkdir()
    (lists / "deny.json").write_text(json.dumps({"ips": ["127.0.0.0/16"]}), encoding="utf-8")
    (lists / "allow.json").write_text(json.dumps({"ips": ["127.0.0.1"]}), encoding="utf-8")
    server_path = kit / "server/yumed.json"
    server = json.loads(server_path.read_text(encoding="utf-8"))
    for adapter in server["adapters"]:
        if adapter["kind"] in {"direct_tcp", "direct_udp"}:
            adapter["destinations"] = {
                "public": False,
                "networks": ["127.0.0.0/16"],
                "lists": [
                    {"action": "deny", "format": "json", "file": "lists/deny.json"},
                    {"action": "allow", "format": "json", "file": "lists/allow.json"},
                ],
            }
    server_path.write_text(json.dumps(server, indent=2), encoding="utf-8")


def check_egress_list_validation(yumed: Path, kit: Path, environment: dict[str, str]) -> None:
    # --validate reads the lists and names the entry whose file it cannot read.
    config = json.loads((kit / "server/yumed.json").read_text(encoding="utf-8"))
    config["adapters"][0]["destinations"]["lists"][1]["file"] = "lists/missing.json"
    variant = kit / "server/missing-list.json"
    variant.write_text(json.dumps(config), encoding="utf-8")
    result = subprocess.run([str(yumed), "--config", str(variant), "--validate"],
                            env=environment, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 2 or \
            "destinations are invalid: /adapters/0/destinations/lists/1:" not in result.stderr:
        raise session.SessionFailure(
            f"--validate accepted a missing egress list: {result.returncode} {result.stderr.strip()}")


PROXY_USERNAME = b"proxy-user"
PROXY_PASSWORD = b"proxy-secret-password"


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise ConnectionError("SOCKS5 peer closed early")
        data += chunk
    return data


class Socks5Relay:
    """A SOCKS5 proxy that requires a username and password and relays CONNECT."""

    def __init__(self) -> None:
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.requests: list[tuple[int, str, int]] = []
        self.authenticated: list[bool] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self.listener.close()

    def _serve(self) -> None:
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _handle(self, connection: socket.socket) -> None:
        with connection:
            try:
                connection.settimeout(10)
                count = _recv_exact(connection, 2)[1]
                if 2 not in _recv_exact(connection, count):
                    connection.sendall(b"\x05\xff")
                    return
                connection.sendall(b"\x05\x02")
                username = _recv_exact(connection, _recv_exact(connection, 2)[1])
                password = _recv_exact(connection, _recv_exact(connection, 1)[0])
                accepted = username == PROXY_USERNAME and password == PROXY_PASSWORD
                self.authenticated.append(accepted)
                connection.sendall(b"\x01\x00" if accepted else b"\x01\x01")
                if not accepted:
                    return
                kind = _recv_exact(connection, 4)[3]
                if kind == 1:
                    host = socket.inet_ntop(socket.AF_INET, _recv_exact(connection, 4))
                elif kind == 4:
                    host = socket.inet_ntop(socket.AF_INET6, _recv_exact(connection, 16))
                else:
                    host = _recv_exact(connection, _recv_exact(connection, 1)[0]).decode("ascii")
                port = int.from_bytes(_recv_exact(connection, 2), "big")
                self.requests.append((kind, host, port))
                upstream = socket.create_connection((host, port), timeout=10)
            except (OSError, ConnectionError):
                return
            with upstream:
                connection.sendall(b"\x05\x00\x00\x01" + bytes(6))
                connection.settimeout(None)
                upstream.settimeout(None)
                pump = threading.Thread(target=_copy, args=(upstream, connection), daemon=True)
                pump.start()
                _copy(connection, upstream)
                pump.join(timeout=10)


def _copy(source: socket.socket, target: socket.socket) -> None:
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            target.sendall(data)
        target.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def check_socks5_upstream(yume: Path, kit: Path, environment: dict[str, str], root: Path,
                          server_port: int, target_port: int) -> None:
    # A second client reaches the same server through an authenticating
    # SOCKS5 proxy. connect_address makes the proxy connect to that address.
    # The file names an unused address and the kit's SOCKS5 port, and the run
    # settings replace both, so the proxy's request shows --connect took effect.
    relay = Socks5Relay()
    try:
        credentials = kit / "client/socks5-proxy"
        credentials.write_bytes(PROXY_USERNAME + b"\n" + PROXY_PASSWORD + b"\n")
        credentials.chmod(0o600)
        config = json.loads((kit / "client/yume.json").read_text(encoding="utf-8"))
        config["endpoint"]["socks5_proxy"] = {
            "address": "127.0.0.1", "port": relay.port, "credentials": {"file": "socks5-proxy"}}
        config["endpoint"]["connect_address"] = "192.0.2.1"
        socks_port = session.free_port()
        run_settings = ["--connect", "127.0.0.1", "--socks-port", str(socks_port)]
        variant = kit / "client/through-proxy.json"
        variant.write_text(json.dumps(config), encoding="utf-8")
        validate(yume, variant, environment, *run_settings)
        log_path = root / "yume-proxy.log"
        with log_path.open("wb") as log:
            client = subprocess.Popen([str(yume), "--config", str(variant), *run_settings],
                                      env=environment,
                                      stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                session.wait_for_port("127.0.0.1", socks_port, client, deadline)
                length, digest, _ = session.get_through_socks(socks_port, "127.0.0.1", target_port,
                                                              time.monotonic() + 30)
                if length != PAYLOAD_BYTES or digest != session.payload_digest(PAYLOAD_BYTES):
                    raise session.SessionFailure("payload through the SOCKS5 proxy differs")
                session.stop_process(client, "yume")
            finally:
                if client.poll() is None:
                    client.kill()
                    client.wait(timeout=5)
        text = log_path.read_text(encoding="utf-8", errors="replace")
        session.reject_secret_output("yume", text)
        if PROXY_PASSWORD.decode() in text:
            raise session.SessionFailure("the client logged its SOCKS5 proxy password")
        if relay.authenticated != [True] or relay.requests != [(1, "127.0.0.1", server_port)]:
            raise session.SessionFailure(
                f"SOCKS5 proxy saw {relay.authenticated} and {relay.requests}")
    finally:
        relay.close()
    print("SOCKS5 upstream verified: the client reached yumed through an authenticating proxy")


def check_module_validation(yumed: Path, kit: Path, program: Path,
                            environment: dict[str, str], root: Path) -> None:
    # --validate refuses a program that the daemon would refuse at start.
    unsafe = root / "unsafe-module"
    shutil.copyfile(program, unsafe)
    unsafe.chmod(0o775)
    config = json.loads((kit / "server/yumed.json").read_text(encoding="utf-8"))
    for adapter in config["adapters"]:
        if adapter["kind"] == "module":
            adapter["program"] = str(unsafe)
    variant = kit / "server/unsafe-module.json"
    variant.write_text(json.dumps(config), encoding="utf-8")
    result = subprocess.run([str(yumed), "--config", str(variant), "--validate"],
                            env=environment, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 2 or \
            "module 'echo' is invalid: module program must be owned" not in result.stderr:
        raise session.SessionFailure(
            f"--validate accepted an unsafe module program: {result.returncode} {result.stderr.strip()}")


def check_module(forward: Path, identity: str) -> None:
    # The echo module greets with the identity from its header line, so the
    # greeting proves that yumed ran it and passed the authenticated client.
    greeting = f"hello {identity}\n".encode()
    payload = bytes(range(256)) * 64
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(str(forward))
        if session.recv_exact(connection, len(greeting)) != greeting:
            raise session.SessionFailure("the module greeting differs")
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        received = bytearray()
        while block := connection.recv(65536):
            received.extend(block)
            if len(received) > len(payload):
                raise session.SessionFailure("the module echoed extra bytes")
        if received != payload:
            raise session.SessionFailure("the module echo differs")


def check_outer_carrier_evidence(yume: Path, kit: Path, environment: dict[str, str],
                                 root: Path, socks_port: int, target_port: int) -> None:
    """A SIGTERM closes the carrier like the captured browser and yume reports it."""
    evidence_dir = root / "evidence"
    evidence_dir.mkdir(mode=0o700)
    report_path = evidence_dir / "behavior.json"
    with (root / "yume-evidence.log").open("wb") as log:
        client = subprocess.Popen(
            [str(yume), "--config", str(kit / "client/yume.json"),
             "--outer-carrier-evidence", str(report_path)],
            env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            session.wait_for_port("127.0.0.1", socks_port, client, time.monotonic() + 30)
            if report_path.stat().st_mode & 0o777 != 0o600:
                raise session.SessionFailure("the evidence file is not reserved with mode 0600")
            check_first_payload(socks_port, target_port)
            # Exit status 0 requires a complete report, so the WebSocket CLOSE
            # was echoed and the connection ended.
            session.stop_process(client, "yume with outer-carrier evidence")
            client = None
        finally:
            if client is not None and client.poll() is None:
                client.kill()
                client.wait(timeout=5)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    close = report["websocket_fixture"]["close"]
    if (report["capture_status"] != "complete" or close["payload_bytes"] != 18 or
            close["client_masked"] is not True or close["server_masked"] is not False or
            report["idle_and_close"]["graceful_websocket_close_observed"] is not True):
        raise session.SessionFailure("the evidence does not show the captured close")
    events = report["observations"]["outer_events"]
    if any(event["kind"] == "h2-frame" and event["h2_type"] == 7 for event in events):
        raise session.SessionFailure("the client sent GOAWAY")
    text = json.dumps(report)
    for secret in ("PRIVATE KEY", str(kit)):
        if secret in text:
            raise session.SessionFailure("the evidence names local secret material or paths")
    print(f"outer-carrier evidence verified: {len(events)} events, graceful close echoed")


def control_request(path: Path, request: dict[str, object]) -> dict[str, object]:
    """One control protocol 1 exchange: a request line, then one reply line."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(str(path))
        connection.sendall(json.dumps(request).encode() + b"\n")
        reply = b""
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            reply += chunk
    if not reply.endswith(b"\n") or reply.count(b"\n") != 1:
        raise session.SessionFailure(f"the control reply is not one line: {reply!r}")
    value = json.loads(reply)
    if not isinstance(value, dict) or value.get("control") != 1:
        raise session.SessionFailure(f"the control reply is not protocol 1: {value!r}")
    return value


def check_control_status(yume: Path, kit: Path, environment: dict[str, str],
                         root: Path, socks_port: int, target_port: int) -> None:
    """The running client's owner-only control socket, at the path
    --control-socket names: yume --status, the posture, the printed lines and
    a stop request that ends the client as SIGTERM does."""
    control_dir = root / "control"
    control_dir.mkdir(mode=0o700)
    socket_path = control_dir / "control.sock"
    config = kit / "client/yume.json"
    if "control" in json.loads(config.read_text(encoding="utf-8")):
        raise session.SessionFailure("the setup kit already names a control socket")
    flags = ["--config", str(config), "--control-socket", str(socket_path)]

    def status() -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(yume), *flags, "--status"], env=environment,
                              capture_output=True, text=True, timeout=10, check=False)

    with (root / "yume-control.log").open("wb") as log:
        client = subprocess.Popen([str(yume), *flags], env=environment,
                                  stdout=log, stderr=subprocess.STDOUT)
        try:
            session.wait_for_port("127.0.0.1", socks_port, client, time.monotonic() + 30)
            check_first_payload(socks_port, target_port)
            if socket_path.stat().st_mode & 0o777 != 0o600:
                raise session.SessionFailure("the control socket is not mode 0600")
            result = status()
            lines = result.stdout.splitlines()
            if (result.returncode != 0 or result.stderr or len(lines) < 4 or
                    not lines[1].startswith("state: connected for ") or
                    "sessions: 1, failed attempts since the last: 0" not in lines or
                    f"SOCKS5: 127.0.0.1:{socks_port}" not in lines or
                    "sent: 0 bytes of payload" in result.stdout):
                raise session.SessionFailure(f"yume --status reported {result!r}")
            reply = control_request(socket_path, {"control": 1, "request": "status"})
            posture = reply.get("posture", {})
            if (reply.get("requests") != ["status", "messages", "stop"] or
                    posture.get("transport") != "YTP/1" or
                    posture.get("limits", {}).get("max_epoch_bytes") != 1048576 or
                    posture.get("epoch_bytes") != 1048576):
                raise session.SessionFailure(f"the status reply is wrong: {reply!r}")
            reply = control_request(socket_path,
                                    {"control": 1, "request": "messages", "after": 0})
            texts = [message["text"] for message in reply["messages"]]
            if ("session authenticated" not in texts or
                    f"SOCKS5 on 127.0.0.1 port {socks_port}" not in texts or
                    reply["missed"] != 0 or reply["more"] is not False or
                    [message["seq"] for message in reply["messages"]] !=
                    list(range(1, len(texts) + 1))):
                raise session.SessionFailure(f"the messages reply is wrong: {reply!r}")
            later = control_request(socket_path, {"control": 1, "request": "messages",
                                                  "after": len(texts)})
            if later["messages"] or later["instance"] != reply["instance"]:
                raise session.SessionFailure(f"messages after the last were {later!r}")
            reply = control_request(socket_path, {"control": 1, "request": "stop"})
            if reply != {"control": 1, "stopping": True}:
                raise session.SessionFailure(f"the stop reply is wrong: {reply!r}")
            code = client.wait(timeout=15)
            client = None
            if code != 0:
                raise session.SessionFailure(f"yume exited with {code} after a stop request")
        finally:
            if client is not None and client.poll() is None:
                client.kill()
                client.wait(timeout=5)
    if socket_path.exists():
        raise session.SessionFailure("yume left its control socket behind")
    log_text = (root / "yume-control.log").read_text(encoding="utf-8", errors="replace")
    if "yume: stopping on a control request" not in log_text:
        raise session.SessionFailure("yume did not report the stop request")
    result = status()
    if result.returncode != 1 or "no yume is running on the control socket" not in result.stderr:
        raise session.SessionFailure(f"--status without a client reported {result!r}")
    print("control socket verified: status, posture, messages and a stop request")


def check_client_reconnects(yumed: Path, yume: Path, kit: Path, environment: dict[str, str],
                            root: Path, server_port: int, socks_port: int,
                            target_port: int) -> None:
    """A restarted daemon ends one session, and the client reconnects with backoff."""
    # The main flow's payload server may still hold its port.
    target_port = session.free_port()
    target = session.serve_payload("127.0.0.1", target_port, PAYLOAD_BYTES)
    server_log = (root / "yumed-restart.log").open("wb")
    client_log_path = root / "yume-restart.log"
    client_log = client_log_path.open("wb")
    command = [str(yumed), "--config", str(kit / "server/yumed.json")]
    server = subprocess.Popen(command, env=environment, stdout=server_log, stderr=subprocess.STDOUT)
    client = None
    try:
        session.wait_for_port("127.0.0.1", server_port, server, time.monotonic() + 30)
        client = subprocess.Popen([str(yume), "--config", str(kit / "client/yume.json")],
                                  env=environment, stdout=client_log, stderr=subprocess.STDOUT)
        session.wait_for_port("127.0.0.1", socks_port, client, time.monotonic() + 30)
        check_first_payload(socks_port, target_port)
        session.stop_process(server, "yumed before its restart")
        server = subprocess.Popen(command, env=environment, stdout=server_log,
                                  stderr=subprocess.STDOUT)
        session.wait_for_port("127.0.0.1", server_port, server, time.monotonic() + 30)
        check_first_payload(socks_port, target_port)
        session.stop_process(client, "yume after the restart")
        client = None
        session.stop_process(server, "yumed after the restart")
        server = None
    finally:
        for process in (client, server):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        target.shutdown()
        server_log.close()
        client_log.close()
        for name in ("yumed-restart", "yume-restart"):
            logged = (root / f"{name}.log").read_text(encoding="utf-8", errors="replace")
            session.reject_secret_output(name, logged)
            sys.stdout.write(f"--- {name} log\n{logged}")
    text = client_log_path.read_text(encoding="utf-8")
    if text.count("yume: session authenticated\n") != 2 or \
            text.count("yume: session ended, reconnecting\n") != 1:
        raise session.SessionFailure(f"the client did not reconnect once: {text!r}")
    print("reconnect verified: the client carried traffic again after yumed restarted")


def process_gone(pid: int) -> bool:
    # A dead child of init can stay a zombie briefly until it is reaped. A
    # process that exits between opening and reading its stat file makes the
    # read fail with ESRCH, which also means it is gone.
    try:
        state = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return True
    return state == "Z"


def check_module_dies_with_daemon(yumed: Path, config: Path, environment: dict[str, str],
                                  log_path: Path) -> None:
    # SIGKILL gives yumed no chance to stop its module. The module must end anyway.
    with log_path.open("wb") as log:
        server = subprocess.Popen([str(yumed), "--config", str(config)], env=environment,
                                  stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 30
        while not (started := re.search(r"module echo: started as process (\d+)\n",
                                        log_path.read_text(encoding="utf-8"))):
            if server.poll() is not None or time.monotonic() > deadline:
                raise session.SessionFailure("the restarted yumed did not start its module")
            time.sleep(0.05)
        module = int(started.group(1))
        server.kill()
        server.wait(timeout=5)
        deadline = time.monotonic() + 10
        while not process_gone(module):
            if time.monotonic() > deadline:
                try:
                    os.kill(module, 9)
                except ProcessLookupError:
                    pass
                raise session.SessionFailure("the module outlived a killed yumed")
            time.sleep(0.05)
    finally:
        if server.poll() is None:
            server.kill()
            server.wait(timeout=5)
    session.reject_secret_output("yumed", log_path.read_text(encoding="utf-8", errors="replace"))


def run(yumed: Path, yume: Path, openssl: Path, *, dns_fixture: bool = False,
        module: Path | None = None) -> None:
    environment = session.openssl_environment(openssl)
    with tempfile.TemporaryDirectory(prefix="yume-native-runtime-") as temporary:
        root = Path(temporary)
        kit = root / "kit"
        server_port, socks_port, target_port, closed_port = (session.free_port() for _ in range(4))
        session.provision_kit(kit, "localhost", server_port, environment,
                              session.setup_program(yume))
        session.configure_kit(kit, listen_address="127.0.0.1", networks=["127.0.0.1/32"],
                              connect_address="127.0.0.1", socks_port=socks_port)
        add_egress_lists(kit)
        if module is not None:
            forward, identity = add_module(kit, module.resolve(strict=True))
            # Module sockets live in a private directory below TMPDIR. A
            # directory of the test's own shows that yumed removes it.
            module_root = root / "module-tmp"
            module_root.mkdir(mode=0o700)
            environment = dict(environment, TMPDIR=str(module_root))
        validate(yumed, kit / "server/yumed.json", environment)
        validate(yume, kit / "client/yume.json", environment)
        check_egress_list_validation(yumed, kit, environment)
        if module is not None:
            check_module_validation(yumed, kit, module.resolve(strict=True), environment, root)

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

            # Inside the adapter's 127.0.0.0/16, but the deny list refuses it.
            # Without the list the route would fail as unreachable instead.
            code, connection = session.socks_connect(socks_port, "127.0.0.2", target_port)
            connection.close()
            if code != session.REPLY_NOT_ALLOWED:
                raise session.SessionFailure(f"listed destination returned SOCKS reply {code}")
            # Outside the adapter's networks: its destinations refuse it.
            code, connection = session.socks_connect(socks_port, "127.1.0.1", target_port)
            connection.close()
            if code != session.REPLY_NOT_ALLOWED:
                raise session.SessionFailure(f"refused destination returned SOCKS reply {code}")
            # Permitted, but nothing listens: the server cannot set up the route.
            code, connection = session.socks_connect(socks_port, "127.0.0.1", closed_port)
            connection.close()
            if code != session.REPLY_HOST_UNREACHABLE:
                raise session.SessionFailure(f"closed destination returned SOCKS reply {code}")

            if dns_fixture:
                check_dns_destinations(socks_port, target_port)

            check_optimistic_data(socks_port)
            check_optimistic_refusal(socks_port)
            check_payload(socks_port, "127.0.0.1", target_port)
            check_udp_associate(socks_port)
            if module is not None:
                check_module(forward, identity)
                print("module verified: yumed ran it with the client identity and echoed its stream")

            session.stop_process(client, "yume")
            client = None
            check_outer_carrier_evidence(yume, kit, environment, root, socks_port, target_port)
            check_control_status(yume, kit, environment, root, socks_port, target_port)
            check_socks5_upstream(yume, kit, environment, root, server_port, target_port)
            session.stop_process(server, "yumed")
            if module is not None and any(module_root.iterdir()):
                raise session.SessionFailure("yumed left the module socket directory behind")
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
        client_log = (root / "yume.log").read_text(encoding="utf-8")
        if client_log.count("yume: session authenticated\n") != 1 or "session ended" in client_log:
            raise session.SessionFailure("SOCKS requests replaced the authenticated session")
        # The DNS variant's resolver fixture expects an exact query count, and
        # the plain variant covers reconnection.
        if not dns_fixture:
            check_client_reconnects(yumed, yume, kit, environment, root, server_port,
                                    socks_port, target_port)
        server_log = (root / "yumed.log").read_text(encoding="utf-8")
        if module is not None and (server_log.count("module echo: started as process") != 1 or
                                   "module echo: exited" in server_log):
            raise session.SessionFailure("the module did not run once without exiting")
        if module is not None:
            check_module_dies_with_daemon(yumed, kit / "server/yumed.json", environment,
                                          root / "yumed-killed.log")
            print("module verified: it ended with a killed yumed")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yumed", type=Path, required=True)
    parser.add_argument("--yume", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--dns-fixture", action="store_true",
                        help="exercise the resolver-wrapped test daemon")
    parser.add_argument("--module", type=Path,
                        help="the echo module, served by yumed and reached through a forward")
    arguments = parser.parse_args()
    try:
        run(arguments.yumed, arguments.yume, arguments.openssl, dns_fixture=arguments.dns_fixture,
            module=arguments.module)
    except (session.SessionFailure, OSError, subprocess.SubprocessError) as error:
        print(f"native runtime test: {error}", file=sys.stderr)
        return 1
    print("native runtime processes carried SOCKS5 traffic and stopped cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
