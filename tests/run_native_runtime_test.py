#!/usr/bin/env python3
"""Run yumed and yume as processes and move bytes through SOCKS5."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import socket
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


def check_payload(socks_port: int, host: str, target_port: int) -> None:
    code, connection = session.socks_connect(socks_port, host, target_port)
    with connection:
        if code != session.REPLY_SUCCEEDED:
            raise session.SessionFailure(f"permitted destination returned SOCKS reply {code}")
        connection.sendall(b"GET /payload HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
        length, digest = session.read_http_body(connection)
    if length != PAYLOAD_BYTES or digest != session.payload_digest(PAYLOAD_BYTES):
        raise session.SessionFailure("destination payload differs")


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


def process_gone(pid: int) -> bool:
    # A dead child of init can stay a zombie briefly until it is reaped.
    try:
        state = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()[0]
    except FileNotFoundError:
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
                os.kill(module, 9)
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
        session.provision_kit(kit, "localhost", server_port, environment)
        session.configure_kit(kit, listen_address="127.0.0.1", networks=["127.0.0.1/32"],
                              connect_address="127.0.0.1", socks_port=socks_port)
        if module is not None:
            forward, identity = add_module(kit, module.resolve(strict=True))
            # Module sockets live in a private directory below TMPDIR. A
            # directory of the test's own shows that yumed removes it.
            module_root = root / "module-tmp"
            module_root.mkdir(mode=0o700)
            environment = dict(environment, TMPDIR=str(module_root))
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
