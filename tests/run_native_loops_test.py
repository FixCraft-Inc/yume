#!/usr/bin/env python3
"""yumed serving sessions on several event loops, as real processes.

One yumed with endpoint.event_loops = 4 and several clients, each with its
own identity and SOCKS5 port. Connections spread over the loops, so the
checks below cross loops:

1. Every client moves data at once, and the control socket counts each
   session.
2. One identity's max_sessions holds across loops: a second client with the
   same identity replaces the first one's session wherever it runs.
3. A reload that removes an identity ends its session on whichever loop
   serves it, while the other clients keep moving data.
4. With --module, every client's stream reaches the echo module.
5. yumed stops cleanly.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))

import yume_native_session as session  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from run_native_runtime_test import check_module  # noqa: E402

PAYLOAD_BYTES = 4 * 1024 * 1024
CLIENTS = 6
LOOPS = 4


def control(path: Path, request: str = "status") -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        connection.sendall(json.dumps({"control": 1, "request": request}).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            block = connection.recv(65536)
            if not block:
                break
            data += block
    return json.loads(data)


def client_sessions(path: Path) -> int:
    return int(control(path)["client_sessions"])


def wait_for_sessions(path: Path, count: int, deadline: float) -> None:
    while (current := client_sessions(path)) != count:
        if time.monotonic() > deadline:
            raise session.SessionFailure(f"yumed holds {current} sessions, expected {count}")
        time.sleep(0.1)


def fetch(socks_port: int, target_port: int) -> None:
    length, digest, _ = session.get_through_socks(socks_port, "127.0.0.1", target_port,
                                                  time.monotonic() + 30)
    if length != PAYLOAD_BYTES or digest != session.payload_digest(PAYLOAD_BYTES):
        raise session.SessionFailure(f"tunnelled payload differs: {length} of {PAYLOAD_BYTES}")


def configure_client(bundle: Path, socks_port: int) -> Path:
    path = bundle / "yume.json"
    config = json.loads(path.read_text(encoding="utf-8"))
    config["endpoint"]["connect_address"] = "127.0.0.1"
    for adapter in config["adapters"]:
        if adapter["kind"] == "socks5":
            adapter["listen_port"] = socks_port
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def add_module(kit: Path, configs: list[Path], program: Path) -> list[Path]:
    """Serves stream service "echo" with the module, grants it to every
    identity and gives every client a forward to it. Returns the forwards."""
    service = {"name": "echo", "kind": "stream", "max_concurrent_streams": 8}
    server_path = kit / "server/yumed.json"
    server = json.loads(server_path.read_text(encoding="utf-8"))
    server["services"].append(service)
    server["adapters"].append({"kind": "module", "service": "echo", "program": str(program)})
    server_path.write_text(json.dumps(server, indent=2), encoding="utf-8")
    forwards = []
    for config in configs:
        forward = config.with_name("echo.sock")
        client = json.loads(config.read_text(encoding="utf-8"))
        client["services"].append(service)
        client["adapters"].append({"kind": "forward", "service": "echo",
                                   "listen_path": str(forward)})
        config.write_text(json.dumps(client, indent=2), encoding="utf-8")
        forwards.append(forward)
    keys_path = kit / "server/credentials/authorized-keys.json"
    keys = json.loads(keys_path.read_text(encoding="utf-8"))
    for entry in keys["keys"]:
        entry["capabilities"].append({"service": "echo", "kind": "stream"})
    keys_path.write_text(json.dumps(keys, indent=2), encoding="utf-8")
    return forwards


def start(program: Path, config: Path, environment: dict[str, str], log: Path) -> subprocess.Popen:
    with log.open("ab") as output:
        return subprocess.Popen([str(program), "--config", str(config)], env=environment,
                                stdout=output, stderr=subprocess.STDOUT)


def run(yumed: Path, yume: Path, openssl: Path, module: Path | None) -> None:
    environment = session.openssl_environment(openssl)
    setup = session.setup_program(yume)
    with tempfile.TemporaryDirectory(prefix="yume-native-loops-") as temporary:
        root = Path(temporary)
        kit = root / "kit"
        server_port, socks_port, target_port = (session.free_port() for _ in range(3))
        session.provision_kit(kit, "localhost", server_port, environment, setup)
        session.configure_kit(kit, listen_address="127.0.0.1", networks=["127.0.0.1/32"],
                              connect_address="127.0.0.1", socks_port=socks_port)
        bundles = [kit / "client"]
        for index in range(1, CLIENTS):
            bundle = root / f"client{index}"
            session.run_setup(setup, ["add-client", "--server", str(kit / "server"),
                                      "--host", "localhost", "--output", str(bundle),
                                      "--client-name", f"loops{index}"], environment)
            bundles.append(bundle)
        ports = [socks_port] + [session.free_port() for _ in range(1, CLIENTS)]
        configs = [configure_client(bundle, port) for bundle, port in zip(bundles, ports)]
        forwards = add_module(kit, configs, module.resolve(strict=True)) if module else []
        control_path = root / "yumed.sock"
        server_config = kit / "server/yumed.json"
        server = json.loads(server_config.read_text(encoding="utf-8"))
        server["endpoint"]["event_loops"] = LOOPS
        server["control"] = {"socket": str(control_path)}
        server_config.write_text(json.dumps(server, indent=2), encoding="utf-8")
        store_path = kit / "server/credentials/authorized-keys.json"
        store = json.loads(store_path.read_text(encoding="utf-8"))
        if len(store["keys"]) != CLIENTS:
            raise session.SessionFailure(f"the store holds {len(store['keys'])} identities")
        # The second identity holds one session at a time.
        store["keys"][1]["max_sessions"] = 1
        store_path.write_text(json.dumps(store), encoding="utf-8")

        target = session.serve_payload("127.0.0.1", target_port, PAYLOAD_BYTES)
        processes: list[subprocess.Popen] = []
        server_log = root / "yumed.log"
        try:
            daemon = start(yumed, server_config, environment, server_log)
            processes.append(daemon)
            session.wait_for_port("127.0.0.1", server_port, daemon, time.monotonic() + 30)
            clients = [start(yume, config, environment, root / f"yume{index}.log")
                       for index, config in enumerate(configs)]
            processes.extend(clients)
            for client, port in zip(clients, ports):
                session.wait_for_port("127.0.0.1", port, client, time.monotonic() + 30)

            # 1. Every client at once, three requests each.
            with ThreadPoolExecutor(max_workers=CLIENTS * 3) as pool:
                for future in [pool.submit(fetch, port, target_port)
                               for port in ports for _ in range(3)]:
                    future.result(timeout=120)
            wait_for_sessions(control_path, CLIENTS, time.monotonic() + 10)
            # The least busy loop takes each connection, so every loop serves.
            loops = control(control_path)["loops"]
            if len(loops) != LOOPS or sum(loops) != CLIENTS or min(loops) == 0:
                raise session.SessionFailure(f"sessions per loop are {loops}")
            print(f"{CLIENTS} clients moved data at once over {LOOPS} loops: {loops}")
            # 4. Each client's module stream runs on its session's loop.
            for forward, entry in zip(forwards, store["keys"]):
                check_module(forward, entry["identity"]["sha256"])
            if forwards:
                print(f"the echo module served every client from {LOOPS} loops")

            # 2. A second client with the second identity replaces the first
            # one's session. The count stays and the replaced client reconnects
            # by itself, so both keep finding a session in turn.
            twin_port = session.free_port()
            twin_bundle = root / "twin"
            twin_bundle.mkdir()
            for name in ("credentials", "adapters"):
                source = bundles[1] / name
                if source.exists():
                    subprocess.run(["cp", "-a", str(source), str(twin_bundle / name)], check=True)
            twin_config = json.loads(configs[1].read_text(encoding="utf-8"))
            for adapter in twin_config["adapters"]:
                if adapter["kind"] == "socks5":
                    adapter["listen_port"] = twin_port
                if adapter["kind"] == "forward":
                    adapter["listen_path"] = str(twin_bundle / "echo.sock")
            (twin_bundle / "yume.json").write_text(json.dumps(twin_config), encoding="utf-8")
            twin = start(yume, twin_bundle / "yume.json", environment, root / "twin.log")
            processes.append(twin)
            session.wait_for_port("127.0.0.1", twin_port, twin, time.monotonic() + 30)
            fetch(twin_port, target_port)
            deadline = time.monotonic() + 15
            while "session ended" not in (root / "yume1.log").read_text(encoding="utf-8"):
                if time.monotonic() > deadline:
                    raise session.SessionFailure("the twin did not replace the first session")
                time.sleep(0.1)
            if client_sessions(control_path) > CLIENTS:
                raise session.SessionFailure("max_sessions let the identity hold two sessions")
            session.stop_process(twin, "the twin yume")
            processes.remove(twin)
            print("max_sessions held across loops: a newer session replaced the older")

            # 3. Remove the last identity while the others move data.
            store["keys"].pop()
            store_path.write_text(json.dumps(store), encoding="utf-8")
            with ThreadPoolExecutor(max_workers=CLIENTS) as pool:
                running = [pool.submit(fetch, port, target_port) for port in ports[:-1]]
                daemon.send_signal(signal.SIGHUP)
                for future in running:
                    future.result(timeout=120)
            deadline = time.monotonic() + 15
            while "credentials reloaded" not in server_log.read_text(encoding="utf-8"):
                if time.monotonic() > deadline:
                    raise session.SessionFailure("yumed did not report the reload")
                time.sleep(0.1)
            deadline = time.monotonic() + 15
            while "session ended" not in (root / f"yume{CLIENTS - 1}.log").read_text(encoding="utf-8"):
                if time.monotonic() > deadline:
                    raise session.SessionFailure("the removed identity kept its session")
                time.sleep(0.1)
            for port in ports[:-1]:
                fetch(port, target_port)
            print("a reload ended the removed identity's session and the others kept moving data")

            for client in clients:
                session.stop_process(client, "yume")
                processes.remove(client)
            session.stop_process(daemon, "yumed")
            processes.remove(daemon)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            target.shutdown()
            for log in sorted(root.glob("*.log")):
                text = log.read_text(encoding="utf-8", errors="replace")
                session.reject_secret_output(log.stem, text)
                sys.stdout.write(f"--- {log.name}\n{text}")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yumed", type=Path, required=True)
    parser.add_argument("--yume", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--module", type=Path,
                        help="the echo module, which every client reaches through a forward")
    arguments = parser.parse_args()
    try:
        run(arguments.yumed, arguments.yume, arguments.openssl, arguments.module)
    except (session.SessionFailure, OSError, subprocess.SubprocessError) as error:
        print(f"native loops test: {error}", file=sys.stderr)
        return 1
    print("yumed served sessions on several loops and stopped cleanly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
