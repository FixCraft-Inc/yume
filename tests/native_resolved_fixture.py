"""Real resolved fixture, confined to the TUN test's user/mount/network namespaces."""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
from typing import Iterator


def command(argv: list[str], timeout: float = 10) -> subprocess.CompletedProcess[str]:
    # The distribution's daemon and bus tools use its own OpenSSL installation.
    env = {key: value for key, value in os.environ.items()
           if key not in {"LD_LIBRARY_PATH", "OPENSSL_CONF", "OPENSSL_MODULES"}}
    return subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, check=True, timeout=timeout)


def bus(*arguments: str) -> object:
    return json.loads(command(["busctl", "--system", "--json=short", *arguments]).stdout)["data"]


def property_value(path: str, interface: str, name: str) -> object:
    return bus("get-property", "org.freedesktop.resolve1", path, interface, name)


@contextmanager
def isolated_resolved(binary: Path, artifacts: Path) -> Iterator[None]:
    mapping = Path("/proc/self/uid_map").read_text().split()
    if len(mapping) != 3 or mapping[0] != "0" or int(mapping[1]) == 0 or mapping[2] != "1":
        raise RuntimeError("resolved fixture requires one unprivileged user mapped to namespace root")
    # The worker entered a new mount namespace. Hide every mutable service path
    # before starting either daemon; no host bus, DNS config or runtime is used.
    command(["mount", "--make-rprivate", "/"])
    command(["mount", "-t", "tmpfs", "-o", "mode=755", "tmpfs", "/run"])
    command(["mount", "-t", "tmpfs", "-o", "mode=755", "tmpfs", "/etc/systemd"])
    Path("/run/systemd").mkdir()
    Path("/etc/systemd/resolved.conf").write_text(
        "[Resolve]\nDNS=\nFallbackDNS=\nLLMNR=no\nMulticastDNS=no\n"
        "DNSSEC=no\nDNSStubListener=no\nReadEtcHosts=no\n")
    # Only UID 0 is mapped in this user namespace. This identity file is visible
    # solely to the worker and its children; resolved still performs its normal
    # privilege dropping and D-Bus authorization.
    (artifacts / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\n"
        "systemd-resolve:x:0:0:resolved:/run/systemd/resolve:/usr/sbin/nologin\n")
    (artifacts / "group").write_text("root:x:0:\n")
    for name in ("passwd", "group"):
        command(["mount", "--bind", str(artifacts / name), "/etc/" + name])
    configuration = artifacts / "bus.conf"
    configuration.write_text(
        '<busconfig><type>system</type><listen>unix:path=/run/yume-test-bus</listen>'
        '<auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/>'
        '<allow receive_sender="*"/><allow own="*"/><allow user="*"/></policy></busconfig>')
    os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/run/yume-test-bus"
    env = {key: value for key, value in os.environ.items()
           if key not in {"LD_LIBRARY_PATH", "OPENSSL_CONF", "OPENSSL_MODULES"}}
    with (artifacts / "bus.log").open("w+") as bus_log, (artifacts / "resolved.log").open("w+") as dns_log:
        processes: list[subprocess.Popen] = []
        try:
            processes.append(subprocess.Popen(
                ["dbus-daemon", "--nofork", "--config-file=" + str(configuration)],
                env=env, stdin=subprocess.DEVNULL, stdout=bus_log, stderr=bus_log))
            deadline = time.monotonic() + 5
            while not Path("/run/yume-test-bus").exists():
                if processes[0].poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("private system bus failed to start")
                time.sleep(0.05)
            processes.append(subprocess.Popen([str(binary)], env=env, stdin=subprocess.DEVNULL,
                                              stdout=dns_log, stderr=dns_log))
            deadline = time.monotonic() + 5
            while True:
                if processes[-1].poll() is not None:
                    raise RuntimeError("resolved exited during startup")
                try:
                    property_value("/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager", "DNS")
                    break
                except subprocess.CalledProcessError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("resolved did not acquire its private bus name") from None
                    time.sleep(0.05)
            yield
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


def check_link_and_query(name: str) -> None:
    index = socket.if_nametoindex("ytp-client")
    path = bus("call", "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
               "org.freedesktop.resolve1.Manager", "GetLink", "i", str(index))[0]
    interface = "org.freedesktop.resolve1.Link"
    if property_value(path, interface, "DNS") != [[socket.AF_INET, [10, 71, 0, 1]]]:
        raise RuntimeError("resolved did not receive the configured per-link DNS server")
    if property_value(path, interface, "Domains") != [["yume.test", True]]:
        raise RuntimeError("resolved did not receive the routing-only domain")
    if property_value(path, interface, "DefaultRoute") is not False:
        raise RuntimeError("TUN unexpectedly became the default DNS route")
    result = bus("call", "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
                 "org.freedesktop.resolve1.Manager", "ResolveHostname", "isit",
                 "0", name, str(socket.AF_INET), "0")
    if result[0] != [[index, socket.AF_INET, [10, 71, 0, 1]]]:
        raise RuntimeError("resolved query did not return the DNS answer through the TUN")


def check_clean() -> None:
    interface = "org.freedesktop.resolve1.Manager"
    deadline = time.monotonic() + 5
    while True:
        servers = property_value("/org/freedesktop/resolve1", interface, "DNS")
        domains = property_value("/org/freedesktop/resolve1", interface, "Domains")
        if not servers and not domains:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("resolved retained the removed TUN's DNS settings")
        time.sleep(0.05)


def serve_dns() -> None:
    """Answer only bounded, uncompressed A queries for this fixture's domain."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("10.71.0.1", 53))
        listener.settimeout(30)
        print("ready", flush=True)
        # Resolved may retransmit while learning server features. Bound total
        # questions, but require all three distinct uncached names before exit.
        seen: set[bytes] = set()
        expected = {b"first.yume.test", b"reconnected.yume.test", b"repeated.yume.test"}
        for _ in range(64):
            query, peer = listener.recvfrom(4096)
            if len(query) < 17 or struct.unpack_from("!H", query, 4)[0] != 1:
                raise RuntimeError("unexpected DNS question header")
            cursor, labels = 12, []
            while cursor < len(query) and query[cursor]:
                length = query[cursor]
                if length > 63 or cursor + 1 + length > len(query):
                    raise RuntimeError("invalid DNS question label")
                labels.append(query[cursor + 1:cursor + 1 + length])
                cursor += 1 + length
            cursor += 1
            if cursor + 4 > len(query) or labels[-2:] != [b"yume", b"test"]:
                raise RuntimeError("unexpected DNS question name")
            if query[cursor:cursor + 4] != b"\x00\x01\x00\x01":
                raise RuntimeError("unexpected DNS question type")
            question = query[12:cursor + 4]
            response = (query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question +
                        b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + bytes([10, 71, 0, 1]))
            listener.sendto(response, peer)
            seen.add(b".".join(labels).lower())
            if expected <= seen:
                return
        raise RuntimeError("DNS target exceeded its bounded query count")
