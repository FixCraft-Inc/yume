#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""A stand-in for yume in the GUI's hermetic tests.

It takes the command lines yume-gui runs and answers on the control socket
as control protocol 1 (docs/protocol/CONTROL_1.md) describes, so the GUI's
lifecycle, import and pages can be tested without a server, keys or a
network. The live test runs the real yume against a real yumed.

  fake_yume.py --config CFG --control-socket SOCK [--validate]
  fake_yume.py --import-kit FILE --into DIR          (code on standard input)

A kit's fake.json, beside its yume.json, shapes the run:
  validate_error   text: --validate fails with it
  start_error      text: the run prints it and exits 1 before its socket opens
  connect_after_ms how long the state stays "connecting" (400)
  circuits         true: a circuits section with a proposal of a shorter route
  name             a text the status's server host takes instead of the kit's
  lines            texts the run prints after it starts, such as right-to-left text
  last_failure     the status's last failure, {"code": ..., "message": ...}
  linger_ms        how long the run lives on after its socket is gone (500), as
                   yume does while it closes its sessions
  blank_cmdline_ms how long the run shows an empty command line before its
                   socket opens, as a wrapper that execs yume does for a moment

A sealed kit for the fake is JSON {"code": CODE, "files": {NAME: TEXT}}.
"""

from __future__ import annotations

import json
import os
import secrets
import select
import signal
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

CONTROL_REPLY_BYTES = 64 * 1024
GIVES_UP = ("The exit's neighbour is your entry. A party that runs both, or watches both, "
            "can link you to the sites you visit.")


def say(text: str) -> None:
    sys.stderr.write(f"yume: {text}\n")
    sys.stderr.flush()


def arguments(argv: list[str]) -> dict[str, str | bool]:
    parsed: dict[str, str | bool] = {}
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag == "--validate":
            parsed["validate"] = True
            index += 1
            continue
        if flag not in ("--config", "--control-socket", "--import-kit", "--into"):
            say(f"unknown argument: {flag}")
            sys.exit(2)
        if index + 1 >= len(argv):
            say(f"{flag} needs exactly one value")
            sys.exit(2)
        parsed[flag[2:]] = argv[index + 1]
        index += 2
    return parsed


def normalize(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum()).replace("O", "0").replace("I", "1")


def import_kit(file: str, into: str) -> int:
    code = sys.stdin.readline().strip()
    try:
        sealed = json.loads(Path(file).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        say("cannot open the kit: the code is wrong or the file is not a sealed kit")
        return 1
    if normalize(code) != normalize(sealed.get("code", "")):
        say("cannot open the kit: the code is wrong or the file is not a sealed kit")
        return 1
    target = Path(into)
    if target.exists():
        say("cannot write the kit: the kit directory exists")
        return 1
    target.mkdir(mode=0o700)
    for name, text in sealed.get("files", {}).items():
        (target / name).write_text(text, encoding="utf-8")
    say(f"imported the kit into {target}, run yume --config {target / 'yume.json'}")
    return 0


class Client:
    """The state a fake client reports, driven by time since its start."""

    def __init__(self, config: Path, socket_path: Path) -> None:
        self.config = json.loads(config.read_text(encoding="utf-8"))
        fake = config.parent / "fake.json"
        self.fake = json.loads(fake.read_text(encoding="utf-8")) if fake.exists() else {}
        self.kit = config.parent
        self.socket_path = socket_path
        self.started = time.monotonic()
        self.instance = secrets.token_hex(8)
        self.lines: list[dict[str, object]] = []
        self.connected_at: float | None = None
        self.proposal_id = secrets.token_hex(8)
        self.accepted = 0
        self.stopping = False

    def line(self, text: str) -> None:
        say(text)
        now = datetime.now(timezone.utc)
        self.lines.append({"seq": len(self.lines) + 1,
                           "time": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
                           "text": text})

    def tick(self) -> None:
        after = self.fake.get("connect_after_ms", 400) / 1000
        if self.connected_at is None and time.monotonic() - self.started >= after:
            self.connected_at = time.monotonic()
            self.line("session authenticated")
            if self.fake.get("circuits"):
                self.line("no route of 3 hops can be built, a route of 2 hops is proposed. "
                          + GIVES_UP + f" Accept with yume --accept-route {self.proposal_id}")

    def circuits(self) -> object:
        if not self.fake.get("circuits"):
            return None
        up = self.connected_at is not None
        age = int((time.monotonic() - (self.connected_at or time.monotonic())) * 1000)
        return {
            "hops": 3, "min_hops": 3, "accepted_hops": self.accepted,
            "current_hops": self.accepted, "plain_http": "refuse", "serial": 7,
            "stopped": None,
            "routes": [{"nodes": ["north", "east"], "age_ms": age, "streams": 2}]
                      if self.accepted else [],
            "proposal": None if self.accepted or not up else {
                "id": self.proposal_id, "hops": 2, "nodes": ["north", "east"], "serial": 7,
                "gives_up": GIVES_UP, "latency_ms": 84},
        }

    def status(self) -> dict[str, object]:
        endpoint = self.config.get("endpoint", {})
        connected = self.connected_at is not None
        seconds = time.monotonic() - self.connected_at if connected else 0.0
        sent = int(46_000 * seconds + 3_000 * (seconds % 7))
        received = int(1_150_000 * seconds + 80_000 * (seconds % 5))
        reply: dict[str, object] = {
            "control": 1,
            "requests": ["status", "messages", "stop"] + (
                ["accept-route"] if self.fake.get("circuits") else []),
            "program": "yume", "version": "0.3.0-dev1",
            "state": "connected" if connected else "connecting",
            "server": {"host": self.fake.get("name", endpoint.get("host", "")),
                       "port": endpoint.get("port", 0)},
            "sessions": 1 if connected else 0,
            "failed_attempts": 0,
            "last_failure": self.fake.get("last_failure"),
            "traffic": {"payload_bytes_sent": sent, "payload_bytes_received": received,
                        "record_bytes_sent": int(sent * 1.03) + 11_621,
                        "record_bytes_received": int(received * 1.016) + 17_050},
            "socks5": ["127.0.0.1:1080"],
            "forwards": ["/run/user/1000/yume/chat.sock"],
            "posture": {"transport": "YTP/1", "suite": "ytp1-tls13-h2",
                        "evidence_profile": "chrome151-node24-v1",
                        "security": "openssl35.ytp1-security", "crypto_backend": "openssl-3.5.7",
                        "limits": {"max_queued_bytes": 4194304, "max_epoch_bytes": 1048576,
                                   "credit_returns_per_window": 2,
                                   "idle_epoch_rotation": False}},
            "circuits": self.circuits(),
        }
        if connected:
            reply["server_identity"] = "2bc6aee2288a77ab0d807051ae4bd2578eeb20584eecdab31a5e3dfb39366f15"
            reply["connected_ms"] = int(seconds * 1000)
            reply["posture"]["epoch_bytes"] = 1048576
        return reply

    def messages(self, after: int) -> dict[str, object]:
        chosen = [line for line in self.lines if line["seq"] > after]
        return {"control": 1, "instance": self.instance, "messages": chosen, "missed": 0,
                "more": False}

    def answer(self, line: bytes) -> dict[str, object]:
        try:
            request = json.loads(line)
        except ValueError:
            return {"control": 1, "error": "the request is not a JSON object", "code": "malformed"}
        if not isinstance(request, dict) or request.get("control") != 1:
            return {"control": 1, "error": "unsupported control protocol", "code": "unsupported"}
        name = request.get("request")
        if name == "status" and len(request) == 2:
            return self.status()
        if name == "messages" and set(request) == {"control", "request", "after"}:
            return self.messages(int(request["after"]))
        if name == "stop" and len(request) == 2:
            self.stopping = True
            return {"control": 1, "stopping": True}
        if name == "accept-route" and self.fake.get("circuits"):
            proposal = self.circuits()["proposal"]
            if not proposal or request.get("id") != proposal["id"]:
                return {"control": 1, "error": "no route proposal has that id", "code": "not_found"}
            with (self.kit / "accepted.log").open("a", encoding="utf-8") as log:
                log.write(request["id"] + "\n")
            self.accepted = 2
            self.line(f"accepted routes of 2 hops, proposal {request['id']}")
            return {"control": 1, "accepted": request["id"]}
        return {"control": 1, "error": "unknown request", "code": "unknown_request"}


def blank_command_line(seconds: float) -> None:
    """Show an empty /proc/PID/cmdline for a while, then restore it.

    A process inside execve has one between the kernel replacing its memory
    and laying out the new arguments. The run's own argument strings, which
    the interpreter copied at startup, are zeroed through /proc/self/mem.
    """
    fields = Path("/proc/self/stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
    start, end = int(fields[45]), int(fields[46])
    with open("/proc/self/mem", "r+b", buffering=0) as memory:
        memory.seek(start)
        saved = memory.read(end - start)
        memory.seek(start)
        memory.write(bytes(end - start))
        time.sleep(seconds)
        memory.seek(start)
        memory.write(saved)


def serve(config: Path, socket_path: Path) -> int:
    client = Client(config, socket_path)
    if client.fake.get("start_error"):
        say(client.fake["start_error"])
        return 1
    if client.fake.get("blank_cmdline_ms"):
        blank_command_line(client.fake["blank_cmdline_ms"] / 1000)
    if socket_path.exists():
        socket_path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    os.chmod(socket_path, 0o600)
    listener.listen(4)
    stop = False

    def terminate(*_: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    client.line("SOCKS5 on 127.0.0.1 port 1080")
    client.line(f"control socket on {socket_path}")
    for text in client.fake.get("lines", []):
        client.line(text)
    while not stop:
        client.tick()
        ready, _, _ = select.select([listener], [], [], 0.05)
        if not ready:
            continue
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(2)
            data = b""
            try:
                while b"\n" not in data and len(data) < 512:
                    chunk = connection.recv(512)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                continue
            reply = json.dumps(client.answer(data.split(b"\n")[0])).encode() + b"\n"
            try:
                connection.sendall(reply[:CONTROL_REPLY_BYTES])
            except OSError:
                pass
        if client.stopping:
            say("stopping on a control request")
            break
    listener.close()
    socket_path.unlink(missing_ok=True)
    time.sleep(client.fake.get("linger_ms", 500) / 1000)
    return 0


def main() -> int:
    parsed = arguments(sys.argv[1:])
    if "import-kit" in parsed:
        return import_kit(str(parsed["import-kit"]), str(parsed.get("into", "")))
    config = Path(str(parsed.get("config", "")))
    socket_path = Path(str(parsed.get("control-socket", "")))
    if parsed.get("validate"):
        fake = config.parent / "fake.json"
        options = json.loads(fake.read_text(encoding="utf-8")) if fake.exists() else {}
        if not config.is_file():
            say("cannot read the configuration file")
            return 2
        say(f"/control/socket {socket_path} (from --control-socket)")
        if options.get("validate_error"):
            say(options["validate_error"])
            return 2
        say("configuration and credentials are valid")
        return 0
    return serve(config, socket_path)


if __name__ == "__main__":
    sys.exit(main())
