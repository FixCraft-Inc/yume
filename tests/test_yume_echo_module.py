#!/usr/bin/env python3
"""Checks that the echo module refuses a connection it cannot serve and keeps
serving. A process limit below this user's thread count makes every new
connection thread fail with EAGAIN, as a pids limit would. The module must
close those connections without exiting, release their slots, and serve
again once the limit is lifted."""

from __future__ import annotations

import argparse
import os
import resource
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# More than the module's 64 connection slots, so a slot leaked by each
# refusal would leave none for the final connection.
REFUSED_CONNECTIONS = 70
SKIP = 77


class Failure(Exception):
    pass


def converse(path: Path) -> bytes:
    """Sends the module header and a line, then reads until the module
    closes or has greeted and echoed. A refused connection closes with the
    request unread, which a UNIX socket reports as a reset."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        expected = b"hello alice\nping"
        received = b""
        try:
            connection.sendall(b"yume-module 1 alice echo\nping")
            while len(received) < len(expected):
                chunk = connection.recv(len(expected) - len(received))
                if not chunk:
                    break
                received += chunk
        except (ConnectionResetError, BrokenPipeError):
            pass
        return received


def run(program: Path) -> int:
    limits = resource.getrlimit(resource.RLIMIT_NPROC)
    with tempfile.TemporaryDirectory(prefix="yume-echo-module-") as temporary:
        path = Path(temporary) / "module.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            os.chmod(path, 0o600)
            listener.listen(64)
            # The shell moves the listener to descriptor 3, as systemd passes it.
            process = subprocess.Popen(
                ["/bin/sh", "-c", 'exec "$0" 3<&"$1"', str(program),
                 str(listener.fileno())],
                pass_fds=(listener.fileno(),), stdin=subprocess.DEVNULL,
                preexec_fn=lambda: resource.setrlimit(
                    resource.RLIMIT_NPROC, (1, limits[1])))
            try:
                for attempt in range(REFUSED_CONNECTIONS):
                    received = converse(path)
                    if received.startswith(b"hello"):
                        if attempt == 0:
                            print("skipped: this user's process limit is not enforced")
                            return SKIP
                        raise Failure("a connection was served under the thread limit")
                    if received:
                        raise Failure(f"a refused connection received {received!r}")
                    # A module that died also closes the connection. Give an
                    # abort time to land before asking.
                    time.sleep(0.01)
                    if process.poll() is not None:
                        raise Failure(f"the module exited with {process.returncode} "
                                      f"after {attempt + 1} refused connections")
                resource.prlimit(process.pid, resource.RLIMIT_NPROC, limits)
                received = converse(path)
                if received != b"hello alice\nping":
                    raise Failure(f"the module did not serve after the limit: {received!r}")
                if process.poll() is not None:
                    raise Failure(f"the module exited with {process.returncode}")
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
    print(f"echo module refused {REFUSED_CONNECTIONS} connections without threads "
          "and served once threads were allowed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        return run(arguments.module.resolve(strict=True))
    except (Failure, OSError, subprocess.SubprocessError) as error:
        print(f"echo module test: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
