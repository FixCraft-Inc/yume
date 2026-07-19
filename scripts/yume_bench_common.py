#!/usr/bin/env python3
"""Shared provisioning and process helpers for YUME 2.0 benchmarks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


@dataclass(frozen=True)
class BenchKeyset:
    server_cert: Path
    server_key: Path
    client_identity: Path
    authorized_keys: Path
    admission_secret: Path
    inner_psk: Path


@dataclass
class ManagedProcess:
    process: subprocess.Popen[bytes]
    log_file: BinaryIO
    log_path: Path

    def stop(self, timeout: float = 5.0, *, interrupt: bool = False) -> None:
        if self.process.poll() is None:
            stop_signal = signal.SIGINT if interrupt else signal.SIGTERM
            try:
                os.killpg(self.process.pid, stop_signal)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait()
        self.log_file.close()


def run_checked(
    argv: list[str],
    *,
    cwd: Path | None = None,
    stdout: int | BinaryIO | None = subprocess.DEVNULL,
    stderr: int | BinaryIO | None = subprocess.DEVNULL,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=True,
        stdout=stdout,
        stderr=stderr,
    )


def start_logged_process(
    argv: list[str],
    log_path: Path,
    *,
    cwd: Path | None = None,
) -> ManagedProcess:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = log_path.open("wb")
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except Exception:
        log_file.close()
        raise
    return ManagedProcess(process, log_file, log_path)


def _write_secret(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        secret = os.urandom(32).hex().encode("ascii")
        view = memoryview(secret)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)


def generate_keyset(
    directory: Path,
    yumed: Path,
    *,
    tls_name: str,
    server_ip: str,
) -> BenchKeyset:
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    keyset = BenchKeyset(
        server_cert=directory / "server.crt",
        server_key=directory / "server.key",
        client_identity=directory / "client.key",
        authorized_keys=directory / "authorized_keys",
        admission_secret=directory / "secrets" / "admission.hex",
        inner_psk=directory / "secrets" / "inner.hex",
    )

    run_checked([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(keyset.server_key),
        "-out", str(keyset.server_cert),
        "-days", "1", "-nodes", "-sha256",
        "-subj", f"/CN={tls_name}",
        "-addext", f"subjectAltName=DNS:{tls_name},IP:{server_ip}",
    ])
    os.chmod(keyset.server_key, 0o600)

    prefix = directory / "client"
    run_checked([str(yumed), "--keys-gen", str(prefix)])
    public_key = directory / "client.pub"
    if not keyset.client_identity.is_file() or not public_key.is_file():
        raise RuntimeError("yumed --keys-gen did not create the client key pair")
    shutil.copyfile(public_key, keyset.authorized_keys)
    os.chmod(keyset.authorized_keys, 0o600)

    der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout
    fingerprint = hashlib.sha256(der).hexdigest()
    metadata = {
        fingerprint: {
            "alias": "benchmark",
            "permissions": {},
        }
    }
    metadata_path = Path(f"{keyset.authorized_keys}.json")
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    os.chmod(metadata_path, 0o600)

    _write_secret(keyset.admission_secret)
    _write_secret(keyset.inner_psk)
    return keyset


def wait_for_tcp(
    host: str,
    port: int,
    timeout: float,
    *,
    namespace: str | None = None,
) -> bool:
    if namespace is None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=0.25):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    probe = (
        "import socket,sys; "
        "s=socket.socket(); s.settimeout(0.3); "
        "s.connect((sys.argv[1],int(sys.argv[2]))); s.close()"
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["ip", "netns", "exec", namespace, "python3", "-c", probe, host, str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            return True
        time.sleep(0.1)
    return False


def command_version(argv: list[str]) -> str:
    try:
        result = subprocess.run(
            argv,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    for line in lines:
        if re.fullmatch(r"Yume\s+\d[^\s]*", line):
            return line
    return lines[0] if lines else "unknown"
