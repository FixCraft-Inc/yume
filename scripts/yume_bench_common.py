#!/usr/bin/env python3
"""Shared provisioning and process helpers for YUME 2.0 benchmarks."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import selectors
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from yume_bench_resources import ProcessResourceSampler


_COVER_MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "tests/fixtures/chrome151-node24/manifest.json"
)
_COVER_PROFILE = json.loads(_COVER_MANIFEST.read_text(encoding="utf-8"))
PINNED_CHROME_VERSION = _COVER_PROFILE["client"]["version"]
PINNED_NODE_VERSION = _COVER_PROFILE["server"]["version"]
PINNED_CHROME_LAUNCHER_SHA256 = _COVER_PROFILE["client"]["launcher_sha256"]
PINNED_CHROME_BINARY_SHA256 = _COVER_PROFILE["client"]["binary_sha256"]
PINNED_NODE_BINARY_SHA256 = _COVER_PROFILE["server"]["binary_sha256"]
_PINNED_CHROME_RE = re.compile(
    rf"\b(?:Chrome|Chromium)\s+{re.escape(PINNED_CHROME_VERSION)}\b"
)
RATE_RE = re.compile(
    r"^(TOTAL|UP|DOWN)\s+([0-9.]+) MiB\s+([0-9.]+) s\s+"
    r"([0-9.]+) MiB/s /\s+([0-9.]+) Mbit/s$",
    re.MULTILINE,
)


def is_pinned_chrome_version(version_output: str) -> bool:
    """Return whether browser --version output matches the evidence fixture."""
    return _PINNED_CHROME_RE.search(version_output) is not None


@dataclass(frozen=True)
class BenchKeyset:
    server_cert: Path
    server_key: Path
    client_identity: Path
    authorized_keys: Path
    admission_secret: Path
    inner_psk: Path


@dataclass(frozen=True)
class RuntimeIdentity:
    uid: int
    gid: int
    home: Path


@dataclass(frozen=True)
class StreamedCommandResult:
    returncode: int
    output: str
    interrupted: bool = False
    timed_out: bool = False
    resources: dict[str, object] | None = None


@dataclass
class ManagedProcess:
    process: subprocess.Popen[bytes]
    log_file: BinaryIO
    log_path: Path
    resource_sampler: ProcessResourceSampler | None = None

    def stop(self, timeout: float = 5.0, *, interrupt: bool = False) -> None:
        if self.resource_sampler:
            self.resource_sampler.capture()
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
        if self.resource_sampler:
            self.resource_sampler.stop()

    def resource_summary(self) -> dict[str, object] | None:
        return self.resource_sampler.summary() if self.resource_sampler else None


def relay_chunk_kib(environment: dict[str, str] | None = None) -> int:
    source = os.environ if environment is None else environment
    try:
        value = int(source.get("YUME_RELAY_READ_BUF", "64"))
    except ValueError:
        return 64
    return value if 4 <= value <= 256 else 64


def endpoint_contract(
    requested_chunk_kib: int | None,
    production_chunk_kib: int,
) -> dict[str, object]:
    """Describe exactly what the synthetic endpoint rate does and does not measure."""
    return {
        "adapter": "authenticated-stream-core",
        "frame_profile": (
            "production-stream"
            if requested_chunk_kib in (None, production_chunk_kib)
            else "explicit-chunk"
        ),
        "includes": ["DATA", "ratchet", "H2", "WebSocket", "TLS"],
        "excludes": ["local SOCKS socket", "target TCP socket", "packet ABI"],
        "security": {
            "ml_kem_1024_x25519_psk_ratchet": True,
            "aes_256_gcm": True,
            "legacy_hop": False,
            "padding": False,
            "jitter": False,
        },
    }


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
    pass_fds: tuple[int, ...] = (),
    resource_sampling: bool = False,
    resource_sample_ms: int = 250,
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
            pass_fds=pass_fds,
        )
    except Exception:
        log_file.close()
        raise
    sampler = None
    if resource_sampling:
        sampler = ProcessResourceSampler(process.pid, resource_sample_ms)
        sampler.start()
    return ManagedProcess(process, log_file, log_path, sampler)


def _emit_output(chunk: bytes, captured: bytearray, *, echo: bool) -> None:
    if not chunk:
        return
    captured.extend(chunk)
    if echo:
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()


def _finish_streamed_process(
    process: subprocess.Popen[bytes],
    captured: bytearray,
    *,
    echo: bool,
    stop_signal: signal.Signals,
) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, stop_signal)
        except ProcessLookupError:
            pass
    try:
        remainder, _ = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        remainder, _ = process.communicate()
    _emit_output(remainder, captured, echo=echo)


def run_streamed_command(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float | None,
    echo: bool = True,
    interrupt_message: str = "interrupted; stopping child process",
    resource_sampling: bool = True,
    resource_sample_ms: int = 250,
    cancel_event: threading.Event | None = None,
) -> StreamedCommandResult:
    """Run a command while teeing merged output and retaining it for reports."""
    process = subprocess.Popen(
        argv,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    sampler = None
    if resource_sampling:
        sampler = ProcessResourceSampler(process.pid, resource_sample_ms)
        sampler.start()
    assert process.stdout is not None
    captured = bytearray()
    deadline = time.monotonic() + timeout if timeout is not None else None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)

    def finish_result(
        returncode: int,
        *,
        interrupted: bool = False,
        timed_out: bool = False,
    ) -> StreamedCommandResult:
        if sampler:
            sampler.stop()
        return StreamedCommandResult(
            returncode,
            captured.decode("utf-8", errors="replace"),
            interrupted=interrupted,
            timed_out=timed_out,
            resources=sampler.summary() if sampler else None,
        )

    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                message = f"\n{interrupt_message}\n".encode()
                _emit_output(message, captured, echo=echo)
                if sampler:
                    sampler.capture()
                _finish_streamed_process(
                    process,
                    captured,
                    echo=echo,
                    stop_signal=signal.SIGINT,
                )
                return finish_result(130, interrupted=True)
            remaining = (
                deadline - time.monotonic() if deadline is not None else None
            )
            if remaining is not None and remaining <= 0:
                message = f"\ncommand timed out after {timeout:g}s\n".encode()
                _emit_output(message, captured, echo=echo)
                if sampler:
                    sampler.capture()
                _finish_streamed_process(
                    process,
                    captured,
                    echo=echo,
                    stop_signal=signal.SIGTERM,
                )
                return finish_result(124, timed_out=True)
            events = selector.select(
                timeout=min(remaining, 0.25) if remaining is not None else 0.25
            )
            if not events:
                continue
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                if sampler:
                    sampler.capture()
                return finish_result(process.wait())
            _emit_output(chunk, captured, echo=echo)
    except KeyboardInterrupt:
        message = f"\n{interrupt_message}\n".encode()
        _emit_output(message, captured, echo=True)
        if sampler:
            sampler.capture()
        _finish_streamed_process(
            process,
            captured,
            echo=echo,
            stop_signal=signal.SIGINT,
        )
        return finish_result(130, interrupted=True)
    finally:
        selector.close()
        process.stdout.close()
        if sampler:
            sampler.stop()


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
            "key_type": "bulk",
            "max_sessions": 128,
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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_pinned_chrome(
    browser: Path,
    version_command_prefix: list[str] | None = None,
) -> dict[str, str]:
    """Validate the exact normal-Chrome launcher and adjacent browser binary."""
    launcher = browser.expanduser().resolve()
    if not launcher.is_file() or not os.access(launcher, os.X_OK):
        raise RuntimeError(f"Chrome launcher is not executable: {launcher}")
    launcher_sha256 = sha256_file(launcher)
    if launcher_sha256 != PINNED_CHROME_LAUNCHER_SHA256:
        raise RuntimeError(
            "Chrome launcher SHA-256 does not match the pinned evidence manifest"
        )

    binary = launcher.parent / Path(_COVER_PROFILE["client"]["binary"]).name
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"adjacent Chrome binary is not executable: {binary}")
    binary_sha256 = sha256_file(binary)
    if binary_sha256 != PINNED_CHROME_BINARY_SHA256:
        raise RuntimeError(
            "Chrome binary SHA-256 does not match the pinned evidence manifest"
        )

    version = command_version([
        *(version_command_prefix or []),
        str(launcher),
        "--version",
    ])
    if not is_pinned_chrome_version(version):
        raise RuntimeError(
            f"{version} does not match pinned Chrome {PINNED_CHROME_VERSION}"
        )
    return {
        "version": version,
        "launcher": str(launcher),
        "launcher_sha256": launcher_sha256,
        "binary": str(binary),
        "binary_sha256": binary_sha256,
    }


def require_user_namespace_sandbox(command_prefix: list[str] | None = None) -> None:
    """Fail unless an unprivileged user namespace can be created in context."""
    unshare = shutil.which("unshare")
    if not unshare:
        raise RuntimeError("unshare is required for the Chrome user-namespace sandbox")
    argv = [*(command_prefix or []), unshare, "--user", "--map-root-user", "true"]
    try:
        result = subprocess.run(
            argv,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("could not validate the Chrome user-namespace sandbox") from exc
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise RuntimeError(f"Chrome user-namespace sandbox is unavailable{suffix}")


def invoking_identity() -> RuntimeIdentity:
    uid = os.geteuid()
    gid = os.getegid()
    if uid == 0:
        sudo_uid = os.environ.get("SUDO_UID")
        sudo_gid = os.environ.get("SUDO_GID")
        if sudo_uid and sudo_gid and int(sudo_uid) > 0:
            uid = int(sudo_uid)
            gid = int(sudo_gid)
        else:
            account = pwd.getpwnam("nobody")
            uid = account.pw_uid
            gid = account.pw_gid
    account = pwd.getpwuid(uid)
    return RuntimeIdentity(uid, gid, Path(account.pw_dir))


def drop_prefix(identity: RuntimeIdentity) -> list[str]:
    return [
        "setpriv",
        f"--reuid={identity.uid}",
        f"--regid={identity.gid}",
        "--clear-groups",
        "--",
    ]


def chown_tree(path: Path, identity: RuntimeIdentity) -> None:
    os.chown(path, identity.uid, identity.gid)
    for item in path.rglob("*"):
        os.chown(item, identity.uid, identity.gid, follow_symlinks=False)


def resolve_pinned_node(
    explicit: Path | None,
    *,
    allow_mismatch: bool,
    bootstrap: bool,
) -> tuple[Path, str, bool]:
    node: Path | None = None
    if explicit:
        candidate = explicit.expanduser().resolve()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            node = candidate
        else:
            raise RuntimeError(f"Node executable not found: {candidate}")
    else:
        found = shutil.which("node")
        if found:
            node = Path(found).resolve()

    version = command_version([str(node), "--version"]) if node else "unavailable"
    expected_prefix = f"v{PINNED_NODE_VERSION.rsplit('.', 1)[0]}."
    if node and (version.startswith(expected_prefix) or allow_mismatch):
        return node, version, False
    if explicit:
        raise RuntimeError(
            f"Node {expected_prefix[1:]}x is required (found {version}); "
            "use --allow-node-version-mismatch only for functional testing"
        )
    if not bootstrap:
        raise RuntimeError(
            f"Node {expected_prefix[1:]}x is required (found {version}); "
            "remove --no-node-bootstrap or pass --node"
        )

    npx = shutil.which("npx")
    if not npx:
        raise RuntimeError(
            f"Node {expected_prefix[1:]}x is required (found {version}) and npx is unavailable"
        )
    identity = invoking_identity()
    argv: list[str] = []
    if os.geteuid() == 0:
        argv.extend(drop_prefix(identity))
    argv.extend([
        "env",
        f"HOME={identity.home}",
        npx,
        "--yes",
        f"node@{PINNED_NODE_VERSION}",
        "-p",
        "process.execPath",
    ])
    result = subprocess.run(
        argv,
        cwd=identity.home,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"could not provision Node {PINNED_NODE_VERSION} through npx:\n"
            f"{result.stdout.strip()}"
        )
    for line in reversed(result.stdout.splitlines()):
        candidate = Path(line.strip())
        if candidate.is_absolute() and candidate.is_file() and os.access(candidate, os.X_OK):
            resolved_version = command_version([str(candidate), "--version"])
            if resolved_version.startswith(expected_prefix):
                return candidate.resolve(), resolved_version, True
    raise RuntimeError("npx completed but did not return a usable Node executable")


def parse_rates(output: str) -> dict[str, dict[str, float]]:
    rates: dict[str, dict[str, float]] = {}
    for row, mib, seconds, mib_s, mbit_s in RATE_RE.findall(output):
        rates[row.lower()] = {
            "mib": float(mib),
            "seconds": float(seconds),
            "mib_per_second": float(mib_s),
            "mbit_per_second": float(mbit_s),
        }
    return rates
