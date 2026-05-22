#!/usr/bin/env python3
"""
YUME localhost latency benchmark.

Spins up yumed + yume client on 127.0.0.1 for each protocol
configuration, drives a small echo loop through the SOCKS5
tunnel, and reports median + p95 round-trip latency per config.
The "base-noise" config measures direct loopback echo with no
yume in the path — that's the system floor (~0.05–0.5 ms on
most boxes; treat anything below that as a measurement artifact).

Configurations exercised (out of the box):

    base-noise          direct loopback echo, no yume
    no-inner            yume with --no-inner (raw TLS proxy, no PQ)
    inner-light         --inner-light, no key hopping
    inner-light-1Hz     --inner-light --hop --hop-interval 1000
    inner-light-2Hz     --inner-light --hop --hop-interval 500
    inner-light-4Hz     --inner-light --hop --hop-interval 250
    inner-heavy         --inner-heavy, no hop
    inner-heavy-2Hz     --inner-heavy --hop --hop-interval 500

The yume "overhead" is reported as (config median - base-noise
median) in milliseconds — that's the per-roundtrip cost of the
yume protocol stack, isolated from the kernel TCP stack and
echo-server loop.

Usage:
    scripts/yume_bench_localhost.py
    scripts/yume_bench_localhost.py --iters 500
    scripts/yume_bench_localhost.py --configs base-noise,inner-light
    scripts/yume_bench_localhost.py --json out.json
    scripts/yume_bench_localhost.py --yume build/bin/yume \\
                                    --yumed build/bin/yumed

Outputs a JSON document (default: stdout, or --json <path>) and a
human-readable summary table on stderr. Exit 0 on success, non-zero
on setup failure or if any config could not complete.

Resource guards (CPU + memory caps from scripts/lib/resource_guards.sh
if available) are applied opt-in via --guards. The bench itself is
light (small TCP roundtrips), but the yume binary startup involves
TLS handshake + PQ key derivation, so on weak hosts you may want
the guards.

This script DOES NOT exercise the full encryption stack at scale —
test_all.sh already covers byte-level cross-runtime parity. The
bench's job is to measure the *protocol delay* you'd observe in a
real interactive workload (one frame in → one frame out).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_YUMED = REPO_ROOT / "build" / "bin" / "yumed"
DEFAULT_YUME = REPO_ROOT / "build" / "bin" / "yume"


# ---------------------------------------------------------------------
# Configuration matrix
# ---------------------------------------------------------------------

@dataclass
class Config:
    """One bench config. `server_flags` are appended to yumed; `client_flags`
    to yume. base_noise=True means skip yume entirely and just hit the echo
    server directly through TCP (system floor)."""
    name: str
    description: str
    base_noise: bool = False
    server_flags: list[str] = field(default_factory=list)
    client_flags: list[str] = field(default_factory=list)


BUILTIN_CONFIGS: list[Config] = [
    Config(
        name="base-noise",
        description="Direct loopback TCP echo, no yume in the path. System floor.",
        base_noise=True,
    ),
    Config(
        name="no-inner",
        description="Plain TLS proxy, --no-inner. Outer TLS + obfs only.",
        server_flags=["--no-inner"],
        client_flags=["--no-inner"],
    ),
    Config(
        name="inner-light",
        description="Inner crypto (light KDF) + AES-GCM. No hop.",
        server_flags=["--inner-light", "--no-hop"],
        client_flags=["--inner-light", "--no-hop"],
    ),
    Config(
        name="inner-light-1Hz",
        description="Inner light + key hop every 1000 ms (1 Hz).",
        server_flags=["--inner-light", "--hop", "--hop-interval", "1000"],
        client_flags=["--inner-light", "--hop", "--hop-interval", "1000"],
    ),
    Config(
        name="inner-light-2Hz",
        description="Inner light + key hop every 500 ms (2 Hz).",
        server_flags=["--inner-light", "--hop", "--hop-interval", "500"],
        client_flags=["--inner-light", "--hop", "--hop-interval", "500"],
    ),
    Config(
        name="inner-light-4Hz",
        description="Inner light + key hop every 250 ms (4 Hz).",
        server_flags=["--inner-light", "--hop", "--hop-interval", "250"],
        client_flags=["--inner-light", "--hop", "--hop-interval", "250"],
    ),
    Config(
        name="inner-heavy",
        description="Inner heavy (Argon2id KDF) + AES-GCM. No hop.",
        server_flags=["--inner-heavy", "--no-hop"],
        client_flags=["--inner-heavy", "--no-hop"],
    ),
    Config(
        name="inner-heavy-2Hz",
        description="Inner heavy + key hop every 500 ms (2 Hz).",
        server_flags=["--inner-heavy", "--hop", "--hop-interval", "500"],
        client_flags=["--inner-heavy", "--hop", "--hop-interval", "500"],
    ),
]


# ---------------------------------------------------------------------
# Echo server: tiny TCP server that echoes incoming bytes back. Used as
# the "target" for the round-trip latency measurement.
# ---------------------------------------------------------------------

class EchoServer:
    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.sock: socket.socket | None = None
        self.port: int | None = None
        self.thread: threading.Thread | None = None
        self.stop_flag = threading.Event()

    def start(self) -> int:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(128)
        self.sock.settimeout(0.25)
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()
        return self.port

    def _accept_loop(self) -> None:
        while not self.stop_flag.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn: socket.socket) -> None:
        conn.settimeout(2.0)
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(data)
        except (OSError, socket.timeout):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self.stop_flag.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------
# SOCKS5 client: minimal CONNECT-only implementation. The yume client's
# default SOCKS port is consumed via this helper.
# ---------------------------------------------------------------------

def socks5_connect(socks_host: str, socks_port: int,
                   target_host: str, target_port: int,
                   timeout: float = 10.0) -> socket.socket:
    """Open a TCP socket to `target_host:target_port` via SOCKS5 proxy at
    `socks_host:socks_port`. Returns a connected socket on success."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((socks_host, socks_port))
    # RFC 1928: greeting — version 5, 1 method, no-auth (0x00)
    sock.sendall(b"\x05\x01\x00")
    reply = sock.recv(2)
    if len(reply) != 2 or reply[0] != 5 or reply[1] != 0:
        sock.close()
        raise RuntimeError(f"SOCKS5 greeting rejected: {reply!r}")
    # CONNECT request: ver 5, CONNECT (0x01), reserved (0x00), addr-type
    # IPv4 (0x01), 4-byte addr, 2-byte port BE
    addr = socket.inet_aton(target_host)
    req = b"\x05\x01\x00\x01" + addr + struct.pack(">H", target_port)
    sock.sendall(req)
    head = sock.recv(4)
    if len(head) != 4 or head[0] != 5 or head[1] != 0:
        sock.close()
        raise RuntimeError(f"SOCKS5 CONNECT rejected: head={head!r}")
    # Consume the bound-addr reply (we don't need it, just drain it).
    atype = head[3]
    if atype == 0x01:
        sock.recv(4 + 2)
    elif atype == 0x03:
        ln = sock.recv(1)
        sock.recv(ln[0] + 2)
    elif atype == 0x04:
        sock.recv(16 + 2)
    else:
        sock.close()
        raise RuntimeError(f"SOCKS5 unknown addr type: {atype}")
    return sock


# ---------------------------------------------------------------------
# Yume process orchestration
# ---------------------------------------------------------------------

@dataclass
class YumeKeyset:
    workdir: Path
    server_cert: Path
    server_key: Path
    auth_keys_file: Path     # server's authorized_keys
    client_identity: Path    # client's private identity key


def generate_keyset(workdir: Path, yumed_bin: Path) -> YumeKeyset:
    """Generate self-signed TLS cert + an Ed25519 keypair for client auth."""
    ks = YumeKeyset(
        workdir=workdir,
        server_cert=workdir / "server.crt",
        server_key=workdir / "server.key",
        auth_keys_file=workdir / "authorized_keys",
        client_identity=workdir / "client.key",
    )
    # TLS cert (self-signed, 1-day validity is plenty for a bench run).
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ed25519",
            "-keyout", str(ks.server_key),
            "-out", str(ks.server_cert),
            "-days", "1", "-nodes",
            "-subj", "/CN=localhost",
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    # Client identity key — use yumed's own --keys-gen so the format is
    # exactly what the server expects.
    keys_prefix = workdir / "client"
    subprocess.run(
        [str(yumed_bin), "--keys-gen", str(keys_prefix)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    # yumed generates <prefix>.key (private) and <prefix>.pub (public).
    pub = workdir / "client.pub"
    if not pub.exists():
        raise FileNotFoundError(f"expected {pub} after --keys-gen")
    # The server's authorized_keys file is just the public key(s) line
    # by line. One key is enough for the bench.
    ks.auth_keys_file.write_bytes(pub.read_bytes())
    return ks


@contextmanager
def run_yume_stack(yumed_bin: Path, yume_bin: Path, ks: YumeKeyset,
                   server_flags: list[str], client_flags: list[str],
                   yume_port: int, socks_port: int,
                   stderr_dir: Path) -> Iterator[None]:
    """Start yumed then yume client, yield once both are listening,
    teardown on exit."""
    server_log = open(stderr_dir / "yumed.log", "wb")
    client_log = open(stderr_dir / "yume.log", "wb")

    server_argv = [
        str(yumed_bin),
        "--listen", f"127.0.0.1:{yume_port}",
        "--cert", str(ks.server_cert),
        "--key", str(ks.server_key),
        "--auth-keys", str(ks.auth_keys_file),
        "--pq-auto-generate",
        "--allow-local-ip",
        "--threads", "2",
        "--boring",
    ] + server_flags

    server_proc = subprocess.Popen(
        server_argv,
        stdout=server_log, stderr=subprocess.STDOUT,
    )
    try:
        # Wait for yumed to be listening.
        if not wait_port_listening("127.0.0.1", yume_port, timeout=10.0):
            raise RuntimeError(
                f"yumed did not listen on :{yume_port} (see {server_log.name})"
            )

        client_argv = [
            str(yume_bin),
            "--server", "127.0.0.1",
            "--port", str(yume_port),
            "--auth", str(ks.client_identity),
            "--socks", str(socks_port),
            "--allow-local-ip",
            "--non-interactive",
            "--boring",
            "--no-stealth",
            "--tls-ca", str(ks.server_cert),
        ] + client_flags
        client_proc = subprocess.Popen(
            client_argv,
            stdout=client_log, stderr=subprocess.STDOUT,
        )
        try:
            if not wait_port_listening("127.0.0.1", socks_port, timeout=15.0):
                raise RuntimeError(
                    f"yume client did not bind SOCKS :{socks_port} "
                    f"(see {client_log.name})"
                )
            yield
        finally:
            client_proc.terminate()
            try:
                client_proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                client_proc.kill()
                client_proc.wait()
    finally:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            server_proc.wait()
        server_log.close()
        client_log.close()


def wait_port_listening(host: str, port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(0.1)
    return False


# ---------------------------------------------------------------------
# Bench loop: drive N roundtrips through a SOCKS5 tunnel, return the
# raw per-iteration latencies in microseconds.
# ---------------------------------------------------------------------

def measure_roundtrips_socks(socks_port: int, echo_host: str, echo_port: int,
                             iters: int, payload_size: int = 64) -> list[float]:
    """Measure round-trip latency of `iters` echo bounces through SOCKS5.
    Returns latencies in milliseconds."""
    payload = os.urandom(payload_size)
    latencies_ms: list[float] = []
    sock = socks5_connect("127.0.0.1", socks_port, echo_host, echo_port)
    try:
        # Discard one warm-up roundtrip — the first frame through any
        # tunnel pays the warm-up cost.
        sock.sendall(payload)
        _ = sock.recv(payload_size)

        for _ in range(iters):
            t0 = time.perf_counter()
            sock.sendall(payload)
            received = b""
            while len(received) < payload_size:
                chunk = sock.recv(payload_size - len(received))
                if not chunk:
                    raise RuntimeError("echo connection closed mid-bench")
                received += chunk
            t1 = time.perf_counter()
            if received != payload:
                raise RuntimeError("echo payload mismatch — protocol drift?")
            latencies_ms.append((t1 - t0) * 1000.0)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return latencies_ms


def measure_roundtrips_direct(echo_host: str, echo_port: int,
                              iters: int, payload_size: int = 64) -> list[float]:
    """Same as above but with NO SOCKS proxy — direct TCP to the echo
    server. Used to measure base noise (system floor)."""
    payload = os.urandom(payload_size)
    latencies_ms: list[float] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((echo_host, echo_port))
    try:
        sock.sendall(payload)
        _ = sock.recv(payload_size)

        for _ in range(iters):
            t0 = time.perf_counter()
            sock.sendall(payload)
            received = b""
            while len(received) < payload_size:
                chunk = sock.recv(payload_size - len(received))
                if not chunk:
                    raise RuntimeError("echo connection closed mid-bench")
                received += chunk
            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)
    finally:
        sock.close()
    return latencies_ms


# ---------------------------------------------------------------------
# Stats summary
# ---------------------------------------------------------------------

@dataclass
class Stats:
    n: int
    min_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    mean_ms: float
    stdev_ms: float

    @classmethod
    def of(cls, samples: list[float]) -> "Stats":
        if not samples:
            return cls(0, 0, 0, 0, 0, 0, 0, 0)
        s = sorted(samples)
        n = len(s)
        return cls(
            n=n,
            min_ms=s[0],
            median_ms=statistics.median(s),
            p95_ms=s[min(n - 1, int(round(0.95 * n)) - 1)] if n >= 2 else s[0],
            p99_ms=s[min(n - 1, int(round(0.99 * n)) - 1)] if n >= 2 else s[0],
            max_ms=s[-1],
            mean_ms=statistics.mean(s),
            stdev_ms=statistics.stdev(s) if n >= 2 else 0.0,
        )


# ---------------------------------------------------------------------
# Bench driver
# ---------------------------------------------------------------------

def run_one_config(cfg: Config, ctx: dict, iters: int) -> dict:
    """Returns a result dict for cfg."""
    echo_host = "127.0.0.1"
    echo_port = ctx["echo_port"]
    yumed_bin = ctx["yumed_bin"]
    yume_bin = ctx["yume_bin"]
    ks = ctx["keyset"]
    yume_port = ctx["yume_port"]
    socks_port = ctx["socks_port"]
    stderr_dir = ctx["stderr_dir"] / cfg.name
    stderr_dir.mkdir(parents=True, exist_ok=True)

    t_start = time.monotonic()
    try:
        if cfg.base_noise:
            latencies = measure_roundtrips_direct(echo_host, echo_port, iters)
        else:
            with run_yume_stack(
                yumed_bin, yume_bin, ks,
                cfg.server_flags, cfg.client_flags,
                yume_port, socks_port, stderr_dir,
            ):
                # Small grace period so the tunnel is fully ready.
                time.sleep(0.2)
                latencies = measure_roundtrips_socks(
                    socks_port, echo_host, echo_port, iters,
                )
        elapsed = time.monotonic() - t_start
        return {
            "name": cfg.name,
            "description": cfg.description,
            "base_noise": cfg.base_noise,
            "server_flags": cfg.server_flags,
            "client_flags": cfg.client_flags,
            "iters": len(latencies),
            "wall_time_s": elapsed,
            "stats_ms": Stats.of(latencies).__dict__,
            "samples_ms": latencies,
            "ok": True,
        }
    except Exception as exc:
        elapsed = time.monotonic() - t_start
        return {
            "name": cfg.name,
            "description": cfg.description,
            "base_noise": cfg.base_noise,
            "server_flags": cfg.server_flags,
            "client_flags": cfg.client_flags,
            "iters": 0,
            "wall_time_s": elapsed,
            "stats_ms": Stats.of([]).__dict__,
            "samples_ms": [],
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def render_summary(results: list[dict]) -> str:
    """Pretty-print a summary table to stderr."""
    base_noise = next((r for r in results if r.get("base_noise") and r["ok"]), None)
    base_median = base_noise["stats_ms"]["median_ms"] if base_noise else None

    lines = []
    lines.append("")
    lines.append("YUME localhost bench — round-trip latency (smaller is better)")
    lines.append("=" * 80)
    lines.append(
        f"{'config':<22} {'iters':>6} {'med ms':>8} {'p95':>7} {'p99':>7} "
        f"{'stdev':>7} {'Δ med vs base':>15}"
    )
    lines.append("-" * 80)
    for r in results:
        if not r["ok"]:
            lines.append(f"{r['name']:<22} FAILED — {r.get('error', '?')[:50]}")
            continue
        s = r["stats_ms"]
        if base_median is not None and not r["base_noise"]:
            delta = s["median_ms"] - base_median
            delta_str = f"+{delta:>5.2f} ms"
        elif r["base_noise"]:
            delta_str = "(base)"
        else:
            delta_str = "—"
        lines.append(
            f"{r['name']:<22} "
            f"{r['iters']:>6} "
            f"{s['median_ms']:>8.3f} "
            f"{s['p95_ms']:>7.3f} "
            f"{s['p99_ms']:>7.3f} "
            f"{s['stdev_ms']:>7.3f} "
            f"{delta_str:>15}"
        )
    lines.append("=" * 80)
    lines.append("Δ med vs base = added latency contributed by the yume stack.")
    lines.append("Stdev ~ 1ms or less is normal for loopback; higher = noisy host.")
    return "\n".join(lines)


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iters", type=int, default=200,
                    help="iterations per config (default 200)")
    ap.add_argument("--configs", type=str, default="",
                    help="comma-separated subset of config names (default: all)")
    ap.add_argument("--yume", type=Path, default=DEFAULT_YUME,
                    help=f"path to yume client binary (default {DEFAULT_YUME})")
    ap.add_argument("--yumed", type=Path, default=DEFAULT_YUMED,
                    help=f"path to yumed daemon binary (default {DEFAULT_YUMED})")
    ap.add_argument("--json", type=Path, default=None,
                    help="write JSON results to this path (default: stdout)")
    ap.add_argument("--list-configs", action="store_true",
                    help="print the available config names and exit")
    args = ap.parse_args()

    if args.list_configs:
        for c in BUILTIN_CONFIGS:
            mark = "  [base]" if c.base_noise else ""
            print(f"  {c.name:<22} {c.description}{mark}")
        return 0

    # Pick configs.
    if args.configs:
        wanted = {n.strip() for n in args.configs.split(",") if n.strip()}
        configs = [c for c in BUILTIN_CONFIGS if c.name in wanted]
        missing = wanted - {c.name for c in configs}
        if missing:
            print(f"unknown configs: {sorted(missing)}", file=sys.stderr)
            return 2
    else:
        configs = BUILTIN_CONFIGS[:]

    # Need binaries (except for base-noise-only runs).
    needs_yume = any(not c.base_noise for c in configs)
    if needs_yume:
        for label, p in (("yume", args.yume), ("yumed", args.yumed)):
            if not p.exists() or not os.access(p, os.X_OK):
                print(f"FATAL: {label} binary not found / not executable: {p}",
                      file=sys.stderr)
                print(f"       build with: cmake --build build  (or pass --{label} <path>)",
                      file=sys.stderr)
                return 2
        if not shutil.which("openssl"):
            print("FATAL: openssl not on PATH (needed for self-signed TLS cert)",
                  file=sys.stderr)
            return 2

    workdir = Path(tempfile.mkdtemp(prefix="yume-bench-"))
    stderr_dir = workdir / "logs"
    stderr_dir.mkdir(parents=True, exist_ok=True)

    try:
        echo = EchoServer()
        echo_port = echo.start()

        keyset = None
        if needs_yume:
            keyset = generate_keyset(workdir, args.yumed)

        # Pick fixed-ish ports per run — high range to avoid clashing
        # with anything the user is running on the host.
        yume_port = 19443
        socks_port = 19440

        ctx = {
            "echo_port": echo_port,
            "yumed_bin": args.yumed,
            "yume_bin": args.yume,
            "keyset": keyset,
            "yume_port": yume_port,
            "socks_port": socks_port,
            "stderr_dir": stderr_dir,
            "workdir": workdir,
        }

        results = []
        for cfg in configs:
            print(f"[bench] {cfg.name}: {cfg.description}", file=sys.stderr)
            r = run_one_config(cfg, ctx, args.iters)
            if r["ok"]:
                s = r["stats_ms"]
                print(f"        median={s['median_ms']:.3f} ms  "
                      f"p95={s['p95_ms']:.3f}  iters={r['iters']}  "
                      f"({r['wall_time_s']:.1f}s wall)", file=sys.stderr)
            else:
                print(f"        FAILED: {r.get('error', '?')}", file=sys.stderr)
                print(f"        logs in {stderr_dir / cfg.name}", file=sys.stderr)
            results.append(r)

        echo.stop()

        # Output.
        output = {
            "schema_version": 1,
            "generated_at_unix": int(time.time()),
            "iters_per_config": args.iters,
            "configs": results,
        }
        if args.json:
            args.json.write_text(json.dumps(output, indent=2))
            print(f"[bench] JSON results written to {args.json}", file=sys.stderr)
        else:
            print(json.dumps(output, indent=2))

        # Human summary always to stderr.
        print(render_summary(results), file=sys.stderr)

        all_ok = all(r["ok"] for r in results)
        return 0 if all_ok else 1
    finally:
        # Leave the workdir on failure so logs can be inspected; clean
        # up on success. The bench writes nothing security-sensitive.
        all_ok = False
        try:
            all_ok = all(r["ok"] for r in results) if "results" in locals() else False
        except Exception:
            pass
        if all_ok and "--keep-workdir" not in sys.argv:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print(f"[bench] workdir preserved at {workdir}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
