#!/usr/bin/env python3
"""yume virtual-WAN bench + DPI-comparison harness.

Spins up yumed + yume client in separate Linux network namespaces
connected by a veth pair, applies a configurable WAN profile via
tc-netem, runs an HTTPS GET workload over the yume tunnel, and runs
the same workload directly as a baseline arm (curl, optionally
chromium --headless). Captures pcap from each arm, classifies via
ndpiReader, emits a side-by-side report.

Default workload is a 1 MB HTTPS GET, repeated 3 times per arm
(median + p95). Chosen because:
  - 1 MB is large enough that throughput matters (not just connection setup)
  - finishes quickly per repeat under realistic mobile profiles (~0.5-2s)
  - HTTP-style transfer is well within ndpiReader's classification scope
  - one tool (curl) covers both yume and baseline arms — apples to apples

WAN profiles ship with four presets; override individual knobs with
--latency / --loss / --bandwidth. Each profile applies symmetrically
(both veth ends get the same netem qdisc; half the configured latency
on each side so round-trip ~= configured).

Usage:
    sudo python3 scripts/yume_bench_wan.py
    sudo python3 scripts/yume_bench_wan.py --profile mobile-4g
    sudo python3 scripts/yume_bench_wan.py --latency 100 --loss 2 --bandwidth 50
    sudo python3 scripts/yume_bench_wan.py --baseline curl --baseline chromium
    sudo python3 scripts/yume_bench_wan.py --quick
    sudo python3 scripts/yume_bench_wan.py --json out.json --report out.md

Run as root (or via sudo). The harness creates two yume-bench-*
namespaces and a veth pair, applies tc qdiscs, and tears them all
down on exit, on Ctrl-C, AND on the next-run pre-cleanup pass if a
prior run was killed with SIGKILL.

Constraints:
  - Python 3.11+, iproute2, tcpdump, curl, openssl in PATH (required).
  - libndpi-bin (Debian 13 package; provides /usr/bin/ndpiReader) for
    the DPI arm. NOTE: the brief mentioned `ndpi-tools` — on Debian 13
    that package is named `libndpi-bin`. Install with:
      apt install libndpi-bin
    If missing, DPI is skipped with a warning rather than failing.
  - Yume binaries must exist at build/bin/yume{,d}. The harness does
    not build them; build them on a dedicated build machine rather
    than a low-RAM laptop.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable

# Reuse keyset generation + Stats from the localhost bench. Pulling the
# helpers in by import rather than copying keeps the two scripts in sync.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from yume_bench_localhost import (  # noqa: E402
    YumeKeyset,
    generate_keyset,
    wait_port_listening,
    Stats,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_YUMED = REPO_ROOT / "build" / "bin" / "yumed"
DEFAULT_YUME = REPO_ROOT / "build" / "bin" / "yume"

# ---------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------

NETNS_SERVER = "yume-bench-srv"
NETNS_CLIENT = "yume-bench-cli"
# Linux IFNAMSIZ caps interface names at 15 chars. Pick short names.
VETH_SERVER = "vyumebsrv"
VETH_CLIENT = "vyumebcli"
# Use 11.0.0.0/24 (DoD-assigned but unrouted in practice). yumed's
# is_private_ipv4 (src/server/session.cpp:71) classifies the RFC 1918
# private blocks, RFC 6598 CGNAT, RFC 5737 test-nets, and IETF reserved
# 192.0/24 / 198.18-19/15 / 198.51/16 / 203.0/24 all as "private" — and
# the SOCKS open path rejects with "blocked destination" unless
# --allow-local-ip is set (which would trigger the LAN-bridging crash
# path) or --control-full is granted (which requires
# YUME_FEATURE_FULL_CONTROL=ON in the build, which is off here). Plain
# 11.x sidesteps the private-IP filter without poking either crash path.
# Inside the netns it can't escape regardless.
SERVER_IP = "11.0.0.1"
CLIENT_IP = "11.0.0.2"

YUME_PORT = 19443       # yumed listens here in NETNS_SERVER
SOCKS_PORT = 19440      # yume client SOCKS5, in NETNS_CLIENT
HTTPS_PORT = 8443       # HTTPS payload server, in NETNS_SERVER

PAYLOAD_BYTES = 32_768  # 32 KB — sized below the 64KB write-batch
# corruption boundary in this yumed build (kMaxWriteBatchBytes,
# session.cpp:63). Brief asked for 1 MB; the 1MB target trips a yumed
# bug that truncates the tunnel mid-transfer with a TLS decode error.
# Document and re-raise once yumed is fixed.


# ---------------------------------------------------------------------
# WAN profile presets — top-of-file so it's easy to extend
# ---------------------------------------------------------------------

PROFILES: dict[str, dict[str, Any]] = {
    "lan": dict(
        latency_ms=1, jitter_ms=0, loss_pct=0.0, bandwidth_mbit=1000,
        label="LAN — 1 ms, 0% loss, 1 Gbps",
    ),
    "broadband": dict(
        latency_ms=20, jitter_ms=2, loss_pct=0.1, bandwidth_mbit=200,
        label="Broadband — 20 ms ± 2 ms, 0.1% loss, 200 Mbps",
    ),
    "mobile-4g": dict(
        latency_ms=50, jitter_ms=5, loss_pct=1.0, bandwidth_mbit=50,
        label="Mobile 4G — 50 ms ± 5 ms, 1% loss, 50 Mbps",
    ),
    "lossy-wifi": dict(
        latency_ms=30, jitter_ms=10, loss_pct=3.0, bandwidth_mbit=30,
        label="Lossy Wi-Fi — 30 ms ± 10 ms, 3% loss, 30 Mbps",
    ),
}


# ---------------------------------------------------------------------
# Cleanup registry — runs on normal exit, on SIGINT/SIGTERM, and
# (defensively) at the START of every run via pre_cleanup() in case a
# prior invocation was SIGKILL'd and never got to clean up.
# ---------------------------------------------------------------------

_cleanup_actions: list[Callable[[], None]] = []


def register_cleanup(fn: Callable[[], None]) -> None:
    _cleanup_actions.append(fn)


def run_cleanup() -> None:
    while _cleanup_actions:
        fn = _cleanup_actions.pop()
        try:
            fn()
        except Exception as exc:
            print(f"[bench] cleanup warning: {exc}", file=sys.stderr)


atexit.register(run_cleanup)


def _signal_handler(signum: int, _frame: Any) -> None:
    print(f"\n[bench] received signal {signum}, cleaning up...", file=sys.stderr)
    run_cleanup()
    raise SystemExit(128 + signum)


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ---------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------

def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    input_text: str | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=capture,
        input=input_text,
        timeout=timeout,
    )


def run_quiet(cmd: list[str]) -> int:
    """Run and swallow output; return exit code. Used for idempotent cleanup."""
    return subprocess.call(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def ns_prefix(netns: str) -> list[str]:
    return ["ip", "netns", "exec", netns]


# ---------------------------------------------------------------------
# Prereqs & root check
# ---------------------------------------------------------------------

REQUIRED_TOOLS = ["ip", "tc", "tcpdump", "curl", "openssl"]
OPTIONAL_TOOLS = ["ndpiReader", "chromium", "iperf3", "ping"]


def require_root() -> bool:
    if os.geteuid() == 0:
        return True
    argv = " ".join([sys.executable] + sys.argv)
    print(
        "FATAL: yume_bench_wan.py needs root (ip netns / tc / tcpdump).\n"
        f"       re-run with: sudo -E {argv}",
        file=sys.stderr,
    )
    return False


def check_prereqs() -> tuple[bool, dict[str, bool]]:
    have = {t: shutil.which(t) is not None for t in REQUIRED_TOOLS + OPTIONAL_TOOLS}
    missing = [t for t in REQUIRED_TOOLS if not have[t]]
    if missing:
        print(
            f"FATAL: missing required tools: {missing}\n"
            f"       apt install iproute2 tcpdump curl openssl",
            file=sys.stderr,
        )
        return False, have
    if not have["ndpiReader"]:
        print(
            "[bench] note: ndpiReader not found — DPI classification disabled.\n"
            "       install on Debian 13: apt install libndpi-bin",
            file=sys.stderr,
        )
    return True, have


# ---------------------------------------------------------------------
# Network namespace + veth setup
# ---------------------------------------------------------------------

def pre_cleanup() -> None:
    """Wipe any leftover yume-bench state from a prior run that crashed
    or was killed with SIGKILL. Idempotent — safe to call when nothing
    is left."""
    for nn in (NETNS_SERVER, NETNS_CLIENT):
        run_quiet(["ip", "netns", "del", nn])
    for veth in (VETH_SERVER, VETH_CLIENT):
        run_quiet(["ip", "link", "del", veth])


def setup_netns() -> None:
    """Build the two-netns topology. Registers teardown for clean exit
    paths; SIGKILL paths rely on pre_cleanup() of the next run."""
    pre_cleanup()
    run(["ip", "netns", "add", NETNS_SERVER])
    register_cleanup(lambda: run_quiet(["ip", "netns", "del", NETNS_SERVER]))
    run(["ip", "netns", "add", NETNS_CLIENT])
    register_cleanup(lambda: run_quiet(["ip", "netns", "del", NETNS_CLIENT]))

    run([
        "ip", "link", "add", VETH_CLIENT,
        "type", "veth", "peer", "name", VETH_SERVER,
    ])
    # The veth pair gets moved into the netns below — when both netns are
    # deleted, the veth pair is destroyed automatically.

    run(["ip", "link", "set", VETH_SERVER, "netns", NETNS_SERVER])
    run(["ip", "link", "set", VETH_CLIENT, "netns", NETNS_CLIENT])

    run(ns_prefix(NETNS_SERVER) + ["ip", "addr", "add", f"{SERVER_IP}/24", "dev", VETH_SERVER])
    run(ns_prefix(NETNS_CLIENT) + ["ip", "addr", "add", f"{CLIENT_IP}/24", "dev", VETH_CLIENT])
    for nn, iface in ((NETNS_SERVER, VETH_SERVER), (NETNS_CLIENT, VETH_CLIENT)):
        run(ns_prefix(nn) + ["ip", "link", "set", iface, "up"])
        run(ns_prefix(nn) + ["ip", "link", "set", "lo", "up"])


def apply_netem(latency_ms: int, jitter_ms: int, loss_pct: float, bandwidth_mbit: int) -> None:
    """Apply symmetric netem on both veth ends.

    half the configured one-way latency goes on each side, so a 50 ms
    profile yields ~100 ms RTT. loss_pct is per-direction; same on each
    side. bandwidth_mbit caps egress rate (netem's built-in rate option,
    available since kernel 4.9)."""
    half = max(1, latency_ms // 2)
    for nn, iface in ((NETNS_SERVER, VETH_SERVER), (NETNS_CLIENT, VETH_CLIENT)):
        argv = ns_prefix(nn) + [
            "tc", "qdisc", "replace", "dev", iface, "root", "netem",
            "delay", f"{half}ms", f"{jitter_ms}ms",
            "loss", f"{loss_pct}%",
        ]
        if bandwidth_mbit > 0:
            argv += ["rate", f"{bandwidth_mbit}mbit"]
        run(argv)


# ---------------------------------------------------------------------
# HTTPS payload server — runs inside NETNS_SERVER, serves /payload as
# a fixed-size random byte string. We use Python's stdlib http.server +
# ssl.SSLContext for zero extra deps.
# ---------------------------------------------------------------------

HTTPS_SERVER_SNIPPET = r"""
import http.server, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    # HTTP/1.1 + Content-Length + Connection: close lets the client read
    # the body to completion and observe a clean TLS close, not a TLS
    # truncation. HTTP/1.0 (the default) leaves curl seeing
    # SSL_read: unexpected eof.
    protocol_version = "HTTP/1.1"
    def log_message(self, *a, **kw): pass
    def do_GET(self):
        if self.path == '/payload':
            with open(__PAYLOAD__, 'rb') as f:
                body = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(__CRT__, __KEY__)
srv = http.server.ThreadingHTTPServer((__BIND__, __PORT__), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
"""


def make_self_signed_cert(workdir: Path, cn: str) -> tuple[Path, Path]:
    crt = workdir / "https.crt"
    key = workdir / "https.key"
    run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(crt),
            "-days", "1", "-nodes",
            "-subj", f"/CN={cn}",
            "-addext", f"subjectAltName=IP:{cn}",
        ],
        capture=True,
    )
    return crt, key


def start_https_server(
    netns: str,
    bind_ip: str,
    port: int,
    payload: Path,
    crt: Path,
    key: Path,
    log: Path,
) -> subprocess.Popen:
    snippet = (
        HTTPS_SERVER_SNIPPET
        .replace("__PAYLOAD__", repr(str(payload)))
        .replace("__CRT__", repr(str(crt)))
        .replace("__KEY__", repr(str(key)))
        .replace("__BIND__", repr(bind_ip))
        .replace("__PORT__", repr(port))
    )
    log_fp = open(log, "wb")
    proc = subprocess.Popen(
        ns_prefix(netns) + [sys.executable, "-c", snippet],
        stdout=log_fp, stderr=subprocess.STDOUT,
    )

    def _stop() -> None:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        log_fp.close()

    register_cleanup(_stop)
    # Poll for the port being open from inside the server netns.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        r = subprocess.call(
            ns_prefix(netns) + ["bash", "-c", f"</dev/tcp/{bind_ip}/{port}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if r == 0:
            return proc
        time.sleep(0.1)
    raise RuntimeError(f"HTTPS payload server didn't start at {bind_ip}:{port}")


# ---------------------------------------------------------------------
# yumed / yume spawn in netns
# ---------------------------------------------------------------------

def start_yume_stack(
    yumed_bin: Path,
    yume_bin: Path,
    ks: YumeKeyset,
    log_dir: Path,
) -> tuple[subprocess.Popen, subprocess.Popen, float]:
    """Spawn yumed in server netns + yume client in client netns. Returns
    (server_proc, client_proc, handshake_seconds) where handshake_seconds
    is the wall-clock time from yume client spawn until its SOCKS port
    becomes reachable (i.e., TLS+AUTH+PQ handshake complete)."""
    server_log = open(log_dir / "yumed.log", "wb")
    client_log = open(log_dir / "yume.log", "wb")

    # yumed's --listen takes a bare port (it parses "ip:port" as just the
    # leading integer — easy to miss). Bind 0.0.0.0:YUME_PORT inside the
    # server netns; the client reaches it via SERVER_IP:YUME_PORT through
    # the veth.
    #
    # --pq-auto-generate writes the PQ keypair into ./.secrets/ (relative
    # to CWD). Set cwd to the bench workdir so the keypair lands in a
    # predictable spot we can point the client at via --pq-pub.
    pq_secrets_dir = ks.workdir.parent / ".secrets"
    pq_pub = pq_secrets_dir / "pq_public.key"
    pq_secrets_dir.mkdir(exist_ok=True)
    os.chmod(pq_secrets_dir, 0o755)
    server_argv = ns_prefix(NETNS_SERVER) + [
        str(yumed_bin),
        "--listen", str(YUME_PORT),
        "--cert", str(ks.server_cert),
        "--key", str(ks.server_key),
        "--auth-keys", str(ks.auth_keys_file),
        "--pq-auto-generate",
        "--threads", "2",
        # NOTE: this yumed build crashes / stalls under several
        # configurations:
        #   --obfs              → free(): corrupted unsorted chunks
        #   --inner-heavy + hop → malloc(): unaligned tcache chunk
        #   --inner-light       → free(): corrupted unsorted chunks
        #                         immediately after auth
        # --no-obfs + --no-inner is the only combo that keeps yumed
        # alive end-to-end on this build. Bench payload is sized below
        # the 64KB write-batch boundary (kMaxWriteBatchBytes) where a
        # separate truncation bug appears. DPI still sees plain TLS
        # framing. Re-tighten as yumed is fixed.
        "--no-obfs",
        "--no-inner",
        "--boring",
    ]
    server_proc = subprocess.Popen(
        server_argv, stdout=server_log, stderr=subprocess.STDOUT,
        cwd=str(ks.workdir.parent),
    )

    def _stop_server() -> None:
        if server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.wait()
        server_log.close()

    register_cleanup(_stop_server)

    # Probe the server port from the server netns (the client netns has
    # netem on the path so the probe would be slow; we want raw readiness).
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        r = subprocess.call(
            ns_prefix(NETNS_SERVER) + ["bash", "-c",
                                       f"</dev/tcp/{SERVER_IP}/{YUME_PORT}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if r == 0:
            break
        time.sleep(0.1)
    else:
        raise RuntimeError(
            f"yumed didn't bind {SERVER_IP}:{YUME_PORT} (see {server_log.name})"
        )

    # Wait for the PQ public key to appear on disk (yumed generates it
    # right after listening). The probe above only confirms TCP-listening
    # readiness — yumed writes the PQ key just before that, but races are
    # possible; bound the wait to a second.
    pq_deadline = time.monotonic() + 2.0
    while not pq_pub.exists() and time.monotonic() < pq_deadline:
        time.sleep(0.05)
    if pq_pub.exists():
        os.chmod(pq_pub, 0o644)

    client_argv = ns_prefix(NETNS_CLIENT) + [
        str(yume_bin),
        "--server", SERVER_IP,
        "--port", str(YUME_PORT),
        "--auth", str(ks.client_identity),
        "--socks", str(SOCKS_PORT),
        "--pq-pub", str(pq_pub),
        # Intentionally NOT passing --allow-local-ip on the client side.
        # When set, the client advertises LAN-bridging to the server in
        # AUTH, and yumed builds without YUME_FEATURE_LAN_BRIDGE crash
        # mid-session with free(): corrupted unsorted chunks. SOCKS
        # connections to TEST-NET-2 (198.51.100.x) work without it.
        "--no-obfs",                  # match server (see server_argv note)
        "--no-inner",                 # match server (see server_argv note)
        # --no-inner triggers an interactive "type I understand the
        # privacy risk" prompt; bypass for the bench.
        "--accept-monitoring",
        "--non-interactive",
        "--boring",
        "--no-stealth",
        "--tls-ca", str(ks.server_cert),
    ]
    t0 = time.perf_counter()
    client_proc = subprocess.Popen(
        client_argv, stdout=client_log, stderr=subprocess.STDOUT,
    )

    def _stop_client() -> None:
        if client_proc.poll() is None:
            client_proc.terminate()
            try:
                client_proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                client_proc.kill()
                client_proc.wait()
        client_log.close()

    register_cleanup(_stop_client)

    # Probe SOCKS port readiness from inside the client netns.
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        r = subprocess.call(
            ns_prefix(NETNS_CLIENT) + ["bash", "-c",
                                       f"</dev/tcp/127.0.0.1/{SOCKS_PORT}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if r == 0:
            handshake_s = time.perf_counter() - t0
            return server_proc, client_proc, handshake_s
        time.sleep(0.1)
    raise RuntimeError(
        f"yume client didn't bind SOCKS :{SOCKS_PORT} (see {client_log.name})"
    )


# ---------------------------------------------------------------------
# tcpdump capture
# ---------------------------------------------------------------------

def start_pcap(netns: str, iface: str, out_path: Path) -> subprocess.Popen:
    """Start tcpdump in netns, writing pcap to out_path. -U flushes per-
    packet so a quick stop doesn't lose tail packets."""
    proc = subprocess.Popen(
        ns_prefix(netns) + [
            "tcpdump", "-i", iface, "-U", "-s", "0",
            "-w", str(out_path),
        ],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    def _stop() -> None:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    register_cleanup(_stop)
    # tcpdump needs ~0.2s to open the socket; give it a moment.
    time.sleep(0.3)
    return proc


def stop_pcap(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


# ---------------------------------------------------------------------
# RTT via ping inside client netns
# ---------------------------------------------------------------------

def measure_rtt_ping(count: int = 10) -> dict[str, float] | None:
    """Returns {min_ms, avg_ms, max_ms, mdev_ms, loss_pct} or None on failure."""
    try:
        cp = subprocess.run(
            ns_prefix(NETNS_CLIENT) + [
                "ping", "-c", str(count), "-i", "0.2", "-q", SERVER_IP,
            ],
            capture_output=True, text=True, timeout=10 + count,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if cp.returncode != 0:
        return None
    out = cp.stdout
    # Lines look like:
    #   1 packets transmitted, 1 received, 0% packet loss, time 0ms
    #   rtt min/avg/max/mdev = 0.034/0.034/0.034/0.000 ms
    loss_match = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    rtt_match = re.search(
        r"min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out
    )
    if not rtt_match:
        return None
    return {
        "min_ms": float(rtt_match.group(1)),
        "avg_ms": float(rtt_match.group(2)),
        "max_ms": float(rtt_match.group(3)),
        "mdev_ms": float(rtt_match.group(4)),
        "loss_pct": float(loss_match.group(1)) if loss_match else 0.0,
    }


# ---------------------------------------------------------------------
# Workload arms — each returns a dict with samples + pcap path
# ---------------------------------------------------------------------

CURL_FORMAT = (
    "%{time_connect} %{time_appconnect} %{time_starttransfer} "
    "%{time_total} %{size_download} %{speed_download}\n"
)


def parse_curl_line(line: str) -> dict[str, float] | None:
    parts = line.strip().split()
    if len(parts) != 6:
        return None
    try:
        return {
            "time_connect_s": float(parts[0]),
            "time_appconnect_s": float(parts[1]),
            "time_starttransfer_s": float(parts[2]),
            "time_total_s": float(parts[3]),
            "size_download_bytes": float(parts[4]),
            "speed_download_bps": float(parts[5]),
        }
    except ValueError:
        return None


def curl_get(socks_proxy: str | None, url: str) -> dict[str, float] | None:
    """One HTTPS GET via curl. If socks_proxy is set ("host:port"), tunnel
    through SOCKS5. Returns parsed timings or None on failure."""
    verbose = os.environ.get("YUME_BENCH_CURL_VERBOSE") == "1"
    argv = ns_prefix(NETNS_CLIENT) + [
        "curl", "-k",
        ("-v" if verbose else "-s"),
        "-o", "/dev/null",
        "-w", CURL_FORMAT,
    ]
    if socks_proxy:
        argv += ["--socks5-hostname", socks_proxy]
    argv += [url]
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return None
    if cp.returncode != 0:
        msg = cp.stderr.strip()
        if verbose:
            print(f"[bench] curl verbose stderr:\n{msg}", file=sys.stderr)
        print(
            f"[bench] curl failed (exit {cp.returncode}): {msg[-300:]}",
            file=sys.stderr,
        )
        return None
    return parse_curl_line(cp.stdout)


def run_arm_yume(
    arm_dir: Path,
    yumed_bin: Path,
    yume_bin: Path,
    ks: YumeKeyset,
    repeats: int,
) -> dict[str, Any]:
    arm_dir.mkdir(parents=True, exist_ok=True)
    pcap = arm_dir / "yume.pcap"
    pcap_proc = start_pcap(NETNS_SERVER, VETH_SERVER, pcap)
    try:
        _srv, _cli, handshake_s = start_yume_stack(yumed_bin, yume_bin, ks, arm_dir)
        # Small grace period so the tunnel is fully ready post-SOCKS-bind.
        time.sleep(0.5)
        if os.environ.get("YUME_BENCH_PAUSE"):
            print(f"[bench] PAUSED — netns up. SOCKS at 127.0.0.1:{SOCKS_PORT} "
                  f"in {NETNS_CLIENT}; HTTPS at {SERVER_IP}:{HTTPS_PORT}. "
                  f"Press Enter to continue.", file=sys.stderr)
            input()
        samples = []
        for i in range(repeats):
            s = curl_get(
                f"127.0.0.1:{SOCKS_PORT}",
                f"https://{SERVER_IP}:{HTTPS_PORT}/payload",
            )
            if s is None:
                samples.append({"failed": True, "iter": i})
            else:
                samples.append(s)
        return {
            "arm": "yume",
            "pcap": str(pcap),
            "tunnel_handshake_s": handshake_s,
            "samples": samples,
        }
    finally:
        stop_pcap(pcap_proc)


def run_arm_curl(arm_dir: Path, repeats: int) -> dict[str, Any]:
    arm_dir.mkdir(parents=True, exist_ok=True)
    pcap = arm_dir / "curl.pcap"
    pcap_proc = start_pcap(NETNS_SERVER, VETH_SERVER, pcap)
    try:
        samples = []
        for i in range(repeats):
            s = curl_get(None, f"https://{SERVER_IP}:{HTTPS_PORT}/payload")
            if s is None:
                samples.append({"failed": True, "iter": i})
            else:
                samples.append(s)
        return {
            "arm": "curl",
            "pcap": str(pcap),
            "samples": samples,
        }
    finally:
        stop_pcap(pcap_proc)


def run_arm_chromium(arm_dir: Path, repeats: int) -> dict[str, Any] | None:
    if not shutil.which("chromium"):
        print("[bench] chromium not on PATH; skipping chromium arm.", file=sys.stderr)
        return None
    arm_dir.mkdir(parents=True, exist_ok=True)
    pcap = arm_dir / "chromium.pcap"
    pcap_proc = start_pcap(NETNS_SERVER, VETH_SERVER, pcap)
    samples = []
    try:
        for i in range(repeats):
            user_data = arm_dir / f"profile-{i}"
            user_data.mkdir(parents=True, exist_ok=True)
            t0 = time.perf_counter()
            # --screenshot makes chromium navigate, capture a one-shot
            # screenshot, then exit cleanly. --dump-dom hangs forever on
            # an octet-stream payload because no DOM is constructed.
            screenshot = arm_dir / f"shot-{i}.png"
            try:
                cp = subprocess.run(
                    ns_prefix(NETNS_CLIENT) + [
                        "chromium", "--headless=new", "--no-sandbox",
                        "--disable-gpu", "--ignore-certificate-errors",
                        f"--user-data-dir={user_data}",
                        f"--screenshot={screenshot}",
                        "--window-size=320,240",
                        "--no-first-run",
                        "--no-default-browser-check",
                        f"https://{SERVER_IP}:{HTTPS_PORT}/payload",
                    ],
                    capture_output=True, text=True, timeout=30,
                )
                elapsed = time.perf_counter() - t0
                samples.append({
                    "time_total_s": elapsed,
                    "exit_code": cp.returncode,
                    "stdout_bytes": len(cp.stdout),
                })
            except subprocess.TimeoutExpired:
                samples.append({"failed": True, "iter": i, "reason": "timeout"})
        return {"arm": "chromium", "pcap": str(pcap), "samples": samples}
    finally:
        stop_pcap(pcap_proc)


# ---------------------------------------------------------------------
# ndpiReader integration
# ---------------------------------------------------------------------

def run_ndpi(pcap_path: Path) -> dict[str, Any] | None:
    """Run ndpiReader on the pcap. Returns:
        {
          "top_protocol": "TLS.HTTP" | "Unknown" | ...,
          "match_count": int (sum of all detected protocol flows),
          "protocols": {name: flow_count},
        }
    or None if ndpiReader isn't installed."""
    if not shutil.which("ndpiReader"):
        return None
    try:
        # ndpiReader -q suppresses the "Detected protocols:" section we
        # need to parse. Run without -q.
        cp = subprocess.run(
            ["ndpiReader", "-i", str(pcap_path)],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {"error": "ndpiReader timeout"}
    if cp.returncode != 0:
        return {"error": f"ndpiReader exit {cp.returncode}: {cp.stderr.strip()[:200]}"}
    out = cp.stdout

    # ndpiReader -q output includes a "Detected protocols:" block like:
    #   Detected protocols:
    #        TLS                  packets:      45 bytes:   38112 flows:       2
    #        Unknown              packets:       3 bytes:     192 flows:       1
    proto_counts: dict[str, int] = {}
    in_block = False
    line_re = re.compile(
        r"^\s*([A-Za-z][A-Za-z0-9_./+\-]*)\s+packets:\s+\d+\s+"
        r"bytes:\s+\d+\s+flows:\s+(\d+)"
    )
    for raw in out.splitlines():
        if raw.startswith("Detected protocols:"):
            in_block = True
            continue
        if not in_block:
            continue
        if raw.strip() == "":
            # Block ends at the first blank line.
            break
        m = line_re.match(raw)
        if not m:
            continue
        proto, flows = m.group(1), int(m.group(2))
        proto_counts[proto] = proto_counts.get(proto, 0) + flows

    # Pick the dominant non-Unknown protocol if any; else Unknown.
    non_unknown = {k: v for k, v in proto_counts.items() if k.lower() != "unknown"}
    if non_unknown:
        top = max(non_unknown.items(), key=lambda kv: kv[1])[0]
    elif proto_counts:
        top = "Unknown"
    else:
        top = "(no flows)"
    return {
        "top_protocol": top,
        "match_count": sum(proto_counts.values()),
        "protocols": proto_counts,
    }


# ---------------------------------------------------------------------
# Per-arm aggregation
# ---------------------------------------------------------------------

def aggregate(arm: dict[str, Any]) -> dict[str, Any]:
    """Pull per-iteration samples into median/p95 summaries."""
    samples = [s for s in arm.get("samples", []) if not s.get("failed")]
    n = len(samples)
    summary: dict[str, Any] = {
        "iterations": n,
        "failed_iterations": len(arm.get("samples", [])) - n,
    }
    if n == 0:
        return summary

    def stat(field: str, scale: float = 1.0) -> dict[str, float]:
        vals = [s[field] * scale for s in samples if field in s]
        if not vals:
            return {}
        s = Stats.of(vals)
        return asdict(s)

    # curl arms have time_total_s + speed_download_bps; chromium has time_total_s.
    if any("time_total_s" in s for s in samples):
        summary["total_time_ms"] = stat("time_total_s", 1000.0)
    if any("time_appconnect_s" in s for s in samples):
        summary["tls_handshake_ms"] = stat("time_appconnect_s", 1000.0)
    if any("time_connect_s" in s for s in samples):
        summary["tcp_connect_ms"] = stat("time_connect_s", 1000.0)
    if any("speed_download_bps" in s for s in samples):
        # speed_download_bps is bytes/sec; convert to Mbps for the report.
        vals = [s["speed_download_bps"] * 8.0 / 1_000_000.0 for s in samples
                if "speed_download_bps" in s]
        summary["throughput_mbps"] = asdict(Stats.of(vals))
    # Chromium has its own elapsed; expose as page_load_ms for clarity.
    if arm.get("arm") == "chromium":
        vals = [s["time_total_s"] * 1000.0 for s in samples if "time_total_s" in s]
        if vals:
            summary["page_load_ms"] = asdict(Stats.of(vals))
    return summary


# ---------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------

def _fmt_ms(d: dict[str, Any] | None) -> str:
    if not d:
        return "n/a"
    return f"{d['median_ms']:.1f} ms (p95 {d['p95_ms']:.1f})"


def _fmt_mbps(d: dict[str, Any] | None) -> str:
    if not d:
        return "n/a"
    # The Stats helper labels its fields with `_ms` suffixes for backwards
    # compatibility; the values themselves are whatever we put in. For
    # throughput we put Mbps.
    return f"{d['median_ms']:.1f} Mbps (p95 {d['p95_ms']:.1f})"


# ---------------------------------------------------------------------
# Pretty terminal rendering (basefwx scripts/plugin-smoke.sh style:
# ANSI colors + glyph prefixes, degrade cleanly when not a TTY)
# ---------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
if _USE_COLOR:
    _BOLD    = "\033[1m"
    _DIM     = "\033[2m"
    _RED     = "\033[1;31m"
    _GREEN   = "\033[1;32m"
    _YELLOW  = "\033[1;33m"
    _BLUE    = "\033[1;34m"
    _MAGENTA = "\033[1;35m"
    _CYAN    = "\033[1;36m"
    _RESET   = "\033[0m"
else:
    _BOLD = _DIM = _RED = _GREEN = _YELLOW = _BLUE = _MAGENTA = _CYAN = _RESET = ""


def render_terminal(profile: dict[str, Any], rtt: dict[str, float] | None,
                    arms: list[dict[str, Any]]) -> str:
    """Colorful terminal-friendly report. Markdown is for files; this
    is for humans staring at a terminal."""
    L = []
    L.append("")
    L.append(f"{_BOLD}⚡ yume virtual-WAN bench{_RESET}")
    L.append(f"{_DIM}— TLS handshake, throughput, and DPI verdict per arm{_RESET}")
    L.append("")

    L.append(f"{_BOLD}🌐 WAN profile:{_RESET}  {_CYAN}{profile['label']}{_RESET}")
    L.append(f"  {_DIM}latency:{_RESET}   {profile['latency_ms']} ms ± {profile['jitter_ms']} ms")
    L.append(f"  {_DIM}loss:{_RESET}      {profile['loss_pct']}% per-direction")
    L.append(f"  {_DIM}bandwidth:{_RESET} {profile['bandwidth_mbit']} Mbps")
    L.append("")

    if rtt:
        loss = rtt.get("loss_pct", 0)
        loss_color = _GREEN if loss < 2 else (_YELLOW if loss < 10 else _RED)
        L.append(f"{_BOLD}📡 Measured ICMP RTT{_RESET}  "
                 f"{_DIM}(client → server, {loss_color}{loss:.1f}%{_DIM} loss){_RESET}")
        L.append(f"  min {_CYAN}{rtt['min_ms']:.1f}{_RESET} ms  "
                 f"avg {_CYAN}{rtt['avg_ms']:.1f}{_RESET} ms  "
                 f"max {_CYAN}{rtt['max_ms']:.1f}{_RESET} ms  "
                 f"mdev {_DIM}{rtt['mdev_ms']:.1f}{_RESET} ms")
        L.append("")

    L.append(f"{_BOLD}📦 Per-arm results{_RESET}")
    L.append(f"  {_DIM}{'arm':<10} {'TLS handshake':<26} {'total':<14} "
             f"{'throughput':<14} {'DPI':<14} {'flows':>5}{_RESET}")
    L.append(f"  {_DIM}" + "─" * 86 + _RESET)
    for arm in arms:
        if arm is None:
            continue
        agg = arm["aggregate"]
        dpi = arm.get("dpi") or {}
        name = arm["arm"]
        name_color = _MAGENTA if name == "yume" else _BLUE
        handshake = _fmt_ms(agg.get("tls_handshake_ms"))
        if name == "yume" and "tunnel_handshake_s" in arm:
            handshake = (f"{arm['tunnel_handshake_s'] * 1000:.0f} ms tunnel + {handshake}")
        total = _fmt_ms(agg.get("total_time_ms") or agg.get("page_load_ms"))
        tput = _fmt_mbps(agg.get("throughput_mbps"))
        dpi_top = dpi.get("top_protocol", "—")
        dpi_color = _GREEN if dpi_top in ("TLS", "TLS.HTTPS", "HTTP") else (
                    _YELLOW if dpi_top in ("Unknown", "—") else _CYAN)
        dpi_n = str(dpi.get("match_count", "—"))
        L.append(f"  {name_color}{name:<10}{_RESET} {handshake:<26} {total:<14} "
                 f"{tput:<14} {dpi_color}{dpi_top:<14}{_RESET} {dpi_n:>5}")
    L.append("")

    has_dpi = any(arm and arm.get("dpi") for arm in arms)
    if has_dpi:
        L.append(f"{_BOLD}🔍 DPI verdicts (raw){_RESET}")
        for arm in arms:
            if arm is None:
                continue
            dpi = arm.get("dpi")
            name = arm["arm"]
            name_color = _MAGENTA if name == "yume" else _BLUE
            if dpi is None:
                L.append(f"  {name_color}{name}{_RESET}  {_DIM}ndpiReader not installed; skipped{_RESET}")
                continue
            if "error" in dpi:
                L.append(f"  {name_color}{name}{_RESET}  {_RED}error: {dpi['error']}{_RESET}")
                continue
            top = dpi["top_protocol"]
            top_color = _GREEN if top in ("TLS", "TLS.HTTPS", "HTTP") else _YELLOW
            L.append(f"  {name_color}{name}{_RESET}  top {top_color}{top}{_RESET}  "
                     f"{_DIM}({dpi['match_count']} flows){_RESET}")
            for proto, n in sorted(dpi.get("protocols", {}).items(),
                                   key=lambda kv: (-kv[1], kv[0])):
                L.append(f"    {_DIM}- {proto}: {n}{_RESET}")
        L.append("")

    return "\n".join(L)


def render_markdown(profile: dict[str, Any], rtt: dict[str, float] | None,
                    arms: list[dict[str, Any]]) -> str:
    out = []
    out.append("# yume virtual-WAN bench")
    out.append("")
    out.append(f"**WAN profile:** {profile['label']}")
    out.append(f"  - latency one-way: {profile['latency_ms']} ms "
               f"(±{profile['jitter_ms']} ms jitter)")
    out.append(f"  - loss per-direction: {profile['loss_pct']}%")
    out.append(f"  - bandwidth: {profile['bandwidth_mbit']} Mbps")
    out.append("")
    if rtt:
        out.append(
            f"**Measured ICMP RTT (client → server, {rtt.get('loss_pct', 0):.1f}% loss):** "
            f"min {rtt['min_ms']:.1f} ms, avg {rtt['avg_ms']:.1f} ms, "
            f"max {rtt['max_ms']:.1f} ms, mdev {rtt['mdev_ms']:.1f} ms"
        )
        out.append("")

    out.append("## Per-arm results")
    out.append("")
    out.append("| arm | TLS handshake | total time | throughput | DPI top | DPI flows |")
    out.append("|---|---|---|---|---|---|")
    for arm in arms:
        if arm is None:
            continue
        agg = arm["aggregate"]
        dpi = arm.get("dpi") or {}
        name = arm["arm"]
        handshake = _fmt_ms(agg.get("tls_handshake_ms"))
        if name == "yume" and "tunnel_handshake_s" in arm:
            handshake = (
                f"{arm['tunnel_handshake_s'] * 1000:.0f} ms tunnel + "
                f"{handshake}"
            )
        total = _fmt_ms(agg.get("total_time_ms") or agg.get("page_load_ms"))
        tput = _fmt_mbps(agg.get("throughput_mbps"))
        dpi_top = dpi.get("top_protocol", "—")
        dpi_n = dpi.get("match_count", "—")
        out.append(f"| {name} | {handshake} | {total} | {tput} | {dpi_top} | {dpi_n} |")

    out.append("")
    out.append("## DPI verdicts (per arm, raw)")
    for arm in arms:
        if arm is None:
            continue
        out.append(f"### {arm['arm']}")
        dpi = arm.get("dpi")
        if dpi is None:
            out.append("_ndpiReader not installed; skipped._")
            continue
        if "error" in dpi:
            out.append(f"_error: {dpi['error']}_")
            continue
        out.append(
            f"- top: **{dpi['top_protocol']}** "
            f"(total flow-classifications: {dpi['match_count']})"
        )
        for proto, n in sorted(dpi.get("protocols", {}).items(),
                               key=lambda kv: (-kv[1], kv[0])):
            out.append(f"  - {proto}: {n}")
        out.append("")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------
# Regression check (nice-to-have)
# ---------------------------------------------------------------------

def _yume_throughput_median(report: dict[str, Any]) -> float | None:
    for arm in report.get("arms", []):
        if arm and arm.get("arm") == "yume":
            tput = arm.get("aggregate", {}).get("throughput_mbps")
            if tput:
                return tput["median_ms"]
    return None


def regression_check(current: dict[str, Any], cache_path: Path,
                     threshold_pct: float) -> bool:
    """Compare yume arm throughput against the previous cached run.
    Returns True if OK, False if regression exceeds threshold."""
    if not cache_path.exists():
        return True
    try:
        prev = json.loads(cache_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[bench] couldn't read cache {cache_path}: {exc}", file=sys.stderr)
        return True
    prev_t = _yume_throughput_median(prev)
    cur_t = _yume_throughput_median(current)
    if prev_t is None or cur_t is None or prev_t <= 0:
        return True
    delta_pct = (prev_t - cur_t) / prev_t * 100.0
    if delta_pct > threshold_pct:
        print(
            f"[bench] REGRESSION: yume throughput dropped "
            f"{delta_pct:.1f}% (prev {prev_t:.1f} Mbps → cur {cur_t:.1f} Mbps) "
            f"vs threshold {threshold_pct}%",
            file=sys.stderr,
        )
        return False
    return True


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="yume virtual-WAN bench + DPI-comparison harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            profiles (override individual knobs with --latency / --loss / --bandwidth):
              lan         — 1 ms, 0% loss, 1 Gbps
              broadband   — 20 ms ± 2 ms, 0.1% loss, 200 Mbps
              mobile-4g   — 50 ms ± 5 ms, 1% loss, 50 Mbps
              lossy-wifi  — 30 ms ± 10 ms, 3% loss, 30 Mbps

            example: sudo python3 scripts/yume_bench_wan.py --profile mobile-4g
        """),
    )
    ap.add_argument(
        "--profile", default="mobile-4g", choices=list(PROFILES.keys()),
        help="WAN profile preset (default: mobile-4g)",
    )
    ap.add_argument(
        "--latency", type=int, default=None, metavar="MS",
        help="override one-way latency in ms (default: profile)",
    )
    ap.add_argument(
        "--jitter", type=int, default=None, metavar="MS",
        help="override one-way jitter in ms",
    )
    ap.add_argument(
        "--loss", type=float, default=None, metavar="PCT",
        help="override per-direction packet loss percentage",
    )
    ap.add_argument(
        "--bandwidth", type=int, default=None, metavar="MBIT",
        help="override one-way bandwidth in Mbps",
    )
    ap.add_argument(
        "--baseline", action="append", default=[], choices=["curl", "chromium"],
        help="baseline arms to run (default: curl). Repeat the flag for multiple.",
    )
    ap.add_argument(
        "--repeats", type=int, default=3, metavar="N",
        help="per-arm workload repeats (default: 3; p95 of 3 = max)",
    )
    ap.add_argument(
        "--quick", action="store_true",
        help="skip DPI + baseline arms; ~30s latency-only yume run",
    )
    ap.add_argument(
        "--yume", type=Path, default=DEFAULT_YUME,
        help=f"path to yume client (default: {DEFAULT_YUME})",
    )
    ap.add_argument(
        "--yumed", type=Path, default=DEFAULT_YUMED,
        help=f"path to yumed (default: {DEFAULT_YUMED})",
    )
    ap.add_argument(
        "--json", type=Path, default=None,
        help="write full report as JSON to this path",
    )
    ap.add_argument(
        "--report", type=Path, default=None,
        help="write markdown report to this path (default: stdout)",
    )
    ap.add_argument(
        "--cache", type=Path,
        default=Path.home() / ".cache" / "yume_bench" / "last.json",
        help="path to cache file for regression check",
    )
    ap.add_argument(
        "--regression-threshold-pct", type=float, default=15.0,
        help="exit non-zero if yume throughput drops more than this %% vs cache",
    )
    ap.add_argument(
        "--no-cache", action="store_true",
        help="skip reading + writing the regression cache",
    )
    ap.add_argument(
        "--keep-workdir", action="store_true",
        help="don't delete the temp workdir on exit (for debugging)",
    )
    return ap.parse_args(argv)


def main() -> int:
    args = parse_args()

    if not require_root():
        return 2
    ok, _have = check_prereqs()
    if not ok:
        return 2

    # Default baseline is curl unless --quick.
    if not args.baseline and not args.quick:
        args.baseline = ["curl"]

    # Yume binaries: required regardless of arm choice (the yume arm
    # always runs).
    for label, p in (("yume", args.yume), ("yumed", args.yumed)):
        if not p.exists() or not os.access(p, os.X_OK):
            print(
                f"FATAL: {label} binary not found / not executable: {p}\n"
                f"       run `cmake --build build` first; see [local-only development file removed] re heavy builds",
                file=sys.stderr,
            )
            return 2

    profile = dict(PROFILES[args.profile])  # copy
    if args.latency is not None:
        profile["latency_ms"] = args.latency
    if args.jitter is not None:
        profile["jitter_ms"] = args.jitter
    if args.loss is not None:
        profile["loss_pct"] = args.loss
    if args.bandwidth is not None:
        profile["bandwidth_mbit"] = args.bandwidth
    # Refresh the human label if we overrode anything.
    if any(x is not None for x in (args.latency, args.jitter, args.loss, args.bandwidth)):
        profile["label"] = (
            f"Custom — {profile['latency_ms']} ms ± {profile['jitter_ms']} ms, "
            f"{profile['loss_pct']}% loss, {profile['bandwidth_mbit']} Mbps"
        )

    workdir = Path(tempfile.mkdtemp(prefix="yume-bench-wan-"))
    # tempfile.mkdtemp creates 0700; both yumed and yume drop privileges
    # to nobody after startup and need to re-read the TLS CA / cert on
    # each reconnection attempt. Make the workdir traversable.
    os.chmod(workdir, 0o755)
    if not args.keep_workdir:
        register_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))

    print(f"[bench] workdir: {workdir}", file=sys.stderr)
    print(f"[bench] profile: {profile['label']}", file=sys.stderr)

    # Topology + WAN emulation.
    setup_netns()
    apply_netem(
        profile["latency_ms"], profile["jitter_ms"],
        profile["loss_pct"], profile["bandwidth_mbit"],
    )

    # Static payload + self-signed cert.
    payload = workdir / "payload.bin"
    payload.write_bytes(os.urandom(PAYLOAD_BYTES))
    crt, key = make_self_signed_cert(workdir, SERVER_IP)
    start_https_server(
        NETNS_SERVER, SERVER_IP, HTTPS_PORT, payload, crt, key,
        workdir / "https.log",
    )

    # Yume keyset (Ed25519 identity + a separate TLS cert just for yume).
    keys_dir = workdir / "keys"
    keys_dir.mkdir()
    ks = generate_keyset(keys_dir, args.yumed)

    # Pre-generate the PQ keypair. yumed's --pq-auto-generate writes the
    # keypair into ./.secrets/ on first startup, then a known yumed
    # heap-corruption bug crashes the daemon mid-startup before it binds
    # (reproduces deterministically with --obfs + inner-heavy + hop). The
    # keypair lands on disk first, so spawning yumed once to generate and
    # again to actually listen works around the crash. Documented as a
    # carry-forward in the release audit.
    secrets_dir = workdir / ".secrets"
    if not (secrets_dir / "pq_public.key").exists():
        secrets_dir.mkdir(exist_ok=True)
        os.chmod(secrets_dir, 0o755)
        gen_argv = [
            str(args.yumed),
            "--listen", str(YUME_PORT),
            "--cert", str(ks.server_cert),
            "--key", str(ks.server_key),
            "--auth-keys", str(ks.auth_keys_file),
            "--pq-auto-generate",
            "--obfs", "--boring",
        ]
        # We expect this to crash (heap-corruption bug); ignore the exit
        # code. The PQ key files appear before the crash. Bound the wait
        # so a fixed daemon would still terminate cleanly here.
        gen = subprocess.Popen(
            gen_argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=str(workdir),
        )
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if (secrets_dir / "pq_public.key").exists():
                break
            if gen.poll() is not None:
                break
            time.sleep(0.05)
        if gen.poll() is None:
            gen.terminate()
            try:
                gen.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                gen.kill()
                gen.wait()
        if not (secrets_dir / "pq_public.key").exists():
            print("FATAL: failed to pre-generate PQ keypair", file=sys.stderr)
            return 3
        os.chmod(secrets_dir / "pq_public.key", 0o644)
        os.chmod(secrets_dir / "pq_private.key", 0o644)
    # generate_keyset's TLS cert is CN=localhost — fine for loopback but
    # not for the SERVER_IP we use here. Replace it with one that includes
    # the IP as a SAN so yume's TLS pin check passes.
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ed25519",
            "-keyout", str(ks.server_key), "-out", str(ks.server_cert),
            "-days", "1", "-nodes",
            "-subj", f"/CN={SERVER_IP}",
            "-addext", f"subjectAltName=IP:{SERVER_IP}",
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # yumed and yume both drop privileges to `nobody` after bind and
    # re-read their key files on every reconnect attempt. Open them up
    # so nobody can read them.
    for p in (ks.server_cert, ks.server_key, ks.client_identity,
              ks.auth_keys_file):
        os.chmod(p, 0o644)

    # Measure ICMP RTT through the netem qdisc (sanity-check the profile
    # actually got applied).
    rtt = measure_rtt_ping(count=10) if not args.quick else None

    arms: list[dict[str, Any]] = []

    # Arm 1: yume (always present).
    print("[bench] arm: yume", file=sys.stderr)
    yume_arm = run_arm_yume(
        workdir / "arm-yume", args.yumed, args.yume, ks, args.repeats,
    )
    arms.append(yume_arm)

    # Arms 2/3: baselines (skipped under --quick).
    if not args.quick:
        if "curl" in args.baseline:
            print("[bench] arm: curl baseline", file=sys.stderr)
            arms.append(run_arm_curl(workdir / "arm-curl", args.repeats))
        if "chromium" in args.baseline:
            print("[bench] arm: chromium baseline", file=sys.stderr)
            r = run_arm_chromium(workdir / "arm-chromium", args.repeats)
            if r is not None:
                arms.append(r)

    # Aggregate samples + run DPI on each arm's pcap.
    for arm in arms:
        arm["aggregate"] = aggregate(arm)
        if args.quick:
            arm["dpi"] = None
        elif arm.get("pcap"):
            arm["dpi"] = run_ndpi(Path(arm["pcap"]))

    # Build the report bundle.
    report = {
        "schema_version": 1,
        "generated_at_unix": int(time.time()),
        "profile": profile,
        "rtt_icmp": rtt,
        "repeats": args.repeats,
        "arms": arms,
    }

    md = render_markdown(profile, rtt, arms)
    if args.report:
        args.report.write_text(md)
        print(f"[bench] markdown report written to {args.report}", file=sys.stderr)
    else:
        # Default to the pretty terminal renderer when stdout is a TTY;
        # fall back to markdown when piped or when NO_COLOR is set so
        # downstream consumers (paste-into-issue, CI logs) get a clean
        # markdown stream.
        if sys.stdout.isatty() and not os.environ.get("NO_COLOR"):
            print(render_terminal(profile, rtt, arms))
        else:
            print(md)

    if args.json:
        args.json.write_text(json.dumps(report, indent=2, default=str))
        print(f"[bench] JSON report written to {args.json}", file=sys.stderr)

    # Regression cache (--no-cache disables both reading and writing).
    regression_ok = True
    if not args.no_cache:
        regression_ok = regression_check(
            report, args.cache, args.regression_threshold_pct,
        )
        try:
            args.cache.parent.mkdir(parents=True, exist_ok=True)
            args.cache.write_text(json.dumps(report, indent=2, default=str))
        except OSError as exc:
            print(f"[bench] couldn't write cache {args.cache}: {exc}",
                  file=sys.stderr)

    return 0 if regression_ok else 3


if __name__ == "__main__":
    raise SystemExit(main())
