#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""
Headless carrier DPI diagnostic for YUME.

This is an explicit integration harness, not a normal unit selftest:
it launches yume with a local SOCKS port, captures the outer TLS flow,
drives headless Chromium through that SOCKS proxy, optionally captures
a direct Chromium baseline, and then runs dpi-human-report.py.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from typing import Any

from yume_bench_common import (
    require_user_namespace_sandbox,
    validate_pinned_chrome,
)


QUICK_URLS = [
    "https://example.com/",
    "https://www.wikipedia.org/",
    "https://www.cloudflare.com/cdn-cgi/trace",
]

MEDIA_URLS = [
    "https://storage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4",
]

with (
    pathlib.Path(__file__).resolve().parents[1]
    / "tests/fixtures/chrome151-node24/chrome_h2_profile.json"
).open(encoding="utf-8") as _profile_file:
    _captured_profile = json.load(_profile_file)

CLIENT_UA = {
    "chrome": next(
        value
        for name, value in _captured_profile["priming_get"]["headers_in_order"]
        if name == "user-agent"
    ),
}


def repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def which_any(names: list[str]) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def run_capture(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        timeout=timeout,
    )


def run_text(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        p = run_capture(cmd, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else ""
        return 124, out + "\n[TIMEOUT]\n"


def is_ipv4_literal(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return value.count(".") == 3
    except OSError:
        return False


def resolve_server_ip(server: str) -> str:
    if is_ipv4_literal(server):
        return server
    code, out = run_text(["getent", "ahostsv4", server], timeout=10)
    if code == 0:
        for line in out.splitlines():
            parts = line.split()
            if parts and is_ipv4_literal(parts[0]):
                return parts[0]
    infos = socket.getaddrinfo(server, None, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise RuntimeError(f"could not resolve IPv4 address for {server}")
    return infos[0][4][0]


def infer_interface(server_ip: str) -> str:
    code, out = run_text(["ip", "route", "get", server_ip], timeout=10)
    if code != 0:
        raise RuntimeError("could not infer interface with `ip route get`; pass --interface")
    match = re.search(r"\bdev\s+(\S+)", out)
    if not match:
        raise RuntimeError("could not parse interface from `ip route get`; pass --interface")
    return match.group(1)


def free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_port(host: str, port: int, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def wait_file(path: pathlib.Path, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if path.exists() and path.stat().st_size > 0:
            return True
        time.sleep(0.1)
    return False


def start_tls_wire_relay(outdir: pathlib.Path,
                         listen_port: int,
                         target_host: str,
                         target_port: int,
                         report_path: pathlib.Path,
                         timeout_s: float) -> subprocess.Popen[Any]:
    ready_path = outdir / "tls-wire-relay.ready.json"
    log_path = outdir / "tls-wire-relay.log"
    log = log_path.open("wb")
    relay = repo_root() / "scripts/yume_tls_wire.py"
    process = subprocess.Popen(
        [
            sys.executable, str(relay), "relay",
            "--listen", f"127.0.0.1:{listen_port}",
            "--target", f"{target_host}:{target_port}",
            "--output", str(report_path),
            "--ready-file", str(ready_path),
            "--timeout", str(max(timeout_s, 120)),
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    process._yume_log_file = log  # type: ignore[attr-defined]
    if not wait_file(ready_path, timeout_s):
        terminate_process(process)
        log.close()
        raise RuntimeError(f"TLS wire relay did not start; see {log_path}")
    return process


def terminate_process(proc: subprocess.Popen[Any], grace_s: float = 4.0) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + grace_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.1)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def redact_args(args: list[str]) -> list[str]:
    redacted = []
    redact_next = False
    secret_flags = {"--auth", "-i", "--operator-ca-cert", "--tls-ca", "--tls-pin"}
    for item in args:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        redacted.append(item)
        if item in secret_flags:
            redact_next = True
    return redacted


def find_yume_binary(explicit: str | None) -> pathlib.Path:
    if explicit:
        path = pathlib.Path(explicit).expanduser().resolve()
        if not path.exists():
            raise RuntimeError(f"yume binary not found: {path}")
        return path
    root = repo_root()
    candidates = [
        root / "build/bin/yume",
        root / "build-final-review/bin/yume",
        root / "build-rf/bin/yume",
    ]
    existing = [p for p in candidates if p.exists()]
    if existing:
        return max(existing, key=lambda p: p.stat().st_mtime)
    found = shutil.which("yume")
    if found:
        return pathlib.Path(found).resolve()
    raise RuntimeError("could not find yume binary; pass --yume-bin")


def find_yumed_binary(explicit: str | None) -> pathlib.Path:
    if explicit:
        path = pathlib.Path(explicit).expanduser().resolve()
        if not path.exists():
            raise RuntimeError(f"yumed binary not found: {path}")
        return path
    root = repo_root()
    candidates = [
        root / "build/bin/yumed",
        root / "build-final-review/bin/yumed",
        root / "build-rf/bin/yumed",
    ]
    existing = [p for p in candidates if p.exists()]
    if existing:
        return max(existing, key=lambda p: p.stat().st_mtime)
    found = shutil.which("yumed")
    if found:
        return pathlib.Path(found).resolve()
    raise RuntimeError("could not find yumed binary; pass --yumed-bin")


def generate_local_keyset(material_dir: pathlib.Path, yumed_bin: pathlib.Path) -> dict[str, pathlib.Path]:
    if not shutil.which("openssl"):
        raise RuntimeError("openssl not found on PATH; needed for ephemeral local TLS cert")
    material_dir.mkdir(parents=True, exist_ok=True)
    cert = material_dir / "server.crt"
    key = material_dir / "server.key"
    auth_keys = material_dir / "authorized_keys"
    client_prefix = material_dir / "client"
    client_key = material_dir / "client.key"
    client_pub = material_dir / "client.pub"
    obfs_secret = material_dir / "obfs.hex"
    inner_psk = material_dir / "inner-psk.hex"

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", str(key),
            "-out", str(cert),
            "-days", "1", "-nodes",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        [str(yumed_bin), "--keys-gen", str(client_prefix)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if not client_pub.exists() or not client_key.exists():
        raise RuntimeError("yumed --keys-gen did not produce expected client.key/client.pub")
    auth_keys.write_bytes(client_pub.read_bytes())
    obfs_secret.write_text(secrets.token_hex(32))
    inner_psk.write_text(secrets.token_hex(32))
    for path in (key, client_key, auth_keys, obfs_secret, inner_psk):
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return {
        "server_cert": cert,
        "server_key": key,
        "auth_keys": auth_keys,
        "client_key": client_key,
        "client_pub": client_pub,
        "obfs_secret": obfs_secret,
        "inner_psk": inner_psk,
    }


def start_local_cover_backend(outdir: pathlib.Path,
                              port: int) -> subprocess.Popen[Any]:
    node = shutil.which("node")
    if not node:
        raise RuntimeError("node not found; local 2.0 diagnosis requires the cover backend")
    backend = repo_root() / "tools/cover-node/backend.mjs"
    log_path = outdir / "cover-backend.log"
    log = log_path.open("wb")
    env = os.environ.copy()
    env["YUME_COVER_HOST"] = "127.0.0.1"
    env["YUME_COVER_PORT"] = str(port)
    proc = subprocess.Popen(
        [node, str(backend)],
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=env,
    )
    proc._yume_log_file = log  # type: ignore[attr-defined]
    if not wait_port("127.0.0.1", port, 10):
        terminate_process(proc)
        log.close()
        raise RuntimeError(f"cover backend did not listen; see {log_path}")
    return proc


def start_local_yumed(args: argparse.Namespace,
                      outdir: pathlib.Path,
                      material_dir: pathlib.Path,
                      yume_port: int,
                      cover_port: int,
                      listen_host: str = "127.0.0.1") -> tuple[subprocess.Popen[Any], dict[str, pathlib.Path]]:
    yumed_bin = find_yumed_binary(args.yumed_bin)
    keyset = generate_local_keyset(material_dir, yumed_bin)
    log_path = outdir / "yumed.log"
    argv = [
        str(yumed_bin),
        "--listen", f"{listen_host}:{yume_port}",
        "--cert", str(keyset["server_cert"]),
        "--key", str(keyset["server_key"]),
        "--auth-keys", str(keyset["auth_keys"]),
        "--threads", "2",
        "--obfs-secret-file", str(keyset["obfs_secret"]),
        "--inner-psk-file", str(keyset["inner_psk"]),
        "--real-backend", f"loopback://127.0.0.1:{cover_port}",
        "--hide-in-the-crowd", args.server_profile,
        "--allow-local-ip",
        "--boring",
    ]
    for extra in args.yumed_arg:
        argv.append(extra)

    log = log_path.open("wb")
    proc = subprocess.Popen(
        argv,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        cwd=material_dir,
    )
    proc._yume_log_file = log  # type: ignore[attr-defined]
    proc._yume_argv_redacted = redact_args(argv)  # type: ignore[attr-defined]
    if not wait_port(listen_host, yume_port, args.startup_timeout):
        terminate_process(proc)
        log.close()
        raise RuntimeError(f"local yumed did not listen on {listen_host}:{yume_port}; see {log_path}")
    return proc, keyset


def build_yume_args(args: argparse.Namespace, socks_port: int) -> list[str]:
    argv = [
        str(find_yume_binary(args.yume_bin)),
        "--server", args.server,
        "--port", str(args.port),
        "--socks", str(socks_port),
        "--profile", args.client_profile,
        "--hide-in-the-crowd", args.client_http_profile or args.client_profile,
        "--self-dpi",
        "--tls-backend", args.tls_backend,
    ]
    if args.auth:
        argv += ["--auth", str(pathlib.Path(args.auth).expanduser())]
    if args.operator_ca_cert:
        argv += ["--operator-ca-cert", str(pathlib.Path(args.operator_ca_cert).expanduser())]
    if args.tls_ca:
        argv += ["--tls-ca", str(pathlib.Path(args.tls_ca).expanduser())]
    if args.tls_name:
        argv += ["--tls-name", args.tls_name]
    if args.obfs_secret_file:
        argv += ["--obfs-secret-file", str(pathlib.Path(args.obfs_secret_file).expanduser())]
    if args.inner_psk_file:
        argv += ["--inner-psk-file", str(pathlib.Path(args.inner_psk_file).expanduser())]
    for extra in args.yume_arg:
        argv.append(extra)
    return argv


def build_local_yume_args(args: argparse.Namespace,
                          socks_port: int,
                          yume_port: int,
                          keyset: dict[str, pathlib.Path]) -> list[str]:
    argv = [
        str(find_yume_binary(args.yume_bin)),
        "--server", "localhost",
        "--port", str(yume_port),
        "--auth", str(keyset["client_key"]),
        "--tls-ca", str(keyset["server_cert"]),
        "--socks", str(socks_port),
        "--profile", args.client_profile,
        "--hide-in-the-crowd", args.client_http_profile or args.client_profile,
        "--self-dpi",
        "--obfs-secret-file", str(keyset["obfs_secret"]),
        "--inner-psk-file", str(keyset["inner_psk"]),
        "--non-interactive",
        "--accept-monitoring",
        "--allow-local-ip",
        "--tls-backend", args.tls_backend,
    ]
    for extra in args.yume_arg:
        argv.append(extra)
    return argv


def find_chromium(explicit: str | None) -> str:
    if explicit:
        path = shutil.which(explicit) or explicit
        if not pathlib.Path(path).exists() and os.sep in path:
            raise RuntimeError(f"chromium binary not found: {path}")
        return path
    path = which_any([
        "chromium",
        "chromium-browser",
        "google-chrome-stable",
        "google-chrome",
        "chrome",
    ])
    if not path:
        raise RuntimeError("could not find Chromium/Chrome; pass --chromium")
    return path


def chromium_base_args(binary: str, user_data_dir: pathlib.Path, timeout_ms: int) -> list[str]:
    argv = [
        binary,
        "--headless=new",
        "--disable-gpu",
        "--disable-setuid-sandbox",
        "--disable-quic",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-sync",
        "--disable-translate",
        "--metrics-recording-only",
        "--no-first-run",
        "--autoplay-policy=no-user-gesture-required",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--window-size=1365,768",
        f"--virtual-time-budget={timeout_ms}",
        f"--user-data-dir={user_data_dir}",
    ]
    return argv


def run_chromium_urls(
    binary: str,
    urls: list[str],
    outdir: pathlib.Path,
    socks_port: int | None,
    timeout_s: int,
    virtual_time_ms: int,
) -> list[dict[str, Any]]:
    outdir.mkdir(parents=True, exist_ok=True)
    profile = outdir / "profile"
    profile.mkdir(parents=True, exist_ok=False)
    results = []
    for idx, url in enumerate(urls, 1):
        stem = f"{idx:02d}"
        stdout_path = outdir / f"{stem}.stdout.txt"
        stderr_path = outdir / f"{stem}.stderr.txt"
        screenshot_path = outdir / f"{stem}.png"
        argv = chromium_base_args(binary, profile, virtual_time_ms)
        if socks_port is not None:
            argv += [
                f"--proxy-server=socks5://127.0.0.1:{socks_port}",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
            ]
        argv += [f"--screenshot={screenshot_path}", url]
        start = time.monotonic()
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            try:
                proc = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout_s)
                code = proc.returncode
                timed_out = False
            except subprocess.TimeoutExpired:
                code = 124
                timed_out = True
        results.append({
            "url": url,
            "command": argv,
            "returncode": code,
            "timed_out": timed_out,
            "duration_s": round(time.monotonic() - start, 3),
            "screenshot": str(screenshot_path),
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        })
    return results


def capture_command(tool: str, iface: str, output: pathlib.Path, bpf: str) -> list[str]:
    if tool == "dumpcap":
        return ["dumpcap", "-i", iface, "-B", "256", "-s", "0", "-f", bpf, "-w", str(output)]
    if tool == "tcpdump":
        return ["tcpdump", "-i", iface, "-U", "-s", "0", "-w", str(output), bpf]
    raise ValueError(tool)


def choose_capture_tool(explicit: str) -> str:
    if explicit == "none":
        return explicit
    if explicit != "auto":
        if not shutil.which(explicit):
            raise RuntimeError(f"{explicit} not found on PATH")
        return explicit
    if shutil.which("dumpcap"):
        return "dumpcap"
    if shutil.which("tcpdump"):
        return "tcpdump"
    raise RuntimeError("neither dumpcap nor tcpdump found on PATH")


def start_capture(tool: str, iface: str, output: pathlib.Path, bpf: str, log_path: pathlib.Path) -> subprocess.Popen[Any]:
    argv = capture_command(tool, iface, output, bpf)
    log = log_path.open("wb")
    proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    proc._yume_log_file = log  # type: ignore[attr-defined]
    time.sleep(0.5)
    if proc.poll() is not None:
        try:
            log.close()
        except OSError as exc:
            print(
                f"warning: failed to close capture log {log_path}: {exc}",
                file=sys.stderr,
            )
        raise RuntimeError(f"{tool} exited early; see {log_path}")
    return proc


def stop_capture(proc: subprocess.Popen[Any]) -> None:
    terminate_process(proc, grace_s=3.0)
    log = getattr(proc, "_yume_log_file", None)
    if log:
        log.close()


def probe_server_http_disguise(host: str,
                               port: int,
                               sni: str | None,
                               outdir: pathlib.Path,
                               client_profile: str,
                               timeout_s: float = 8.0) -> dict[str, Any]:
    outdir.mkdir(parents=True, exist_ok=True)
    raw_path = outdir / "server-probe-response.txt"
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "sni": sni or host,
        "raw_response": str(raw_path),
    }
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["http/1.1"])
        ua = CLIENT_UA.get(client_profile, CLIENT_UA["chrome"])
        req = (
            f"GET /yume-dpi-probe-{secrets.token_hex(4)} HTTP/1.1\r\n"
            f"Host: {sni or host}\r\n"
            f"User-Agent: {ua}\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.5\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            with context.wrap_socket(sock, server_hostname=sni or host) as tls:
                result["selected_alpn"] = tls.selected_alpn_protocol()
                tls.sendall(req)
                chunks: list[bytes] = []
                while sum(len(c) for c in chunks) < 65536:
                    try:
                        chunk = tls.recv(8192)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
        raw = b"".join(chunks)
        raw_path.write_bytes(raw)
        text = raw.decode("iso-8859-1", errors="replace")
        header_text = text.split("\r\n\r\n", 1)[0]
        lines = header_text.splitlines()
        result["ok"] = bool(lines)
        result["status_line"] = lines[0] if lines else ""
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        result["server_header"] = headers.get("server", "")
        result["headers"] = headers
    except Exception as exc:
        result["ok"] = False
        result["error"] = str(exc)
        raw_path.write_text("")
    return result


def extract_clienthellos(pcap: pathlib.Path) -> list[dict[str, str]]:
    if not shutil.which("tshark"):
        return []
    fields = [
        "frame.number",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tls.handshake.extensions_server_name",
        "tls.handshake.extensions_alpn_str",
        "tls.handshake.ja3",
        "tls.handshake.ja4",
        "tls.handshake.ja4_r",
    ]
    cmd = ["tshark", "-r", str(pcap), "-Y", "tls.handshake.type == 1", "-T", "fields", "-E", "separator=\t"]
    for field in fields:
        cmd += ["-e", field]
    code, out = run_text(cmd, timeout=120)
    if code != 0:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        parts += [""] * (len(fields) - len(parts))
        rows.append(dict(zip(fields, parts)))
    return rows


def run_dpi_report(
    report_script: pathlib.Path,
    pcap: pathlib.Path,
    outdir: pathlib.Path,
    server_ip: str,
    baseline_pcap: pathlib.Path | None,
) -> dict[str, Any]:
    if not report_script.exists():
        return {"ran": False, "error": f"report script not found: {report_script}"}
    argv = [sys.executable, str(report_script), str(pcap), "-o", str(outdir), "--server", server_ip]
    if baseline_pcap is not None and baseline_pcap.exists():
        argv += ["--baseline", str(baseline_pcap)]
    code, out = run_text(argv, timeout=1800)
    (outdir.parent / "dpi-report-run.txt").write_text(out)
    return {
        "ran": code == 0,
        "returncode": code,
        "report": str(outdir / "REPORT.md"),
        "score_json": str(outdir / "score.json"),
    }


def summarize(outdir: pathlib.Path, data: dict[str, Any]) -> None:
    target_ch = data.get("target_clienthellos", [])
    capture_available = pathlib.Path(data["target_pcap"]).exists()
    alpns = [row.get("tls.handshake.extensions_alpn_str", "") for row in target_ch]
    has_h2 = any("h2" in a.split(",") or a.startswith("h2") for a in alpns)
    target_ja4 = {
        row.get("tls.handshake.ja4", "") for row in target_ch
        if row.get("tls.handshake.ja4", "")
    }
    baseline_ch = data.get("baseline_clienthellos", [])
    baseline_ja4 = {
        row.get("tls.handshake.ja4", "") for row in baseline_ch
        if row.get("tls.handshake.ja4", "")
    }
    ja4_overlap = sorted(target_ja4 & baseline_ja4)
    alpn_summary = ", ".join(f"`{a or '-'}`" for a in alpns) or "`-`"
    log_text = pathlib.Path(data["yume_log"]).read_text(errors="replace") if data.get("yume_log") else ""
    yumed_log_text = pathlib.Path(data["yumed_log"]).read_text(errors="replace") if data.get("yumed_log") else ""
    selected_h2 = "TLS ALPN selected: h2" in log_text
    self_dpi_lines = [line for line in log_text.splitlines() if "self-DPI carrier metadata:" in line]
    server_probe = data.get("server_probe", {})
    report = [
        "# YUME Carrier Diagnose Summary",
        "",
        f"Created: `{data['created_at']}`",
        f"Server: `{data['server']}:{data['port']}` (`{data['server_ip']}`)",
        f"Server disguise profile: `{data.get('server_profile', '-')}`",
        f"Client profile: `{data.get('client_profile', '-')}`",
        f"Interface: `{data['interface']}`",
        f"Target pcap: `{data['target_pcap']}`",
    ]
    if data.get("yumed_log"):
        report.append(f"Server log: `{data['yumed_log']}`")
    if data.get("baseline_pcap"):
        report.append(f"Baseline pcap: `{data['baseline_pcap']}`")
    report += [
        "",
        "## Result",
        "",
        f"- ClientHello count: {len(target_ch)}",
        f"- Target ALPN values: {alpn_summary}",
        f"- ALPN offer includes h2: {'yes' if has_h2 else 'no'}",
        f"- Yume log selected h2: {'yes' if selected_h2 else 'no'}",
        f"- Target JA4: `{', '.join(sorted(target_ja4)) or '-'}`",
        f"- Direct Chromium JA4 overlap: `{', '.join(ja4_overlap) or 'none'}`",
        f"- Client self-DPI log: `{self_dpi_lines[-1] if self_dpi_lines else '-'}`",
    ]
    if server_probe:
        report += [
            f"- Server probe status: `{server_probe.get('status_line', '-')}`",
            f"- Server probe Server header: `{server_probe.get('server_header', '') or '(none)'}`",
            f"- Server probe TLS ALPN: `{server_probe.get('selected_alpn') or '-'}`",
        ]
    if yumed_log_text:
        server_summary_lines = [
            line for line in yumed_log_text.splitlines()
            if "effective carrier:" in line or "effective inner mode:" in line
        ]
        if server_summary_lines:
            report.append(f"- Server startup summary: `{server_summary_lines[-1]}`")
    dpi = data.get("dpi_report", {})
    if dpi.get("ran"):
        report.append(f"- DPI report: `{dpi.get('report')}`")
    elif dpi:
        report.append(f"- DPI report: not run ({dpi.get('error') or dpi.get('returncode')})")

    failed_browser_runs = browser_failures(data)
    if failed_browser_runs:
        report.append(
            f"- Browser navigation failures/timeouts: {len(failed_browser_runs)}"
        )
    report += [
        "",
        "## Diagnosis",
        "",
    ]
    if failed_browser_runs:
        report.append(
            "FAIL: at least one target or baseline Chrome navigation failed or timed out."
        )
    elif not capture_available and selected_h2:
        report.append(
            "FUNCTIONAL PASS: Yume selected HTTP/2 and the tunneled browser run "
            "completed, but no raw packet capture was available."
        )
    elif has_h2 and selected_h2:
        report.append("TRANSPORT PASS: the captured target handshake and Yume logs agree on HTTP/2 carrier ALPN.")
    elif has_h2:
        report.append("PARTIAL: ClientHello offers h2, but the Yume log did not show selected h2.")
    else:
        report.append("FAIL: captured ClientHello did not show h2 in ALPN.")
    if not capture_available:
        report.append(
            "STEALTH UNPROVEN: rerun with dumpcap/tcpdump permission to compare "
            "the outer ClientHello against direct Chromium."
        )
    elif ja4_overlap:
        report.append(
            "JA4 overlaps the direct Chromium sample, but this is not proof of "
            "ClientHello byte/order or whole-connection browser parity."
        )
    else:
        report.append(
            "STEALTH GAP: the outer YUME JA4 did not overlap the direct Chromium "
            "sample; inspect JA3/JA4_r and the packet capture before making a browser claim."
        )
    report.append("")
    (outdir / "SUMMARY.md").write_text("\n".join(report))


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run an autonomous headless YUME carrier DPI diagnostic.")
    ap.add_argument("--server", default=None, help="YUME server hostname or IP. Omit for ephemeral local yumed.")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--server-ip", default=None, help="Override resolved server IP for capture filtering")
    ap.add_argument("--interface", default=None, help="Capture interface; default: ip route get <server-ip>")
    ap.add_argument("--baseline-interface", default=None, help="Interface for direct Chromium baseline capture")
    ap.add_argument("--local-server", action="store_true", help="Force ephemeral local yumed mode")
    ap.add_argument("--no-local-server", action="store_true", help="Require remote mode; --server must be set")
    ap.add_argument("--local-yumed-port", type=int, default=0, help="0 means choose a free local yumed port")
    ap.add_argument("--auth", default=None, help="YUME auth key path")
    ap.add_argument("--operator-ca-cert", default=None)
    ap.add_argument("--tls-ca", default=None)
    ap.add_argument("--tls-name", default=None)
    ap.add_argument("--obfs-secret-file", default=None,
                    help="required protected 2.0 admission secret file in remote mode")
    ap.add_argument("--inner-psk-file", default=None,
                    help="required protected 2.0 inner PSK file in remote mode")
    ap.add_argument("--server-profile", default="nginx",
                    choices=["nginx", "nginx-stable", "apache", "caddy", "cloudflare", "express", "gunicorn", "none"],
                    help="local yumed HTTP disguise profile for active-probe responses")
    ap.add_argument("--client-profile", default="chrome", choices=["chrome"],
                    help="pinned YUME outer TLS/H2 cover profile")
    ap.add_argument("--client-http-profile", default=None,
                    choices=["chrome"],
                    help="compatibility spelling for the pinned cover profile")
    ap.add_argument("--tls-backend", default="openssl-diagnostic",
                    choices=["chrome151", "openssl-diagnostic"],
                    help="client TLS backend; chrome151 requires a helper-enabled build")
    ap.add_argument("--tls-wire-report", default=None,
                    help="local mode only: route YUME through the unprivileged TLS wire relay")
    ap.add_argument("--yume-arg", action="append", default=[], help="Extra single argument passed to yume; repeat as needed")
    ap.add_argument("--yumed-arg", action="append", default=[], help="Extra single argument passed to local yumed; repeat as needed")
    ap.add_argument("--yume-bin", default=None)
    ap.add_argument("--yumed-bin", default=None)
    ap.add_argument("--chromium", default=None)
    ap.add_argument(
        "--capture-tool",
        choices=["auto", "dumpcap", "tcpdump", "none"],
        default="auto",
        help="use none for an unprivileged functional audit without raw JA3/JA4 evidence",
    )
    ap.add_argument("--socks-port", type=int, default=0, help="0 means choose a free local port")
    ap.add_argument("--out", default=None)
    ap.add_argument("--keep-workdir", action="store_true")
    ap.add_argument("--url", action="append", default=[], help="URL to visit; repeatable")
    ap.add_argument("--media", action="store_true", help="Also visit a direct MP4 sample URL")
    ap.add_argument("--skip-baseline", action="store_true")
    ap.add_argument("--baseline-pcap", default=None, help="Use an existing Chrome baseline instead of capturing one")
    ap.add_argument("--browser-timeout", type=int, default=45)
    ap.add_argument("--virtual-time-ms", type=int, default=12000)
    ap.add_argument("--startup-timeout", type=int, default=20)
    ap.add_argument(
        "--report-script",
        default="dpi-human-report.py",
        help="path to the optional DPI report generator (default: ./dpi-human-report.py)",
    )
    return ap.parse_args()


def require_unprivileged_browser_driver() -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise RuntimeError(
            "refusing to launch Chrome as root; run the browser driver unprivileged "
            "and use a permissioned capture tool or separate privileged capture sidecar"
        )


def browser_failures(data: dict[str, Any]) -> list[dict[str, Any]]:
    runs = [
        *data.get("target_browser", []),
        *data.get("baseline_browser", []),
    ]
    return [run for run in runs if run.get("returncode") != 0]


def diagnostic_exit_code(data: dict[str, Any]) -> int:
    return 1 if browser_failures(data) else 0


def main() -> int:
    args = parse_args()
    try:
        require_unprivileged_browser_driver()
        require_user_namespace_sandbox()
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    if args.local_server and args.no_local_server:
        raise SystemExit("--local-server and --no-local-server are mutually exclusive")

    local_mode = args.local_server or not args.server
    if args.no_local_server:
        local_mode = False
    if not local_mode and not args.server:
        raise SystemExit("--server is required with --no-local-server")
    if not local_mode and (not args.obfs_secret_file or not args.inner_psk_file):
        raise SystemExit(
            "remote 2.0 diagnosis requires --obfs-secret-file and --inner-psk-file"
        )
    if args.tls_wire_report and not local_mode:
        raise SystemExit("--tls-wire-report currently requires local server mode")

    capture_tool = choose_capture_tool(args.capture_tool)
    chromium = find_chromium(args.chromium)
    try:
        chromium_identity = validate_pinned_chrome(pathlib.Path(chromium))
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    chromium = chromium_identity["launcher"]
    socks_port = args.socks_port or free_local_port()
    local_yumed_port = args.local_yumed_port or free_local_port()
    local_cover_port = free_local_port()
    urls = list(args.url) if args.url else list(QUICK_URLS)
    if args.media:
        urls.extend(MEDIA_URLS)

    if args.out:
        outdir = pathlib.Path(args.out).expanduser().resolve()
        try:
            outdir.mkdir(parents=True, exist_ok=False)
        except FileExistsError as exc:
            raise SystemExit(f"--out must name a fresh directory: {outdir}") from exc
        cleanup_outdir = False
    else:
        outdir = pathlib.Path(tempfile.mkdtemp(prefix="yume-carrier-diagnose-"))
        cleanup_outdir = not args.keep_workdir
    # The default is to keep the directory because it contains the report.
    cleanup_outdir = False if not args.out else cleanup_outdir

    data: dict[str, Any] = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "mode": "local" if local_mode else "remote",
        "capture_tool": capture_tool,
        "chromium": chromium,
        "chromium_identity": chromium_identity,
        "outdir": str(outdir),
        "urls": urls,
        "server_profile": args.server_profile if local_mode else "remote-unknown",
        "client_profile": args.client_profile,
        "client_http_profile": args.client_http_profile or args.client_profile,
    }

    yume_log = outdir / "yume.log"
    yumed_proc: subprocess.Popen[Any] | None = None
    key_material_dir = outdir / "ephemeral-material"
    local_keyset: dict[str, pathlib.Path] | None = None
    cover_proc: subprocess.Popen[Any] | None = None

    if local_mode:
        server = "localhost"
        port = local_yumed_port
        server_ip = "127.0.0.1"
        iface = args.interface or "lo"
        try:
            baseline_iface = args.baseline_interface or infer_interface("1.1.1.1")
        except Exception as exc:
            baseline_iface = None
            data["baseline_skip_reason"] = f"could not infer baseline interface: {exc}"
        data["server"] = server
        data["port"] = port
        data["server_ip"] = server_ip
        data["interface"] = iface
        data["baseline_interface"] = baseline_iface
        data["local_secret_files_generated"] = True
    else:
        server = args.server
        port = args.port
        server_ip = args.server_ip or resolve_server_ip(server)
        iface = args.interface or infer_interface(server_ip)
        baseline_iface = args.baseline_interface or iface
        data["server"] = server
        data["port"] = port
        data["server_ip"] = server_ip
        data["interface"] = iface
        data["baseline_interface"] = baseline_iface

    target_pcap = outdir / "target-yume.pcapng"
    baseline_pcap = pathlib.Path(args.baseline_pcap).expanduser().resolve() if args.baseline_pcap else None
    data["yume_log"] = str(yume_log)
    data["yumed_log"] = str(outdir / "yumed.log") if local_mode else None
    data["target_pcap"] = str(target_pcap)
    data["baseline_pcap"] = str(baseline_pcap) if baseline_pcap else None

    yume_proc: subprocess.Popen[Any] | None = None
    wire_relay_proc: subprocess.Popen[Any] | None = None
    target_cap: subprocess.Popen[Any] | None = None
    baseline_cap: subprocess.Popen[Any] | None = None
    try:
        if local_mode:
            cover_proc = start_local_cover_backend(outdir, local_cover_port)
            yumed_proc, local_keyset = start_local_yumed(
                args,
                outdir,
                key_material_dir,
                local_yumed_port,
                local_cover_port,
                "127.0.0.2" if args.tls_wire_report else "127.0.0.1",
            )
            data["yumed_argv_redacted"] = getattr(yumed_proc, "_yume_argv_redacted", [])
            if args.tls_wire_report:
                wire_report = pathlib.Path(args.tls_wire_report).expanduser().resolve()
                wire_relay_proc = start_tls_wire_relay(
                    outdir,
                    local_yumed_port,
                    "127.0.0.2",
                    local_yumed_port,
                    wire_report,
                    args.startup_timeout,
                )
                data["tls_wire_report"] = str(wire_report)

        target_bpf = f"host {server_ip} and tcp port {args.port}"
        if local_mode:
            target_bpf = f"host 127.0.0.1 and tcp port {local_yumed_port}"
        if capture_tool != "none":
            target_cap = start_capture(
                capture_tool,
                iface,
                target_pcap,
                target_bpf,
                outdir / "target-capture.log",
            )

        if local_mode:
            yume_argv = build_local_yume_args(
                args,
                socks_port,
                local_yumed_port,
                local_keyset,
            )
        else:
            yume_argv = build_yume_args(args, socks_port)
        data["yume_argv_redacted"] = redact_args(yume_argv)
        ylog = yume_log.open("wb")
        yume_proc = subprocess.Popen(yume_argv, stdout=ylog, stderr=subprocess.STDOUT, start_new_session=True)
        yume_proc._yume_log_file = ylog  # type: ignore[attr-defined]
        if not wait_port("127.0.0.1", socks_port, args.startup_timeout):
            raise RuntimeError(f"yume did not open SOCKS on 127.0.0.1:{socks_port}; see {yume_log}")

        data["target_browser"] = run_chromium_urls(
            chromium,
            urls,
            outdir / "chromium-target",
            socks_port,
            args.browser_timeout,
            args.virtual_time_ms,
        )
        if target_cap is not None:
            stop_capture(target_cap)
            target_cap = None
        data["server_probe"] = probe_server_http_disguise(
            "127.0.0.2" if args.tls_wire_report else server,
            port,
            args.tls_name or server,
            outdir / "server-probe",
            args.client_http_profile or args.client_profile,
        )
    finally:
        if yume_proc is not None:
            terminate_process(yume_proc)
            log = getattr(yume_proc, "_yume_log_file", None)
            if log:
                log.close()
        if wire_relay_proc is not None:
            try:
                wire_relay_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                terminate_process(wire_relay_proc)
            log = getattr(wire_relay_proc, "_yume_log_file", None)
            if log:
                log.close()
        if yumed_proc is not None:
            terminate_process(yumed_proc)
            log = getattr(yumed_proc, "_yume_log_file", None)
            if log:
                log.close()
        if cover_proc is not None:
            terminate_process(cover_proc)
            log = getattr(cover_proc, "_yume_log_file", None)
            if log:
                log.close()
        if target_cap is not None:
            stop_capture(target_cap)
        if local_mode and not args.keep_workdir and key_material_dir.exists():
            shutil.rmtree(key_material_dir, ignore_errors=True)

    data["target_clienthellos"] = (
        extract_clienthellos(target_pcap) if target_pcap.exists() else []
    )

    if capture_tool == "none":
        data["baseline_skip_reason"] = "capture disabled by --capture-tool none"
    elif not args.skip_baseline and baseline_pcap is None and baseline_iface:
        baseline_pcap = outdir / "baseline-chromium.pcapng"
        data["baseline_pcap"] = str(baseline_pcap)
        baseline_bpf = "tcp port 443"
        try:
            baseline_cap = start_capture(capture_tool, baseline_iface, baseline_pcap, baseline_bpf, outdir / "baseline-capture.log")
            data["baseline_browser"] = run_chromium_urls(
                chromium,
                urls,
                outdir / "chromium-baseline",
                None,
                args.browser_timeout,
                args.virtual_time_ms,
            )
        finally:
            if baseline_cap is not None:
                stop_capture(baseline_cap)
    elif not args.skip_baseline and baseline_pcap is None:
        data.setdefault("baseline_skip_reason", "baseline interface unavailable")

    if baseline_pcap is not None and baseline_pcap.exists():
        data["baseline_clienthellos"] = extract_clienthellos(baseline_pcap)

    if target_pcap.exists():
        data["dpi_report"] = run_dpi_report(
            pathlib.Path(args.report_script).expanduser().resolve(),
            target_pcap,
            outdir / "dpi-report",
            server_ip,
            baseline_pcap,
        )
    else:
        data["dpi_report"] = {
            "ran": False,
            "error": "raw capture not available",
        }

    (outdir / "diagnose.json").write_text(json.dumps(data, indent=2))
    summarize(outdir, data)
    print(f"[+] Output: {outdir}")
    print(f"[+] Summary: {outdir / 'SUMMARY.md'}")
    if data["dpi_report"].get("ran"):
        print(f"[+] DPI report: {data['dpi_report']['report']}")
    if cleanup_outdir:
        shutil.rmtree(outdir, ignore_errors=True)
    return diagnostic_exit_code(data)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
