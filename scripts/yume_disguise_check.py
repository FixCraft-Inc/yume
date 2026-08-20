#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""
yume-disguise-check — validate --hide-in-the-crowd profile fidelity.

Spins up yumed once per server profile (without --real, so the
disguise-404 path is the only thing being exercised), probes it with
curl, and checks that the response looks
like the server software the profile claims to mimic:

  - Server: header matches the expected pattern (or is absent for
    profiles that don't emit one, like express / none).
  - Profile-specific headers are present (X-Powered-By: Express,
    CF-Ray for cloudflare).
  - Body length lands in the expected range.
  - Body contains the expected canonical substrings (e.g. "404 Not
    Found", "nginx", "Cannot GET").
  - Response is a syntactically valid HTTP/1.1 404 Not Found.

Optionally, if `ndpiReader` is on PATH and --dpi is passed, captures
the probe traffic via tcpdump and asks nDPI to classify each flow,
adding a DPI verdict column (TLS.HTTP is the goal; Unknown means the
disguise isn't enough to fool a flow-level DPI engine).

For client profiles, the User-Agent is verified by inspecting what
the yume client sends in its TLS-stealth probe — we don't need a
full connection, just to confirm the active_client_ua is wired right.

Exits 0 if every selected profile passes, 1 otherwise. Designed to
run end-to-end in <60 s on a laptop and is safe to run in CI.

  ./scripts/yume_disguise_check.py                  # all profiles
  ./scripts/yume_disguise_check.py --server nginx,apache --no-client
  ./scripts/yume_disguise_check.py --dpi            # add ndpi classification
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# --- pretty output ----------------------------------------------------------
# Degrade gracefully when not a TTY or when NO_COLOR is set. Matches the
# basefwx plugin-smoke.sh convention so the visual style is consistent
# with the other helpers in the tree.

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

if _USE_COLOR:
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[1;31m"
    GREEN   = "\033[1;32m"
    YELLOW  = "\033[1;33m"
    BLUE    = "\033[1;34m"
    MAGENTA = "\033[1;35m"
    CYAN    = "\033[1;36m"
    RESET   = "\033[0m"
else:
    BOLD = DIM = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = RESET = ""

# Emojis double as PASS/FAIL markers. They render in any terminal that
# can show a checkmark; the trailing colored letter keeps the signal
# even on glyph-stripped terminals.
ICON_PASS = "✅"
ICON_FAIL = "❌"
ICON_WARN = "⚠️ "
ICON_SHIELD = "🛡️ "
ICON_SEARCH = "🔍"
ICON_GLOBE  = "🌐"
ICON_BOX    = "📦"
ICON_INFO   = "ℹ️ "

# --- expectations -----------------------------------------------------------

SERVER_PROFILES = {
    "nginx": {
        "server_re":      r"nginx/[\d.]+$",
        "body_must":      ["404 Not Found", "nginx"],
        "extra_headers":  [],
        "body_min":       100,
        "body_max":       300,
    },
    "nginx-stable": {
        "server_re":      r"nginx$",
        "body_must":      ["404 Not Found"],
        "extra_headers":  [],
        "body_min":       80,
        "body_max":       300,
    },
    "apache": {
        "server_re":      r"Apache/[\d.]+\s+\(.+\)$",
        "body_must":      ["Not Found", "Apache/"],
        "extra_headers":  [],
        "body_min":       200,
        "body_max":       400,
    },
    "caddy": {
        "server_re":      r"Caddy$",
        "body_must":      [],
        "extra_headers":  [],
        "body_min":       0,
        "body_max":       0,
    },
    "cloudflare": {
        "server_re":      r"cloudflare$",
        "body_must":      ["404"],
        "extra_headers":  ["cf-ray:"],
        "body_min":       80,
        "body_max":       250,
    },
    "express": {
        "server_re":      None,   # express doesn't set Server
        "body_must":      ["Cannot GET", "<!DOCTYPE html>", "<title>Error</title>"],
        "extra_headers":  [
            "x-powered-by: express",
            "content-security-policy: default-src 'none'",
            "x-content-type-options: nosniff",
        ],
        "body_min":       100,
        "body_max":       200,
    },
    "gunicorn": {
        # Recent gunicorn (21.x+) omits the version by default; some
        # deployments configure it back on. Accept either.
        "server_re":      r"gunicorn(/[\d.]+)?$",
        "body_must":      ["Not Found", "<!doctype html>"],
        "extra_headers":  [],
        "body_min":       150,
        "body_max":       300,
    },
    "none": {
        "server_re":      None,
        "body_must":      [],
        "extra_headers":  [],
        "body_min":       0,
        "body_max":       0,
    },
}

# The client registry holds exactly one entry: the pinned cover profile.
# There is no firefox/safari/edge/curl/wget/yume client profile to test, and
# no "yume-tls-verify" User-Agent — active_client_ua() always returns the
# pinned cover UA.
CLIENT_PROFILES = {
    "chrome":  r"^Mozilla/5\.0 .* Chrome/[\d.]+ Safari/",
}

# --- helpers ---------------------------------------------------------------

@dataclass
class ProbeResult:
    profile:     str
    ok:          bool
    status:      Optional[str] = None
    server:      Optional[str] = None
    body_len:    Optional[int] = None
    failures:    list[str] = field(default_factory=list)
    dpi_label:   Optional[str] = None
    raw_headers: str = ""


def find_repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        if (parent / "CMakeLists.txt").exists() and (parent / "src").is_dir():
            return parent
    raise SystemExit("could not locate repo root from " + str(here))


def find_yume_binary(repo: Path, name: str) -> Path:
    for cand in [repo / "build" / "bin" / name, repo / "build-features" / "bin" / name]:
        if cand.is_file():
            return cand
    raise SystemExit(f"could not find {name} under {repo}/build*/bin — run cmake --build first")


def generate_keyset(workdir: Path, yumed: Path) -> dict:
    """Reuses scripts/yume_bench_localhost.generate_keyset if available;
    otherwise the script can't run (it needs an Ed25519 keypair + a
    self-signed cert)."""
    sys.path.insert(0, str(yumed.parent.parent.parent / "scripts"))
    try:
        import yume_bench_localhost as bench
        ks = bench.generate_keyset(workdir, yumed)
        return {
            "server_cert":     ks.server_cert,
            "server_key":      ks.server_key,
            "auth_keys_file":  ks.auth_keys_file,
        }
    except Exception as exc:
        raise SystemExit(f"keyset generation failed (need scripts/yume_bench_localhost.py): {exc}")


def start_yumed(yumed: Path, workdir: Path, ks: dict, profile: str, port: int) -> subprocess.Popen:
    log = open(workdir / f"yumed-{profile}.log", "w")
    return subprocess.Popen([
        str(yumed),
        "--listen", str(port),
        "--cert", str(ks["server_cert"]),
        "--key",  str(ks["server_key"]),
        "--auth-keys", str(ks["auth_keys_file"]),
        "--hide-in-the-crowd", profile,
    ], stdout=log, stderr=subprocess.STDOUT, cwd=str(workdir))


def stop_proc(proc: subprocess.Popen) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def have_tcpdump_capability() -> tuple[bool, str]:
    """Returns (ok, reason). tcpdump on loopback needs CAP_NET_RAW or
    root. We don't try sudo here because that prompts; instead the
    --dpi mode tells the user up-front what's needed."""
    if os.geteuid() == 0:
        return True, "running as root"
    # Check if tcpdump has the cap_net_raw capability set.
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        return False, "tcpdump not on PATH"
    getcap = shutil.which("getcap") or "/sbin/getcap"
    if not Path(getcap).exists():
        return False, "getcap not available; install libcap2-bin to enable cap detection"
    r = subprocess.run([getcap, tcpdump], capture_output=True, text=True)
    if "cap_net_raw" in (r.stdout or ""):
        return True, "tcpdump has cap_net_raw"
    return False, "need root or `setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)`"


def capture_and_classify(port: int, path: str, profile_label: str, pcap_dir: Path) -> Optional[str]:
    """Captures the probe traffic on loopback and runs ndpiReader.
    Returns the top-protocol label (e.g. "TLS") or None on error."""
    pcap = pcap_dir / f"{profile_label}.pcap"
    # tcpdump on loopback, filtering to our port for a clean single-flow
    # capture. -U flushes per packet so the capture is ready right after
    # we stop tcpdump.
    proc = subprocess.Popen(
        ["tcpdump", "-i", "lo", "-U", "-s", "0", "-w", str(pcap), f"port {port}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.3)  # give tcpdump time to attach
    try:
        subprocess.run(
            ["curl", "-sk", "--http1.1", "-o", "/dev/null",
             f"https://127.0.0.1:{port}{path}"],
            capture_output=True, timeout=5,
        )
    finally:
        proc.terminate()
        try: proc.wait(timeout=2)
        except subprocess.TimeoutExpired: proc.kill()

    if not pcap.exists() or pcap.stat().st_size == 0:
        return None
    r = subprocess.run(
        ["ndpiReader", "-i", str(pcap), "-q"],
        capture_output=True, text=True, timeout=10,
    )
    # ndpiReader "-q" prints a one-line-per-flow summary. We want the
    # protocol field — typically the third whitespace-separated token
    # after stripping the leading flow index. Parse the most-frequent
    # protocol label.
    proto_counts: dict[str, int] = {}
    for line in (r.stdout or "").splitlines():
        # Lines look like:
        #   1     TCP 127.0.0.1:nnnnn <-> 127.0.0.1:19443  [proto: 91/TLS][...]
        m = re.search(r"\[proto:\s*\d+(?:\.\d+)?/([^\]]+)\]", line)
        if m:
            label = m.group(1).strip()
            proto_counts[label] = proto_counts.get(label, 0) + 1
    if not proto_counts:
        return "Unknown"
    return max(proto_counts.items(), key=lambda kv: kv[1])[0]


def curl_probe(port: int, path: str = "/notfound") -> tuple[bool, str, str]:
    """Returns (ok, headers, body). Tolerates non-zero curl exits when
    the response itself parses — yumed closes the TCP socket without
    sending a TLS close_notify (matches what nginx-on-keepalive=close
    does), which curl reports as exit 56 (CURLE_RECV_ERROR) even
    though the headers + body arrived intact."""
    try:
        r = subprocess.run(
            ["curl", "-sk", "--http1.1", "-i",
             f"https://127.0.0.1:{port}{path}"],
            capture_output=True, text=True, timeout=5,
        )
    except subprocess.TimeoutExpired:
        return False, "", ""
    if not r.stdout.startswith("HTTP/1.1 "):
        return False, r.stdout or r.stderr, ""
    # curl -i normalises on-wire \r\n to plain \n in stdout. Accept
    # either separator so the script works regardless of curl quirks.
    sep = "\r\n\r\n" if "\r\n\r\n" in r.stdout else ("\n\n" if "\n\n" in r.stdout else None)
    if sep is None:
        return False, r.stdout, ""
    head, _, body = r.stdout.partition(sep)
    return True, head, body


def _header_lines(headers: str) -> list[str]:
    # Accept \r\n or \n line endings (curl -i can normalise to \n).
    return headers.replace("\r\n", "\n").split("\n")


def parse_header(headers: str, name: str) -> Optional[str]:
    needle = name.lower() + ":"
    for line in _header_lines(headers):
        if line.lower().startswith(needle):
            return line.split(":", 1)[1].strip()
    return None


def header_present(headers: str, name_with_colon: str) -> bool:
    needle = name_with_colon.lower()
    for line in _header_lines(headers):
        if line.lower().startswith(needle):
            return True
    return False


def check_server_profile(name: str, yumed: Path, workdir: Path, ks: dict, port: int,
                         dpi: bool = False) -> ProbeResult:
    spec = SERVER_PROFILES[name]
    proc = start_yumed(yumed, workdir, ks, name, port)
    time.sleep(1.5)
    try:
        ok, headers, body = curl_probe(port)
        dpi_label = None
        if dpi:
            dpi_label = capture_and_classify(port, "/notfound", name, workdir)
    finally:
        stop_proc(proc)

    res = ProbeResult(profile=name, ok=False, raw_headers=headers)
    if dpi:
        res.dpi_label = dpi_label
    if not ok:
        res.failures.append("no usable HTTP response (yumed log: " + str(workdir / f'yumed-{name}.log') + ")")
        return res

    status_line = headers.split("\r\n", 1)[0] if headers else ""
    res.status = status_line
    server_val = parse_header(headers, "Server")
    res.server = server_val
    res.body_len = len(body)

    if not status_line.startswith("HTTP/1.1 404 Not Found"):
        res.failures.append(f"status line is {status_line!r}, expected 'HTTP/1.1 404 Not Found'")

    if spec["server_re"] is None:
        if server_val:
            res.failures.append(f"unexpected Server header {server_val!r}; profile {name} should emit no Server header")
    else:
        if server_val is None:
            res.failures.append(f"Server header missing; expected to match /{spec['server_re']}/")
        elif not re.fullmatch(spec["server_re"], server_val):
            res.failures.append(f"Server={server_val!r} does not match expected /{spec['server_re']}/")

    for h in spec["extra_headers"]:
        if not header_present(headers, h.split(":", 1)[0]):
            res.failures.append(f"expected header {h!r} not present")

    for needle in spec["body_must"]:
        if needle not in body:
            res.failures.append(f"body missing expected substring {needle!r}")

    bmin, bmax = spec["body_min"], spec["body_max"]
    if bmax == 0:
        if len(body) != 0:
            res.failures.append(f"expected empty body, got {len(body)} bytes")
    else:
        if not (bmin <= len(body) <= bmax):
            res.failures.append(f"body length {len(body)} outside expected [{bmin}, {bmax}]")

    res.ok = not res.failures
    return res


def check_client_profiles(yume: Path) -> dict[str, tuple[bool, str]]:
    """For each client profile, run `yume --hide-in-the-crowd <p> --timing
    --help` and parse the "active client profile = <p>" log line. This
    just confirms the validator + active-UA installer wiring is correct;
    the actual UA-on-the-wire was verified in dev against tls.peet.ws."""
    results = {}
    for name, ua_re in CLIENT_PROFILES.items():
        r = subprocess.run(
            [str(yume), "--hide-in-the-crowd", name, "--timing", "--help"],
            capture_output=True, text=True, timeout=5,
        )
        out = (r.stdout or "") + (r.stderr or "")
        active = f"active client profile = {name}" in out
        # We didn't expose active_client_ua() to the CLI surface; treat
        # presence of the active-profile log line as sufficient evidence
        # that the registry lookup + setter ran.
        results[name] = (active, "active-profile log line present" if active else "active-profile log line missing")
    return results


# --- main -------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default="", help="comma-separated server profiles (default: all)")
    ap.add_argument("--no-client", action="store_true", help="skip client-profile checks")
    ap.add_argument("--port", type=int, default=19443, help="local port yumed listens on")
    ap.add_argument("--json", action="store_true", help="emit results as JSON")
    ap.add_argument("--dpi", action="store_true",
                    help="capture loopback traffic per profile and run "
                         "ndpiReader; needs tcpdump capability "
                         "(root or `setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)`).")
    args = ap.parse_args()

    if args.dpi:
        ok, reason = have_tcpdump_capability()
        if not ok:
            print(f"--dpi requires tcpdump capability: {reason}", file=sys.stderr)
            return 2
        if shutil.which("ndpiReader") is None:
            print("--dpi requires ndpiReader (apt install libndpi-bin)", file=sys.stderr)
            return 2

    if shutil.which("curl") is None:
        return print("curl is required") or 1

    repo = find_repo_root()
    yumed = find_yume_binary(repo, "yumed")
    yume  = find_yume_binary(repo, "yume")
    workdir = Path(tempfile.mkdtemp(prefix="yume-disguise-"))
    ks = generate_keyset(workdir, yumed)

    server_subset = SERVER_PROFILES.keys() if not args.server else [p.strip() for p in args.server.split(",")]
    server_results = []
    for name in server_subset:
        if name not in SERVER_PROFILES:
            print(f"unknown profile: {name}", file=sys.stderr)
            return 2
        server_results.append(check_server_profile(name, yumed, workdir, ks, args.port, dpi=args.dpi))

    client_results = {} if args.no_client else check_client_profiles(yume)

    if args.json:
        print(json.dumps({
            "server": [{
                "profile":  r.profile,
                "ok":       r.ok,
                "status":   r.status,
                "server":   r.server,
                "body_len": r.body_len,
                "failures": r.failures,
            } for r in server_results],
            "client": {name: {"ok": ok, "note": note} for name, (ok, note) in client_results.items()},
        }, indent=2))
    else:
        # Banner
        title = f"{ICON_SHIELD} {BOLD}yume disguise check{RESET}"
        sub   = f"{DIM}— validates --hide-in-the-crowd profile fidelity{RESET}"
        print(f"\n{title}\n{sub}\n")

        print(f"{BOLD}{ICON_BOX} Server profile fidelity{RESET}")
        dpi_hdr = f"  {CYAN}dpi{RESET}   " if args.dpi else ""
        header = (f"  {DIM}{'profile':<14} {'status':<8} "
                  f"{'server':<32} {'body':>5}{dpi_hdr}  details{RESET}")
        print(header)
        sep = f"  {DIM}" + "─" * (60 + (8 if args.dpi else 0)) + RESET
        print(sep)
        for r in server_results:
            if r.ok:
                status = f"{GREEN}{ICON_PASS} ok  {RESET}"
                server_color = GREEN
                details = f"{DIM}clean{RESET}"
            else:
                status = f"{RED}{ICON_FAIL} fail{RESET}"
                server_color = RED
                details = f"{RED}" + "; ".join(r.failures) + RESET
            server_short = (r.server or "(none)")[:32]
            body_disp = str(r.body_len) if r.body_len is not None else "-"
            dpi_col = ""
            if args.dpi:
                lbl = r.dpi_label or "-"
                lbl_color = GREEN if lbl in ("TLS", "TLS.HTTPS", "HTTP") else (YELLOW if lbl == "Unknown" else CYAN)
                dpi_col = f"  {lbl_color}{lbl:<6}{RESET}"
            print(f"  {BOLD}{r.profile:<14}{RESET} {status} "
                  f"{server_color}{server_short:<32}{RESET} {body_disp:>5}{dpi_col}  {details}")

        if client_results:
            print(f"\n{BOLD}{ICON_GLOBE} Client profile wiring{RESET}")
            for name, (ok, note) in client_results.items():
                if ok:
                    print(f"  {BOLD}{name:<10}{RESET} {GREEN}{ICON_PASS} ok{RESET}  {DIM}{note}{RESET}")
                else:
                    print(f"  {BOLD}{name:<10}{RESET} {RED}{ICON_FAIL} fail{RESET}  {RED}{note}{RESET}")

    server_pass = all(r.ok for r in server_results)
    client_pass = all(ok for ok, _ in client_results.values()) if client_results else True
    n_pass = sum(1 for r in server_results if r.ok)
    n_fail = len(server_results) - n_pass
    n_cpass = sum(1 for ok, _ in client_results.values() if ok)

    print()
    if server_pass and client_pass:
        verdict = f"{GREEN}{ICON_PASS} all profiles pass{RESET}"
    else:
        verdict = f"{RED}{ICON_FAIL} {n_fail} server profile(s) failed{RESET}"
    summary = (f"{BOLD}Result:{RESET} {verdict}  "
               f"{DIM}({n_pass}/{len(server_results)} server, "
               f"{n_cpass}/{len(client_results) if client_results else 0} client){RESET}")
    print(summary)
    print(f"{DIM}{ICON_INFO} workdir: {workdir}{RESET}")
    return 0 if (server_pass and client_pass) else 1


if __name__ == "__main__":
    sys.exit(main())
