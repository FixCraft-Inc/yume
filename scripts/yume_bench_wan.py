#!/usr/bin/env python3
"""Run YUME 2.0 through a reproducible virtual WAN and retain its PCAPs."""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from yume_bench_common import (  # noqa: E402
    BenchKeyset,
    ManagedProcess,
    RuntimeIdentity,
    chown_tree,
    command_version,
    drop_prefix,
    endpoint_contract,
    generate_keyset,
    invoking_identity,
    parse_rates,
    relay_chunk_kib,
    resolve_pinned_node,
    run_streamed_command,
    start_logged_process,
    wait_for_tcp,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_IP = "10.77.0.1"
CLIENT_IP = "10.77.0.2"
TLS_NAME = "cover.yume.test"
YUME_PORT = 443
COVER_PORT = 3000


@dataclass(frozen=True)
class WanProfile:
    rtt_ms: int
    jitter_ms: int
    loss_pct: float
    bandwidth_mbit: int


PROFILES = {
    "lan": WanProfile(2, 0, 0.0, 1000),
    "broadband": WanProfile(30, 4, 0.1, 200),
    "mobile-4g": WanProfile(60, 10, 1.0, 50),
    "lossy-wifi": WanProfile(40, 12, 3.0, 30),
}


class NetworkLab:
    def __init__(self, profile: WanProfile) -> None:
        suffix = str(os.getpid())[-6:]
        self.server_ns = f"yume-bench-server-{suffix}"
        self.client_ns = f"yume-bench-client-{suffix}"
        self.server_if = f"ybs{suffix}"
        self.client_if = f"ybc{suffix}"
        self.profile = profile
        self.created = False

    @staticmethod
    def _run(argv: list[str]) -> None:
        subprocess.run(argv, check=True, stdout=subprocess.DEVNULL)

    def create(self) -> None:
        self._run(["ip", "netns", "add", self.server_ns])
        try:
            self._run(["ip", "netns", "add", self.client_ns])
            self._run([
                "ip", "link", "add", self.server_if, "type", "veth",
                "peer", "name", self.client_if,
            ])
            self._run(["ip", "link", "set", self.server_if, "netns", self.server_ns])
            self._run(["ip", "link", "set", self.client_if, "netns", self.client_ns])
            self._configure_side(self.server_ns, self.server_if, f"{SERVER_IP}/24")
            self._configure_side(self.client_ns, self.client_if, f"{CLIENT_IP}/24")
            self._shape(self.server_ns, self.server_if)
            self._shape(self.client_ns, self.client_if)
            self.created = True
        except Exception:
            self.close()
            raise

    def _configure_side(self, namespace: str, interface: str, address: str) -> None:
        self._run(["ip", "-n", namespace, "link", "set", "lo", "up"])
        self._run(["ip", "-n", namespace, "addr", "add", address, "dev", interface])
        self._run(["ip", "-n", namespace, "link", "set", interface, "up"])

    def _shape(self, namespace: str, interface: str) -> None:
        delay = max(self.profile.rtt_ms / 2.0, 0.1)
        jitter = self.profile.jitter_ms / 2.0
        argv = [
            "ip", "netns", "exec", namespace,
            "tc", "qdisc", "replace", "dev", interface, "root", "netem",
            "delay", f"{delay:g}ms",
        ]
        if jitter > 0:
            argv.extend([f"{jitter:g}ms", "distribution", "normal"])
        if self.profile.loss_pct > 0:
            argv.extend(["loss", "random", f"{self.profile.loss_pct:g}%"])
        argv.extend(["rate", f"{self.profile.bandwidth_mbit}mbit"])
        self._run(argv)

    def command(self, namespace: str, argv: list[str]) -> list[str]:
        return ["ip", "netns", "exec", namespace, *argv]

    def close(self) -> None:
        for namespace in (self.client_ns, self.server_ns):
            subprocess.run(
                ["ip", "netns", "del", namespace],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        self.created = False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Provision a temporary YUME 2.0 endpoint, real Node cover, "
            "netem path, endpoint benchmark, Chrome cover load, and PCAPs."
        )
    )
    parser.add_argument("--profile", choices=PROFILES, default="mobile-4g")
    parser.add_argument("--rtt", type=int, metavar="MS", help="override target RTT")
    parser.add_argument("--jitter", type=int, metavar="MS", help="override RTT jitter")
    parser.add_argument("--loss", type=float, metavar="PCT", help="override per-side loss")
    parser.add_argument("--bandwidth", type=int, metavar="MBIT", help="override link rate")
    parser.add_argument("--bench-mib", type=int, default=128, help="MiB per direction")
    parser.add_argument("--bench-streams", type=int, default=8)
    parser.add_argument(
        "--bench-chunk-kib",
        type=int,
        help="explicit DATA chunk size; omit to match the production relay buffer",
    )
    parser.add_argument("--bench-direction", choices=("both", "up", "down"), default="both")
    size = parser.add_mutually_exclusive_group()
    size.add_argument("--quick", action="store_true", help="32 MiB, 4 streams; skip browser")
    size.add_argument("--full", action="store_true", help="1024 MiB, 64 streams")
    parser.add_argument("--no-browser", action="store_true", help="skip the Chrome cover load")
    parser.add_argument("--no-pcap", action="store_true", help="disable tcpdump capture")
    parser.add_argument("--browser", type=Path, help="Chromium/Chrome executable")
    parser.add_argument("--node", type=Path, help="Node executable")
    parser.add_argument("--allow-node-version-mismatch", action="store_true")
    parser.add_argument(
        "--no-node-bootstrap",
        action="store_true",
        help="do not resolve pinned Node through npx when the system version differs",
    )
    parser.add_argument("--yume", type=Path, default=REPO_ROOT / "build" / "bin" / "yume")
    parser.add_argument("--yumed", type=Path, default=REPO_ROOT / "build" / "bin" / "yumed")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    return parser.parse_args()


def require_tools(names: list[str]) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise SystemExit(f"missing required tools: {', '.join(missing)}")


def executable(value: Path | None, candidates: tuple[str, ...]) -> Path | None:
    if value:
        resolved = value.expanduser().resolve()
        return resolved if resolved.is_file() and os.access(resolved, os.X_OK) else None
    for name in candidates:
        found = shutil.which(name)
        if found:
            return Path(found).resolve()
    return None


def choose_profile(args: argparse.Namespace) -> WanProfile:
    profile = PROFILES[args.profile]
    return WanProfile(
        args.rtt if args.rtt is not None else profile.rtt_ms,
        args.jitter if args.jitter is not None else profile.jitter_ms,
        args.loss if args.loss is not None else profile.loss_pct,
        args.bandwidth if args.bandwidth is not None else profile.bandwidth_mbit,
    )


def validate_args(args: argparse.Namespace, profile: WanProfile) -> None:
    if profile.rtt_ms < 0 or profile.jitter_ms < 0:
        raise SystemExit("RTT and jitter must be non-negative")
    if not 0 <= profile.loss_pct < 100:
        raise SystemExit("loss must be at least 0 and less than 100 percent")
    if profile.bandwidth_mbit <= 0:
        raise SystemExit("bandwidth must be positive")
    if not 1 <= args.bench_mib <= 16384:
        raise SystemExit("--bench-mib must be 1..16384")
    if not 1 <= args.bench_streams <= 240:
        raise SystemExit("--bench-streams must be 1..240")
    if args.bench_chunk_kib is not None and not 1 <= args.bench_chunk_kib <= 256:
        raise SystemExit("--bench-chunk-kib must be 1..256")


def start_node(
    lab: NetworkLab,
    node: Path,
    log: Path,
    identity: RuntimeIdentity,
) -> ManagedProcess:
    argv = lab.command(lab.server_ns, [*drop_prefix(identity),
        "env", "YUME_COVER_HOST=127.0.0.1", f"YUME_COVER_PORT={COVER_PORT}",
        str(node), str(REPO_ROOT / "tools" / "cover-node" / "backend.mjs"),
    ])
    process = start_logged_process(argv, log, cwd=REPO_ROOT)
    if not wait_for_tcp("127.0.0.1", COVER_PORT, 10, namespace=lab.server_ns):
        process.stop()
        raise RuntimeError(f"Node cover failed to listen; see {log}")
    return process


def start_yumed(
    lab: NetworkLab,
    yumed: Path,
    keys: BenchKeyset,
    log: Path,
) -> ManagedProcess:
    argv = lab.command(lab.server_ns, [
        str(yumed),
        "--listen", f"{SERVER_IP}:{YUME_PORT}",
        "--cert", str(keys.server_cert),
        "--key", str(keys.server_key),
        "--auth-keys", str(keys.authorized_keys),
        "--obfs-secret-file", str(keys.admission_secret),
        "--inner-psk-file", str(keys.inner_psk),
        "--real-backend", f"loopback://127.0.0.1:{COVER_PORT}",
        "--bench", "--boring",
    ])
    process = start_logged_process(argv, log)
    if not wait_for_tcp(SERVER_IP, YUME_PORT, 15, namespace=lab.client_ns):
        process.stop()
        raise RuntimeError(f"yumed failed to listen; see {log}")
    return process


def start_capture(lab: NetworkLab, output: Path, log: Path) -> ManagedProcess:
    argv = lab.command(lab.client_ns, [
        "tcpdump", "-i", lab.client_if, "-n", "-s", "0", "-U",
        "-w", str(output), "tcp", "port", str(YUME_PORT), "and", "host", SERVER_IP,
    ])
    capture = start_logged_process(argv, log)
    time.sleep(0.5)
    if capture.process.poll() is not None:
        capture.stop()
        raise RuntimeError(f"tcpdump failed; see {log}")
    return capture


def run_endpoint(
    args: argparse.Namespace,
    lab: NetworkLab,
    yume: Path,
    keys: BenchKeyset,
    workdir: Path,
    output: Path,
) -> tuple[int, str, list[str]]:
    if args.quick:
        mib, streams = 32, 4
    elif args.full:
        mib, streams = 1024, 64
    else:
        mib, streams = args.bench_mib, args.bench_streams
    argv = lab.command(lab.client_ns, [
        "env", f"HOME={workdir / 'home'}", f"XDG_RUNTIME_DIR={workdir / 'runtime'}",
        str(yume),
        "--server", SERVER_IP,
        "--port", str(YUME_PORT),
        "--tls-name", TLS_NAME,
        "--tls-ca", str(keys.server_cert),
        "--auth", str(keys.client_identity),
        "--obfs-secret-file", str(keys.admission_secret),
        "--inner-psk-file", str(keys.inner_psk),
        "--profile", "chrome",
        "--bench",
        "--bench-mib", str(mib),
        "--bench-streams", str(streams),
        "--bench-direction", args.bench_direction,
        "--non-interactive", "--accept-monitoring", "--boring", "--no-color",
    ])
    if args.bench_chunk_kib is not None:
        argv.extend(["--bench-chunk-kib", str(args.bench_chunk_kib)])
    directions = 2 if args.bench_direction == "both" else 1
    transfer_seconds = mib * 8 * directions / max(1, lab.profile.bandwidth_mbit)
    timeout = max(120, int(transfer_seconds * 4 + 90))
    result = run_streamed_command(
        argv,
        timeout=timeout,
        interrupt_message="[bench] interrupted; stopping the endpoint benchmark",
    )
    output.write_text(result.output, encoding="utf-8")
    return result.returncode, result.output, argv


def run_browser_cover(
    lab: NetworkLab,
    browser: Path,
    workdir: Path,
    output: Path,
    identity: RuntimeIdentity,
) -> tuple[int, list[str]]:
    profile = workdir / "chromium-profile"
    argv = lab.command(lab.client_ns, [*drop_prefix(identity),
        "env", f"HOME={workdir / 'home'}", f"XDG_RUNTIME_DIR={workdir / 'runtime'}",
        str(browser), "--headless", "--disable-gpu", "--no-sandbox",
        "--disable-breakpad", "--disable-crash-reporter",
        "--disable-background-networking", "--disable-component-update",
        "--no-first-run", "--no-default-browser-check",
        f"--user-data-dir={profile}",
        f"--host-resolver-rules=MAP {TLS_NAME} {SERVER_IP}",
        "--ignore-certificate-errors", "--dump-dom", f"https://{TLS_NAME}/",
    ])
    result = run_streamed_command(
        argv,
        timeout=30,
        echo=False,
        interrupt_message="[bench] interrupted; stopping the Chrome cover load",
    )
    output.write_text(result.output, encoding="utf-8")
    return result.returncode, argv


def restore_output_owner(path: Path) -> None:
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if uid is None or gid is None:
        return
    for item in [path, *path.rglob("*")]:
        os.chown(item, int(uid), int(gid), follow_symlinks=False)


def main() -> int:
    args = parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run with sudo: network namespaces, netem, and tcpdump need root")
    require_tools(
        ["ip", "tc", "openssl", "python3", "setpriv"]
        + ([] if args.no_pcap else ["tcpdump"])
    )

    yume = executable(args.yume, ())
    yumed = executable(args.yumed, ())
    if not yume or not yumed:
        raise SystemExit("build/bin/yume and build/bin/yumed are required")
    try:
        node, node_version, node_bootstrapped = resolve_pinned_node(
            args.node,
            allow_mismatch=args.allow_node_version_mismatch,
            bootstrap=not args.no_node_bootstrap,
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    if node_bootstrapped:
        print(f"[bench] using pinned {node_version} from the invoking user's npm cache")

    browser = None if args.no_browser or args.quick else executable(
        args.browser, ("chromium", "chromium-browser", "google-chrome")
    )
    if not args.no_browser and not args.quick and not browser:
        print("[bench] Chrome/Chromium not found; skipping the public-cover capture", file=sys.stderr)
    browser_version = command_version([str(browser), "--version"]) if browser else None
    if browser_version and not re.search(r"\b(?:Chrome|Chromium)\s+150\.", browser_version):
        print(
            f"[bench] {browser_version} does not match Chrome 150; "
            "the cover arm is functional evidence only",
            file=sys.stderr,
        )

    production_chunk_kib = relay_chunk_kib()
    effective_chunk_kib = args.bench_chunk_kib or production_chunk_kib
    profile = choose_profile(args)
    validate_args(args, profile)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = (args.output_dir or REPO_ROOT / "yume-bench-results" / timestamp).resolve()
    output_dir.mkdir(parents=True, exist_ok=False, mode=0o750)
    workdir = Path(tempfile.mkdtemp(prefix="yume-bench-2-"))
    os.chmod(workdir, 0o700)
    run_identity = invoking_identity()

    lab = NetworkLab(profile)
    processes: list[ManagedProcess] = []
    atexit.register(lab.close)
    started = datetime.now(timezone.utc).isoformat()
    print(f"[bench] artifacts: {output_dir}")
    print(
        f"[bench] network: {args.profile}, RTT {profile.rtt_ms} ms, "
        f"jitter {profile.jitter_ms} ms, loss {profile.loss_pct:g}%, "
        f"rate {profile.bandwidth_mbit} Mbit/s"
    )

    endpoint_code = 1
    browser_code: int | None = None
    endpoint_command: list[str] = []
    browser_command: list[str] = []
    endpoint_output = ""
    try:
        keys = generate_keyset(
            workdir / "keys", yumed, tls_name=TLS_NAME, server_ip=SERVER_IP
        )
        (workdir / "home").mkdir(mode=0o700)
        (workdir / "runtime").mkdir(mode=0o700)
        chown_tree(workdir, run_identity)
        lab.create()
        node_process = start_node(
            lab, node, output_dir / "node.log", run_identity
        )
        processes.append(node_process)
        yumed_process = start_yumed(lab, yumed, keys, output_dir / "yumed.log")
        processes.append(yumed_process)

        capture = None
        if not args.no_pcap:
            capture = start_capture(
                lab, output_dir / "endpoint.pcap", output_dir / "tcpdump-endpoint.log"
            )
            processes.append(capture)
        print("[bench] running authenticated YUME 2.0 endpoint benchmark")
        endpoint_code, endpoint_output, endpoint_command = run_endpoint(
            args, lab, yume, keys, workdir, output_dir / "endpoint.log"
        )
        if capture:
            capture.stop(interrupt=True)
            processes.remove(capture)
        if browser and endpoint_code == 0:
            capture = None
            if not args.no_pcap:
                capture = start_capture(
                    lab,
                    output_dir / "cover-chromium.pcap",
                    output_dir / "tcpdump-cover.log",
                )
                processes.append(capture)
            print("[bench] loading the public Node cover with Chrome/Chromium")
            browser_code, browser_command = run_browser_cover(
                lab,
                browser,
                workdir,
                output_dir / "cover-chromium.log",
                run_identity,
            )
            if capture:
                capture.stop(interrupt=True)
                processes.remove(capture)
    except KeyboardInterrupt:
        endpoint_code = 130
        print("\n[bench] interrupted; stopping the benchmark lab", file=sys.stderr)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"[bench] failed: {exc}", file=sys.stderr)
    finally:
        while processes:
            processes.pop().stop(interrupt=True)
        lab.close()

        report = {
            "schema": 1,
            "started_utc": started,
            "finished_utc": datetime.now(timezone.utc).isoformat(),
            "profile_name": args.profile,
            "network": asdict(profile),
            "versions": {
                "yume": command_version([str(yume), "--version"]),
                "node": node_version,
                "browser": browser_version,
            },
            "endpoint": {
                "exit_code": endpoint_code,
                "command": endpoint_command,
                "chunk_kib": effective_chunk_kib,
                "requested_chunk_kib": args.bench_chunk_kib,
                "chunk_source": (
                    "production-relay-buffer"
                    if args.bench_chunk_kib is None
                    else "explicit"
                ),
                "contract": endpoint_contract(
                    args.bench_chunk_kib,
                    production_chunk_kib,
                ),
                "rates": parse_rates(endpoint_output),
                "pcap": "endpoint.pcap" if not args.no_pcap else None,
            },
            "cover": {
                "exit_code": browser_code,
                "command": browser_command,
                "pcap": "cover-chromium.pcap" if browser and not args.no_pcap else None,
            },
        }
        (output_dir / "report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        if args.keep_workdir:
            (output_dir / "workdir.txt").write_text(str(workdir) + "\n", encoding="utf-8")
            print(f"[bench] retained secrets and scratch files in {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)
        restore_output_owner(output_dir)

    if endpoint_code != 0:
        print(f"[bench] endpoint benchmark failed; inspect {output_dir}", file=sys.stderr)
        return endpoint_code or 1
    if browser_code not in (None, 0):
        print(f"[bench] cover load failed; inspect {output_dir}", file=sys.stderr)
        return browser_code or 1
    print(f"[bench] complete: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
