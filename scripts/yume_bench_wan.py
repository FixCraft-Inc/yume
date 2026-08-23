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
    StreamedCommandResult,
    chown_tree,
    command_version,
    drop_prefix,
    endpoint_contract,
    generate_keyset,
    invoking_identity,
    parse_rates,
    relay_chunk_kib,
    require_user_namespace_sandbox,
    resolve_pinned_node,
    run_streamed_command,
    sha256_file,
    start_logged_process,
    validate_pinned_chrome,
    wait_for_tcp,
)
from yume_bench_resources import (  # noqa: E402
    host_resource_info,
    print_host_resources,
    print_process_resources,
    write_resource_samples,
)
from yume_bench_provenance import git_source_snapshot  # noqa: E402
from yume_bench_isolation import (  # noqa: E402
    EXEC_GUARD,
    FrozenExecutable,
    capability_drop_prefix,
    enforce_private_artifact_modes,
    enter_isolated_controller,
    freeze_executable,
    frozen_executable_version,
    guarded_command,
    isolated_reexec_argv,
    namespace_inodes,
    node_sandbox_command,
    output_owner,
    remove_private_tree,
    restore_output_owner,
    root_mount_is_private,
    runtime_security_log,
    runtime_security_state,
    single_id_mapping,
    write_private_text,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_IP = "10.77.0.1"
CLIENT_IP = "10.77.0.2"
TLS_NAME = "cover.yume.test"
YUME_PORT = 443
# A rootless workload has no initial-namespace CAP_NET_BIND_SERVICE after its
# capability drop. The isolated synthetic mode therefore uses a high internal
# port while binding that port into both the admission authority and capture.
ISOLATED_YUME_PORT = 8443
COVER_PORT = 3000
RUNTIME_SOURCE_INPUTS = (
    Path("scripts/yume_bench_wan.py"),
    Path("scripts/yume_bench_common.py"),
    Path("scripts/yume_bench_resources.py"),
    Path("scripts/yume_bench_isolation.py"),
    Path("scripts/yume_bench_provenance.py"),
    Path("scripts/yume_bench_exec_guard.py"),
    Path("tools/cover-node/backend.mjs"),
    Path("config/transport_profiles.json"),
    Path("tests/fixtures/chrome151-node24/manifest.json"),
)


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
    def __init__(self, profile: WanProfile, *, isolated_userns: bool = False) -> None:
        suffix = str(os.getpid())[-6:]
        self.server_ns = f"yume-bench-server-{suffix}"
        self.client_ns = f"yume-bench-client-{suffix}"
        self.server_if = f"ybs{suffix}"
        self.client_if = f"ybc{suffix}"
        self.profile = profile
        self.isolated_userns = isolated_userns
        self.yume_port = ISOLATED_YUME_PORT if isolated_userns else YUME_PORT
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

    def tune_tcp_memory(self, max_bytes: int) -> None:
        """Raise the per-namespace TCP autotuning ceiling.

        A single TCP connection at high RTT is bounded by tcp_rmem/tcp_wmem
        maxima long before it is bounded by TCP itself: at 60 ms the Debian
        defaults (6 MiB read / 4 MiB write) cap one stream near 390 Mbit/s,
        while a 64 MiB ceiling lets the same stream reach ~5.3 Gbit/s. YUME
        multiplexes every logical stream onto one tunnel, so it inherits that
        single-connection ceiling exactly. Sweep this to separate a deployment
        tuning limit from a limit inside YUME.
        """
        for namespace in (self.server_ns, self.client_ns):
            for key, default_min, default_start in (
                    ("net.ipv4.tcp_rmem", 4096, 131072),
                    ("net.ipv4.tcp_wmem", 4096, 16384)):
                subprocess.run(
                    ["ip", "netns", "exec", namespace, "sysctl", "-qw",
                     f"{key}={default_min} {default_start} {max_bytes}"],
                    check=False, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)

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
        help="explicit upload DATA chunk size; omit to match the client relay buffer",
    )
    parser.add_argument("--bench-direction", choices=("both", "up", "down"), default="both")
    parser.add_argument(
        "--tcp-mem-max",
        type=int,
        metavar="MIB",
        help=(
            "raise net.ipv4.tcp_rmem/tcp_wmem maxima inside the lab "
            "namespaces. YUME muxes every stream onto one tunnel, so it is "
            "bounded by what a single TCP connection can do, which at high RTT "
            "is set by these caps rather than by TCP"
        ),
    )
    parser.add_argument(
        "--security-mode",
        choices=("extreme", "normal", "soft", "session"),
        help=(
            "ratchet epoch policy on both endpoints. extreme is the default "
            "256 KiB/512 frames/500 ms; normal 8 GiB/60 s; soft 256 GiB/30 min; "
            "session is an `ultimate` custom policy at the maximum permitted "
            "limits, i.e. effectively one key for the whole session. Anything "
            "other than extreme widens the cryptographic compromise window and "
            "is for measurement, not deployment"
        ),
    )
    parser.add_argument(
        "--rekey-window",
        type=int,
        metavar="N",
        help=(
            "concurrent directional epoch offers on both endpoints (1..64); "
            "omit to use the negotiated default. Sweep it to test whether the "
            "ratchet is the binding constraint at a given RTT"
        ),
    )
    parser.add_argument(
        "--tls-backend",
        choices=("chrome151", "openssl-diagnostic"),
        default="openssl-diagnostic",
        help="outer client TLS backend used for the endpoint benchmark",
    )
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
    parser.add_argument("--resource-sample-ms", type=int, default=250)
    parser.add_argument("--no-resource-sampling", action="store_true")
    parser.add_argument(
        "--isolated-userns",
        action="store_true",
        help=(
            "run the root network lab inside disposable user/mount/PID/network "
            "namespaces; requires an unprivileged caller and --no-browser"
        ),
    )
    parser.add_argument(
        "--isolated-controller",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--outer-userns", help=argparse.SUPPRESS)
    parser.add_argument("--outer-mountns", help=argparse.SUPPRESS)
    parser.add_argument("--outer-pidns", help=argparse.SUPPRESS)
    parser.add_argument("--outer-netns", help=argparse.SUPPRESS)
    parser.add_argument("--isolated-node-sha256", help=argparse.SUPPRESS)
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
    if args.rekey_window is not None and not 1 <= args.rekey_window <= 64:
        raise SystemExit("--rekey-window must be 1..64")
    if args.tcp_mem_max is not None and not 1 <= args.tcp_mem_max <= 1024:
        raise SystemExit("--tcp-mem-max must be 1..1024 (MiB)")
    if not 100 <= args.resource_sample_ms <= 5000:
        raise SystemExit("--resource-sample-ms must be 100..5000")


def start_node(
    lab: NetworkLab,
    node: FrozenExecutable,
    log: Path,
    identity: RuntimeIdentity,
    *,
    resource_sampling: bool,
    resource_sample_ms: int,
    isolated_userns: bool,
) -> tuple[ManagedProcess, dict[str, object]]:
    privilege_prefix = (
        [] if isolated_userns else drop_prefix(identity)
    )
    argv = lab.command(lab.server_ns, [
        *privilege_prefix,
        *node_sandbox_command(node),
    ])
    os.lseek(node.descriptor, 0, os.SEEK_SET)
    process = start_logged_process(
        argv,
        log,
        cwd=REPO_ROOT,
        pass_fds=(node.descriptor,),
        resource_sampling=resource_sampling,
        resource_sample_ms=resource_sample_ms,
    )
    if not wait_for_tcp("127.0.0.1", COVER_PORT, 10, namespace=lab.server_ns):
        process.stop()
        raise RuntimeError(f"Node cover failed to listen; see {log}")
    try:
        security = runtime_security_log(log)
    except RuntimeError:
        process.stop()
        raise
    return process, security


# Ratchet policy is a config-file setting, not a flag, deliberately: it is a
# security knob rather than a tuning one. The harness writes a minimal config
# so a measurement can sweep it without adding CLI surface to the product.
SECURITY_MODE_CONFIG = {
    "extreme": {"security_mode": "extreme"},
    "normal": {"security_mode": "normal"},
    "soft": {"security_mode": "soft"},
    # `ultimate` takes exact bounded values; these are the maxima the policy
    # validator accepts, which is as close to "one key per session" as the
    # wire format allows.
    "session": {
        "security_mode": "ultimate",
        "security_custom": {
            "epoch_bytes": 1 << 40,
            "epoch_frames": 1 << 30,
            "epoch_active_ms": 24 * 60 * 60 * 1000,
        },
    },
}


def write_security_config(workdir: Path, name: str, mode: str) -> Path:
    path = workdir / f"{name}-security.json"
    path.write_text(json.dumps(SECURITY_MODE_CONFIG[mode], indent=2) + "\n",
                    encoding="utf-8")
    return path


def start_yumed(
    lab: NetworkLab,
    yumed: Path,
    keys: BenchKeyset,
    log: Path,
    *,
    resource_sampling: bool,
    resource_sample_ms: int,
    isolated_userns: bool,
    rekey_window: int | None,
    security_config: Path | None,
) -> tuple[ManagedProcess, dict[str, object] | None]:
    command = [
        str(yumed),
        *(["--root"] if isolated_userns else []),
        *(["--rekey-window", str(rekey_window)] if rekey_window else []),
        *(["--config", str(security_config)] if security_config else []),
        "--listen", f"{SERVER_IP}:{lab.yume_port}",
        "--cert", str(keys.server_cert),
        "--key", str(keys.server_key),
        "--auth-keys", str(keys.authorized_keys),
        "--obfs-secret-file", str(keys.admission_secret),
        "--inner-psk-file", str(keys.inner_psk),
        "--real-backend", f"loopback://127.0.0.1:{COVER_PORT}",
        "--bench", "--boring",
    ]
    argv = lab.command(lab.server_ns, [
        *capability_drop_prefix(isolated_userns),
        *(guarded_command(command) if isolated_userns else command),
    ])
    process = start_logged_process(
        argv,
        log,
        resource_sampling=resource_sampling,
        resource_sample_ms=resource_sample_ms,
    )
    if not wait_for_tcp(SERVER_IP, lab.yume_port, 15, namespace=lab.client_ns):
        process.stop()
        raise RuntimeError(f"yumed failed to listen; see {log}")
    security = None
    if isolated_userns:
        try:
            security = runtime_security_log(log)
        except RuntimeError:
            process.stop()
            raise
    return process, security


def start_capture(lab: NetworkLab, output: Path, log: Path) -> ManagedProcess:
    argv = lab.command(lab.client_ns, [
        "env", "LC_ALL=C",
        "tcpdump", "-i", lab.client_if, "-n", "-s", "0", "-U",
        *(["-Z", "root"] if lab.isolated_userns else []),
        "-w", str(output), "tcp", "port", str(lab.yume_port), "and", "host", SERVER_IP,
    ])
    capture = start_logged_process(argv, log)
    time.sleep(0.5)
    if capture.process.poll() is not None:
        capture.stop()
        raise RuntimeError(f"tcpdump failed; see {log}")
    return capture


def validate_stopped_capture(capture: ManagedProcess, output: Path) -> dict[str, int]:
    if capture.process.returncode != 0:
        raise RuntimeError(
            f"tcpdump exited {capture.process.returncode}; see {capture.log_path}"
        )
    if not output.is_file() or output.stat().st_size <= 24:
        raise RuntimeError(f"tcpdump produced no packet evidence: {output}")
    log = capture.log_path.read_text(encoding="utf-8", errors="replace")
    captured = re.search(r"(\d+) packets? captured", log)
    received = re.search(r"(\d+) packets? received by filter", log)
    dropped = re.search(r"(\d+) packets? dropped by kernel", log)
    if not captured or int(captured.group(1)) == 0:
        raise RuntimeError(f"tcpdump captured no packets; see {capture.log_path}")
    if not received or int(received.group(1)) == 0:
        raise RuntimeError(f"tcpdump filter received no packets; see {capture.log_path}")
    if not dropped or int(dropped.group(1)) != 0:
        raise RuntimeError(f"tcpdump did not report zero drops; see {capture.log_path}")
    return {
        "packets_captured": int(captured.group(1)),
        "packets_received_by_filter": int(received.group(1)),
        "packets_dropped_by_kernel": int(dropped.group(1)),
        "pcap_bytes": output.stat().st_size,
    }


def run_endpoint(
    args: argparse.Namespace,
    lab: NetworkLab,
    yume: Path,
    keys: BenchKeyset,
    workdir: Path,
    output: Path,
) -> tuple[StreamedCommandResult, list[str]]:
    if args.quick:
        mib, streams = 32, 4
    elif args.full:
        mib, streams = 1024, 64
    else:
        mib, streams = args.bench_mib, args.bench_streams
    command = [
        str(yume),
        *(["--root"] if args.isolated_controller else []),
        "--server", SERVER_IP,
        "--port", str(lab.yume_port),
        "--tls-name", TLS_NAME,
        "--tls-ca", str(keys.server_cert),
        "--auth", str(keys.client_identity),
        "--obfs-secret-file", str(keys.admission_secret),
        "--inner-psk-file", str(keys.inner_psk),
        "--profile", "chrome",
        "--tls-backend", args.tls_backend,
        "--bench",
        "--bench-mib", str(mib),
        "--bench-streams", str(streams),
        "--bench-direction", args.bench_direction,
        *(["--bench-chunk-kib", str(args.bench_chunk_kib)]
          if args.bench_chunk_kib is not None else []),
        *(["--rekey-window", str(args.rekey_window)]
          if args.rekey_window else []),
        *(["--config", str(write_security_config(
            workdir, "client", args.security_mode))]
          if args.security_mode else []),
        "--non-interactive", "--accept-monitoring", "--boring", "--no-color",
    ]
    argv = lab.command(lab.client_ns, [
        *capability_drop_prefix(args.isolated_controller),
        "env", f"HOME={workdir / 'home'}", f"XDG_RUNTIME_DIR={workdir / 'runtime'}",
        *(guarded_command(command) if args.isolated_controller else command),
    ])
    directions = 2 if args.bench_direction == "both" else 1
    transfer_seconds = mib * 8 * directions / max(1, lab.profile.bandwidth_mbit)
    timeout = max(120, int(transfer_seconds * 4 + 90))
    result = run_streamed_command(
        argv,
        timeout=timeout,
        interrupt_message="[bench] interrupted; stopping the endpoint benchmark",
        resource_sampling=not args.no_resource_sampling,
        resource_sample_ms=args.resource_sample_ms,
    )
    output.write_text(result.output, encoding="utf-8")
    return result, argv


def run_browser_cover(
    lab: NetworkLab,
    browser: Path,
    workdir: Path,
    output: Path,
    identity: RuntimeIdentity,
) -> tuple[int, list[str]]:
    profile = workdir / "chromium-profile"
    require_user_namespace_sandbox(
        lab.command(lab.client_ns, drop_prefix(identity))
    )
    argv = lab.command(lab.client_ns, [*drop_prefix(identity),
        "env", f"HOME={workdir / 'home'}", f"XDG_RUNTIME_DIR={workdir / 'runtime'}",
        str(browser), "--headless", "--disable-gpu", "--disable-setuid-sandbox",
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
        resource_sampling=False,
    )
    output.write_text(result.output, encoding="utf-8")
    return result.returncode, argv


def main() -> int:
    args = parse_args()
    if args.isolated_controller and not args.isolated_userns:
        raise SystemExit("--isolated-controller requires --isolated-userns")
    if args.isolated_userns and not args.isolated_controller:
        if os.geteuid() == 0:
            raise SystemExit("--isolated-userns must be started by an unprivileged user")
        if not args.no_browser:
            raise SystemExit("--isolated-userns requires --no-browser")
        require_tools(["unshare", "mount", "ip", "tc", "setpriv", "bwrap"])
        try:
            frozen_node, _, node_bootstrapped = resolve_pinned_node(
                args.node,
                allow_mismatch=args.allow_node_version_mismatch,
                bootstrap=not args.no_node_bootstrap,
            )
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from exc
        if node_bootstrapped:
            print("[bench] resolved the pinned Node executable before namespace entry")
        inner_argv = [
            *sys.argv[1:],
            "--node", str(frozen_node),
            "--isolated-node-sha256", sha256_file(frozen_node),
            "--no-node-bootstrap",
        ]
        argv = isolated_reexec_argv(Path(__file__), inner_argv)
        os.execv(argv[0], argv)
        raise AssertionError("os.execv returned unexpectedly")
    if os.geteuid() != 0:
        raise SystemExit(
            "run with sudo, or use --isolated-userns --no-browser as an unprivileged user"
        )
    controller_checks: dict[str, object] | None = None
    if args.isolated_controller:
        if not args.no_browser:
            raise SystemExit("the isolated controller requires --no-browser")
        if not args.isolated_node_sha256:
            raise SystemExit("the isolated controller requires a frozen Node identity")
        try:
            controller_checks = enter_isolated_controller({
                "user": args.outer_userns or "",
                "mount": args.outer_mountns or "",
                "pid": args.outer_pidns or "",
                "network": args.outer_netns or "",
            })
        except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
            raise SystemExit(f"could not create isolated network controller: {exc}") from exc
    require_tools(
        ["ip", "tc", "openssl", "python3", "setpriv", "bwrap"]
        + (["mount"] if args.isolated_controller else [])
        + ([] if args.no_pcap else ["tcpdump"])
    )

    yume = executable(args.yume, ())
    yumed = executable(args.yumed, ())
    if not yume or not yumed:
        raise SystemExit("build/bin/yume and build/bin/yumed are required")
    try:
        if args.isolated_controller:
            if args.node is None:
                raise RuntimeError(
                    "the isolated controller requires an explicit pinned Node path"
                )
            node_source = args.node.expanduser()
            node_bootstrapped = False
        else:
            node_source, _, node_bootstrapped = resolve_pinned_node(
                args.node,
                allow_mismatch=args.allow_node_version_mismatch,
                bootstrap=not args.no_node_bootstrap,
            )
        frozen_node = freeze_executable(
            node_source,
            args.isolated_node_sha256 if args.isolated_controller else None,
        )
        node_version = frozen_executable_version(
            frozen_node,
            allow_mismatch=args.allow_node_version_mismatch,
        )
    except (OSError, RuntimeError) as exc:
        raise SystemExit(str(exc)) from exc
    node_sha256 = frozen_node.sha256
    if node_bootstrapped:
        print(f"[bench] using pinned {node_version} from the invoking user's npm cache")
    binary_hashes = {
        "yume": sha256_file(yume),
        "yumed": sha256_file(yumed),
        "node": node_sha256,
        "exec_guard": sha256_file(EXEC_GUARD),
    }

    run_identity = (
        RuntimeIdentity(0, 0, Path("/root"))
        if args.isolated_controller
        else invoking_identity()
    )
    browser = None
    browser_identity: dict[str, str] | None = None
    if not args.no_browser and not args.quick:
        browser = executable(
            args.browser, ("chromium", "chromium-browser", "google-chrome")
        )
        if not browser:
            raise SystemExit("exact pinned Chrome is required unless --no-browser is set")
        try:
            browser_identity = validate_pinned_chrome(
                browser,
                drop_prefix(run_identity),
            )
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from exc
        browser = Path(browser_identity["launcher"])
    browser_version = browser_identity["version"] if browser_identity else None

    production_chunk_kib = relay_chunk_kib()
    effective_chunk_kib = args.bench_chunk_kib or production_chunk_kib
    profile = choose_profile(args)
    validate_args(args, profile)
    try:
        source_snapshot_before = git_source_snapshot(
            REPO_ROOT, RUNTIME_SOURCE_INPUTS
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        frozen_node.close()
        raise SystemExit(f"could not record benchmark source provenance: {exc}") from exc
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = (args.output_dir or REPO_ROOT / "yume-bench-results" / timestamp).resolve()
    output_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    workdir = Path(tempfile.mkdtemp(prefix="yume-bench-2-"))
    os.chmod(workdir, 0o700)
    host = host_resource_info()

    lab = NetworkLab(profile, isolated_userns=args.isolated_controller)
    processes: list[ManagedProcess] = []
    atexit.register(lab.close)
    started = datetime.now(timezone.utc).isoformat()
    print(f"[bench] artifacts: {output_dir}")
    print(
        f"[bench] network: {args.profile}, RTT {profile.rtt_ms} ms, "
        f"jitter {profile.jitter_ms} ms, loss {profile.loss_pct:g}%, "
        f"rate {profile.bandwidth_mbit} Mbit/s"
    )
    if not args.no_resource_sampling:
        print_host_resources("[bench]", host)

    endpoint_code = 1
    endpoint_result: StreamedCommandResult | None = None
    endpoint_started_utc: str | None = None
    endpoint_finished_utc: str | None = None
    browser_code: int | None = None
    endpoint_command: list[str] = []
    browser_command: list[str] = []
    endpoint_output = ""
    failure: str | None = None
    endpoint_capture: dict[str, int] | None = None
    cover_capture: dict[str, int] | None = None
    node_process: ManagedProcess | None = None
    yumed_process: ManagedProcess | None = None
    node_security: dict[str, object] | None = None
    yumed_security: dict[str, object] | None = None
    endpoint_security: dict[str, object] | None = None
    try:
        keys = generate_keyset(
            workdir / "keys", yumed, tls_name=TLS_NAME, server_ip=SERVER_IP
        )
        (workdir / "home").mkdir(mode=0o700)
        (workdir / "runtime").mkdir(mode=0o700)
        chown_tree(workdir, run_identity)
        lab.create()
        if args.tcp_mem_max:
            lab.tune_tcp_memory(args.tcp_mem_max * 1024 * 1024)
        node_process, node_security = start_node(
            lab,
            frozen_node,
            output_dir / "node.log",
            run_identity,
            resource_sampling=not args.no_resource_sampling,
            resource_sample_ms=args.resource_sample_ms,
            isolated_userns=args.isolated_controller,
        )
        processes.append(node_process)
        yumed_process, yumed_security = start_yumed(
            lab,
            yumed,
            keys,
            output_dir / "yumed.log",
            resource_sampling=not args.no_resource_sampling,
            resource_sample_ms=args.resource_sample_ms,
            isolated_userns=args.isolated_controller,
            rekey_window=args.rekey_window,
            security_config=(write_security_config(
                workdir, "server", args.security_mode)
                if args.security_mode else None),
        )
        processes.append(yumed_process)

        capture = None
        if not args.no_pcap:
            capture = start_capture(
                lab, output_dir / "endpoint.pcap", output_dir / "tcpdump-endpoint.log"
            )
            processes.append(capture)
        print("[bench] running authenticated YUME 2.0 endpoint benchmark")
        endpoint_started_utc = datetime.now(timezone.utc).isoformat()
        endpoint_result, endpoint_command = run_endpoint(
            args, lab, yume, keys, workdir, output_dir / "endpoint.log"
        )
        endpoint_finished_utc = datetime.now(timezone.utc).isoformat()
        endpoint_code = endpoint_result.returncode
        endpoint_output = endpoint_result.output
        if args.isolated_controller:
            endpoint_security = runtime_security_state(endpoint_output)
        if capture:
            capture.stop(interrupt=True)
            processes.remove(capture)
            endpoint_capture = validate_stopped_capture(
                capture, output_dir / "endpoint.pcap"
            )
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
                cover_capture = validate_stopped_capture(
                    capture, output_dir / "cover-chromium.pcap"
                )
    except KeyboardInterrupt:
        endpoint_code = 130
        failure = "interrupted"
        print("\n[bench] interrupted; stopping the benchmark lab", file=sys.stderr)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        failure = str(exc)
        print(f"[bench] failed: {exc}", file=sys.stderr)
    finally:
        while processes:
            processes.pop().stop(interrupt=True)
        lab.close()

        yumed_resources = (
            yumed_process.resource_summary() if yumed_process else None
        )
        node_resources = node_process.resource_summary() if node_process else None
        if not args.no_resource_sampling:
            if yumed_process:
                write_resource_samples(
                    output_dir / "yumed-resources.jsonl",
                    yumed_process.resource_sampler,
                )
            if node_process:
                write_resource_samples(
                    output_dir / "node-resources.jsonl",
                    node_process.resource_sampler,
                )

        final_binary_hashes: dict[str, str] = {}
        try:
            final_binary_hashes = {
                "yume": sha256_file(yume),
                "yumed": sha256_file(yumed),
                "node": sha256_file(node_source),
                "exec_guard": sha256_file(EXEC_GUARD),
            }
            if final_binary_hashes != binary_hashes:
                failure = failure or "a benchmark executable changed during the run"
        except OSError as exc:
            failure = failure or f"could not revalidate benchmark executables: {exc}"

        source_snapshot_after: dict[str, object] = {}
        try:
            source_snapshot_after = git_source_snapshot(
                REPO_ROOT, RUNTIME_SOURCE_INPUTS
            )
            if source_snapshot_after != source_snapshot_before:
                failure = failure or "benchmark source provenance changed during the run"
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            failure = failure or f"could not revalidate benchmark source: {exc}"

        try:
            frozen_node.close()
        except OSError as exc:
            failure = failure or f"could not close the frozen Node executable: {exc}"

        workdir_cleanup = {
            "retained_by_request": args.keep_workdir,
            "removed": False,
            "error": None,
        }
        if not args.keep_workdir:
            try:
                remove_private_tree(workdir)
                workdir_cleanup["removed"] = True
            except (OSError, RuntimeError) as exc:
                workdir_cleanup["error"] = str(exc)
                failure = failure or f"could not remove private work directory: {exc}"
                print(f"[bench] private workdir cleanup failed: {exc}", file=sys.stderr)

        artifact_owner: tuple[int, int] | None = None
        try:
            # An isolated controller's uid 0 maps directly to the unprivileged
            # outer user. Sudo ownership restoration applies only to the
            # initial-namespace root workflow.
            if not args.isolated_controller:
                artifact_owner = output_owner()
            if args.keep_workdir:
                write_private_text(output_dir / "workdir.txt", str(workdir) + "\n")
                print(f"[bench] retained secrets and scratch files in {workdir}")
            enforce_private_artifact_modes(output_dir)
            restore_output_owner(output_dir, artifact_owner)
        except (OSError, RuntimeError) as exc:
            failure = failure or f"could not finalize private artifacts: {exc}"
            print(f"[bench] artifact finalization failed: {exc}", file=sys.stderr)

        report = {
            "schema": 2,
            "started_utc": started,
            "finished_utc": datetime.now(timezone.utc).isoformat(),
            "profile_name": args.profile,
            "network": asdict(profile),
            "ratchet": {
                # None means "whatever the endpoints negotiate by default".
                # Recorded explicitly so a window sweep is reproducible from
                # the report alone.
                "rekey_window_override": args.rekey_window,
                "security_mode_override": args.security_mode,
            },
            "host_tuning": {
                "tcp_mem_max_mib": args.tcp_mem_max,
            },
            "internal_endpoint": {
                "server_ip": SERVER_IP,
                "client_ip": CLIENT_IP,
                "port": lab.yume_port,
                "tls_name": TLS_NAME,
            },
            "host": host,
            "execution": {
                "isolated_user_namespace": args.isolated_controller,
                "outer_namespace": {
                    "user": args.outer_userns,
                    "mount": args.outer_mountns,
                    "pid": args.outer_pidns,
                    "network": args.outer_netns,
                } if args.isolated_controller else None,
                "controller_namespace": namespace_inodes(),
                "controller_checks": controller_checks,
                "network_mutation_scope": (
                    "disposable-user-mount-pid-network-wrapper"
                    if args.isolated_controller
                    else "host-named-network-namespaces"
                ),
                "host_routes_or_qdiscs_targeted": False,
                "node_filesystem_sandbox": {
                    "engine": "bubblewrap",
                    "minimal_read_only_usr": True,
                    "exact_node_and_backend_only": True,
                    "host_home_absent": True,
                    "secret_workdir_absent": True,
                    "artifact_directory_absent": True,
                    "network_namespace_shared_with_server": True,
                },
                "runtime_security": {
                    "node": node_security,
                    "yumed": yumed_security,
                    "yume": endpoint_security,
                },
                "private_workdir_cleanup": workdir_cleanup,
            },
            "versions": {
                "yume": command_version([str(yume), "--version"]),
                "node": node_version,
                "browser": browser_version,
            },
            "browser_identity": browser_identity,
            "source_provenance": {
                "before": source_snapshot_before,
                "after": source_snapshot_after,
                "unchanged": source_snapshot_after == source_snapshot_before,
            },
            "binary_sha256": {
                "before": binary_hashes,
                "after": final_binary_hashes,
                "unchanged": final_binary_hashes == binary_hashes,
            },
            "failure": failure,
            "endpoint": {
                "started_utc": endpoint_started_utc,
                "finished_utc": endpoint_finished_utc,
                "exit_code": endpoint_code,
                "command": endpoint_command,
                "tls_backend": args.tls_backend,
                "chunk_kib": effective_chunk_kib,
                "requested_chunk_kib": args.bench_chunk_kib,
                "chunk_source": (
                    "production-relay-buffer"
                    if args.bench_chunk_kib is None
                    else "explicit"
                ),
                "upload_chunk_kib": effective_chunk_kib,
                "upload_chunk_source": (
                    "client-production-relay-buffer"
                    if args.bench_chunk_kib is None
                    else "explicit"
                ),
                "download_chunk_kib": None,
                "download_chunk_source": "server-target/source-policy",
                "contract": endpoint_contract(
                    args.bench_chunk_kib,
                    production_chunk_kib,
                ),
                "rates": parse_rates(endpoint_output),
                "resources": endpoint_result.resources if endpoint_result else None,
                "pcap": "endpoint.pcap" if not args.no_pcap else None,
                "capture": endpoint_capture,
            },
            "server": {
                "yumed_resources": yumed_resources,
                "node_resources": node_resources,
            },
            "cover": {
                "exit_code": browser_code,
                "command": browser_command,
                "pcap": "cover-chromium.pcap" if browser and not args.no_pcap else None,
                "capture": cover_capture,
            },
        }
        try:
            write_private_text(
                output_dir / "report.json",
                json.dumps(report, indent=2) + "\n",
                owner=artifact_owner,
            )
        except (OSError, RuntimeError) as exc:
            failure = failure or f"could not write final report: {exc}"
            print(f"[bench] final report write failed: {exc}", file=sys.stderr)

    if not args.no_resource_sampling:
        print_process_resources(
            "[bench] yume client",
            endpoint_result.resources if endpoint_result else None,
        )
        print_process_resources("[bench] yumed server", yumed_resources)

    if failure is not None:
        print(f"[bench] failed; inspect {output_dir}: {failure}", file=sys.stderr)
        return endpoint_code if endpoint_code not in (0, 1) else 1
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
