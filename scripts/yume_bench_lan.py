#!/usr/bin/env python3
"""Provision and run a physical two-host YUME 2.0 LAN benchmark."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from yume_bench_common import (  # noqa: E402
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
    resolve_pinned_node,
    run_streamed_command,
    start_logged_process,
    wait_for_tcp,
)
from yume_bench_resources import (  # noqa: E402
    aggregate_resource_summaries,
    host_resource_info,
    print_host_resources,
    print_process_resources,
    write_resource_samples,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_YUME = REPO_ROOT / "build" / "bin" / "yume"
DEFAULT_YUMED = REPO_ROOT / "build" / "bin" / "yumed"
DEFAULT_COVER = REPO_ROOT / "tools" / "cover-node" / "backend.mjs"
DEFAULT_TLS_NAME = "yume-lan.test"
DEFAULT_COVER_PORT = 3000
MIB = 1024 * 1024
CAPTURE_SAFETY_BYTES = 256 * MIB
DEFAULT_CLIENT_LIMIT = 64
HARD_CLIENT_LIMIT = 128


def executable(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise SystemExit(f"{label} executable not found: {resolved}")
    return resolved


def find_executable(explicit: Path | None, names: tuple[str, ...], label: str) -> Path:
    if explicit:
        return executable(explicit, label)
    for name in names:
        path = shutil.which(name)
        if path:
            return Path(path).resolve()
    raise SystemExit(f"{label} executable not found; pass --{label.lower()}")


def write_private_text(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        data = text.encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)


def copy_private(source: Path, destination: Path) -> None:
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o600)


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"configuration root must be an object: {path}")
    return value


def require_secret(path: Path) -> None:
    try:
        value = path.read_text(encoding="ascii")
        mode = path.stat().st_mode & 0o777
    except OSError as exc:
        raise SystemExit(f"cannot read secret file {path}: {exc}") from exc
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SystemExit(f"secret file must contain exactly 64 lowercase hex characters: {path}")
    if mode & 0o077:
        raise SystemExit(f"secret file must not be group/world-readable: {path}")


def capture_required_bytes(mib: int, direction: str) -> int:
    directions = 2 if direction == "both" else 1
    payload_bytes = mib * directions * MIB
    # Preserve room for packet overhead and for the final logs/report.
    return payload_bytes + payload_bytes // 3 + CAPTURE_SAFETY_BYTES


def available_bytes(path: Path) -> int:
    existing = path
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    return shutil.disk_usage(existing).free


def require_capture_space(
    output: Path,
    mib: int,
    direction: str,
    clients: int = 1,
) -> None:
    required = capture_required_bytes(mib, direction) * clients
    available = available_bytes(output.parent)
    if available >= required:
        return
    raise SystemExit(
        "--capture needs approximately "
        f"{required / MIB:.0f} MiB free for this workload, but only "
        f"{available / MIB:.0f} MiB is available; move or remove old captures "
        "or run without --capture"
    )


def capture_error(process: ManagedProcess) -> str | None:
    return_code = process.process.returncode
    try:
        log_text = process.log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"cannot read tcpdump log: {exc}"
    if "No space left on device" in log_text:
        return "tcpdump exhausted filesystem space"
    if return_code not in (0, -signal.SIGINT):
        return f"tcpdump exited with status {return_code}"
    return None


def install_server_shutdown_handlers() -> dict[signal.Signals, signal.Handlers]:
    previous: dict[signal.Signals, signal.Handlers] = {}

    def interrupt_server(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    for signum in (signal.SIGHUP, signal.SIGTERM):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, interrupt_server)
    return previous


def restore_signal_handlers(
    previous: dict[signal.Signals, signal.Handlers],
) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def prepare_bundle(args: argparse.Namespace) -> int:
    server_ip = str(ipaddress.IPv4Address(args.server))
    yumed = executable(args.yumed, "yumed")
    output = args.output.expanduser().resolve()
    if output.exists():
        raise SystemExit(f"output already exists; choose a new directory: {output}")
    output.mkdir(parents=True, mode=0o700)
    os.chmod(output, 0o700)
    server_dir = output / "server"
    client_dir = output / "client"
    server_dir.mkdir(mode=0o700)
    client_dir.mkdir(mode=0o700)

    with tempfile.TemporaryDirectory(prefix="yume-lan-provision-") as temporary:
        keys = generate_keyset(
            Path(temporary) / "keys",
            yumed,
            tls_name=args.tls_name,
            server_ip=server_ip,
        )
        for destination in (server_dir, client_dir):
            copy_private(keys.server_cert, destination / "server.crt")
            copy_private(keys.admission_secret, destination / "admission.hex")
            copy_private(keys.inner_psk, destination / "inner.hex")
        copy_private(keys.server_key, server_dir / "server.key")
        copy_private(keys.authorized_keys, server_dir / "authorized_keys")
        copy_private(
            Path(f"{keys.authorized_keys}.json"),
            server_dir / "authorized_keys.json",
        )
        copy_private(keys.client_identity, client_dir / "client.key")

    server_config = {
        "listen_port": args.port,
        "tls_cert": "server.crt",
        "tls_key": "server.key",
        "auth_keys": "authorized_keys",
        "auth_keys_meta": "authorized_keys.json",
        "obfuscation": True,
        "obfs_secret_file": "admission.hex",
        "inner_psk_file": "inner.hex",
        "real_backend": f"loopback://127.0.0.1:{DEFAULT_COVER_PORT}",
        "benchmark_enable": True,
    }
    client_config = {
        "server": server_ip,
        "port": args.port,
        "identity": "client.key",
        "obfuscation": True,
        "obfs_secret_file": "admission.hex",
        "inner_psk_file": "inner.hex",
        "tls_ca_cert": "server.crt",
        "tls_server_name": args.tls_name,
        "tls_stealth_profile": "chrome",
    }
    write_private_text(
        server_dir / "yumed.json", json.dumps(server_config, indent=2) + "\n"
    )
    write_private_text(
        client_dir / "yume.json", json.dumps(client_config, indent=2) + "\n"
    )

    certificate_sha256 = hashlib.sha256((server_dir / "server.crt").read_bytes()).hexdigest()
    manifest = {
        "schema": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "server": server_ip,
        "port": args.port,
        "tls_name": args.tls_name,
        "certificate_sha256": certificate_sha256,
        "yumed": command_version([str(yumed), "--version"]),
    }
    write_private_text(output / "manifest.json", json.dumps(manifest, indent=2) + "\n")

    print(f"LAN benchmark bundle created: {output}")
    print()
    print("Copy the server half to the server:")
    print(f"  scp -r {server_dir} USER@{server_ip}:~/yume-lan-server")
    print()
    print("On the server:")
    print("  sudo scripts/yume_bench_lan.py server --bundle ~/yume-lan-server")
    print()
    print("On this client:")
    print(
        f"  sudo scripts/yume_bench_lan.py client --bundle {client_dir} "
        "--full --capture --cover"
    )
    return 0


def node_command(
    node: Path,
    cover: Path,
    identity: RuntimeIdentity,
    cover_port: int,
) -> list[str]:
    argv: list[str] = []
    if os.geteuid() == 0:
        argv.extend(drop_prefix(identity))
    argv.extend([
        "env",
        f"HOME={identity.home}",
        "YUME_COVER_HOST=127.0.0.1",
        f"YUME_COVER_PORT={cover_port}",
        str(node),
        str(cover),
    ])
    return argv


def run_server(args: argparse.Namespace) -> int:
    bundle = args.bundle.expanduser().resolve()
    config_path = bundle / "yumed.json"
    config = load_json(config_path)
    port = int(config.get("listen_port", 443))
    for name in ("admission.hex", "inner.hex"):
        require_secret(bundle / name)
    yumed = executable(args.yumed, "yumed")
    cover = args.cover.expanduser().resolve()
    if not cover.is_file():
        raise SystemExit(f"Node cover script not found: {cover}")
    if os.geteuid() == 0 and not shutil.which("setpriv"):
        raise SystemExit("setpriv is required to run the Node cover without root privileges")
    if wait_for_tcp("127.0.0.1", DEFAULT_COVER_PORT, 0.1):
        raise SystemExit(
            f"loopback port {DEFAULT_COVER_PORT} is already in use; stop that service first"
        )
    try:
        node, node_version, bootstrapped = resolve_pinned_node(
            args.node,
            allow_mismatch=args.allow_node_version_mismatch,
            bootstrap=not args.no_node_bootstrap,
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    if bootstrapped:
        print(f"[lan] using pinned {node_version} from the invoking user's npm cache")

    identity = invoking_identity()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output_dir or bundle / "results" / f"server-{timestamp}").resolve()
    if output.exists():
        raise SystemExit(f"output already exists; choose a new directory: {output}")
    output.mkdir(parents=True, mode=0o750)
    node_process = start_logged_process(
        node_command(node, cover, identity, DEFAULT_COVER_PORT),
        output / "node.log",
        cwd=REPO_ROOT,
        resource_sampling=not args.no_resource_sampling,
        resource_sample_ms=args.resource_sample_ms,
    )
    yumed_process: ManagedProcess | None = None
    yumed_argv: list[str] = []
    host = host_resource_info()
    previous_signal_handlers = install_server_shutdown_handlers()
    try:
        if not wait_for_tcp("127.0.0.1", DEFAULT_COVER_PORT, 10):
            raise RuntimeError(f"Node cover did not start; see {output / 'node.log'}")
        if node_process.process.poll() is not None:
            raise RuntimeError(f"Node cover exited during startup; see {output / 'node.log'}")
        yumed_argv = [
            str(yumed),
            "--config", str(config_path),
            "--listen", f"0.0.0.0:{port}",
            "--bench", "--boring",
        ]
        if args.threads is not None:
            yumed_argv.extend(["--threads", str(args.threads)])
        if args.timing:
            yumed_argv.append("--timing")
        yumed_process = start_logged_process(
            yumed_argv,
            output / "yumed.log",
            resource_sampling=not args.no_resource_sampling,
            resource_sample_ms=args.resource_sample_ms,
        )
        if not wait_for_tcp("127.0.0.1", port, 15):
            raise RuntimeError(f"yumed did not start; see {output / 'yumed.log'}")
        if yumed_process.process.poll() is not None:
            raise RuntimeError(f"yumed exited during startup; see {output / 'yumed.log'}")
        print(f"[lan] ready on 0.0.0.0:{port}")
        print(f"[lan] Node cover {node_version} on loopback:{DEFAULT_COVER_PORT}")
        if not args.no_resource_sampling:
            print_host_resources("[lan]", host)
        print(f"[lan] logs: {output}")
        print("[lan] press Ctrl-C after the client benchmark finishes")
        while node_process.process.poll() is None and yumed_process.process.poll() is None:
            time.sleep(0.5)
        return_code = yumed_process.process.poll()
        if return_code is not None:
            print(f"[lan] yumed exited with status {return_code}", file=sys.stderr)
            return return_code or 1
        print("[lan] Node cover exited unexpectedly", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    except RuntimeError as exc:
        print(f"[lan] {exc}", file=sys.stderr)
        return 1
    finally:
        if yumed_process:
            yumed_process.stop(interrupt=True)
        node_process.stop(interrupt=True)
        if not args.no_resource_sampling:
            yumed_resources = (
                yumed_process.resource_summary() if yumed_process else None
            )
            node_resources = node_process.resource_summary()
            report = {
                "schema": 1,
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "host": host,
                "processes": {
                    "yumed": {
                        "command": yumed_argv,
                        "resources": yumed_resources,
                    },
                    "node_cover": {
                        "version": node_version,
                        "resources": node_resources,
                    },
                },
            }
            (output / "resources.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
            if yumed_process:
                write_resource_samples(
                    output / "yumed-resources.jsonl",
                    yumed_process.resource_sampler,
                )
            write_resource_samples(
                output / "node-resources.jsonl", node_process.resource_sampler
            )
            print_process_resources("[lan] yumed", yumed_resources)
            print_process_resources("[lan] Node cover", node_resources)
            print(f"[lan] resource report: {output / 'resources.json'}")
        restore_signal_handlers(previous_signal_handlers)
        if os.geteuid() == 0:
            chown_tree(output, identity)


def infer_interface(server: str) -> str:
    result = subprocess.run(
        ["ip", "route", "get", server],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode == 0:
        match = re.search(r"\bdev\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    raise SystemExit("could not infer the LAN interface; pass --interface")


def benchmark_shape(args: argparse.Namespace) -> tuple[int, int]:
    if args.quick:
        return 32, 4
    if args.full:
        return 1024, 64
    return args.bench_mib, args.bench_streams


def start_capture(interface: str, server: str, port: int, output: Path) -> ManagedProcess:
    capture = start_logged_process([
        "tcpdump", "-i", interface, "-n", "-s", "0", "-U",
        "-w", str(output), "host", server, "and", "tcp", "port", str(port),
    ], output.with_suffix(".tcpdump.log"))
    time.sleep(0.5)
    if capture.process.poll() is not None:
        capture.stop()
        raise RuntimeError(f"tcpdump failed; see {capture.log_path}")
    return capture


def run_endpoint(
    args: argparse.Namespace,
    yume: Path,
    config_path: Path,
    environment: dict[str, str],
    mib: int,
    streams: int,
    *,
    echo: bool = True,
    cancel_event: threading.Event | None = None,
) -> tuple[StreamedCommandResult, list[str]]:
    mode = "--bench-full" if args.full else "--bench"
    argv = [
        str(yume), "--config", str(config_path), mode,
        "--bench-mib", str(mib),
        "--bench-streams", str(streams),
        "--bench-direction", args.bench_direction,
        "--boring", "--no-color",
    ]
    if args.bench_chunk_kib is not None:
        argv.extend(["--bench-chunk-kib", str(args.bench_chunk_kib)])
    if args.timing:
        argv.append("--timing")
    directions = 2 if args.bench_direction == "both" else 1
    timeout = max(120, int(mib * directions * 8 / 5 + 120))
    result = run_streamed_command(
        argv,
        env=environment,
        timeout=timeout,
        echo=echo,
        interrupt_message="[lan] interrupted; stopping the endpoint benchmark",
        resource_sampling=not args.no_resource_sampling,
        resource_sample_ms=args.resource_sample_ms,
        cancel_event=cancel_event,
    )
    return result, argv


def run_endpoint_clients(
    args: argparse.Namespace,
    yume: Path,
    config_path: Path,
    environments: list[dict[str, str]],
    mib: int,
    streams: int,
) -> tuple[list[tuple[StreamedCommandResult, list[str]]], float]:
    cancel_event = threading.Event()
    results: list[tuple[StreamedCommandResult, list[str]] | None] = [
        None
    ] * len(environments)

    def run_one(index: int) -> tuple[StreamedCommandResult, list[str]]:
        delay = index * args.client_stagger_ms / 1000.0
        if delay > 0 and cancel_event.wait(delay):
            return StreamedCommandResult(130, "cancelled before start", interrupted=True), []
        return run_endpoint(
            args,
            yume,
            config_path,
            environments[index],
            mib,
            streams,
            echo=len(environments) == 1,
            cancel_event=cancel_event,
        )

    started = time.monotonic()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(environments))
    futures = {
        executor.submit(run_one, index): index
        for index in range(len(environments))
    }
    try:
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            results[index] = future.result()
            result, _argv = results[index]
            if len(environments) > 1:
                print(
                    f"[lan] client {index + 1}/{len(environments)} "
                    f"completed with status {result.returncode}",
                    flush=True,
                )
    except KeyboardInterrupt:
        cancel_event.set()
        for future, index in futures.items():
            try:
                results[index] = future.result()
            except Exception as exc:  # Preserve cleanup and report the failed arm.
                results[index] = StreamedCommandResult(1, str(exc)), []
    finally:
        cancel_event.set()
        executor.shutdown(wait=True, cancel_futures=True)
    elapsed = time.monotonic() - started
    return [result for result in results if result is not None], elapsed


def aggregate_client_rates(
    runs: list[tuple[StreamedCommandResult, list[str]]],
) -> dict[str, dict[str, float]]:
    aggregate: dict[str, dict[str, float]] = {}
    for result, _argv in runs:
        for direction, rate in parse_rates(result.output).items():
            row = aggregate.setdefault(
                direction,
                {
                    "mib": 0.0,
                    "seconds": 0.0,
                    "mib_per_second": 0.0,
                    "mbit_per_second": 0.0,
                },
            )
            row["mib"] += rate["mib"]
            row["seconds"] = max(row["seconds"], rate["seconds"])
            row["mib_per_second"] += rate["mib_per_second"]
            row["mbit_per_second"] += rate["mbit_per_second"]
    for row in aggregate.values():
        for key, value in row.items():
            row[key] = round(value, 3)
    return aggregate


def wall_throughput(payload_mib: int, wall_seconds: float) -> dict[str, float]:
    mib_per_second = payload_mib / max(wall_seconds, 1e-9)
    return {
        "payload_mib": payload_mib,
        "wall_seconds": round(wall_seconds, 3),
        "mib_per_second": round(mib_per_second, 3),
        "mbit_per_second": round(mib_per_second * 8.388608, 3),
    }


def run_browser_cover(
    browser: Path,
    identity: RuntimeIdentity,
    home: Path,
    runtime: Path,
    profile: Path,
    server: str,
    port: int,
    tls_name: str,
) -> tuple[StreamedCommandResult, list[str]]:
    authority = tls_name if port == 443 else f"{tls_name}:{port}"
    argv: list[str] = []
    if os.geteuid() == 0:
        argv.extend(drop_prefix(identity))
    argv.extend([
        "env", f"HOME={home}", f"XDG_RUNTIME_DIR={runtime}",
        str(browser), "--headless", "--disable-gpu",
        "--disable-breakpad", "--disable-crash-reporter",
        "--disable-background-networking", "--disable-component-update",
        "--no-first-run", "--no-default-browser-check",
        f"--user-data-dir={profile}",
        f"--host-resolver-rules=MAP {tls_name} {server}",
        "--ignore-certificate-errors", "--dump-dom", f"https://{authority}/",
    ])
    result = run_streamed_command(
        argv,
        timeout=30,
        echo=False,
        interrupt_message="[lan] interrupted; stopping the Chrome cover load",
        resource_sampling=False,
    )
    return result, argv


def run_client(args: argparse.Namespace) -> int:
    bundle = args.bundle.expanduser().resolve()
    config_path = bundle / "yume.json"
    config = load_json(config_path)
    server = str(ipaddress.IPv4Address(str(config.get("server", ""))))
    port = int(config.get("port", 443))
    tls_name = str(config.get("tls_server_name", DEFAULT_TLS_NAME))
    for name in ("admission.hex", "inner.hex"):
        require_secret(bundle / name)
    yume = executable(args.yume, "yume")
    if args.capture and os.geteuid() != 0:
        raise SystemExit("--capture requires sudo for tcpdump")
    if args.capture and not shutil.which("tcpdump"):
        raise SystemExit("--capture requires tcpdump")
    if os.geteuid() == 0 and args.cover and not shutil.which("setpriv"):
        raise SystemExit("setpriv is required to run Chrome without root privileges")
    browser = None
    if args.cover:
        browser = find_executable(
            args.browser, ("chromium", "chromium-browser", "google-chrome"), "browser"
        )
    mib, streams = benchmark_shape(args)
    directions = 2 if args.bench_direction == "both" else 1
    total_payload_mib = mib * directions * args.clients
    if args.clients > DEFAULT_CLIENT_LIMIT and not args.allow_high_client_count:
        raise SystemExit(
            f"more than {DEFAULT_CLIENT_LIMIT} client processes requires "
            "--allow-high-client-count after checking host RAM and process limits"
        )
    if total_payload_mib > 16384 and not args.allow_large_workload:
        raise SystemExit(
            f"workload is {total_payload_mib} MiB across {args.clients} clients; "
            "pass --allow-large-workload after checking RAM, disk, and expected duration"
        )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output_dir or REPO_ROOT / "yume-bench-results" / f"lan-{timestamp}").resolve()
    if output.exists():
        raise SystemExit(f"output already exists; choose a new directory: {output}")
    if args.capture:
        require_capture_space(output, mib, args.bench_direction, args.clients)
    output.mkdir(parents=True, mode=0o750)
    runtime = output / "runtime"
    home = output / "home"
    runtime.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
    identity = invoking_identity()
    if os.geteuid() == 0:
        chown_tree(output, identity)
    base_environment = dict(os.environ)
    base_environment.update({
        "HOME": str(home),
        "XDG_RUNTIME_DIR": str(runtime),
        "NO_COLOR": "1",
    })
    environments: list[dict[str, str]] = []
    for index in range(args.clients):
        environment = dict(base_environment)
        if args.clients > 1:
            client_root = output / "clients" / f"client-{index + 1:03d}"
            client_home = client_root / "home"
            client_runtime = client_root / "runtime"
            client_home.mkdir(parents=True, mode=0o700)
            client_runtime.mkdir(mode=0o700)
            environment.update({
                "HOME": str(client_home),
                "XDG_RUNTIME_DIR": str(client_runtime),
            })
        environments.append(environment)
    production_chunk_kib = relay_chunk_kib(base_environment)
    effective_chunk_kib = args.bench_chunk_kib or production_chunk_kib
    interface = (args.interface or infer_interface(server)) if args.capture else ""
    print(
        f"[lan] endpoint {server}:{port}: {mib} MiB per direction, "
        f"{streams} stream(s) per client, {args.clients} client(s), "
        + (
            "production upload DATA shape; download server-selected"
            if args.bench_chunk_kib is None
            else (
                f"explicit {args.bench_chunk_kib} KiB upload DATA shape; "
                "download server-selected"
            )
        ),
        flush=True,
    )
    if args.clients > 1:
        print(
            f"[lan] aggregate payload: {total_payload_mib} MiB; "
            f"client start stagger: {args.client_stagger_ms} ms",
            flush=True,
        )
    if not args.no_resource_sampling:
        print_host_resources("[lan]", host_resource_info())
    if args.capture:
        print(f"[lan] capturing {interface} to {output / 'endpoint.pcap'}", flush=True)
    print(f"[lan] artifacts: {output}", flush=True)
    capture: ManagedProcess | None = None
    endpoint_capture_error: str | None = None
    try:
        if args.capture:
            capture = start_capture(interface, server, port, output / "endpoint.pcap")
        endpoint_started_utc = datetime.now(timezone.utc).isoformat()
        endpoint_runs, endpoint_wall_seconds = run_endpoint_clients(
            args, yume, config_path, environments, mib, streams
        )
        endpoint_finished_utc = datetime.now(timezone.utc).isoformat()
    finally:
        if capture:
            capture.stop(interrupt=True)
            endpoint_capture_error = capture_error(capture)
    for index, (result, _argv) in enumerate(endpoint_runs, start=1):
        log_name = "endpoint.log" if args.clients == 1 else f"endpoint-client-{index:03d}.log"
        (output / log_name).write_text(result.output, encoding="utf-8")

    endpoint_code = next(
        (result.returncode for result, _argv in endpoint_runs if result.returncode != 0),
        0,
    )
    endpoint_interrupted = any(result.interrupted for result, _argv in endpoint_runs)
    endpoint_timed_out = any(result.timed_out for result, _argv in endpoint_runs)
    endpoint_resources = aggregate_resource_summaries(
        [result.resources for result, _argv in endpoint_runs],
        endpoint_wall_seconds,
    )
    endpoint_rates = aggregate_client_rates(endpoint_runs)
    endpoint_wall_throughput = wall_throughput(
        total_payload_mib, endpoint_wall_seconds
    )

    browser_code: int | None = None
    browser_version: str | None = None
    browser_argv: list[str] = []
    browser_result: StreamedCommandResult | None = None
    cover_capture_error: str | None = None
    if browser and endpoint_code == 0:
        browser_version = command_version([str(browser), "--version"])
        if not re.search(r"\b(?:Chrome|Chromium)\s+150\.", browser_version):
            print(
                f"[lan] {browser_version} does not match Chrome 151; "
                "the cover capture is functional evidence only",
                file=sys.stderr,
            )
        capture = None
        try:
            if args.capture:
                capture = start_capture(
                    interface, server, port, output / "cover-chromium.pcap"
                )
            browser_result, browser_argv = run_browser_cover(
                browser,
                identity,
                home,
                runtime,
                output / "chromium-profile",
                server,
                port,
                tls_name,
            )
        finally:
            if capture:
                capture.stop(interrupt=True)
                cover_capture_error = capture_error(capture)
        browser_code = browser_result.returncode
        (output / "cover-chromium.log").write_text(
            browser_result.output, encoding="utf-8"
        )

    report = {
        "schema": 2,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "server": server,
        "port": port,
        "yume": command_version([str(yume), "--version"]),
        "host": host_resource_info(),
        "endpoint": {
            "started_utc": endpoint_started_utc,
            "finished_utc": endpoint_finished_utc,
            "exit_code": endpoint_code,
            "interrupted": endpoint_interrupted,
            "timed_out": endpoint_timed_out,
            "command": endpoint_runs[0][1] if endpoint_runs else [],
            "mib_per_direction": mib,
            "streams": streams,
            "clients": args.clients,
            "client_stagger_ms": args.client_stagger_ms,
            "aggregate_payload_mib": total_payload_mib,
            # Retain chunk_kib/chunk_source as upload aliases for existing
            # report consumers. Download DATA records are selected by yumed.
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
            "direction": args.bench_direction,
            "timing": args.timing,
            "contract": endpoint_contract(
                args.bench_chunk_kib,
                production_chunk_kib,
            ),
            "rates": endpoint_rates,
            "rates_aggregation": "sum-of-client-rates",
            "wall_seconds": round(endpoint_wall_seconds, 3),
            "wall_throughput": endpoint_wall_throughput,
            "resources": endpoint_resources,
            "client_runs": [
                {
                    "index": index,
                    "exit_code": result.returncode,
                    "interrupted": result.interrupted,
                    "timed_out": result.timed_out,
                    "command": argv,
                    "rates": parse_rates(result.output),
                    "resources": result.resources,
                    "log": (
                        "endpoint.log"
                        if args.clients == 1
                        else f"endpoint-client-{index:03d}.log"
                    ),
                }
                for index, (result, argv) in enumerate(endpoint_runs, start=1)
            ],
            "pcap": (
                "endpoint.pcap"
                if args.capture and not endpoint_capture_error
                else None
            ),
            "capture_error": endpoint_capture_error,
        },
        "cover": {
            "exit_code": browser_code,
            "interrupted": browser_result.interrupted if browser_result else False,
            "timed_out": browser_result.timed_out if browser_result else False,
            "browser": browser_version,
            "command": browser_argv,
            "pcap": (
                "cover-chromium.pcap"
                if browser and args.capture and not cover_capture_error
                else None
            ),
            "capture_error": cover_capture_error,
            "resources": browser_result.resources if browser_result else None,
        },
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    shutil.rmtree(runtime, ignore_errors=True)
    shutil.rmtree(home, ignore_errors=True)
    if os.geteuid() == 0:
        chown_tree(output, identity)
    if browser_result:
        status = "passed" if browser_code == 0 else f"failed ({browser_code})"
        print(f"[lan] Chrome cover load: {status}")
    if not args.no_resource_sampling:
        print_process_resources("[lan] clients aggregate", endpoint_resources)
    print(
        "[lan] aggregate wall throughput: "
        f"{endpoint_wall_throughput['mib_per_second']:.1f} MiB/s / "
        f"{endpoint_wall_throughput['mbit_per_second']:.1f} Mbit/s"
    )
    if endpoint_code != 0:
        print(f"[lan] partial artifacts: {output}")
        return endpoint_code
    if endpoint_capture_error or cover_capture_error:
        error = endpoint_capture_error or cover_capture_error
        print(f"[lan] capture failed: {error}", file=sys.stderr)
        print(f"[lan] partial artifacts: {output}")
        return 1
    if browser_code:
        print(f"[lan] partial artifacts: {output}")
        return browser_code
    print(f"[lan] complete; artifacts: {output}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare", help="generate matching server/client bundles")
    prepare.add_argument("--server", required=True, help="server IPv4 address")
    prepare.add_argument("--port", type=int, default=443)
    prepare.add_argument("--tls-name", default=DEFAULT_TLS_NAME)
    prepare.add_argument("--output", type=Path, default=Path("yume-lan-kit"))
    prepare.add_argument("--yumed", type=Path, default=DEFAULT_YUMED)
    prepare.set_defaults(handler=prepare_bundle)

    server = commands.add_parser("server", help="run Node and yumed from a server bundle")
    server.add_argument("--bundle", type=Path, required=True)
    server.add_argument("--yumed", type=Path, default=DEFAULT_YUMED)
    server.add_argument("--node", type=Path)
    server.add_argument("--cover", type=Path, default=DEFAULT_COVER)
    server.add_argument("--allow-node-version-mismatch", action="store_true")
    server.add_argument("--no-node-bootstrap", action="store_true")
    server.add_argument("--timing", action="store_true", help="enable yumed timing counters")
    server.add_argument(
        "--threads",
        type=int,
        help="override yumed worker threads for a scaling comparison",
    )
    server.add_argument("--resource-sample-ms", type=int, default=250)
    server.add_argument("--no-resource-sampling", action="store_true")
    server.add_argument("--output-dir", type=Path)
    server.set_defaults(handler=run_server)

    client = commands.add_parser("client", help="run the endpoint benchmark from a client bundle")
    client.add_argument("--bundle", type=Path, required=True)
    client.add_argument("--yume", type=Path, default=DEFAULT_YUME)
    size = client.add_mutually_exclusive_group()
    size.add_argument("--quick", action="store_true", help="32 MiB and four streams")
    size.add_argument("--full", action="store_true", help="1024 MiB and 64 streams")
    client.add_argument("--bench-mib", type=int, default=128)
    client.add_argument("--bench-streams", type=int, default=8)
    client.add_argument(
        "--clients",
        type=int,
        default=1,
        help="concurrent yume client processes (default: 1; hard maximum: 128)",
    )
    client.add_argument(
        "--client-stagger-ms",
        type=int,
        default=25,
        help="delay between concurrent client starts (default: 25 ms)",
    )
    client.add_argument(
        "--allow-large-workload",
        action="store_true",
        help="allow more than 16 GiB aggregate application payload",
    )
    client.add_argument(
        "--allow-high-client-count",
        action="store_true",
        help="allow 65..128 client processes after checking host capacity",
    )
    client.add_argument(
        "--bench-chunk-kib",
        type=int,
        help="explicit upload DATA chunk size; omit to match the client relay buffer",
    )
    client.add_argument("--bench-direction", choices=("both", "up", "down"), default="both")
    client.add_argument("--timing", action="store_true", help="enable yume timing counters")
    client.add_argument("--resource-sample-ms", type=int, default=250)
    client.add_argument("--no-resource-sampling", action="store_true")
    client.add_argument("--capture", action="store_true")
    client.add_argument("--interface")
    client.add_argument("--cover", action="store_true", help="also load and capture the Node cover with Chrome")
    client.add_argument("--browser", type=Path, help="Chromium/Chrome executable")
    client.add_argument("--output-dir", type=Path)
    client.set_defaults(handler=run_client)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if hasattr(args, "port") and not 1 <= args.port <= 65535:
        raise SystemExit("--port must be 1..65535")
    if hasattr(args, "bench_mib") and not 1 <= args.bench_mib <= 16384:
        raise SystemExit("--bench-mib must be 1..16384")
    if hasattr(args, "bench_streams") and not 1 <= args.bench_streams <= 240:
        raise SystemExit("--bench-streams must be 1..240")
    if hasattr(args, "clients") and not 1 <= args.clients <= HARD_CLIENT_LIMIT:
        raise SystemExit(f"--clients must be 1..{HARD_CLIENT_LIMIT}")
    if hasattr(args, "threads") and args.threads is not None and not 1 <= args.threads <= 256:
        raise SystemExit("--threads must be 1..256")
    if hasattr(args, "client_stagger_ms") and not 0 <= args.client_stagger_ms <= 5000:
        raise SystemExit("--client-stagger-ms must be 0..5000")
    if hasattr(args, "resource_sample_ms") and not 100 <= args.resource_sample_ms <= 5000:
        raise SystemExit("--resource-sample-ms must be 100..5000")
    if (
        hasattr(args, "bench_chunk_kib")
        and args.bench_chunk_kib is not None
        and not 1 <= args.bench_chunk_kib <= 256
    ):
        raise SystemExit("--bench-chunk-kib must be 1..256")
    try:
        return args.handler(args)
    except KeyboardInterrupt:
        print("\n[lan] interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
