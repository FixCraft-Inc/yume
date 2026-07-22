#!/usr/bin/env python3
"""Opt-in, reversible Linux TUN/NAT setup for yumed packet egress."""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import ipaddress
import json
import os
import pathlib
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence


STATE_DIRECTORY = pathlib.Path("/run/yume-packet-quick")
LOCK_PATH = pathlib.Path("/run/yume-packet-quick.lock")
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


class SetupError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class SetupConfig:
    tun: str
    packet_cidr: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address
    mtu: int
    owner: str
    wan: str
    listen_address: ipaddress.IPv4Address
    listen_port: int
    allow_from: ipaddress.IPv4Network
    firewall: str
    nft_table: str


def command_text(command: Sequence[str]) -> str:
    return shlex.join(str(part) for part in command)


def validate_interface(value: str, label: str) -> str:
    if not INTERFACE_PATTERN.fullmatch(value):
        raise SetupError(f"{label} must be a 1-15 character Linux interface name")
    return value


def parse_listen(value: str) -> tuple[ipaddress.IPv4Address, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text:
        raise SetupError("--listen must be an IPv4 address and port, for example build-host.example:8443")
    try:
        address = ipaddress.IPv4Address(host)
        port = int(port_text)
    except ValueError as error:
        raise SetupError(f"invalid --listen value: {value}") from error
    if not 1 <= port <= 65535:
        raise SetupError("--listen port must be in 1..65535")
    return address, port


def parse_packet_cidr(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.IPv4Network(value, strict=True)
    except ValueError as error:
        raise SetupError(f"invalid --packet-cidr: {value}") from error
    if not 24 <= network.prefixlen <= 30:
        raise SetupError("--packet-cidr prefix must be /24 through /30")
    return network


def find_command(name: str) -> str:
    located = shutil.which(name)
    if located:
        return located
    for directory in ("/usr/sbin", "/sbin", "/usr/bin", "/bin"):
        candidate = pathlib.Path(directory, name)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise SetupError(f"required command not found: {name}")


def run_command(
    command: Sequence[str],
    *,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(part) for part in command],
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    if check and result.returncode != 0:
        detail = result.stdout.strip() if result.stdout else f"exit status {result.returncode}"
        raise SetupError(f"command failed: {command_text(command)}\n{detail}")
    return result


def infer_default_wan(ip_command: str) -> str:
    result = run_command([ip_command, "-4", "route", "show", "default"], capture=True)
    candidates: list[tuple[int, str]] = []
    for line in result.stdout.splitlines():
        words = line.split()
        if "dev" not in words:
            continue
        interface = words[words.index("dev") + 1]
        metric = 0
        if "metric" in words:
            try:
                metric = int(words[words.index("metric") + 1])
            except (ValueError, IndexError):
                metric = 2**31 - 1
        candidates.append((metric, interface))
    if not candidates:
        raise SetupError("could not infer the default IPv4 interface; pass --wan")
    return validate_interface(min(candidates)[1], "default IPv4 interface")


def host_ipv4_addresses(ip_command: str) -> set[ipaddress.IPv4Address]:
    result = run_command([ip_command, "-json", "-4", "address", "show"], capture=True)
    try:
        links = json.loads(result.stdout)
        return {
            ipaddress.IPv4Address(info["local"])
            for link in links
            for info in link.get("addr_info", [])
            if info.get("family") == "inet" and info.get("local")
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise SetupError("could not parse local IPv4 addresses from iproute2") from error


def host_ipv4_routes(ip_command: str) -> list[ipaddress.IPv4Network]:
    result = run_command([ip_command, "-json", "-4", "route", "show"], capture=True)
    routes: list[ipaddress.IPv4Network] = []
    try:
        for route in json.loads(result.stdout):
            destination = route.get("dst")
            if not destination or destination == "default":
                continue
            routes.append(ipaddress.IPv4Network(destination, strict=False))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise SetupError("could not parse local IPv4 routes from iproute2") from error
    return routes


def resolve_owner(requested: str | None) -> str:
    owner = requested or os.environ.get("SUDO_USER") or os.environ.get("USER")
    if not owner or owner == "root":
        raise SetupError("could not determine the non-root yumed owner; pass --owner USER")
    try:
        pwd.getpwnam(owner)
    except KeyError as error:
        raise SetupError(f"unknown local user: {owner}") from error
    return owner


def ufw_is_active(ufw_command: str) -> bool:
    result = run_command([ufw_command, "status"], check=False, capture=True)
    return result.returncode == 0 and any(
        line.strip().lower() == "status: active" for line in result.stdout.splitlines()
    )


def resolve_config(args: argparse.Namespace, *, dry_run: bool) -> SetupConfig:
    tun = validate_interface(args.tun, "--tun")
    packet_cidr = parse_packet_cidr(args.packet_cidr)
    gateway = ipaddress.IPv4Address(int(packet_cidr.network_address) + 1)
    listen_address, listen_port = parse_listen(args.listen)
    try:
        allow_from = ipaddress.IPv4Network(args.allow_from, strict=True)
    except ValueError as error:
        raise SetupError(f"invalid --allow-from: {args.allow_from}") from error
    if not 576 <= args.mtu <= 65535:
        raise SetupError("--mtu must be in 576..65535")

    ip_command = find_command("ip")
    if not dry_run:
        if listen_address not in host_ipv4_addresses(ip_command):
            raise SetupError(f"--listen address is not assigned to this host: {listen_address}")
        overlaps = [route for route in host_ipv4_routes(ip_command) if route.overlaps(packet_cidr)]
        if overlaps:
            raise SetupError(
                f"--packet-cidr overlaps an existing host route: {overlaps[0]}"
            )
    wan = validate_interface(args.wan, "--wan") if args.wan else (
        "WAN_INTERFACE" if dry_run else infer_default_wan(ip_command)
    )
    owner = args.owner or os.environ.get("SUDO_USER") or os.environ.get("USER")
    if dry_run:
        owner = owner or "YUMED_USER"
    else:
        owner = resolve_owner(args.owner)

    firewall = args.firewall
    if firewall == "auto":
        if dry_run:
            firewall = "ufw"
        else:
            try:
                firewall = "ufw" if ufw_is_active(find_command("ufw")) else "none"
            except SetupError:
                firewall = "none"
    if firewall == "ufw" and not dry_run:
        ufw_command = find_command("ufw")
        if not ufw_is_active(ufw_command):
            raise SetupError("--firewall ufw was requested, but UFW is not active")

    table_suffix = re.sub(r"[^A-Za-z0-9_]", "_", tun)
    return SetupConfig(
        tun=tun,
        packet_cidr=packet_cidr,
        gateway=gateway,
        mtu=args.mtu,
        owner=owner,
        wan=wan,
        listen_address=listen_address,
        listen_port=listen_port,
        allow_from=allow_from,
        firewall=firewall,
        nft_table=f"yume_{table_suffix}",
    )


def planned_commands(config: SetupConfig) -> list[list[str]]:
    ip_command = find_command("ip")
    sysctl_command = find_command("sysctl")
    nft_command = find_command("nft")
    commands = [
        [ip_command, "tuntap", "add", "dev", config.tun, "mode", "tun", "user", config.owner],
        [ip_command, "address", "add", f"{config.gateway}/{config.packet_cidr.prefixlen}", "dev", config.tun],
        [ip_command, "link", "set", "dev", config.tun, "mtu", str(config.mtu), "up"],
        [sysctl_command, "-w", "net.ipv4.ip_forward=1"],
        [nft_command, "add", "table", "ip", config.nft_table],
        [
            nft_command,
            "add",
            "chain",
            "ip",
            config.nft_table,
            "postrouting",
            "{ type nat hook postrouting priority srcnat; policy accept; }",
        ],
        [
            nft_command,
            "add",
            "rule",
            "ip",
            config.nft_table,
            "postrouting",
            "ip",
            "saddr",
            str(config.packet_cidr),
            "oifname",
            config.wan,
            "masquerade",
        ],
    ]
    if config.firewall == "ufw":
        ufw_command = find_command("ufw")
        commands.extend(
            [
                [
                    ufw_command,
                    "allow",
                    "proto",
                    "tcp",
                    "from",
                    str(config.allow_from),
                    "to",
                    str(config.listen_address),
                    "port",
                    str(config.listen_port),
                    "comment",
                    "YUME packet ingress",
                ],
                [
                    ufw_command,
                    "route",
                    "allow",
                    "in",
                    "on",
                    config.tun,
                    "out",
                    "on",
                    config.wan,
                    "from",
                    str(config.packet_cidr),
                    "comment",
                    "YUME packet egress",
                ],
            ]
        )
    return commands


def state_path(tun: str) -> pathlib.Path:
    validate_interface(tun, "--tun")
    return STATE_DIRECTORY / f"{tun}.json"


def write_state(path: pathlib.Path, state: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        pathlib.Path(temporary_name).unlink(missing_ok=True)
        raise


def read_forwarding() -> str:
    return pathlib.Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="ascii").strip()


def interface_exists(ip_command: str, interface: str) -> bool:
    return run_command(
        [ip_command, "link", "show", "dev", interface], check=False, capture=True
    ).returncode == 0


def table_exists(nft_command: str, table: str) -> bool:
    return run_command(
        [nft_command, "list", "table", "ip", table], check=False, capture=True
    ).returncode == 0


def require_root() -> None:
    if os.geteuid() != 0:
        raise SetupError("this operation changes host networking; run it through sudo")


def confirm(message: str, assume_yes: bool) -> None:
    if assume_yes:
        return
    if not sys.stdin.isatty():
        raise SetupError("confirmation requires a terminal; pass --yes after reviewing --dry-run")
    answer = input(f"{message} Type 'yes' to continue: ").strip().lower()
    if answer != "yes":
        raise SetupError("cancelled; no changes were made")


def delete_ufw_rules(state: dict[str, object], *, check: bool) -> None:
    if state.get("firewall") != "ufw":
        return
    ufw_command = find_command("ufw")
    if state.get("ufw_route_added"):
        run_command(
            [
                ufw_command,
                "--force",
                "route",
                "delete",
                "allow",
                "in",
                "on",
                str(state["tun"]),
                "out",
                "on",
                str(state["wan"]),
                "from",
                str(state["packet_cidr"]),
            ],
            check=check,
        )
    if state.get("ufw_input_added"):
        run_command(
            [
                ufw_command,
                "--force",
                "delete",
                "allow",
                "proto",
                "tcp",
                "from",
                str(state["allow_from"]),
                "to",
                str(state["listen_address"]),
                "port",
                str(state["listen_port"]),
            ],
            check=check,
        )


def bring_up(args: argparse.Namespace) -> int:
    config = resolve_config(args, dry_run=args.dry_run)
    commands = planned_commands(config)
    print("YUME packet-egress network plan:")
    for command in commands:
        print(f"  {command_text(command)}")
    print()
    print(
        "Matching yumed flags: "
        f"--packet-egress tun --packet-tun-name {config.tun} "
        f"--packet-cidr {config.packet_cidr} --packet-mtu {config.mtu}"
    )
    if args.dry_run:
        return 0

    if config.firewall == "none":
        print(
            "WARNING: no firewall rules will be managed; the administrator must allow "
            "the listener and routed TUN traffic.",
            file=sys.stderr,
        )

    require_root()
    confirm("Apply this reversible TUN/NAT/firewall plan?", args.yes)
    ip_command = find_command("ip")
    nft_command = find_command("nft")
    path = state_path(config.tun)
    if path.exists():
        raise SetupError(f"state already exists: {path}; use status or down")
    if interface_exists(ip_command, config.tun):
        raise SetupError(f"interface {config.tun} already exists; refusing to adopt or overwrite it")
    if table_exists(nft_command, config.nft_table):
        raise SetupError(f"nft table ip {config.nft_table} already exists; refusing to adopt it")

    state: dict[str, object] = {
        "schema": 1,
        "status": "applying",
        **{
            field.name: str(getattr(config, field.name))
            for field in dataclasses.fields(config)
        },
        "listen_port": config.listen_port,
        "mtu": config.mtu,
        "previous_ip_forward": read_forwarding(),
        "tun_created": False,
        "nft_table_created": False,
        "ufw_input_added": False,
        "ufw_route_added": False,
    }
    write_state(path, state)
    try:
        for index, command in enumerate(commands):
            capture = config.firewall == "ufw" and index >= len(commands) - 2
            result = run_command(command, capture=capture)
            if index == 0:
                state["tun_created"] = True
            elif command[1:4] == ["add", "table", "ip"]:
                state["nft_table_created"] = True
            elif config.firewall == "ufw" and index == len(commands) - 2:
                state["ufw_input_added"] = "Skipping adding existing rule" not in result.stdout
            elif config.firewall == "ufw" and index == len(commands) - 1:
                state["ufw_route_added"] = "Skipping adding existing rule" not in result.stdout
            write_state(path, state)
    except BaseException:
        print("setup failed; rolling back owned changes", file=sys.stderr)
        rollback_state(state)
        path.unlink(missing_ok=True)
        raise

    state["status"] = "up"
    write_state(path, state)
    print(f"YUME packet egress is ready; state: {path}")
    return 0


def rollback_state(state: dict[str, object]) -> None:
    try:
        delete_ufw_rules(state, check=False)
    except SetupError:
        pass
    try:
        nft_command = find_command("nft")
        if state.get("nft_table_created"):
            run_command(
                [nft_command, "delete", "table", "ip", str(state["nft_table"])],
                check=False,
            )
    except SetupError:
        pass
    try:
        ip_command = find_command("ip")
        if state.get("tun_created"):
            run_command([ip_command, "link", "delete", "dev", str(state["tun"])], check=False)
    except SetupError:
        pass
    if state.get("previous_ip_forward") == "0" and read_forwarding() == "1":
        try:
            run_command([find_command("sysctl"), "-w", "net.ipv4.ip_forward=0"], check=False)
        except SetupError:
            pass


def bring_down(args: argparse.Namespace) -> int:
    require_root()
    path = state_path(args.tun)
    if not path.is_file():
        raise SetupError(f"no managed state for {args.tun}: {path}")
    state = json.loads(path.read_text(encoding="utf-8"))
    confirm(f"Remove networking owned by {path}?", args.yes)
    delete_ufw_rules(state, check=True)

    nft_command = find_command("nft")
    if state.get("nft_table_created") and table_exists(nft_command, str(state["nft_table"])):
        run_command([nft_command, "delete", "table", "ip", str(state["nft_table"])])
    ip_command = find_command("ip")
    if state.get("tun_created") and interface_exists(ip_command, str(state["tun"])):
        run_command([ip_command, "link", "delete", "dev", str(state["tun"])])
    if state.get("previous_ip_forward") == "0":
        if read_forwarding() == "1":
            run_command([find_command("sysctl"), "-w", "net.ipv4.ip_forward=0"])
        else:
            print("IPv4 forwarding changed externally; leaving its current value unchanged")
    path.unlink()
    print(f"Removed YUME packet-egress networking for {args.tun}")
    return 0


def show_status(args: argparse.Namespace) -> int:
    path = state_path(args.tun)
    if not path.is_file():
        print(f"{args.tun}: unmanaged/down (no state at {path})")
        return 1
    state = json.loads(path.read_text(encoding="utf-8"))
    ip_command = find_command("ip")
    nft_command = find_command("nft")
    print(f"state: {state.get('status', 'unknown')}")
    print(f"tun: {state['tun']} ({'present' if interface_exists(ip_command, str(state['tun'])) else 'missing'})")
    print(
        f"nft table: ip {state['nft_table']} "
        f"({'present' if table_exists(nft_command, str(state['nft_table'])) else 'missing'})"
    )
    print(f"IPv4 forwarding: {read_forwarding()}")
    print(f"WAN: {state['wan']}; client pool: {state['packet_cidr']}")
    print(f"ingress: {state['listen_address']}:{state['listen_port']} from {state['allow_from']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely prepare or remove Linux networking for yumed packet_bulk_v1 egress."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    up = subparsers.add_parser("up", help="create a TUN, scoped NAT, and optional UFW rules")
    up.add_argument("--listen", required=True, metavar="IP:PORT")
    up.add_argument("--allow-from", required=True, metavar="CIDR")
    up.add_argument("--tun", default="yume-pkt0")
    up.add_argument("--packet-cidr", default="10.89.0.0/24")
    up.add_argument("--mtu", type=int, default=1420)
    up.add_argument("--wan", help="default-route interface when omitted")
    up.add_argument("--owner", help="non-root account that runs yumed; defaults to SUDO_USER")
    up.add_argument("--firewall", choices=("auto", "ufw", "none"), default="auto")
    up.add_argument("--dry-run", action="store_true", help="print the plan without changing the host")
    up.add_argument("--yes", action="store_true", help="apply a previously reviewed plan without prompting")
    up.set_defaults(handler=bring_up)

    down = subparsers.add_parser("down", help="remove only networking recorded in managed state")
    down.add_argument("--tun", default="yume-pkt0")
    down.add_argument("--yes", action="store_true")
    down.set_defaults(handler=bring_down)

    status = subparsers.add_parser("status", help="show managed and live networking state")
    status.add_argument("--tun", default="yume-pkt0")
    status.set_defaults(handler=show_status)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "status" or (args.command == "up" and args.dry_run):
            return int(args.handler(args))
        lock_descriptor = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lock_descriptor, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            return int(args.handler(args))
    except (OSError, SetupError, json.JSONDecodeError) as error:
        print(f"yume-packet-quick: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
