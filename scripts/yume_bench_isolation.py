#!/usr/bin/env python3
"""Fail-closed Linux isolation primitives for YUME benchmark helpers."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from yume_bench_common import PINNED_NODE_VERSION


REPO_ROOT = Path(__file__).resolve().parent.parent
COVER_PORT = 3000
EXEC_GUARD = REPO_ROOT / "scripts" / "yume_bench_exec_guard.py"


@dataclass
class FrozenExecutable:
    path: Path
    sha256: str
    descriptor: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def isolated_reexec_argv(script: Path, original_argv: list[str]) -> list[str]:
    """Build the fail-closed disposable namespace wrapper command."""
    unshare = shutil.which("unshare") or "unshare"
    outer = namespace_inodes()
    return [
        unshare,
        "--user",
        "--map-root-user",
        "--keep-caps",
        "--mount",
        "--propagation",
        "private",
        "--pid",
        "--fork",
        "--kill-child=SIGKILL",
        "--mount-proc",
        "--net",
        "--",
        sys.executable,
        str(script.resolve()),
        *original_argv,
        "--isolated-controller",
        "--outer-userns",
        outer["user"],
        "--outer-mountns",
        outer["mount"],
        "--outer-pidns",
        outer["pid"],
        "--outer-netns",
        outer["network"],
    ]


def single_id_mapping(text: str) -> tuple[int, int] | None:
    """Return (inside, outside) only for an exact one-ID namespace map."""
    rows = [line.split() for line in text.splitlines() if line.strip()]
    if len(rows) != 1 or len(rows[0]) != 3:
        return None
    try:
        inside, outside, count = (int(value) for value in rows[0])
    except ValueError:
        return None
    if inside != 0 or outside <= 0 or count != 1:
        return None
    return inside, outside


def namespace_inodes() -> dict[str, str]:
    return {
        "user": os.readlink("/proc/self/ns/user"),
        "mount": os.readlink("/proc/self/ns/mnt"),
        "pid": os.readlink("/proc/self/ns/pid"),
        "network": os.readlink("/proc/self/ns/net"),
    }


def freeze_executable(path: Path, expected_sha256: str | None = None) -> FrozenExecutable:
    """Copy an executable into a sealed memfd before it can be executed."""
    source_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    source_fd = os.open(path, source_flags)
    frozen_fd = os.memfd_create("yume-pinned-node", os.MFD_ALLOW_SEALING)
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise RuntimeError(f"Node executable is not a regular file: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(frozen_fd, view)
                view = view[written:]
        source_after = os.fstat(source_fd)
        if (
            (source_stat.st_dev, source_stat.st_ino, source_stat.st_size)
            != (source_after.st_dev, source_after.st_ino, source_after.st_size)
            or source_stat.st_mtime_ns != source_after.st_mtime_ns
        ):
            raise RuntimeError("Node executable changed while it was being frozen")
        actual_sha256 = digest.hexdigest()
        if expected_sha256 is not None and actual_sha256 != expected_sha256:
            raise RuntimeError("the pinned Node executable changed during namespace entry")
        os.fchmod(frozen_fd, 0o500)
        seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(frozen_fd, fcntl.F_ADD_SEALS, seals)
        return FrozenExecutable(
            Path(f"/proc/self/fd/{frozen_fd}"),
            actual_sha256,
            frozen_fd,
        )
    except Exception:
        os.close(frozen_fd)
        raise
    finally:
        os.close(source_fd)


def frozen_executable_version(
    executable: FrozenExecutable,
    *,
    allow_mismatch: bool,
) -> str:
    result = subprocess.run(
        [str(executable.path), "--version"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
        pass_fds=(executable.descriptor,),
    )
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    version = lines[0] if lines else "unavailable"
    expected_prefix = f"v{PINNED_NODE_VERSION.rsplit('.', 1)[0]}."
    if result.returncode != 0 or (
        not version.startswith(expected_prefix) and not allow_mismatch
    ):
        raise RuntimeError(
            f"Node {expected_prefix[1:]}x is required (found {version}); "
            "use --allow-node-version-mismatch only for functional testing"
        )
    return version


def root_mount_is_private(mountinfo: str) -> bool:
    """Return whether the root mount has no shared/slave propagation tag."""
    for line in mountinfo.splitlines():
        left = line.split(" - ", 1)[0].split()
        if len(left) < 6 or left[4] != "/":
            continue
        propagation = left[6:]
        return not any(
            field.startswith(("shared:", "master:", "propagate_from:"))
            for field in propagation
        )
    return False


def fresh_network_namespace_state() -> dict[str, object]:
    """Fail unless the controller starts in an otherwise empty network ns."""
    links_result = subprocess.run(
        ["ip", "-json", "address", "show"],
        check=True,
        capture_output=True,
        text=True,
    )
    routes_result = subprocess.run(
        ["ip", "-json", "route", "show", "table", "all"],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        links = json.loads(links_result.stdout)
        routes = json.loads(routes_result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("could not parse isolated network namespace state") from exc
    if (
        not isinstance(links, list)
        or len(links) != 1
        or links[0].get("ifname") != "lo"
    ):
        raise RuntimeError("isolated controller network namespace is not fresh")
    non_loopback_addresses = [
        address
        for address in links[0].get("addr_info", [])
        if address.get("local") not in ("127.0.0.1", "::1")
    ]
    if non_loopback_addresses or not isinstance(routes, list) or routes:
        raise RuntimeError("isolated controller network namespace has prior network state")
    return {
        "initial_interfaces": ["lo"],
        "initial_routes": 0,
        "initial_non_loopback_addresses": 0,
    }


def enter_isolated_controller(outer: dict[str, str]) -> dict[str, object]:
    """Create a private ip-netns mount point inside the throwaway mount ns."""
    if os.geteuid() != 0:
        raise RuntimeError("isolated network controller did not map the caller to UID 0")
    uid_map = Path("/proc/self/uid_map").read_text(encoding="ascii")
    gid_map = Path("/proc/self/gid_map").read_text(encoding="ascii")
    uid_mapping = single_id_mapping(uid_map)
    gid_mapping = single_id_mapping(gid_map)
    if uid_mapping is None or gid_mapping is None:
        raise RuntimeError("isolated controller requires exact one-ID user/group maps")
    if os.getpid() != 1:
        raise RuntimeError("isolated controller must be PID 1 in its disposable PID namespace")
    current = namespace_inodes()
    if set(outer) != set(current) or any(
        not outer[name] or outer[name] == current[name] for name in current
    ):
        raise RuntimeError("isolated controller namespace provenance check failed")
    mountinfo = Path("/proc/self/mountinfo").read_text(encoding="ascii")
    if not root_mount_is_private(mountinfo):
        raise RuntimeError("isolated controller root mount is not private")
    network_state = fresh_network_namespace_state()
    subprocess.run(
        [
            "mount", "-t", "tmpfs", "-o", "mode=0755,nosuid,nodev,noexec",
            "tmpfs", "/run",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    Path("/run/netns").mkdir(mode=0o755)
    subprocess.run(
        ["mount", "--bind", "/run/netns", "/run/netns"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["mount", "--make-shared", "/run/netns"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return {
        "pid_1": True,
        "single_id_uid_map": uid_mapping[1],
        "single_id_gid_map": gid_mapping[1],
        "root_mount_private_before_run_mount": True,
        **network_state,
    }


def capability_drop_prefix(isolated_userns: bool) -> list[str]:
    if not isolated_userns:
        return []
    return [
        "setpriv",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--nnp",
        "--",
    ]


def guarded_command(argv: list[str]) -> list[str]:
    """Assert the runtime cap/no-new-privs state immediately before exec."""
    return [sys.executable, str(EXEC_GUARD), "--", *argv]


def runtime_security_state(text: str) -> dict[str, object]:
    marker = "YUME_BENCH_SECURITY_STATE="
    records = [line[len(marker):] for line in text.splitlines() if line.startswith(marker)]
    if len(records) != 1:
        raise RuntimeError("workload did not emit exactly one runtime security record")
    try:
        state = json.loads(records[0])
    except json.JSONDecodeError as exc:
        raise RuntimeError("workload emitted an invalid runtime security record") from exc
    expected_caps = {
        "CapInh": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000",
    }
    if (
        not isinstance(state, dict)
        or any(state.get(name) != value for name, value in expected_caps.items())
        or state.get("NoNewPrivs") != "1"
    ):
        raise RuntimeError("workload runtime security state is not fail-closed")
    return state


def runtime_security_log(path: Path) -> dict[str, object]:
    return runtime_security_state(path.read_text(encoding="utf-8", errors="replace"))


def node_sandbox_command(node: FrozenExecutable) -> list[str]:
    """Build a minimal read-only Node cover filesystem/process boundary."""
    return [
        "bwrap",
        "--die-with-parent",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--dir", "/opt/yume",
        "--file", str(node.descriptor), "/opt/yume/node",
        "--chmod", "0500", "/opt/yume/node",
        "--ro-bind",
        str(REPO_ROOT / "tools" / "cover-node" / "backend.mjs"),
        "/opt/yume/backend.mjs",
        "--ro-bind", str(EXEC_GUARD), "/opt/yume/exec_guard.py",
        "--cap-drop", "ALL",
        "--clearenv",
        "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "HOME", "/nonexistent",
        "--setenv", "YUME_COVER_HOST", "127.0.0.1",
        "--setenv", "YUME_COVER_PORT", str(COVER_PORT),
        "--chdir", "/",
        sys.executable,
        "/opt/yume/exec_guard.py",
        "--",
        "/opt/yume/node",
        "/opt/yume/backend.mjs",
    ]


def secure_artifact_tree(
    path: Path,
    *,
    owner: tuple[int, int] | None = None,
) -> None:
    """Validate and secure an artifact tree through no-follow descriptors."""
    base_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK

    def visit(directory_fd: int, display: Path) -> None:
        for name in os.listdir(directory_fd):
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            child_display = display / name
            if stat.S_ISLNK(before.st_mode):
                raise RuntimeError(
                    f"refusing symlink in private artifact tree: {child_display}"
                )
            is_directory = stat.S_ISDIR(before.st_mode)
            if not is_directory and not stat.S_ISREG(before.st_mode):
                raise RuntimeError(
                    f"refusing special file in private artifact tree: {child_display}"
                )
            flags = base_flags | (os.O_DIRECTORY if is_directory else 0)
            child_fd = os.open(name, flags, dir_fd=directory_fd)
            try:
                after = os.fstat(child_fd)
                if (
                    (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                    or is_directory != stat.S_ISDIR(after.st_mode)
                    or (not is_directory and not stat.S_ISREG(after.st_mode))
                ):
                    raise RuntimeError(
                        f"artifact changed during validation: {child_display}"
                    )
                if is_directory:
                    visit(child_fd, child_display)
                if owner is not None:
                    os.fchown(child_fd, *owner)
                os.fchmod(child_fd, 0o700 if is_directory else 0o600)
            finally:
                os.close(child_fd)

    root_fd = os.open(path, base_flags | os.O_DIRECTORY)
    try:
        visit(root_fd, path)
        if owner is not None:
            os.fchown(root_fd, *owner)
        os.fchmod(root_fd, 0o700)
    finally:
        os.close(root_fd)


def output_owner() -> tuple[int, int] | None:
    """Return the sudo invoker identity only when it is complete and valid."""
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if uid is None and gid is None:
        return None
    if uid is None or gid is None:
        raise RuntimeError("incomplete sudo output-owner identity")
    try:
        owner = int(uid), int(gid)
    except ValueError as exc:
        raise RuntimeError("invalid sudo output-owner identity") from exc
    if owner[0] < 0 or owner[1] < 0:
        raise RuntimeError("invalid sudo output-owner identity")
    return owner


def restore_output_owner(path: Path, owner: tuple[int, int] | None) -> None:
    if owner is not None:
        secure_artifact_tree(path, owner=owner)


def enforce_private_artifact_modes(path: Path) -> None:
    secure_artifact_tree(path)


def remove_private_tree(path: Path) -> None:
    shutil.rmtree(path)
    if path.exists():
        raise RuntimeError(f"private work directory still exists after removal: {path}")


def write_private_text(
    path: Path,
    value: str,
    *,
    owner: tuple[int, int] | None = None,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        if owner is not None:
            os.fchown(descriptor, *owner)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(value)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
