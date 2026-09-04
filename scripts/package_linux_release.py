#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

from generate_transport_profiles import ProfileError, active_profile_metadata


PROFILE = "linux-desktop-0.3.0"
BUNDLE_NAME = "yume-amd64-linux.tar.xz"
SERVER_NAME = "yumed-amd64-linux"
BUNDLE_DIRECTORY = "yume-amd64-linux"
GO_VERSION = "go1.26.5"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_regular_file(path: pathlib.Path, description: str) -> None:
    require(path.is_file() and not path.is_symlink(), f"Missing regular {description}: {path}")


def require_elf_amd64(path: pathlib.Path, description: str) -> None:
    require_regular_file(path, description)
    header = path.read_bytes()[:20]
    require(len(header) == 20 and header[:4] == b"\x7fELF", f"{description} is not ELF: {path}")
    require(header[4] == 2 and header[5] == 1, f"{description} is not little-endian ELF64: {path}")
    require(int.from_bytes(header[18:20], "little") == 62, f"{description} is not x86-64: {path}")


def require_glibc_dynamic(path: pathlib.Path, description: str) -> None:
    require_elf_amd64(path, description)
    result = subprocess.run(
        ["readelf", "-lW", str(path)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    require("Requesting program interpreter" in result.stdout,
            f"{description} is not dynamically linked")
    require("ld-linux-x86-64.so.2" in result.stdout,
            f"{description} does not use the x86-64 glibc loader")
    dynamic = subprocess.run(
        ["readelf", "-dW", str(path)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout
    require("(RPATH)" not in dynamic and "(RUNPATH)" not in dynamic,
            f"{description} contains an unsafe runtime library search path")
    require("Shared library: [liboqs" not in dynamic,
            f"{description} dynamically links liboqs; release binaries must use the pinned static archive")
    require("Shared library: [libssl" not in dynamic and
            "Shared library: [libcrypto" not in dynamic,
            f"{description} dynamically links OpenSSL; the native Chrome TLS "
            "patch must be embedded in the release binary")


def version_output(path: pathlib.Path) -> str:
    result = subprocess.run(
        [str(path), "--version"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
    )
    return result.stdout.strip()


def normalized_tar(output: pathlib.Path, root: pathlib.Path) -> None:
    temporary_output = output.with_name(f".{output.name}.tmp")
    temporary_output.unlink(missing_ok=True)
    with tarfile.open(temporary_output, "w:xz", format=tarfile.PAX_FORMAT) as archive:
        entries = [root, *sorted(root.rglob("*"), key=lambda item: item.as_posix())]
        for path in entries:
            arcname = pathlib.PurePosixPath(BUNDLE_DIRECTORY)
            if path != root:
                arcname /= path.relative_to(root).as_posix()
            info = archive.gettarinfo(str(path), arcname=str(arcname))
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = 0
            if info.isdir():
                info.mode = 0o755
                archive.addfile(info)
            else:
                info.mode = 0o755 if path.name in {"yume", "yume-chrome-tls-helper"} else 0o644
                with path.open("rb") as handle:
                    archive.addfile(info, handle)
    os.replace(temporary_output, output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the YUME 0.3.0 Linux x86-64 release bundle")
    parser.add_argument("--yume", required=True, type=pathlib.Path)
    parser.add_argument("--yumed", required=True, type=pathlib.Path)
    parser.add_argument("--helper", required=True, type=pathlib.Path)
    parser.add_argument("--helper-rebuild", required=True, type=pathlib.Path)
    parser.add_argument("--license", required=True, type=pathlib.Path)
    parser.add_argument("--notices", required=True, type=pathlib.Path)
    parser.add_argument("--quick-start", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        transport = active_profile_metadata()
    except (OSError, ProfileError) as error:
        raise SystemExit(f"Invalid active transport profile: {error}") from error
    helper_build_id = transport["helper_build_id"]
    transport_profile = transport["id"]
    require(bool(re.fullmatch(r"[0-9a-f]{40}", args.source_commit)),
            "Source commit must be an exact 40-hex Git object ID")
    require_glibc_dynamic(args.yume, "yume client")
    require_glibc_dynamic(args.yumed, "yumed server")
    require_elf_amd64(args.helper, "Chrome TLS helper")
    require_elf_amd64(args.helper_rebuild, "rebuilt Chrome TLS helper")
    for path, description in (
        (args.license, "license"),
        (args.notices, "third-party notices"),
        (args.quick_start, "quick-start document"),
    ):
        require_regular_file(path, description)

    helper_hash = sha256_file(args.helper)
    rebuilt_helper_hash = sha256_file(args.helper_rebuild)
    require(helper_hash == rebuilt_helper_hash,
            "Chrome TLS helper clean rebuild SHA-256 mismatch")

    yume_version = version_output(args.yume)
    yumed_version = version_output(args.yumed)
    helper_version = version_output(args.helper)
    require(args.version in yume_version, "yume --version does not match source version")
    require(args.version in yumed_version, "yumed --version does not match source version")
    require(helper_build_id in helper_version, "Chrome TLS helper build identity mismatch")
    require("protocol=1" in helper_version, "Chrome TLS helper IPC version mismatch")
    require(f"go={GO_VERSION}" in helper_version, "Chrome TLS helper Go version mismatch")
    server_hash = sha256_file(args.yumed)
    server_size = args.yumed.stat().st_size

    args.output_dir.mkdir(parents=True, exist_ok=True)
    require(args.output_dir.is_dir(), f"Output path is not a directory: {args.output_dir}")
    bundle_output = args.output_dir / BUNDLE_NAME
    server_output = args.output_dir / SERVER_NAME
    with tempfile.TemporaryDirectory(prefix="yume-linux-release-") as temporary:
        bundle_root = pathlib.Path(temporary) / BUNDLE_DIRECTORY
        bundle_root.mkdir(mode=0o755)
        copies = {
            "yume": (args.yume, 0o755),
            "yume-chrome-tls-helper": (args.helper, 0o755),
            "LICENSE": (args.license, 0o644),
            "THIRD_PARTY_NOTICES.md": (args.notices, 0o644),
            "QUICKSTART.md": (args.quick_start, 0o644),
        }
        for name, (source, mode) in copies.items():
            destination = bundle_root / name
            shutil.copyfile(source, destination)
            destination.chmod(mode)

        files = []
        for path in sorted(bundle_root.iterdir(), key=lambda item: item.name):
            files.append({
                "file": path.name,
                "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            })
        manifest = {
            "schema": 1,
            "project": "yume",
            "release_profile": PROFILE,
            "version": args.version,
            "source_commit": args.source_commit,
            "platform": "linux",
            "architecture": "x86_64",
            "libc": "glibc",
            "transport_profile": transport_profile,
            "chrome_tls_helper": {
                "required_at_runtime": False,
                "build_id": helper_build_id,
                "ipc_protocol": 1,
                "go_version": GO_VERSION,
                "sha256": helper_hash,
                "clean_rebuild_sha256": rebuilt_helper_hash,
            },
            "standalone_server": {
                "file": SERVER_NAME,
                "mode": "0755",
                "size": server_size,
                "sha256": server_hash,
                "version_output": yumed_version,
            },
            "required_features": {
                "argon2": True,
                "post_quantum": True,
                "native_chrome_client_hello": True,
                "patched_openssl_embedded": True,
                "openssl_minimum": "3.5.0",
            },
            "optional_features": {
                "chrome_tls_helper": True,
            },
            "unsupported_in_first_2_0_release": [
                "android", "gui", "windows", "macos", "arm", "openwrt",
                "static", "debian-archive",
            ],
            "files": files,
        }
        (bundle_root / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        normalized_tar(bundle_output, bundle_root)

    shutil.copyfile(args.yumed, server_output)
    server_output.chmod(0o755)
    require(sha256_file(server_output) == server_hash,
            "Copied yumed server differs from the validated input")
    print(f"Packaged {bundle_output} ({sha256_file(bundle_output)})")
    print(f"Packaged {server_output} ({sha256_file(server_output)})")


if __name__ == "__main__":
    main()
