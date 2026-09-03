#!/usr/bin/env python3
"""Create a permission-safe experimental YTP/1 kit and client bundle."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import BinaryIO


PRODUCT_VERSION = "0.3.0-dev1"
PROFILE = "chrome151-node24-v1"
SUITE = {
    "id": "ytp1-tls13-h2",
    "secure_channel": "tls13-native",
    "front_door": "h2-web",
    "carrier": "h2-duplex",
    "session": "ytp1-hybrid",
}
LIMITS = {
    "max_frame_bytes": 262_144,
    "max_streams": 256,
    "max_queued_bytes": 4_194_304,
    "max_pending_opens": 64,
    "max_rekey_jobs": 4,
    "max_control_messages": 128,
    "max_packet_bytes": 65_535,
    "max_packet_batch": 64,
}
SERVICES = (
    {"name": "tcp", "kind": "stream", "max_concurrent_streams": 256},
    {"name": "udp", "kind": "packet", "max_concurrent_streams": 256},
    {"name": "packet", "kind": "packet", "max_concurrent_streams": 256},
)
CLIENT_NAME = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?\Z"
)
STAGING_PREFIX = ".yume-setup-staging-"
IDENTITY_DOMAIN = b"yume/ytp/1/composite-identity/v1"


class SetupError(RuntimeError):
    """A fail-closed provisioning error safe to report to the operator."""


def _openssl_path() -> str:
    executable = shutil.which("openssl")
    if executable is None:
        raise SetupError("required command is unavailable: openssl")
    return executable


def _run_openssl(
    executable: str,
    arguments: list[str],
    *,
    input_bytes: bytes | bytearray | None = None,
    required_algorithm: str | None = None,
) -> bytes:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    try:
        result = subprocess.run(
            [executable, *arguments],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SetupError("OpenSSL invocation failed") from exc
    if result.returncode != 0:
        if required_algorithm is not None:
            raise SetupError(
                "required OpenSSL algorithm is unavailable or failed: "
                f"{required_algorithm}"
            )
        detail = result.stderr.decode("utf-8", "replace").strip()
        if detail:
            raise SetupError(f"OpenSSL operation failed: {detail[:2048]}")
        raise SetupError("OpenSSL operation failed")
    return result.stdout


def _mkdir_private(path: Path) -> None:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def _open_exclusive(path: Path, mode: int) -> BinaryIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    os.fchmod(descriptor, mode)
    return os.fdopen(descriptor, "wb", buffering=0)


def _write_bytes(path: Path, payload: bytes | bytearray, mode: int = 0o600) -> None:
    with _open_exclusive(path, mode) as output:
        view = memoryview(payload)
        while view:
            written = output.write(view)
            if written is None or written <= 0:
                raise SetupError(f"short write while creating {path.name}")
            view = view[written:]
        output.flush()
        os.fsync(output.fileno())


def _write_text(path: Path, text: str, mode: int = 0o600) -> None:
    _write_bytes(path, text.encode("utf-8"), mode)


def _write_json(path: Path, value: object) -> None:
    _write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _copy_stream(source: Path, destination: Path, mode: int = 0o600) -> None:
    buffer = bytearray(64 * 1024)
    try:
        with source.open("rb", buffering=0) as input_file:
            with _open_exclusive(destination, mode) as output_file:
                while True:
                    count = input_file.readinto(buffer)
                    if count == 0:
                        break
                    view = memoryview(buffer)[:count]
                    while view:
                        written = output_file.write(view)
                        if written is None or written <= 0:
                            raise SetupError(
                                f"short write while creating {destination.name}"
                            )
                        view = view[written:]
                    buffer[:count] = b"\0" * count
                output_file.flush()
                os.fsync(output_file.fileno())
    finally:
        buffer[:] = b"\0" * len(buffer)


def _concatenate(sources: tuple[Path, ...], destination: Path) -> None:
    buffer = bytearray(64 * 1024)
    try:
        with _open_exclusive(destination, 0o600) as output_file:
            for source in sources:
                with source.open("rb", buffering=0) as input_file:
                    while True:
                        count = input_file.readinto(buffer)
                        if count == 0:
                            break
                        view = memoryview(buffer)[:count]
                        while view:
                            written = output_file.write(view)
                            if written is None or written <= 0:
                                raise SetupError(
                                    f"short write while creating {destination.name}"
                                )
                            view = view[written:]
                        buffer[:count] = b"\0" * count
            output_file.flush()
            os.fsync(output_file.fileno())
    finally:
        buffer[:] = b"\0" * len(buffer)


def _require_client_name(value: str) -> str:
    if CLIENT_NAME.fullmatch(value) is None:
        raise SetupError(
            "client name must contain 1..63 letters, digits, '.', '_', or '-', "
            "and must begin with a letter or digit"
        )
    return value


def _require_host(value: str) -> str:
    if value != value.strip() or not value or len(value) > 253:
        raise SetupError("host must be a bounded IP literal or DNS name")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if value.endswith(".") or all(ch in "0123456789." for ch in value):
        raise SetupError("host must be a valid IP literal or DNS name")
    labels = value.split(".")
    if any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        is None
        for label in labels
    ):
        raise SetupError("host must be a valid IP literal or DNS name")
    return value.lower()


def _require_output_path(raw_path: Path) -> Path:
    path_text = os.fspath(raw_path)
    if "\0" in path_text or any(part == "~" for part in raw_path.parts):
        raise SetupError("output path is invalid")
    absolute = raw_path if raw_path.is_absolute() else Path.cwd() / raw_path
    if os.path.lexists(absolute):
        raise SetupError(f"refusing to overwrite existing path: {absolute}")
    try:
        output = absolute.resolve(strict=False)
    except OSError as exc:
        raise SetupError("output path cannot be resolved") from exc
    if output == Path(output.anchor) or not output.name:
        raise SetupError("output must name a new directory below an existing parent")
    try:
        parent = output.parent.resolve(strict=True)
        parent_status = parent.lstat()
    except OSError as exc:
        raise SetupError("output parent must already exist and be accessible") from exc
    if not stat.S_ISDIR(parent_status.st_mode) or stat.S_ISLNK(parent_status.st_mode):
        raise SetupError("output parent must be a real directory")
    output = parent / output.name
    if os.path.lexists(output):
        raise SetupError(f"refusing to overwrite existing path: {output}")
    return output


def _generate_private_key(
    openssl: str, algorithm: str, destination: Path
) -> None:
    _run_openssl(
        openssl,
        ["genpkey", "-algorithm", algorithm, "-out", str(destination)],
        required_algorithm=algorithm,
    )
    os.chmod(destination, 0o600)
    status = destination.lstat()
    if not stat.S_ISREG(status.st_mode) or status.st_size == 0:
        raise SetupError(f"OpenSSL did not create a valid {algorithm} key")


def _derive_public(openssl: str, private_key: Path, public_key: Path) -> None:
    _run_openssl(
        openssl,
        [
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ],
    )
    os.chmod(public_key, 0o600)


def _public_der(openssl: str, public_key: Path) -> bytes:
    return _run_openssl(
        openssl,
        ["pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
    )


def _composite_fingerprint(openssl: str, public_keys: tuple[Path, Path]) -> str:
    digest = hashlib.sha256()
    digest.update(IDENTITY_DOMAIN)
    for key in public_keys:
        encoded = _public_der(openssl, key)
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _generate_composite_identity(
    openssl: str,
    work_directory: Path,
    private_output: Path,
    public_output: Path,
) -> str:
    _mkdir_private(work_directory)
    ed_private = work_directory / "ed25519.key.pem"
    ed_public = work_directory / "ed25519.pub.pem"
    pq_private = work_directory / "ml-dsa-87.key.pem"
    pq_public = work_directory / "ml-dsa-87.pub.pem"
    _generate_private_key(openssl, "Ed25519", ed_private)
    _derive_public(openssl, ed_private, ed_public)
    _generate_private_key(openssl, "ML-DSA-87", pq_private)
    _derive_public(openssl, pq_private, pq_public)
    _concatenate((ed_private, pq_private), private_output)
    _concatenate((ed_public, pq_public), public_output)
    return _composite_fingerprint(openssl, (ed_public, pq_public))


def _generate_random_file(openssl: str, destination: Path, size: int) -> None:
    _run_openssl(openssl, ["rand", "-out", str(destination), str(size)])
    os.chmod(destination, 0o600)
    if destination.lstat().st_size != size:
        raise SetupError(f"OpenSSL produced an invalid {destination.name}")


def _generate_tls_material(
    openssl: str,
    work_directory: Path,
    host: str,
    key_output: Path,
    certificate_output: Path,
    trust_output: Path,
) -> None:
    _mkdir_private(work_directory)
    ca_key = work_directory / "ca.key.pem"
    ca_certificate = work_directory / "ca.pem"
    request = work_directory / "server.csr.pem"
    extensions = work_directory / "server.ext"

    _generate_private_key(openssl, "Ed25519", ca_key)
    _run_openssl(
        openssl,
        [
            "req",
            "-x509",
            "-new",
            "-key",
            str(ca_key),
            "-out",
            str(ca_certificate),
            "-days",
            "3650",
            "-subj",
            "/CN=YUME 0.3 Local Setup CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-addext",
            "subjectKeyIdentifier=hash",
        ],
    )
    os.chmod(ca_certificate, 0o600)

    _generate_private_key(openssl, "Ed25519", key_output)
    _run_openssl(
        openssl,
        [
            "req",
            "-new",
            "-key",
            str(key_output),
            "-out",
            str(request),
            "-subj",
            f"/CN={host}",
        ],
    )
    san_kind = "IP" if _is_ip(host) else "DNS"
    _write_text(
        extensions,
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName={san_kind}:{host}\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n",
    )
    _run_openssl(
        openssl,
        [
            "x509",
            "-req",
            "-in",
            str(request),
            "-CA",
            str(ca_certificate),
            "-CAkey",
            str(ca_key),
            "-set_serial",
            "0x" + secrets.token_hex(16),
            "-days",
            "825",
            "-extfile",
            str(extensions),
            "-out",
            str(certificate_output),
        ],
    )
    os.chmod(certificate_output, 0o600)
    _run_openssl(
        openssl,
        ["verify", "-CAfile", str(ca_certificate), str(certificate_output)],
    )
    _copy_stream(ca_certificate, trust_output)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _server_config(port: int) -> dict[str, object]:
    return {
        "schema": 1,
        "role": "server",
        "endpoint": {"listen_addresses": ["0.0.0.0", "::"], "port": port},
        "suite": dict(SUITE),
        "credentials": {
            "composite_key": {"file": "credentials/server-composite.pem"},
            "authorized_keys": {
                "file": "credentials/authorized-keys.json"
            },
            "admin_keys": {"file": "credentials/admin-keys.json"},
            "tls_certificate": {"file": "credentials/server-tls.pem"},
            "tls_key": {"file": "credentials/server-tls.key.pem"},
            "admission_key": {"file": "credentials/admission.key"},
            "mlkem_key": {"file": "credentials/server-mlkem.key.pem"},
        },
        "cover": {"profile": PROFILE, "root": {"file": "cover-site"}},
        "services": [dict(service) for service in SERVICES],
        "adapters": [
            {"kind": "direct_tcp", "service": "tcp"},
            {"kind": "direct_udp", "service": "udp"},
            {
                "kind": "packet",
                "service": "packet",
                "interface_name": "yume0",
                "mtu": 1420,
            },
        ],
        "limits": dict(LIMITS),
    }


def _client_config(host: str, port: int) -> dict[str, object]:
    return {
        "schema": 1,
        "role": "client",
        "endpoint": {"host": host, "port": port},
        "suite": dict(SUITE),
        "credentials": {
            "composite_key": {"file": "credentials/client-composite.pem"},
            "access_psk": {"file": "credentials/client-access.psk"},
            "admission_key": {"file": "credentials/admission.key"},
            "server_trust": {"file": "credentials/server-trust.pem"},
            "server_identity": {
                "file": "credentials/server-composite.pub.pem"
            },
            "server_mlkem": {"file": "credentials/server-mlkem.pub.pem"},
        },
        "cover": {"profile": PROFILE},
        "services": [dict(service) for service in SERVICES],
        "adapters": [
            {
                "kind": "socks5",
                "service": "tcp",
                "listen_address": "127.0.0.1",
                "listen_port": 1080,
            },
            {
                "kind": "packet",
                "service": "packet",
                "interface_name": "yume0",
                "mtu": 1420,
            },
        ],
        "limits": dict(LIMITS),
    }


def _write_cover_site(root: Path) -> None:
    _mkdir_private(root)
    _write_text(
        root / "index.html",
        """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Northwind Field Notes</title>
  <style>
    body { margin: 0; font: 17px/1.6 system-ui, sans-serif; color: #24323d; background: #f4f1e8; }
    main { max-width: 48rem; margin: 10vh auto; padding: 2rem; }
    h1 { font-size: clamp(2rem, 7vw, 4.5rem); line-height: 1; margin-bottom: 1rem; }
    article { background: #fff; border-radius: 1rem; padding: 2rem; box-shadow: 0 1rem 3rem #26323d18; }
    a { color: #176b68; }
  </style>
</head>
<body>
  <main>
    <article>
      <p>Field note 01</p>
      <h1>Northwind</h1>
      <p>A small notebook about trails, changing weather, and the quiet work of keeping a good map.</p>
      <p><a href="/about.html">About this notebook</a></p>
    </article>
  </main>
</body>
</html>
""",
    )
    _write_text(
        root / "about.html",
        """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>About Northwind</title></head>
<body><main><h1>About Northwind</h1><p>Independent field notes, maintained slowly and published when useful.</p><p><a href="/">Return home</a></p></main></body></html>
""",
    )


def _write_service_manifests(server: Path, client: Path) -> None:
    server_services = server / "services"
    client_adapters = client / "adapters"
    _mkdir_private(server_services)
    _mkdir_private(client_adapters)
    adapters = {
        "tcp": {"kind": "direct_tcp", "service": "tcp"},
        "udp": {"kind": "direct_udp", "service": "udp"},
        "packet": {
            "kind": "packet",
            "service": "packet",
            "interface_name": "yume0",
            "mtu": 1420,
        },
    }
    for service in SERVICES:
        name = service["name"]
        _write_json(
            server_services / f"{name}.json",
            {"schema": 1, "service": dict(service), "adapter": adapters[name]},
        )
    _write_json(
        client_adapters / "socks5.json",
        {
            "schema": 1,
            "adapter": {
                "kind": "socks5",
                "service": "tcp",
                "listen_address": "127.0.0.1",
                "listen_port": 1080,
            },
        },
    )
    _write_json(
        client_adapters / "packet.json",
        {
            "schema": 1,
            "adapter": {
                "kind": "packet",
                "service": "packet",
                "interface_name": "yume0",
                "mtu": 1420,
            },
        },
    )


def _write_launchers(server: Path, client: Path) -> None:
    _write_text(
        server / "start-server",
        """#!/bin/sh
set -eu
cd "$(dirname "$0")"
exec "${YUMED_BIN:-yumed}" --config yumed.json
""",
        0o700,
    )
    _write_text(
        client / "start-client",
        """#!/bin/sh
set -eu
cd "$(dirname "$0")"
exec "${YUME_BIN:-yume}" --config yume.json
""",
        0o700,
    )


def _write_admin_keys(credentials: Path) -> None:
    """Emit the separate second-factor store.

    It starts empty on purpose. Admin is proved by a distinct identity from
    this store in addition to an authorized traffic identity, so a fresh kit
    must have no administrator until an operator deliberately adds one. The
    file exists from the start so the two key classes are never one list.
    """
    _write_json(
        credentials / "admin-keys.json",
        {"schema": 1, "keys": []},
    )


def _write_authorized_keys(
    credentials: Path,
    client_name: str,
    fingerprint: str,
) -> None:
    _write_json(
        credentials / "authorized-keys.json",
        {
            "schema": 1,
            "keys": [
                {
                    "name": client_name,
                    "identity": {
                        "file": f"authorized/{client_name}-composite.pub.pem",
                        "sha256": fingerprint,
                    },
                    "access_psk": {
                        "file": f"authorized/{client_name}-access.psk"
                    },
                    "capabilities": [
                        {"service": service["name"], "kind": service["kind"]}
                        for service in SERVICES
                    ],
                }
            ],
        },
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_tree(root: Path) -> None:
    for current, directory_names, file_names in os.walk(
        root, topdown=False, followlinks=False
    ):
        current_path = Path(current)
        for name in file_names:
            path = current_path / name
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            try:
                status = os.fstat(descriptor)
                if not stat.S_ISREG(status.st_mode):
                    raise SetupError("generated kit contains a non-regular file")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for name in directory_names:
            directory = current_path / name
            status = directory.lstat()
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                raise SetupError("generated kit contains an invalid directory")
            _fsync_directory(directory)
        _fsync_directory(current_path)


def _rename_noreplace(source: Path, destination: Path) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (OSError, AttributeError) as exc:
        raise SetupError(
            "atomic no-overwrite directory publication is unavailable on this system"
        ) from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in (errno.EEXIST, errno.ENOTEMPTY):
        raise SetupError(f"refusing to overwrite existing path: {destination}")
    if error_number in (errno.ENOSYS, errno.EINVAL):
        raise SetupError(
            "atomic no-overwrite directory publication is unavailable on this filesystem"
        )
    raise SetupError(
        f"unable to publish generated kit: {os.strerror(error_number)}"
    )


def _remove_staging(path: Path, parent: Path) -> None:
    try:
        if (
            path.parent == parent
            and path.name.startswith(STAGING_PREFIX)
            and not path.is_symlink()
            and path.is_dir()
        ):
            shutil.rmtree(path)
    except OSError:
        pass


def init_kit(host: str, output_path: Path, port: int, client_name: str) -> Path:
    host = _require_host(host)
    client_name = _require_client_name(client_name)
    if not 1 <= port <= 65535:
        raise SetupError("port must be in 1..65535")
    output = _require_output_path(output_path)
    parent = output.parent
    staging = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=parent))
    os.chmod(staging, 0o700)
    published = False
    try:
        server = staging / "server"
        client = staging / "client"
        server_credentials = server / "credentials"
        client_credentials = client / "credentials"
        authorized = server_credentials / "authorized"
        work = staging / ".work"
        for directory in (
            server,
            client,
            server_credentials,
            client_credentials,
            authorized,
            work,
        ):
            _mkdir_private(directory)

        openssl = _openssl_path()
        server_public = server_credentials / "server-composite.pub.pem"
        _generate_composite_identity(
            openssl,
            work / "server-identity",
            server_credentials / "server-composite.pem",
            server_public,
        )
        client_public = client_credentials / "client-composite.pub.pem"
        client_fingerprint = _generate_composite_identity(
            openssl,
            work / "client-identity",
            client_credentials / "client-composite.pem",
            client_public,
        )

        server_mlkem_private = server_credentials / "server-mlkem.key.pem"
        server_mlkem_public = server_credentials / "server-mlkem.pub.pem"
        _generate_private_key(openssl, "ML-KEM-1024", server_mlkem_private)
        _derive_public(openssl, server_mlkem_private, server_mlkem_public)

        server_trust = server_credentials / "server-trust.pem"
        _generate_tls_material(
            openssl,
            work / "tls",
            host,
            server_credentials / "server-tls.key.pem",
            server_credentials / "server-tls.pem",
            server_trust,
        )
        server_admission = server_credentials / "admission.key"
        _generate_random_file(openssl, server_admission, 32)

        server_psk = authorized / f"{client_name}-access.psk"
        _generate_random_file(openssl, server_psk, 32)
        _copy_stream(
            client_public,
            authorized / f"{client_name}-composite.pub.pem",
        )
        _copy_stream(server_psk, client_credentials / "client-access.psk")
        _copy_stream(server_admission, client_credentials / "admission.key")
        _copy_stream(server_trust, client_credentials / "server-trust.pem")
        _copy_stream(
            server_public, client_credentials / "server-composite.pub.pem"
        )
        _copy_stream(server_mlkem_public, client_credentials / "server-mlkem.pub.pem")
        _write_authorized_keys(
            server_credentials, client_name, client_fingerprint
        )
        _write_admin_keys(server_credentials)

        _write_json(server / "yumed.json", _server_config(port))
        _write_json(client / "yume.json", _client_config(host, port))
        _write_cover_site(server / "cover-site")
        _write_service_manifests(server, client)
        _write_launchers(server, client)
        _write_json(
            staging / "manifest.json",
            {
                "format": 1,
                "product": PRODUCT_VERSION,
                "ytp": 1,
                "config": 1,
                "abi": 1,
                "providers": dict(SUITE),
                "profile": PROFILE,
                "suite": SUITE["id"],
                "runtime_status": "unwired-development-foundation",
                "server": {
                    "host": host,
                    "port": port,
                    "config": "server/yumed.json",
                },
                "client": {
                    "name": client_name,
                    "config": "client/yume.json",
                },
            },
        )

        shutil.rmtree(work)
        _fsync_tree(staging)
        _rename_noreplace(staging, output)
        published = True
        _fsync_directory(parent)
        return output
    finally:
        if not published:
            _remove_staging(staging, parent)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yume-setup-ytp1",
        description=(
            "Create an experimental YTP/1 server kit and first client bundle; "
            "the live endpoint provider is not yet qualified."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="create a new server and client kit")
    init.add_argument("--host", required=True, help="public DNS name or IP address")
    init.add_argument("--output", required=True, type=Path, help="new kit directory")
    init.add_argument("--port", type=int, default=443)
    init.add_argument("--client-name", default="client1")
    return parser


def main() -> int:
    os.umask(0o077)
    arguments = build_parser().parse_args()
    try:
        output = init_kit(
            arguments.host,
            arguments.output,
            arguments.port,
            arguments.client_name,
        )
    except (SetupError, OSError, ValueError) as exc:
        print(f"yume-setup-ytp1: {exc}", file=sys.stderr)
        return 1
    print(f"Created YUME server kit and client bundle: {output}")
    print(f"Server config: {output / 'server' / 'yumed.json'}")
    print(f"Client config: {output / 'client' / 'yume.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
