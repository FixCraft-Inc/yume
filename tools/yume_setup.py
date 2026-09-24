#!/usr/bin/env python3
"""Create a permission-safe experimental YTP/1 kit and client bundle."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import ipaddress
import json
import math
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
# The default kit exposes SOCKS TCP/UDP. Managed TUN is configured explicitly
# because its addresses, routes, DNS and directional policy belong to the
# operator; provisioning must not invent host-networking settings.
SERVICES = (
    {"name": "tcp", "kind": "stream", "max_concurrent_streams": 256},
    {"name": "udp", "kind": "packet", "max_concurrent_streams": 256},
)
CLIENT_NAME = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,61}[A-Za-z0-9])?\Z"
)
STAGING_PREFIX = ".yume-setup-staging-"
# Matches the daemon's bound for an authorized-keys entry's max_sessions and
# its traffic store size.
MAX_SESSIONS_PER_IDENTITY = 1024
MAX_AUTHORIZED_IDENTITIES = 1024
# Match the daemon's bounds for an entry's weight and limits.max_egress_mbps.
MIN_WEIGHT = 0.1
MAX_WEIGHT = 100.0
MAX_EGRESS_MBPS = 1_000_000
MAX_JSON_BYTES = 4 * 1024 * 1024
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
    openssl: str, algorithm: str, destination: Path, *, curve: str | None = None
) -> None:
    arguments = ["genpkey", "-algorithm", algorithm]
    if curve is not None:
        arguments += ["-pkeyopt", f"ec_paramgen_curve:{curve}"]
    arguments += ["-out", str(destination)]
    _run_openssl(
        openssl,
        arguments,
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

    # Outer TLS follows the browser profile; composite YTP identity keys have
    # a separate algorithm contract. The profile does not offer Ed25519 TLS.
    _generate_private_key(openssl, "EC", ca_key, curve="prime256v1")
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
            "-sha256",
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

    _generate_private_key(openssl, "EC", key_output, curve="prime256v1")
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
            "-sha256",
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


def _server_config(port: int, max_egress_mbps: int | None = None) -> dict[str, object]:
    limits: dict[str, object] = dict(LIMITS)
    if max_egress_mbps is not None:
        limits["max_egress_mbps"] = max_egress_mbps
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
            {
                "kind": "direct_tcp",
                "service": "tcp",
                "destinations": _public_destinations(),
            },
            {
                "kind": "direct_udp",
                "service": "udp",
                "destinations": _public_destinations(),
            },
        ],
        "limits": limits,
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
                "udp_service": "udp",
            },
        ],
        "limits": dict(LIMITS),
    }


def _write_cover_site(root: Path) -> None:
    _mkdir_private(root)
    _mkdir_private(root / "assets")
    _write_text(
        root / "assets/site.css",
        """body { margin: 0; font: 17px/1.6 system-ui, sans-serif; color: #24323d; background: #f4f1e8; }
main { max-width: 48rem; margin: 10vh auto; padding: 2rem; }
h1 { font-size: clamp(2rem, 7vw, 4.5rem); line-height: 1; margin-bottom: 1rem; }
article { background: #fff; border-radius: 1rem; padding: 2rem; box-shadow: 0 1rem 3rem #26323d18; }
a { color: #176b68; }
button { font: inherit; color: #176b68; background: transparent; border: 1px solid currentColor; padding: .3rem .75rem; cursor: pointer; }
@media print { body, article { background: #fff; } main { margin: 0; } article { box-shadow: none; } button { display: none; } }
""",
    )
    _write_text(
        root / "assets/site.js",
        """'use strict';
// Printing is an optional enhancement; field notes remain readable without scripts.
for (const button of document.querySelectorAll('[data-print-note]')) {
    button.hidden = false;
    button.addEventListener('click', () => window.print());
}
""",
    )
    _write_text(
        root / "index.html",
        """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Northwind Field Notes</title>
  <link rel="stylesheet" href="/assets/site.css">
  <script src="/assets/site.js" defer></script>
</head>
<body>
  <main>
    <article>
      <p>Field note 01</p>
      <h1>Northwind</h1>
      <p>A small notebook about trails, changing weather, and the quiet work of keeping a good map.</p>
      <p><a href="/about.html">About this notebook</a></p>
      <button type="button" data-print-note hidden>Print this note</button>
    </article>
  </main>
</body>
</html>
""",
    )
    _write_text(
        root / "about.html",
        """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>About Northwind</title><link rel="stylesheet" href="/assets/site.css"></head>
<body><main><h1>About Northwind</h1><p>Independent field notes, maintained slowly and published when useful.</p><p><a href="/">Return home</a></p></main></body></html>
""",
    )
    _write_text(
        root / "404.html",
        """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Page not found — Northwind Field Notes</title>
  <link rel="stylesheet" href="/assets/site.css">
</head>
<body>
  <main>
    <h1>Page not found</h1>
    <p>This address does not lead to a field note. The page may have moved or the link may be incomplete.</p>
    <p><a href="/">Return to Northwind</a></p>
  </main>
</body>
</html>
""",
    )


def _public_destinations() -> dict[str, object]:
    # Globally reachable unicast only. Private, loopback and other
    # special-purpose networks need an explicit operator entry.
    return {"public": True, "networks": []}


def _write_service_manifests(server: Path) -> None:
    server_services = server / "services"
    _mkdir_private(server_services)
    adapters = {
        "tcp": {
            "kind": "direct_tcp",
            "service": "tcp",
            "destinations": _public_destinations(),
        },
        "udp": {
            "kind": "direct_udp",
            "service": "udp",
            "destinations": _public_destinations(),
        },
    }
    for service in SERVICES:
        name = service["name"]
        _write_json(
            server_services / f"{name}.json",
            {"schema": 1, "service": dict(service), "adapter": adapters[name]},
        )


def _write_server_launcher(server: Path) -> None:
    _write_text(
        server / "start-server",
        """#!/bin/sh
set -eu
cd "$(dirname "$0")"
exec "${YUMED_BIN:-yumed}" --config yumed.json
""",
        0o700,
    )


# Server public material every client bundle carries, as named in a server
# credentials directory written by init.
CLIENT_SERVER_MATERIAL = (
    ("admission.key", "admission.key"),
    ("server-trust.pem", "server-trust.pem"),
    ("server-composite.pub.pem", "server-composite.pub.pem"),
    ("server-mlkem.pub.pem", "server-mlkem.pub.pem"),
)


def _write_client_bundle(
    openssl: str,
    client: Path,
    work: Path,
    server_credentials: Path,
    host: str,
    port: int,
) -> tuple[str, Path, Path]:
    """Write a complete client directory for one new identity.

    Returns the identity fingerprint and the client's public key and access
    PSK, which the server's authorized store must list.
    """
    client_credentials = client / "credentials"
    _mkdir_private(client_credentials)
    client_public = client_credentials / "client-composite.pub.pem"
    fingerprint = _generate_composite_identity(
        openssl,
        work,
        client_credentials / "client-composite.pem",
        client_public,
    )
    client_psk = client_credentials / "client-access.psk"
    _generate_random_file(openssl, client_psk, 32)
    for source, destination in CLIENT_SERVER_MATERIAL:
        _copy_stream(server_credentials / source, client_credentials / destination)
    _write_json(client / "yume.json", _client_config(host, port))
    client_adapters = client / "adapters"
    _mkdir_private(client_adapters)
    _write_json(
        client_adapters / "socks5.json",
        {
            "schema": 1,
            "adapter": {
                "kind": "socks5",
                "service": "tcp",
                "listen_address": "127.0.0.1",
                "listen_port": 1080,
                "udp_service": "udp",
            },
        },
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
    return fingerprint, client_public, client_psk


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


def _authorized_entry(
    client_name: str, fingerprint: str, max_sessions: int | None, weight: float | None
) -> dict[str, object]:
    entry: dict[str, object] = {
        "name": client_name,
        "identity": {
            "file": f"authorized/{client_name}-composite.pub.pem",
            "sha256": fingerprint,
        },
        "access_psk": {"file": f"authorized/{client_name}-access.psk"},
        "capabilities": [
            {"service": service["name"], "kind": service["kind"]}
            for service in SERVICES
        ],
    }
    if max_sessions is not None:
        entry["max_sessions"] = max_sessions
    if weight is not None:
        entry["weight"] = weight
    return entry


def _write_authorized_keys(
    credentials: Path,
    client_name: str,
    fingerprint: str,
    max_sessions: int | None,
    weight: float | None,
) -> None:
    _write_json(
        credentials / "authorized-keys.json",
        {
            "schema": 1,
            "keys": [_authorized_entry(client_name, fingerprint, max_sessions, weight)],
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


def _require_max_sessions(value: int | None) -> int | None:
    if value is not None and not 1 <= value <= MAX_SESSIONS_PER_IDENTITY:
        raise SetupError(f"max sessions must be in 1..{MAX_SESSIONS_PER_IDENTITY}")
    return value


def _require_weight(value: float | None) -> float | None:
    if value is not None and not (math.isfinite(value) and MIN_WEIGHT <= value <= MAX_WEIGHT):
        raise SetupError(f"weight must be in {MIN_WEIGHT:g}..{MAX_WEIGHT:g}")
    return value


def _require_max_egress_mbps(value: int | None) -> int | None:
    if value is not None and not 1 <= value <= MAX_EGRESS_MBPS:
        raise SetupError(f"max egress Mbps must be in 1..{MAX_EGRESS_MBPS}")
    return value


def init_kit(
    host: str,
    output_path: Path,
    port: int,
    client_name: str,
    max_sessions: int | None = None,
    weight: float | None = None,
    max_egress_mbps: int | None = None,
) -> Path:
    host = _require_host(host)
    client_name = _require_client_name(client_name)
    max_sessions = _require_max_sessions(max_sessions)
    weight = _require_weight(weight)
    max_egress_mbps = _require_max_egress_mbps(max_egress_mbps)
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
        authorized = server_credentials / "authorized"
        work = staging / ".work"
        for directory in (
            server,
            client,
            server_credentials,
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

        client_fingerprint, client_public, client_psk = _write_client_bundle(
            openssl, client, work / "client-identity", server_credentials, host, port
        )
        _copy_stream(client_psk, authorized / f"{client_name}-access.psk")
        _copy_stream(
            client_public,
            authorized / f"{client_name}-composite.pub.pem",
        )
        _write_authorized_keys(
            server_credentials, client_name, client_fingerprint, max_sessions, weight
        )
        _write_admin_keys(server_credentials)

        _write_json(server / "yumed.json", _server_config(port, max_egress_mbps))
        _write_cover_site(server / "cover-site")
        _write_service_manifests(server)
        _write_server_launcher(server)
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
                "runtime_status": "development-runtimes",
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


def _read_json(path: Path) -> object:
    """Read one bounded, regular, non-symlink JSON file."""
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SetupError(f"cannot open {path}") from exc
    with os.fdopen(descriptor, "rb") as source:
        status = os.fstat(source.fileno())
        if not stat.S_ISREG(status.st_mode) or status.st_size > MAX_JSON_BYTES:
            raise SetupError(f"{path} is not a bounded regular file")
        payload = source.read(MAX_JSON_BYTES + 1)
    if len(payload) > MAX_JSON_BYTES:
        raise SetupError(f"{path} is not a bounded regular file")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise SetupError(f"{path} contains a duplicate key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SetupError(f"{path} is not valid JSON") from exc


def _server_reference(server: Path, config: dict[str, object], name: str) -> Path:
    credentials = config.get("credentials")
    reference = credentials.get(name) if isinstance(credentials, dict) else None
    relative = reference.get("file") if isinstance(reference, dict) else None
    if not isinstance(relative, str) or not relative:
        raise SetupError(f"server configuration lacks credentials.{name}")
    path = Path(relative)
    return path if path.is_absolute() else server / path


def _write_replacement(path: Path, value: object) -> Path:
    """Write value beside path for a later atomic replace, and return it."""
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.new")
    _write_json(temporary, value)
    return temporary


def add_client(
    server_path: Path,
    host: str,
    output_path: Path,
    client_name: str,
    max_sessions: int | None = None,
    weight: float | None = None,
) -> Path:
    """Issue one client bundle for an existing server tree.

    The new identity is appended to the server's authorized-keys store with
    the kit's standard services. Nothing changes unless every step succeeds:
    the bundle, the server's new key and PSK files and the store replacement
    are removed again on failure. A running daemon accepts the client after
    it reloads its credentials (SIGHUP).
    """
    host = _require_host(host)
    client_name = _require_client_name(client_name)
    max_sessions = _require_max_sessions(max_sessions)
    weight = _require_weight(weight)
    try:
        server = server_path.resolve(strict=True)
    except OSError as exc:
        raise SetupError("server directory does not exist") from exc
    config = _read_json(server / "yumed.json")
    if not isinstance(config, dict) or config.get("schema") != 1 or config.get("role") != "server":
        raise SetupError("server directory must hold a schema-1 server yumed.json")
    endpoint = config.get("endpoint")
    port = endpoint.get("port") if isinstance(endpoint, dict) else None
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise SetupError("server configuration has no valid endpoint.port")
    declared = {
        (service.get("name"), service.get("kind"))
        for service in config.get("services", [])
        if isinstance(service, dict)
    }
    if any((service["name"], service["kind"]) not in declared for service in SERVICES):
        raise SetupError("server configuration does not declare the standard tcp and udp services")

    store_path = _server_reference(server, config, "authorized_keys")
    admission_path = _server_reference(server, config, "admission_key")
    store = _read_json(store_path)
    keys = store.get("keys") if isinstance(store, dict) else None
    if not isinstance(store, dict) or store.get("schema") != 1 or not isinstance(keys, list):
        raise SetupError("authorized-keys store is not a schema-1 key list")
    if len(keys) >= MAX_AUTHORIZED_IDENTITIES:
        raise SetupError("authorized-keys store is full")
    if any(isinstance(entry, dict) and entry.get("name") == client_name for entry in keys):
        raise SetupError(f"client name is already authorized: {client_name}")
    server_credentials = admission_path.parent
    for source, _ in CLIENT_SERVER_MATERIAL:
        if not (server_credentials / source).is_file():
            raise SetupError(
                f"server credentials lack {source}; add-client needs the layout init writes"
            )

    store_directory = store_path.parent
    authorized = store_directory / "authorized"
    authorized_public = authorized / f"{client_name}-composite.pub.pem"
    authorized_psk = authorized / f"{client_name}-access.psk"
    output = _require_output_path(output_path)
    parent = output.parent
    staging = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=parent))
    os.chmod(staging, 0o700)
    created: list[Path] = []
    replacement: Path | None = None
    published = False
    committed = False
    try:
        work = staging / ".work"
        client = staging / "client"
        _mkdir_private(work)
        _mkdir_private(client)
        openssl = _openssl_path()
        fingerprint, client_public, client_psk = _write_client_bundle(
            openssl, client, work / "client-identity", server_credentials, host, port
        )
        if any(
            isinstance(entry, dict)
            and isinstance(entry.get("identity"), dict)
            and entry["identity"].get("sha256") == fingerprint
            for entry in keys
        ):
            raise SetupError("generated identity is already authorized")
        if client_psk.read_bytes() == admission_path.read_bytes():
            raise SetupError("generated access PSK equals the admission key")
        shutil.rmtree(work)

        # Files added to the server tree keep the store's owner, so a root
        # operator does not lock the daemon's account out of its own store.
        owner = store_path.stat()
        new_directory = not authorized.is_dir()
        if new_directory:
            _mkdir_private(authorized)
        for source, destination in ((client_public, authorized_public),
                                    (client_psk, authorized_psk)):
            _copy_stream(source, destination)
            created.append(destination)
        updated = dict(store)
        updated["keys"] = [
            *keys, _authorized_entry(client_name, fingerprint, max_sessions, weight)
        ]
        replacement = _write_replacement(store_path, updated)
        if os.geteuid() == 0:
            for path in (*created, replacement, *((authorized,) if new_directory else ())):
                os.chown(path, owner.st_uid, owner.st_gid, follow_symlinks=False)
        _fsync_directory(authorized)

        _fsync_tree(client)
        _rename_noreplace(client, output)
        published = True
        _fsync_directory(parent)
        os.replace(replacement, store_path)
        replacement = None
        committed = True
        _fsync_directory(store_directory)
        return output
    finally:
        if replacement is not None:
            replacement.unlink(missing_ok=True)
        if not committed:
            for path in created:
                path.unlink(missing_ok=True)
            if published:
                shutil.rmtree(output, ignore_errors=True)
        _remove_staging(staging, parent)


def _read_server_store(server_path: Path) -> tuple[Path, dict[str, object], list[object]]:
    try:
        server = server_path.resolve(strict=True)
    except OSError as exc:
        raise SetupError("server directory does not exist") from exc
    config = _read_json(server / "yumed.json")
    if not isinstance(config, dict) or config.get("schema") != 1 or config.get("role") != "server":
        raise SetupError("server directory must hold a schema-1 server yumed.json")
    store_path = _server_reference(server, config, "authorized_keys")
    store = _read_json(store_path)
    keys = store.get("keys") if isinstance(store, dict) else None
    if not isinstance(store, dict) or store.get("schema") != 1 or not isinstance(keys, list):
        raise SetupError("authorized-keys store is not a schema-1 key list")
    return store_path, store, keys


def remove_client(server_path: Path, client_name: str) -> Path:
    """Remove one client from a server's authorized-keys store.

    The store is replaced atomically first, keeping its owner, so the daemon
    never references a missing file. The client's public key and access PSK
    are deleted afterwards when they lie below the store's directory. A
    running daemon ends the client's sessions when it reloads (SIGHUP). The
    last client cannot be removed, because the daemon requires one.
    """
    client_name = _require_client_name(client_name)
    store_path, store, keys = _read_server_store(server_path)
    matches = [entry for entry in keys if isinstance(entry, dict) and entry.get("name") == client_name]
    if not matches:
        raise SetupError(f"client name is not authorized: {client_name}")
    if len(keys) == 1:
        raise SetupError("the store must keep at least one client; add another first")
    entry = matches[0]
    store_directory = store_path.parent.resolve(strict=True)
    owned: list[Path] = []
    for field in ("identity", "access_psk"):
        reference = entry.get(field)
        relative = reference.get("file") if isinstance(reference, dict) else None
        if isinstance(relative, str) and relative and not Path(relative).is_absolute():
            candidate = (store_directory / relative).resolve(strict=False)
            if store_directory in candidate.parents:
                owned.append(candidate)
    updated = dict(store)
    updated["keys"] = [other for other in keys if other is not entry]
    owner = store_path.stat()
    replacement = _write_replacement(store_path, updated)
    try:
        if os.geteuid() == 0:
            os.chown(replacement, owner.st_uid, owner.st_gid, follow_symlinks=False)
        os.replace(replacement, store_path)
        replacement = None
        _fsync_directory(store_directory)
    finally:
        if replacement is not None:
            replacement.unlink(missing_ok=True)
    for path in owned:
        path.unlink(missing_ok=True)
        _fsync_directory(path.parent)
    return store_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yume-setup",
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
    init.add_argument(
        "--max-sessions",
        type=int,
        help="sessions the client may hold at once; a newer one replaces the oldest",
    )
    init.add_argument(
        "--weight",
        type=float,
        help="the client's share of the egress rate against other busy clients, 0.1 to 100",
    )
    init.add_argument(
        "--max-egress-mbps",
        type=int,
        help="the rate in Mbit/s that clients share by weight; unlimited when omitted",
    )
    add = commands.add_parser(
        "add-client",
        help="issue another client bundle for an existing server directory",
    )
    add.add_argument(
        "--server",
        required=True,
        type=Path,
        help="server directory holding yumed.json and its credentials",
    )
    add.add_argument(
        "--host",
        required=True,
        help="the public DNS name or IP address the server certificate names",
    )
    add.add_argument("--output", required=True, type=Path, help="new client bundle directory")
    add.add_argument("--client-name", required=True)
    add.add_argument(
        "--max-sessions",
        type=int,
        help="sessions the client may hold at once; a newer one replaces the oldest",
    )
    add.add_argument(
        "--weight",
        type=float,
        help="the client's share of the egress rate against other busy clients, 0.1 to 100",
    )
    remove = commands.add_parser(
        "remove-client",
        help="remove a client from an existing server directory",
    )
    remove.add_argument(
        "--server",
        required=True,
        type=Path,
        help="server directory holding yumed.json and its credentials",
    )
    remove.add_argument("--client-name", required=True)
    return parser


def main() -> int:
    os.umask(0o077)
    arguments = build_parser().parse_args()
    try:
        if arguments.command == "remove-client":
            store = remove_client(arguments.server, arguments.client_name)
            print(f"Removed {arguments.client_name} from {store}")
            print("Reload yumed (SIGHUP, or systemctl reload yumed) to end its sessions.")
            return 0
        if arguments.command == "add-client":
            output = add_client(
                arguments.server,
                arguments.host,
                arguments.output,
                arguments.client_name,
                arguments.max_sessions,
                arguments.weight,
            )
        else:
            output = init_kit(
                arguments.host,
                arguments.output,
                arguments.port,
                arguments.client_name,
                arguments.max_sessions,
                arguments.weight,
                arguments.max_egress_mbps,
            )
    except (SetupError, OSError, ValueError) as exc:
        print(f"yume-setup: {exc}", file=sys.stderr)
        return 1
    if arguments.command == "add-client":
        print(f"Created YUME client bundle: {output}")
        print(f"Client config: {output / 'yume.json'}")
        print("Reload yumed (SIGHUP, or systemctl reload yumed) to accept the new client.")
        return 0
    print(f"Created YUME server kit and client bundle: {output}")
    print(f"Server config: {output / 'server' / 'yumed.json'}")
    print(f"Client config: {output / 'client' / 'yume.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
