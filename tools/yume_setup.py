#!/usr/bin/env python3
"""Create a permission-safe experimental YTP/1 kit and client bundle."""

from __future__ import annotations

import argparse
import ctypes
import datetime
import errno
import hashlib
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
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
# Tuning presets trade far-path speed against how much data one key
# protects and how close the carrier stays to the captured browser behavior.
# They match config/tuning_presets.json, which a test compares, and the YTP/1
# guide's "Tuning presets" describes them. A preset sets these keys in both
# the server's and the client's limits.
TUNING_PRESETS = {
    "stealth": {
        "max_queued_bytes": 4_194_304,
        "max_epoch_bytes": 1_048_576,
        "credit_returns_per_window": 2,
        "idle_epoch_rotation": False,
    },
    "balanced": {
        "max_queued_bytes": 16_777_216,
        "max_epoch_bytes": 4_194_304,
        "credit_returns_per_window": 2,
        "idle_epoch_rotation": False,
    },
    "fast": {
        "max_queued_bytes": 33_554_432,
        "max_epoch_bytes": 16_777_216,
        "credit_returns_per_window": 4,
        "idle_epoch_rotation": True,
    },
    "max": {
        "max_queued_bytes": 67_108_864,
        "max_epoch_bytes": 67_108_864,
        "credit_returns_per_window": 8,
        "idle_epoch_rotation": True,
    },
}
DEFAULT_PRESET = "stealth"
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
# The cluster list: its signature domain, node bound and validity window.
# They match src/runtime/cluster_list.hpp.
CLUSTER_LIST_DOMAIN = b"yume-cluster-list/1"
# The routes view clients choose circuit routes from, signed beside the list.
CLUSTER_ROUTES_DOMAIN = b"yume-cluster-routes/1"
# The key network tags are made under. It stays in the operator directory.
ROUTES_TAG_KEY = "routes-tag.key"
NETWORK_TAG_BYTES = 8
# The daemon's own circuit service, granted with add-client --circuits.
CIRCUIT_CAPABILITY = {"service": "yume.circuit", "kind": "packet"}
MAX_CLUSTER_NODES = 64
DEFAULT_CLUSTER_DAYS = 30
MAX_CLUSTER_DAYS = 366
COMPOSITE_SIGNATURE_BYTES = 64 + 4627
# Where a node keeps its cluster files, relative to its server directory.
NODE_CLUSTER_DIRECTORY = Path("credentials") / "cluster"
# Where yumed saves the highest list serial, next to yumed.json.
NODE_CLUSTER_STATE = "cluster-state.json"
PEM_BLOCK = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+)-----\s+[A-Za-z0-9+/=\s]+?-----END \1-----\s*"
)


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


def _limits(tuning: dict[str, int]) -> dict[str, object]:
    limits: dict[str, object] = dict(LIMITS)
    limits.update(tuning)
    return limits


def _server_config(
    port: int, tuning: dict[str, int], max_egress_mbps: int | None = None
) -> dict[str, object]:
    limits = _limits(tuning)
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


def _client_config(host: str, port: int, tuning: dict[str, int]) -> dict[str, object]:
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
        "limits": _limits(tuning),
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
    tuning: dict[str, int],
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
    _write_json(client / "yume.json", _client_config(host, port, tuning))
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
    client_name: str,
    fingerprint: str,
    max_sessions: int | None,
    weight: float | None,
    circuits: bool = False,
) -> dict[str, object]:
    capabilities: list[dict[str, str]] = [
        {"service": service["name"], "kind": service["kind"]} for service in SERVICES
    ]
    if circuits:
        capabilities.append(dict(CIRCUIT_CAPABILITY))
    entry: dict[str, object] = {
        "name": client_name,
        "identity": {
            "file": f"authorized/{client_name}-composite.pub.pem",
            "sha256": fingerprint,
        },
        "access_psk": {"file": f"authorized/{client_name}-access.psk"},
        "capabilities": capabilities,
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
    preset: str = DEFAULT_PRESET,
) -> Path:
    host = _require_host(host)
    client_name = _require_client_name(client_name)
    if preset not in TUNING_PRESETS:
        raise SetupError(f"unknown tuning preset: {preset}")
    tuning = dict(TUNING_PRESETS[preset])
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
            openssl, client, work / "client-identity", server_credentials, host, port,
            tuning,
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

        _write_json(server / "yumed.json", _server_config(port, tuning, max_egress_mbps))
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


def _cluster_reference(server: Path, config: dict[str, object], name: str) -> Path:
    section = config.get("cluster")
    reference = section.get(name) if isinstance(section, dict) else None
    relative = reference.get("file") if isinstance(reference, dict) else None
    if not isinstance(relative, str) or not relative:
        raise SetupError(f"server configuration lacks cluster.{name}")
    path = Path(relative)
    return path if path.is_absolute() else server / path


# Where a circuits client keeps its kit copies and the state it writes.
CLIENT_CIRCUITS_DIRECTORY = "credentials/circuits"
CLIENT_CIRCUITS_STATE = "circuits-state.json"


def _add_client_circuits(client: Path, server: Path, config: dict[str, object]) -> None:
    """Give a client bundle its circuits section and the kit copies it needs.

    The operator key verifies every routes view, and the node's current view
    and signature are the kit's copy. The client keeps the highest serial it
    has verified in circuits-state.json. Circuits carry TCP only, so the
    SOCKS5 adapter loses its UDP service.
    """
    material = client / CLIENT_CIRCUITS_DIRECTORY
    _mkdir_private(material)
    for name, target in (("operator_key", "operator.pub.pem"),
                         ("routes", "cluster-routes.json"),
                         ("routes_signature", "cluster-routes.sig")):
        source = _cluster_reference(server, config, name)
        if not source.is_file():
            raise SetupError(f"{source} is missing; sign the cluster with cluster-sign first")
        _copy_stream(source, material / target)
    client_config = _read_json(client / "yume.json")
    if not isinstance(client_config, dict):
        raise SetupError("the new client configuration is not an object")
    client_config["circuits"] = {
        "hops": 3,
        "operator_key": {"file": f"{CLIENT_CIRCUITS_DIRECTORY}/operator.pub.pem"},
        "routes": {"file": f"{CLIENT_CIRCUITS_DIRECTORY}/cluster-routes.json"},
        "routes_signature": {"file": f"{CLIENT_CIRCUITS_DIRECTORY}/cluster-routes.sig"},
        "state": {"file": CLIENT_CIRCUITS_STATE},
    }
    for adapter in client_config.get("adapters", []):
        if isinstance(adapter, dict) and adapter.get("kind") == "socks5":
            adapter.pop("udp_service", None)
    (client / "yume.json").unlink()
    _write_json(client / "yume.json", client_config)


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
    circuits: bool = False,
) -> Path:
    """Issue one client bundle for an existing server tree.

    The new identity is appended to the server's authorized-keys store with
    the kit's standard services. With circuits, which needs a server in a
    signed cluster, it is also granted yume.circuit and the bundle gets a
    circuits section of three hops with the kit's copies of the operator key
    and the routes view. Nothing changes unless every step succeeds:
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
    if circuits and not isinstance(config.get("cluster"), dict):
        raise SetupError("--circuits needs a server that belongs to a cluster")
    # A new client takes the server's tuning, so both sides of the kit match.
    server_limits = config.get("limits")
    tuning = dict(TUNING_PRESETS[DEFAULT_PRESET])
    if isinstance(server_limits, dict):
        for key in tuning:
            value = server_limits.get(key)
            if type(value) is type(tuning[key]):
                tuning[key] = value

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
            openssl, client, work / "client-identity", server_credentials, host, port,
            tuning,
        )
        if circuits:
            _add_client_circuits(client, server, config)
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
            *keys, _authorized_entry(client_name, fingerprint, max_sessions, weight, circuits)
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


# Clusters. An operator directory holds the composite operator key, which
# never goes to a node, and cluster.json, the operator's record of its nodes:
# each node's name, the server directory it was added from, its host and an
# optional address to dial. cluster-sign builds the signed list from the node
# directories' public material, so the list always matches their keys.


def _pem_blocks(text: str, count: int, what: str) -> list[str]:
    blocks = [match.group(0) for match in PEM_BLOCK.finditer(text)]
    if len(blocks) != count or "".join(blocks).strip() != text.strip():
        raise SetupError(f"{what} must hold exactly {count} PEM block(s)")
    return [block.strip() + "\n" for block in blocks]


def _pem_fingerprint(openssl: str, composite_public: str) -> str:
    digest = hashlib.sha256()
    digest.update(IDENTITY_DOMAIN)
    for block in _pem_blocks(composite_public, 2, "a composite public key"):
        encoded = _run_openssl(
            openssl, ["pkey", "-pubin", "-outform", "DER"], input_bytes=block.encode("ascii")
        )
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _require_node_name(value: str) -> str:
    if CLIENT_NAME.fullmatch(value) is None:
        raise SetupError(
            "node name must contain 1..63 letters, digits, '.', '_', or '-', "
            "and must begin and end with a letter or digit"
        )
    return value


def _certificate_names(openssl: str, certificate: Path, host: str) -> bool:
    option = "-checkip" if _is_ip(host) else "-checkhost"
    try:
        result = subprocess.run(
            [openssl, "x509", "-in", str(certificate), "-noout", option, host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SetupError("OpenSSL invocation failed") from exc
    output = result.stdout.decode("utf-8", "replace")
    return result.returncode == 0 and "does match certificate" in output


def _read_bytes_file(path: Path, limit: int = MAX_JSON_BYTES) -> bytes:
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SetupError(f"cannot open {path}") from exc
    with os.fdopen(descriptor, "rb") as source:
        status = os.fstat(source.fileno())
        if not stat.S_ISREG(status.st_mode) or status.st_size > limit:
            raise SetupError(f"{path} is not a bounded regular file")
        payload = source.read(limit + 1)
    if len(payload) > limit:
        raise SetupError(f"{path} is not a bounded regular file")
    return payload


def _read_text_file(path: Path, limit: int = MAX_JSON_BYTES) -> str:
    payload = _read_bytes_file(path, limit)
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SetupError(f"{path} is not ASCII text") from exc


class _Node:
    """A server directory in the init layout, as a cluster sees it."""

    def __init__(self, openssl: str, server_path: Path) -> None:
        try:
            self.server = server_path.resolve(strict=True)
        except OSError as exc:
            raise SetupError(f"server directory does not exist: {server_path}") from exc
        self.config_path = self.server / "yumed.json"
        config = _read_json(self.config_path)
        if not isinstance(config, dict) or config.get("schema") != 1 or config.get("role") != "server":
            raise SetupError(f"{self.server} must hold a schema-1 server yumed.json")
        self.config = config
        endpoint = config.get("endpoint")
        port = endpoint.get("port") if isinstance(endpoint, dict) else None
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise SetupError(f"{self.config_path} has no valid endpoint.port")
        self.port = port
        self.credentials = _server_reference(self.server, config, "admission_key").parent
        self.admission = _server_reference(self.server, config, "admission_key")
        for name in ("server-composite.pub.pem", "server-mlkem.pub.pem", "server-trust.pem",
                     "server-tls.pem"):
            if not (self.credentials / name).is_file():
                raise SetupError(
                    f"{self.credentials} lacks {name}; clusters need the layout init writes"
                )
        self.identity_key = _read_text_file(self.credentials / "server-composite.pub.pem")
        self.identity = _pem_fingerprint(openssl, self.identity_key)
        self.cluster = self.server / NODE_CLUSTER_DIRECTORY
        self.peers_path = self.cluster / "peers.json"
        self.owner = self.config_path.stat()

    def peers(self) -> list[object]:
        if not self.peers_path.exists():
            return []
        store = _read_json(self.peers_path)
        keys = store.get("keys") if isinstance(store, dict) else None
        if not isinstance(store, dict) or store.get("schema") != 1 or not isinstance(keys, list):
            raise SetupError(f"{self.peers_path} is not a schema-1 peer store")
        return keys


class _Changes:
    """Files a cluster command creates and stores it replaces.

    New files are created exclusively and replacements are staged beside
    their targets, so nothing a node reads changes until commit(). Until
    then, rollback() removes everything created. After a commit that fails
    part way, the nodes it names may need another run.
    """

    def __init__(self) -> None:
        self.created: list[Path] = []
        self.replacements: list[tuple[Path, Path]] = []
        self.owners: dict[Path, os.stat_result] = {}

    def directory(self, path: Path, owner: os.stat_result) -> None:
        if path.is_dir():
            return
        self.directory(path.parent, owner)
        _mkdir_private(path)
        self.created.append(path)
        self.owners[path] = owner

    def create(self, path: Path, payload: bytes, owner: os.stat_result) -> None:
        self.directory(path.parent, owner)
        _write_bytes(path, payload)
        self.created.append(path)
        self.owners[path] = owner

    def copy(self, source: Path, path: Path, owner: os.stat_result) -> None:
        self.directory(path.parent, owner)
        _copy_stream(source, path)
        self.created.append(path)
        self.owners[path] = owner

    def replace(self, path: Path, payload: bytes, owner: os.stat_result) -> None:
        self.directory(path.parent, owner)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.new")
        _write_bytes(temporary, payload)
        self.replacements.append((temporary, path))
        self.owners[temporary] = owner

    def commit(self) -> None:
        if os.geteuid() == 0:
            for path, owner in self.owners.items():
                os.chown(path, owner.st_uid, owner.st_gid, follow_symlinks=False)
        for path in self.created:
            _fsync_directory(path.parent)
        for temporary, path in self.replacements:
            os.replace(temporary, path)
            _fsync_directory(path.parent)
        self.replacements = []
        self.created = []

    def rollback(self) -> None:
        for temporary, _ in self.replacements:
            temporary.unlink(missing_ok=True)
        for path in reversed(self.created):
            if path.is_dir() and not path.is_symlink():
                try:
                    path.rmdir()
                except OSError:
                    pass
            else:
                path.unlink(missing_ok=True)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _read_cluster(directory: Path) -> tuple[Path, dict[str, object], list[dict[str, object]]]:
    try:
        root = directory.resolve(strict=True)
    except OSError as exc:
        raise SetupError(f"cluster directory does not exist: {directory}") from exc
    state = _read_json(root / "cluster.json")
    nodes = state.get("nodes") if isinstance(state, dict) else None
    if (
        not isinstance(state, dict)
        or state.get("schema") != 1
        or not isinstance(state.get("cluster"), str)
        or not isinstance(state.get("serial"), int)
        or not isinstance(nodes, list)
        or not all(
            isinstance(node, dict)
            and set(node) <= {"name", "server", "host", "address", "exit"}
            and all(isinstance(node.get(key), str) for key in ("name", "server", "host"))
            and isinstance(node.get("address", ""), str)
            and isinstance(node.get("exit", False), bool)
            for node in nodes
        )
    ):
        raise SetupError(f"{root / 'cluster.json'} is not a schema-1 cluster record")
    return root, state, nodes


def cluster_init(output_path: Path) -> tuple[Path, str]:
    """Create an operator directory with a new composite operator key."""
    output = _require_output_path(output_path)
    parent = output.parent
    staging = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=parent))
    os.chmod(staging, 0o700)
    published = False
    try:
        openssl = _openssl_path()
        fingerprint = _generate_composite_identity(
            openssl,
            staging / ".work",
            staging / "operator-composite.pem",
            staging / "operator-composite.pub.pem",
        )
        shutil.rmtree(staging / ".work")
        _write_bytes(staging / ROUTES_TAG_KEY, secrets.token_bytes(32))
        _write_json(
            staging / "cluster.json",
            {"schema": 1, "cluster": fingerprint, "serial": 0, "nodes": []},
        )
        _fsync_tree(staging)
        _rename_noreplace(staging, output)
        published = True
        _fsync_directory(parent)
        return output, fingerprint
    finally:
        if not published:
            _remove_staging(staging, parent)


def _peer_entry(name: str, identity: str) -> dict[str, object]:
    return {
        "identity": identity,
        "outbound_psk": {"file": f"peers/{name}-outbound.psk"},
        "inbound_psk": {"file": f"peers/{name}-inbound.psk"},
        "admission_key": {"file": f"peers/{name}-admission.key"},
    }


def _cluster_section(exit_service: str | None = None) -> dict[str, object]:
    base = NODE_CLUSTER_DIRECTORY.as_posix()
    section: dict[str, object] = {
        "operator_key": {"file": f"{base}/operator.pub.pem"},
        "list": {"file": f"{base}/cluster-list.json"},
        "signature": {"file": f"{base}/cluster-list.sig"},
        "peers": {"file": f"{base}/peers.json"},
        "routes": {"file": f"{base}/cluster-routes.json"},
        "routes_signature": {"file": f"{base}/cluster-routes.sig"},
        # yumed writes this itself, so it stays outside the credentials that
        # the operator deploys.
        "state": {"file": NODE_CLUSTER_STATE},
    }
    if exit_service is not None:
        section["exit"] = {"service": exit_service}
    return section


def _exit_service(node: "_Node") -> str:
    """The one direct_tcp service an exit carries circuits' streams through."""
    services = [
        adapter.get("service")
        for adapter in node.config.get("adapters", [])
        if isinstance(adapter, dict) and adapter.get("kind") == "direct_tcp"
    ]
    if len(services) != 1 or not isinstance(services[0], str):
        raise SetupError(
            f"{node.config_path} needs exactly one direct_tcp adapter to be an exit"
        )
    return services[0]


def _network_tag(key: bytes, host: str, address: str | None) -> str:
    """The network tag of a node: the first bytes of an HMAC of its IPv4 /16
    or IPv6 /32 under the operator's tag key, from its address or, without
    one, from resolving its host now, preferring an IPv4 address."""
    if address is None:
        try:
            answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise SetupError(
                f"cannot resolve {host} for its network tag; give the node an --address"
            ) from exc
        found = sorted({str(answer[4][0]) for answer in answers},
                       key=lambda text: (":" in text, text))
        if not found:
            raise SetupError(f"{host} resolves to no address; give the node an --address")
        address = found[0]
    parsed = ipaddress.ip_address(address)
    prefix = 16 if parsed.version == 4 else 32
    network = ipaddress.ip_network(f"{parsed}/{prefix}", strict=False)
    # The exploded form is the same on every Python release, and only this
    # tool ever computes the text, so tags stay equal from one signing to
    # the next.
    text = f"{network.network_address.exploded}/{prefix}"
    return hmac.new(key, text.encode("ascii"), hashlib.sha256).digest()[:NETWORK_TAG_BYTES].hex()


def cluster_add(
    cluster_path: Path,
    server_path: Path,
    name: str,
    host: str,
    address: str | None = None,
    exit_node: bool = False,
) -> Path:
    """Enter one node into a cluster.

    For every node already in the cluster it writes a fresh PSK for each
    direction into both nodes' peer stores, with the other node's admission
    key, and it gives the new node the operator's public key and a cluster
    section in its yumed.json. An exit carries circuits' streams through its
    one direct_tcp service, and the routes view marks it. The list and the
    view are signed separately by cluster-sign.
    """
    name = _require_node_name(name)
    host = _require_host(host)
    if address is not None:
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError as exc:
            raise SetupError("node address must be an IP literal") from exc
    root, state, records = _read_cluster(cluster_path)
    if len(records) >= MAX_CLUSTER_NODES:
        raise SetupError(f"a cluster holds at most {MAX_CLUSTER_NODES} nodes")
    if any(record.get("name") == name for record in records):
        raise SetupError(f"the cluster already has a node named {name}")
    openssl = _openssl_path()
    node = _Node(openssl, server_path)
    if node.config.get("cluster") is not None:
        raise SetupError(f"{node.config_path} already belongs to a cluster")
    if not _certificate_names(openssl, node.credentials / "server-tls.pem", host):
        raise SetupError(f"the node's TLS certificate does not name {host}")
    exit_service = _exit_service(node) if exit_node else None
    existing = [_Node(openssl, Path(str(record.get("server")))) for record in records]
    if any(other.identity == node.identity or other.server == node.server for other in existing):
        raise SetupError("that server directory is already in the cluster")

    changes = _Changes()
    try:
        new_entries: list[object] = []
        for record, other in zip(records, existing):
            other_name = str(record["name"])
            outbound = secrets.token_bytes(32)
            inbound = secrets.token_bytes(32)
            if outbound == inbound:
                raise SetupError("generated link PSKs are equal")
            peers = node.cluster / "peers"
            changes.create(peers / f"{other_name}-outbound.psk", outbound, node.owner)
            changes.create(peers / f"{other_name}-inbound.psk", inbound, node.owner)
            changes.copy(other.admission, peers / f"{other_name}-admission.key", node.owner)
            new_entries.append(_peer_entry(other_name, other.identity))
            # The other node's inbound PSK from this node is this node's
            # outbound PSK, and the other way round.
            other_peers = other.cluster / "peers"
            changes.create(other_peers / f"{name}-outbound.psk", inbound, other.owner)
            changes.create(other_peers / f"{name}-inbound.psk", outbound, other.owner)
            changes.copy(node.admission, other_peers / f"{name}-admission.key", other.owner)
            changes.replace(
                other.peers_path,
                _json_bytes({"schema": 1, "keys": [*other.peers(), _peer_entry(name, node.identity)]}),
                other.owner,
            )
        changes.replace(node.peers_path, _json_bytes({"schema": 1, "keys": new_entries}), node.owner)
        changes.copy(root / "operator-composite.pub.pem", node.cluster / "operator.pub.pem", node.owner)
        config = dict(node.config)
        config["cluster"] = _cluster_section(exit_service)
        changes.replace(node.config_path, _json_bytes(config), node.owner)
        record: dict[str, object] = {"name": name, "server": str(node.server), "host": host}
        if address is not None:
            record["address"] = address
        if exit_node:
            record["exit"] = True
        updated = dict(state)
        updated["nodes"] = [*records, record]
        changes.replace(root / "cluster.json", _json_bytes(updated), (root / "cluster.json").stat())
        changes.commit()
    except BaseException:
        changes.rollback()
        raise
    return node.server


def cluster_remove(cluster_path: Path, name: str) -> Path:
    """Take one node out of a cluster.

    Every other node forgets it: its entry leaves their peer stores and its
    link files are deleted. The removed node loses its cluster section, its
    credentials/cluster directory and the serial it saved, so it runs alone
    after a restart and can join this or another cluster again. Sign a new
    list afterwards, so that no node keeps accepting it once the other nodes
    reload.
    """
    name = _require_node_name(name)
    root, state, records = _read_cluster(cluster_path)
    removed = [record for record in records if record.get("name") == name]
    if not removed:
        raise SetupError(f"the cluster has no node named {name}")
    openssl = _openssl_path()
    leaving = _Node(openssl, Path(str(removed[0].get("server"))))
    remaining = [record for record in records if record is not removed[0]]
    changes = _Changes()
    stale: list[Path] = []
    try:
        for record in remaining:
            other = _Node(openssl, Path(str(record.get("server"))))
            kept = [
                entry
                for entry in other.peers()
                if not (isinstance(entry, dict) and entry.get("identity") == leaving.identity)
            ]
            changes.replace(other.peers_path, _json_bytes({"schema": 1, "keys": kept}), other.owner)
            stale += [
                other.cluster / "peers" / f"{name}-{kind}"
                for kind in ("outbound.psk", "inbound.psk", "admission.key")
            ]
        section = leaving.config.get("cluster")
        state_reference = section.get("state") if isinstance(section, dict) else None
        # Only a state file inside the server directory is this node's to remove.
        if (isinstance(state_reference, dict) and isinstance(state_reference.get("file"), str)
                and not Path(state_reference["file"]).is_absolute()):
            saved = leaving.server / state_reference["file"]
            stale += [saved, saved.with_name(saved.name + ".new")]
        config = {key: value for key, value in leaving.config.items() if key != "cluster"}
        changes.replace(leaving.config_path, _json_bytes(config), leaving.owner)
        updated = dict(state)
        updated["nodes"] = remaining
        changes.replace(root / "cluster.json", _json_bytes(updated), (root / "cluster.json").stat())
        changes.commit()
    except BaseException:
        changes.rollback()
        raise
    for path in stale:
        path.unlink(missing_ok=True)
    if leaving.cluster.is_dir() and not leaving.cluster.is_symlink():
        shutil.rmtree(leaving.cluster)
    return leaving.server


def _sign_list(openssl: str, work: Path, private_key: Path, message: bytes) -> bytes:
    blocks = _pem_blocks(_read_text_file(private_key), 2, "the operator key")
    message_path = work / "message"
    _write_bytes(message_path, message)
    signature = b""
    for index, (block, size) in enumerate(zip(blocks, (64, 4627))):
        key = work / f"key-{index}.pem"
        public = work / f"key-{index}.pub.pem"
        output = work / f"signature-{index}"
        _write_text(key, block)
        _run_openssl(openssl, ["pkeyutl", "-sign", "-rawin", "-inkey", str(key),
                               "-in", str(message_path), "-out", str(output)])
        _derive_public(openssl, key, public)
        _run_openssl(openssl, ["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public),
                               "-in", str(message_path), "-sigfile", str(output)])
        part = output.read_bytes()
        if len(part) != size:
            raise SetupError("the operator key produced a signature of the wrong size")
        signature += part
    return signature


def cluster_sign(cluster_path: Path, days: int = DEFAULT_CLUSTER_DAYS) -> tuple[int, str]:
    """Sign the next list and routes view and give them to every node.

    The serial goes up by one and not_after is days from now, the same for
    both. The routes view names each node, its identity, its exit mark and
    its network tag, and no address. Both documents and their signatures
    replace each node's copies, which a running node applies when it
    reloads (SIGHUP).
    """
    if not 1 <= days <= MAX_CLUSTER_DAYS:
        raise SetupError(f"days must be in 1..{MAX_CLUSTER_DAYS}")
    root, state, records = _read_cluster(cluster_path)
    if not records:
        raise SetupError("the cluster has no nodes; add one with cluster-add")
    openssl = _openssl_path()
    operator_public = _read_text_file(root / "operator-composite.pub.pem")
    if _pem_fingerprint(openssl, operator_public) != state["cluster"]:
        raise SetupError("the operator key does not match cluster.json")
    tag_key = _read_bytes_file(root / ROUTES_TAG_KEY, 32)
    if len(tag_key) != 32:
        raise SetupError(f"{root / ROUTES_TAG_KEY} must hold 32 bytes")
    nodes = []
    entries = []
    routes = []
    for record in records:
        node = _Node(openssl, Path(str(record.get("server"))))
        nodes.append(node)
        entry: dict[str, object] = {
            "name": record["name"],
            "identity": node.identity,
            "host": record["host"],
            "port": node.port,
            "identity_key": node.identity_key,
            "mlkem_key": _read_text_file(node.credentials / "server-mlkem.pub.pem"),
            "tls_trust": _read_text_file(node.credentials / "server-trust.pem"),
        }
        if "address" in record:
            entry["address"] = record["address"]
        entries.append(entry)
        routes.append({
            "name": record["name"],
            "identity": node.identity,
            "identity_key": node.identity_key,
            "exit": bool(record.get("exit", False)),
            "network": _network_tag(tag_key, str(record["host"]), record.get("address")),
        })
    serial = int(state["serial"]) + 1
    not_after = (
        datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        + datetime.timedelta(days=days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = {"schema": 1, "cluster": state["cluster"], "serial": serial, "not_after": not_after}
    document = _json_bytes({**header, "nodes": entries})
    view = _json_bytes({**header, "nodes": routes})
    work = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=root))
    os.chmod(work, 0o700)
    try:
        signed = []
        for label, domain, message in (("list", CLUSTER_LIST_DOMAIN, document),
                                       ("routes", CLUSTER_ROUTES_DOMAIN, view)):
            _mkdir_private(work / label)
            signed.append(_sign_list(openssl, work / label, root / "operator-composite.pem",
                                     domain + b"\0" + message))
    finally:
        _remove_staging(work, root)
    signature, view_signature = signed
    if any(len(part) != COMPOSITE_SIGNATURE_BYTES for part in signed):
        raise SetupError("the composite signature has the wrong size")
    published = {
        "cluster-list.json": document,
        "cluster-list.sig": signature,
        "cluster-routes.json": view,
        "cluster-routes.sig": view_signature,
    }
    changes = _Changes()
    try:
        owner = (root / "cluster.json").stat()
        for name, payload in published.items():
            for node in nodes:
                changes.replace(node.cluster / name, payload, node.owner)
            changes.replace(root / name, payload, owner)
        updated = dict(state)
        updated["serial"] = serial
        changes.replace(root / "cluster.json", _json_bytes(updated), owner)
        changes.commit()
    except BaseException:
        changes.rollback()
        raise
    return serial, not_after


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yume-setup",
        description=(
            "Create a YTP/1 server kit and its first client bundle for the "
            "experimental native yumed and yume. It does not start either program."
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
    init.add_argument(
        "--preset",
        choices=tuple(TUNING_PRESETS),
        default=DEFAULT_PRESET,
        help="tuning for both sides: stealth (default), balanced, fast or max trade "
        "far-path speed against data per key and closeness to browser traffic",
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
    add.add_argument(
        "--circuits",
        action="store_true",
        help="send the client's connections through circuits of three cluster servers, this one the entry",
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
    cluster_init_parser = commands.add_parser(
        "cluster-init",
        help="create an operator directory with a new cluster operator key",
    )
    cluster_init_parser.add_argument(
        "--output", required=True, type=Path, help="new operator directory, kept off the nodes"
    )
    cluster_add_parser = commands.add_parser(
        "cluster-add",
        help="enter a server directory into a cluster and write its link secrets",
    )
    cluster_add_parser.add_argument(
        "--cluster", required=True, type=Path, help="operator directory from cluster-init"
    )
    cluster_add_parser.add_argument(
        "--server", required=True, type=Path, help="server directory holding yumed.json"
    )
    cluster_add_parser.add_argument("--name", required=True, help="the node's name in the list")
    cluster_add_parser.add_argument(
        "--host",
        required=True,
        help="the DNS name or IP address the node's TLS certificate names",
    )
    cluster_add_parser.add_argument(
        "--address", help="an IP address other nodes dial instead of resolving the host"
    )
    cluster_add_parser.add_argument(
        "--exit",
        action="store_true",
        help="carry circuits' streams to destinations through the node's direct_tcp service",
    )
    cluster_remove_parser = commands.add_parser(
        "cluster-remove",
        help="take a node out of a cluster and delete its link secrets on the others",
    )
    cluster_remove_parser.add_argument(
        "--cluster", required=True, type=Path, help="operator directory from cluster-init"
    )
    cluster_remove_parser.add_argument("--name", required=True)
    cluster_sign_parser = commands.add_parser(
        "cluster-sign",
        help="sign the next cluster list and routes view and copy them to every node",
    )
    cluster_sign_parser.add_argument(
        "--cluster", required=True, type=Path, help="operator directory from cluster-init"
    )
    cluster_sign_parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_CLUSTER_DAYS,
        help=f"days the list stays valid, 1 to {MAX_CLUSTER_DAYS} (default {DEFAULT_CLUSTER_DAYS})",
    )
    return parser


def _run_cluster_command(arguments: argparse.Namespace) -> int:
    if arguments.command == "cluster-init":
        output, fingerprint = cluster_init(arguments.output)
        print(f"Created cluster operator directory: {output}")
        print(f"Cluster ID: {fingerprint}")
        print("Keep this directory off the nodes. Add nodes with cluster-add.")
    elif arguments.command == "cluster-add":
        server = cluster_add(
            arguments.cluster, arguments.server, arguments.name, arguments.host,
            arguments.address, arguments.exit,
        )
        print(f"Added {arguments.name} ({server}) to the cluster")
        print("Sign the list with cluster-sign, then deploy the nodes' credentials/cluster.")
    elif arguments.command == "cluster-remove":
        server = cluster_remove(arguments.cluster, arguments.name)
        print(f"Removed {arguments.name} ({server}) from the cluster")
        print("Sign a new list with cluster-sign and reload the other nodes (SIGHUP).")
    else:
        serial, not_after = cluster_sign(arguments.cluster, arguments.days)
        print(f"Signed cluster list and routes view serial {serial}, valid until {not_after}")
        print("Deploy each node's credentials/cluster and reload it (SIGHUP).")
    return 0


def main() -> int:
    os.umask(0o077)
    arguments = build_parser().parse_args()
    try:
        if arguments.command.startswith("cluster-"):
            return _run_cluster_command(arguments)
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
                arguments.circuits,
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
                arguments.preset,
            )
    except (SetupError, OSError, ValueError) as exc:
        print(f"yume-setup: {exc}", file=sys.stderr)
        return 1
    if arguments.command == "add-client":
        print(f"Created YUME client bundle: {output}")
        print(f"Client config: {output / 'yume.json'}")
        print("Reload yumed (SIGHUP, or systemctl reload yumed) to accept the new client.")
        print(f"To move it to the client's device: yume --seal-kit {output} --output FILE")
        return 0
    print(f"Created YUME server kit and client bundle: {output}")
    print(f"Server config: {output / 'server' / 'yumed.json'}")
    print(f"Client config: {output / 'client' / 'yume.json'}")
    print(f"Tuning preset: {arguments.preset}")
    print(f"To move the client to its device: yume --seal-kit {output / 'client'} --output FILE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
