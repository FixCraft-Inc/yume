#!/usr/bin/env python3
"""Read-only validation for experimental YTP/1 schema-1 configurations."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable
from urllib.parse import urlsplit


PROFILE = "chrome151-node24-v1"
SUITE = {
    "id": "ytp1-tls13-h2",
    "secure_channel": "tls13-native",
    "front_door": "h2-web",
    "carrier": "h2-duplex",
    "session": "ytp1-hybrid",
}
IDENTITY_DOMAIN = b"yume/ytp/1/composite-identity/v1"
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_FILE_REFERENCE_BYTES = 4096
MAX_SERVICES = 64
MAX_ADAPTERS = 16
MAX_LISTEN_ADDRESSES = 16
MAX_CONFIG_STREAMS = 65_535
MAX_SERVICE_NAME_BYTES = 128
SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?\Z")
SERVICE_NAME = re.compile(
    r"[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*\Z"
)
PEM_BLOCK = re.compile(
    rb"-----BEGIN ([A-Z0-9][A-Z0-9 ]*)-----\s+.*?-----END \1-----",
    re.DOTALL,
)


class DoctorError(RuntimeError):
    def __init__(self, pointer: str, detail: str):
        super().__init__(detail)
        self.pointer = pointer or "/"
        self.detail = detail


class DuplicateKeyError(ValueError):
    pass


def _duplicate_guard(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise DuplicateKeyError("duplicate object key")
        value[key] = child
    return value


def _reject_json_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _check_json_depth(value: Any, pointer: str) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > 16:
            _fail(pointer, "JSON nesting exceeds the 16-level limit")
        if type(current) is dict:
            stack.extend((child, depth + 1) for child in current.values())
        elif type(current) is list:
            stack.extend((child, depth + 1) for child in current)


def _join_pointer(base: str, token: str | int) -> str:
    escaped = str(token).replace("~", "~0").replace("/", "~1")
    return f"{base}/{escaped}" if base else f"/{escaped}"


def _fail(pointer: str, detail: str) -> None:
    raise DoctorError(pointer, detail)


def _closed_object(
    value: Any,
    pointer: str,
    allowed: Iterable[str],
    required: Iterable[str] | None = None,
) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(pointer, "must be an object")
    allowed_keys = set(allowed)
    required_keys = set(required if required is not None else allowed_keys)
    for key in value:
        if key not in allowed_keys:
            _fail(_join_pointer(pointer, key), "unknown key")
    for key in sorted(required_keys):
        if key not in value:
            _fail(_join_pointer(pointer, key), "required key is missing")
    return value


def _string(value: Any, pointer: str, maximum: int) -> str:
    if type(value) is not str:
        _fail(pointer, "must be a string")
    if len(value.encode("utf-8")) > maximum:
        _fail(pointer, f"must be at most {maximum} bytes")
    return value


def _integer(value: Any, pointer: str, minimum: int, maximum: int) -> int:
    if type(value) is not int:
        _fail(pointer, "must be an integer")
    if not minimum <= value <= maximum:
        _fail(pointer, f"must be in {minimum}..{maximum}")
    return value


def _valid_identifier(value: str, maximum: int = 64) -> bool:
    return (
        0 < len(value.encode("utf-8")) <= maximum
        and SAFE_IDENTIFIER.fullmatch(value) is not None
    )


def _valid_service_name(value: str) -> bool:
    return (
        value.isascii()
        and 0 < len(value) <= MAX_SERVICE_NAME_BYTES
        and SERVICE_NAME.fullmatch(value) is not None
    )


def _valid_host(value: str) -> bool:
    if not value or len(value.encode("utf-8")) > 253:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if value.endswith(".") or all(ch in "0123456789." for ch in value):
        return False
    return all(
        0 < len(label) <= 63
        and re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label
        )
        is not None
        for label in value.split(".")
    )


def _validate_file_text(value: Any, pointer: str) -> str:
    path = _string(value, pointer, MAX_FILE_REFERENCE_BYTES)
    if not path:
        _fail(pointer, "file reference must not be empty")
    if path != path.strip():
        _fail(pointer, "file reference must not have surrounding whitespace")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):
        _fail(pointer, "file reference must not contain control characters")
    if path.startswith("~") or "://" in path:
        _fail(pointer, "file reference must be a literal path")
    components = re.split(r"[/\\]", path)
    if path == "." or ".." in components:
        _fail(pointer, "file reference must not contain parent traversal")
    if path.startswith("-----BEGIN") or re.fullmatch(r"[0-9A-Fa-f]{64}", path):
        _fail(pointer, "inline credential material is forbidden")
    return path


def _file_reference(value: Any, pointer: str) -> str:
    reference = _closed_object(value, pointer, {"file"})
    return _validate_file_text(reference["file"], _join_pointer(pointer, "file"))


def _validate_endpoint(value: Any, role: str) -> None:
    pointer = "/endpoint"
    if role == "client":
        endpoint = _closed_object(value, pointer, {"host", "port"})
        host = _string(endpoint["host"], "/endpoint/host", 253)
        if not _valid_host(host):
            _fail("/endpoint/host", "must be an IP literal or DNS host name")
        _integer(endpoint["port"], "/endpoint/port", 1, 65535)
        return
    endpoint = _closed_object(value, pointer, {"listen_addresses", "port"})
    addresses = endpoint["listen_addresses"]
    if type(addresses) is not list:
        _fail("/endpoint/listen_addresses", "must be an array")
    if not 1 <= len(addresses) <= MAX_LISTEN_ADDRESSES:
        _fail(
            "/endpoint/listen_addresses",
            f"must contain 1..{MAX_LISTEN_ADDRESSES} addresses",
        )
    seen: set[str] = set()
    for index, address_value in enumerate(addresses):
        item_pointer = f"/endpoint/listen_addresses/{index}"
        address = _string(address_value, item_pointer, 64)
        try:
            ipaddress.ip_address(address)
        except ValueError:
            _fail(item_pointer, "must be an IP literal")
        if address in seen:
            _fail(item_pointer, "duplicate listen address")
        seen.add(address)
    _integer(endpoint["port"], "/endpoint/port", 1, 65535)


def _validate_suite(value: Any) -> None:
    suite = _closed_object(value, "/suite", SUITE.keys())
    for key, required in SUITE.items():
        pointer = f"/suite/{key}"
        parsed = _string(suite[key], pointer, 64)
        if parsed != required:
            _fail(pointer, "unsupported provider or suite value")


def _validate_credentials(value: Any, role: str) -> dict[str, str]:
    if role == "client":
        keys = {
            "composite_key",
            "access_psk",
            "admission_key",
            "server_trust",
            "server_identity",
            "server_mlkem",
        }
    else:
        keys = {
            "composite_key",
            "authorized_keys",
            "admin_keys",
            "tls_certificate",
            "tls_key",
            "admission_key",
            "mlkem_key",
        }
    credentials = _closed_object(value, "/credentials", keys)
    return {
        key: _file_reference(credentials[key], f"/credentials/{key}")
        for key in keys
    }


def _validate_cover(value: Any, role: str) -> str | None:
    if role == "client":
        cover = _closed_object(value, "/cover", {"profile"})
        root = None
    else:
        cover = _closed_object(
            value,
            "/cover",
            {"profile", "root", "reverse_proxy"},
            {"profile"},
        )
        has_root = "root" in cover
        has_proxy = "reverse_proxy" in cover
        if has_root == has_proxy:
            _fail("/cover", "requires exactly one of root or reverse_proxy")
        root = _file_reference(cover["root"], "/cover/root") if has_root else None
        if has_proxy:
            proxy = _closed_object(
                cover["reverse_proxy"], "/cover/reverse_proxy", {"url"}
            )
            url = _string(proxy["url"], "/cover/reverse_proxy/url", 128)
            try:
                parsed = urlsplit(url)
                hostname = parsed.hostname
            except ValueError:
                _fail("/cover/reverse_proxy/url", "is not a valid URL")
            if (
                parsed.scheme != "http"
                or hostname not in {"127.0.0.1", "::1"}
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                _fail(
                    "/cover/reverse_proxy/url",
                    "must be a plain loopback HTTP origin",
                )
            try:
                port = parsed.port
            except ValueError:
                _fail("/cover/reverse_proxy/url", "contains an invalid port")
            if port is None or not 1 <= port <= 65535:
                _fail("/cover/reverse_proxy/url", "requires a valid explicit port")
    profile = _string(cover["profile"], "/cover/profile", 128)
    if not _valid_identifier(profile, 128):
        _fail("/cover/profile", "must be a bounded profile identifier")
    if profile != PROFILE:
        _fail("/cover/profile", "profile is not qualified by this build")
    return root


def _validate_services(value: Any) -> dict[tuple[str, str], int]:
    if type(value) is not list:
        _fail("/services", "must be an array")
    if not 1 <= len(value) <= MAX_SERVICES:
        _fail("/services", f"must contain 1..{MAX_SERVICES} services")
    services: dict[tuple[str, str], int] = {}
    for index, item in enumerate(value):
        pointer = f"/services/{index}"
        service = _closed_object(
            item, pointer, {"name", "kind", "max_concurrent_streams"}
        )
        name = _string(
            service["name"], f"{pointer}/name", MAX_SERVICE_NAME_BYTES
        )
        if not _valid_service_name(name):
            _fail(
                f"{pointer}/name",
                "must use lowercase ASCII namespace segments",
            )
        kind = _string(service["kind"], f"{pointer}/kind", 16)
        if kind not in {"stream", "packet"}:
            _fail(f"{pointer}/kind", "must be 'stream' or 'packet'")
        key = (name, kind)
        if key in services:
            _fail(f"{pointer}/name", "duplicate service name and kind")
        services[key] = _integer(
            service["max_concurrent_streams"],
            f"{pointer}/max_concurrent_streams",
            1,
            MAX_CONFIG_STREAMS,
        )
    return services


def _validate_adapters(
    value: Any, role: str, services: dict[tuple[str, str], int]
) -> None:
    if type(value) is not list:
        _fail("/adapters", "must be an array")
    if len(value) > MAX_ADAPTERS:
        _fail("/adapters", f"must contain at most {MAX_ADAPTERS} adapters")
    socks_listeners: set[tuple[str, int]] = set()
    packet_interfaces: set[str] = set()
    direct_services: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        pointer = f"/adapters/{index}"
        if type(item) is not dict:
            _fail(pointer, "must be an object")
        if "kind" not in item:
            _fail(f"{pointer}/kind", "required key is missing")
        kind = _string(item["kind"], f"{pointer}/kind", 24)
        if kind not in {"socks5", "packet", "direct_tcp", "direct_udp"}:
            _fail(f"{pointer}/kind", "unsupported adapter kind")
        if kind == "socks5":
            adapter = _closed_object(
                item,
                pointer,
                {"kind", "service", "listen_address", "listen_port"},
            )
            if role != "client":
                _fail(f"{pointer}/kind", "socks5 adapter is client-only")
            listen_address = _string(
                adapter["listen_address"], f"{pointer}/listen_address", 64
            )
            if listen_address not in {"127.0.0.1", "::1"}:
                _fail(f"{pointer}/listen_address", "must be a loopback address")
            listen_port = _integer(
                adapter["listen_port"], f"{pointer}/listen_port", 1, 65535
            )
            if (listen_address, listen_port) in socks_listeners:
                _fail(
                    f"{pointer}/listen_port",
                    "duplicate SOCKS5 listen address and port",
                )
            socks_listeners.add((listen_address, listen_port))
            required_kind = "stream"
        elif kind == "packet":
            adapter = _closed_object(
                item,
                pointer,
                {"kind", "service", "interface_name", "mtu"},
            )
            interface = _string(
                adapter["interface_name"], f"{pointer}/interface_name", 32
            )
            if not _valid_identifier(interface, 32):
                _fail(f"{pointer}/interface_name", "invalid interface name")
            if interface in packet_interfaces:
                _fail(
                    f"{pointer}/interface_name", "duplicate packet interface name"
                )
            packet_interfaces.add(interface)
            _integer(adapter["mtu"], f"{pointer}/mtu", 576, 65535)
            required_kind = "packet"
        else:
            adapter = _closed_object(item, pointer, {"kind", "service"})
            if role != "server":
                _fail(f"{pointer}/kind", "direct adapters are server-only")
            required_kind = "stream" if kind == "direct_tcp" else "packet"
        service = _string(
            adapter["service"], f"{pointer}/service", MAX_SERVICE_NAME_BYTES
        )
        if not _valid_service_name(service):
            _fail(
                f"{pointer}/service",
                "must use lowercase ASCII namespace segments",
            )
        if kind in {"direct_tcp", "direct_udp"}:
            direct_key = (kind, service)
            if direct_key in direct_services:
                _fail(
                    f"{pointer}/service",
                    "duplicate direct adapter service and kind",
                )
            direct_services.add(direct_key)
        if not any(name == service for name, _ in services):
            _fail(f"{pointer}/service", "references an undeclared service")
        if (service, required_kind) not in services:
            _fail(f"{pointer}/service", f"requires a {required_kind} service")


def _validate_limits(value: Any, adapters: list[Any]) -> None:
    bounds = {
        "max_frame_bytes": (1024, 1024 * 1024),
        "max_streams": (1, 65535),
        "max_queued_bytes": (64 * 1024, 64 * 1024 * 1024),
        "max_pending_opens": (1, 1024),
        "max_rekey_jobs": (1, 64),
        "max_control_messages": (8, 4096),
        "max_packet_bytes": (576, 65535),
        "max_packet_batch": (1, 256),
    }
    limits = _closed_object(value, "/limits", bounds.keys())
    parsed = {
        key: _integer(limits[key], f"/limits/{key}", minimum, maximum)
        for key, (minimum, maximum) in bounds.items()
    }
    if parsed["max_frame_bytes"] > parsed["max_queued_bytes"]:
        _fail("/limits/max_frame_bytes", "must not exceed max_queued_bytes")
    if parsed["max_pending_opens"] > parsed["max_streams"]:
        _fail("/limits/max_pending_opens", "must not exceed max_streams")
    if parsed["max_packet_bytes"] > parsed["max_frame_bytes"]:
        _fail("/limits/max_packet_bytes", "must not exceed max_frame_bytes")
    for index, adapter in enumerate(adapters):
        if type(adapter) is dict and adapter.get("kind") == "packet":
            mtu = adapter.get("mtu")
            if type(mtu) is int and mtu > parsed["max_packet_bytes"]:
                _fail(
                    f"/adapters/{index}/mtu",
                    "must not exceed limits.max_packet_bytes",
                )


def _validate_config(document: Any) -> tuple[str, dict[str, str], str | None]:
    top = _closed_object(
        document,
        "",
        {
            "schema",
            "role",
            "endpoint",
            "suite",
            "credentials",
            "cover",
            "services",
            "adapters",
            "limits",
        },
    )
    _integer(top["schema"], "/schema", 1, 1)
    role = _string(top["role"], "/role", 16)
    if role not in {"client", "server"}:
        _fail("/role", "must be 'client' or 'server'")
    _validate_endpoint(top["endpoint"], role)
    _validate_suite(top["suite"])
    credentials = _validate_credentials(top["credentials"], role)
    cover_root = _validate_cover(top["cover"], role)
    services = _validate_services(top["services"])
    _validate_adapters(top["adapters"], role, services)
    _validate_limits(top["limits"], top["adapters"])
    return role, credentials, cover_root


def _checked_bytes(
    path: Path,
    pointer: str,
    *,
    private: bool = True,
    maximum: int = MAX_DOCUMENT_BYTES,
) -> bytearray:
    try:
        before = path.lstat()
    except OSError:
        _fail(pointer, "referenced file is missing or inaccessible")
    if stat.S_ISLNK(before.st_mode):
        _fail(pointer, "symlink files are forbidden")
    if not stat.S_ISREG(before.st_mode):
        _fail(pointer, "must reference a regular file")
    if private and before.st_mode & 0o077:
        _fail(pointer, "group/world permissions are forbidden")
    if before.st_size <= 0:
        _fail(pointer, "file must not be empty")
    if before.st_size > maximum:
        _fail(pointer, f"file exceeds the {maximum}-byte limit")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _fail(pointer, "referenced file is not safely readable")
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            _fail(pointer, "file changed during validation")
        if private and after.st_mode & 0o077:
            _fail(pointer, "group/world permissions are forbidden")
        if after.st_size <= 0:
            _fail(pointer, "file must not be empty")
        if after.st_size > maximum:
            _fail(pointer, f"file exceeds the {maximum}-byte limit")
        data = bytearray(after.st_size)
        try:
            view = memoryview(data)
            offset = 0
            while offset < len(data):
                count = os.readv(descriptor, [view[offset:]])
                if count <= 0:
                    _fail(pointer, "file changed during validation")
                offset += count
            if os.read(descriptor, 1):
                _fail(pointer, "file changed during validation")
            final = os.fstat(descriptor)
            if (
                after.st_dev != final.st_dev
                or after.st_ino != final.st_ino
                or after.st_size != final.st_size
                or after.st_mtime_ns != final.st_mtime_ns
                or after.st_ctime_ns != final.st_ctime_ns
            ):
                _fail(pointer, "file changed during validation")
            return data
        except BaseException:
            data[:] = b"\0" * len(data)
            raise
    finally:
        os.close(descriptor)


def _resolve_reference(base: Path, reference: str) -> Path:
    path = Path(reference)
    return path if path.is_absolute() else base / path


def _openssl(
    executable: str,
    arguments: list[str],
    pointer: str,
    *,
    input_bytes: bytes | bytearray | None = None,
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
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail(pointer, "OpenSSL validation could not run")
    if result.returncode != 0:
        _fail(pointer, "OpenSSL rejected the credential material")
    return result.stdout


def _pem_blocks(payload: bytearray, pointer: str, count: int) -> list[bytearray]:
    matches = list(PEM_BLOCK.finditer(payload))
    if len(matches) != count:
        _fail(pointer, f"must contain exactly {count} PEM objects")
    position = 0
    blocks: list[bytearray] = []
    for match in matches:
        if bytes(payload[position : match.start()]).strip():
            _fail(pointer, "contains data outside PEM objects")
        blocks.append(bytearray(payload[match.start() : match.end()]) + b"\n")
        position = match.end()
    if bytes(payload[position:]).strip():
        _fail(pointer, "contains data outside PEM objects")
    return blocks


def _public_der_from_private(
    openssl: str, payload: bytearray, pointer: str
) -> bytes:
    return _openssl(
        openssl,
        ["pkey", "-pubout", "-outform", "DER"],
        pointer,
        input_bytes=payload,
    )


def _normalize_public_der(openssl: str, payload: bytearray, pointer: str) -> bytes:
    return _openssl(
        openssl,
        ["pkey", "-pubin", "-pubout", "-outform", "DER"],
        pointer,
        input_bytes=payload,
    )


def _public_algorithm(openssl: str, public_der: bytes, pointer: str) -> str:
    details = _openssl(
        openssl,
        ["pkey", "-pubin", "-inform", "DER", "-text", "-noout"],
        pointer,
        input_bytes=public_der,
    )
    first_line = details.splitlines()[0].decode("ascii", "replace") if details else ""
    for algorithm in ("ED25519", "ML-DSA-87", "ML-KEM-1024"):
        if first_line == f"{algorithm} Public-Key:":
            return algorithm
    _fail(pointer, "uses an unsupported key algorithm")


def _composite_public_ders(
    openssl: str, payload: bytearray, pointer: str, private: bool
) -> list[bytes]:
    blocks = _pem_blocks(payload, pointer, 2)
    try:
        ders = [
            _public_der_from_private(openssl, block, pointer)
            if private
            else _normalize_public_der(openssl, block, pointer)
            for block in blocks
        ]
        algorithms = [
            _public_algorithm(openssl, der, pointer) for der in ders
        ]
        if algorithms != ["ED25519", "ML-DSA-87"]:
            _fail(pointer, "must be Ed25519 followed by ML-DSA-87")
        return ders
    finally:
        for block in blocks:
            block[:] = b"\0" * len(block)


def _composite_fingerprint(public_ders: list[bytes]) -> str:
    digest = hashlib.sha256()
    digest.update(IDENTITY_DOMAIN)
    for encoded in public_ders:
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _single_public_der(
    openssl: str,
    payload: bytearray,
    pointer: str,
    *,
    private: bool,
    algorithm: str,
) -> bytes:
    blocks = _pem_blocks(payload, pointer, 1)
    try:
        der = (
            _public_der_from_private(openssl, blocks[0], pointer)
            if private
            else _normalize_public_der(openssl, blocks[0], pointer)
        )
        if _public_algorithm(openssl, der, pointer) != algorithm:
            _fail(pointer, f"must use {algorithm}")
        return der
    finally:
        blocks[0][:] = b"\0" * len(blocks[0])


def _companion_public_path(private_path: Path) -> Path:
    name = private_path.name
    if name.endswith(".pem"):
        name = name[:-4] + ".pub.pem"
    else:
        name += ".pub.pem"
    return private_path.with_name(name)


def _check_composite_pair(
    openssl: str,
    private_payload: bytearray,
    private_path: Path,
    pointer: str,
    diagnostics: list[DoctorError],
) -> None:
    public_pointer = f"{pointer}/public"
    try:
        public_payload = _checked_bytes(
            _companion_public_path(private_path), public_pointer
        )
    except DoctorError as error:
        diagnostics.append(error)
        return
    try:
        private_ders = _composite_public_ders(
            openssl, private_payload, pointer, True
        )
        public_ders = _composite_public_ders(
            openssl, public_payload, public_pointer, False
        )
        if any(
            not hmac.compare_digest(private_der, public_der)
            for private_der, public_der in zip(private_ders, public_ders)
        ):
            _fail(public_pointer, "does not match the composite private key")
    finally:
        public_payload[:] = b"\0" * len(public_payload)


def _secret_digest(payload: bytearray, pointer: str) -> bytes:
    if len(payload) != 32:
        _fail(pointer, "must contain exactly 32 binary bytes")
    return hashlib.sha256(payload).digest()


def _load_json_payload(payload: bytearray, pointer: str) -> Any:
    try:
        text = payload.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_guard,
            parse_constant=_reject_json_constant,
        )
        _check_json_depth(value, pointer)
        return value
    except UnicodeDecodeError:
        _fail(pointer, "must be UTF-8 JSON")
    except DuplicateKeyError:
        _fail(pointer, "contains a duplicate object key")
    except json.JSONDecodeError as error:
        _fail(pointer, f"invalid JSON syntax at line {error.lineno}, column {error.colno}")
    except (RecursionError, ValueError):
        _fail(pointer, "contains invalid or excessively nested JSON")


def _check_admin_keys(
    openssl: str,
    payload: bytearray,
    store_path: Path,
    authorized_fingerprints: set[str],
    diagnostics: list[DoctorError],
) -> None:
    """Validate the separate second-factor store.

    Admin is proved by an identity from this store *in addition to* an
    authorized traffic identity. An identity present in both stores would
    satisfy both halves by itself, collapsing the two-key requirement, so
    overlap is rejected outright. An empty store is valid and means the
    deployment currently has no administrator.
    """
    pointer = "/credentials/admin_keys"
    document = _load_json_payload(payload, pointer)
    store = _closed_object(document, pointer, {"schema", "keys"})
    _integer(store["schema"], f"{pointer}/schema", 1, 1)
    keys = store["keys"]
    if type(keys) is not list:
        _fail(f"{pointer}/keys", "must be an array")
    if len(keys) > 4096:
        _fail(f"{pointer}/keys", "must contain at most 4096 admin keys")
    names: set[str] = set()
    for index, item in enumerate(keys):
        key_pointer = f"{pointer}/keys/{index}"
        # No policy metadata lives here on purpose: this store proves a second
        # identity, it never describes what anyone may do.
        entry = _closed_object(item, key_pointer, {"name", "identity"})
        name = _string(entry["name"], f"{key_pointer}/name", 63)
        if not _valid_identifier(name, 63):
            _fail(f"{key_pointer}/name", "invalid admin key name")
        if name in names:
            _fail(f"{key_pointer}/name", "duplicate admin key name")
        names.add(name)

        identity = _closed_object(
            entry["identity"], f"{key_pointer}/identity", {"file", "sha256"}
        )
        identity_ref = _validate_file_text(
            identity["file"], f"{key_pointer}/identity/file"
        )
        fingerprint = _string(
            identity["sha256"], f"{key_pointer}/identity/sha256", 64
        )
        if re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
            _fail(
                f"{key_pointer}/identity/sha256",
                "must be a lowercase SHA-256 fingerprint",
            )
        if fingerprint in authorized_fingerprints:
            _fail(
                f"{key_pointer}/identity/sha256",
                "admin identity must not also appear in authorized_keys",
            )
        identity_pointer = f"{key_pointer}/identity/file"
        try:
            identity_payload = _checked_bytes(
                _resolve_reference(store_path.parent, identity_ref),
                identity_pointer,
            )
            try:
                ders = _composite_public_ders(
                    openssl, identity_payload, identity_pointer, False
                )
                if not hmac.compare_digest(
                    _composite_fingerprint(ders), fingerprint
                ):
                    _fail(identity_pointer, "identity fingerprint does not match")
            finally:
                identity_payload[:] = b"\0" * len(identity_payload)
        except DoctorError as error:
            diagnostics.append(error)


def _check_authorized_keys(
    openssl: str,
    payload: bytearray,
    store_path: Path,
    services: dict[tuple[str, str], int],
    admission_digest: bytes | None,
    diagnostics: list[DoctorError],
) -> set[str]:
    pointer = "/credentials/authorized_keys"
    document = _load_json_payload(payload, pointer)
    store = _closed_object(document, pointer, {"schema", "keys"})
    _integer(store["schema"], f"{pointer}/schema", 1, 1)
    keys = store["keys"]
    if type(keys) is not list:
        _fail(f"{pointer}/keys", "must be an array")
    if not 1 <= len(keys) <= 4096:
        _fail(f"{pointer}/keys", "must contain 1..4096 authorized keys")
    names: set[str] = set()
    psk_digests: set[bytes] = set()
    fingerprints: set[str] = set()
    for index, item in enumerate(keys):
        key_pointer = f"{pointer}/keys/{index}"
        entry = _closed_object(
            item,
            key_pointer,
            {"name", "identity", "access_psk", "capabilities"},
        )
        name = _string(entry["name"], f"{key_pointer}/name", 63)
        if not _valid_identifier(name, 63):
            _fail(f"{key_pointer}/name", "invalid client name")
        if name in names:
            _fail(f"{key_pointer}/name", "duplicate client name")
        names.add(name)

        identity = _closed_object(
            entry["identity"],
            f"{key_pointer}/identity",
            {"file", "sha256"},
        )
        identity_ref = _validate_file_text(
            identity["file"], f"{key_pointer}/identity/file"
        )
        fingerprint = _string(
            identity["sha256"], f"{key_pointer}/identity/sha256", 64
        )
        if re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
            _fail(
                f"{key_pointer}/identity/sha256",
                "must be a lowercase SHA-256 fingerprint",
            )
        fingerprints.add(fingerprint)
        identity_pointer = f"{key_pointer}/identity/file"
        try:
            identity_payload = _checked_bytes(
                _resolve_reference(store_path.parent, identity_ref),
                identity_pointer,
            )
            try:
                ders = _composite_public_ders(
                    openssl, identity_payload, identity_pointer, False
                )
                if not hmac.compare_digest(
                    _composite_fingerprint(ders), fingerprint
                ):
                    _fail(identity_pointer, "identity fingerprint does not match")
            finally:
                identity_payload[:] = b"\0" * len(identity_payload)
        except DoctorError as error:
            diagnostics.append(error)

        psk_object = _closed_object(
            entry["access_psk"],
            f"{key_pointer}/access_psk",
            {"file"},
        )
        psk_ref = _validate_file_text(
            psk_object["file"], f"{key_pointer}/access_psk/file"
        )
        psk_pointer = f"{key_pointer}/access_psk/file"
        try:
            psk_payload = _checked_bytes(
                _resolve_reference(store_path.parent, psk_ref), psk_pointer
            )
            try:
                digest = _secret_digest(psk_payload, psk_pointer)
                if digest in psk_digests:
                    _fail(psk_pointer, "access PSK is reused by another authorized key")
                if admission_digest is not None and hmac.compare_digest(
                    digest, admission_digest
                ):
                    _fail(psk_pointer, "access PSK must differ from admission key")
                psk_digests.add(digest)
            finally:
                psk_payload[:] = b"\0" * len(psk_payload)
        except DoctorError as error:
            diagnostics.append(error)

        capabilities = entry["capabilities"]
        if type(capabilities) is not list:
            _fail(f"{key_pointer}/capabilities", "must be an array")
        if not 1 <= len(capabilities) <= MAX_SERVICES:
            _fail(
                f"{key_pointer}/capabilities",
                f"must contain 1..{MAX_SERVICES} capabilities",
            )
        seen_capabilities: set[tuple[str, str]] = set()
        for capability_index, capability_value in enumerate(capabilities):
            capability_pointer = (
                f"{key_pointer}/capabilities/{capability_index}"
            )
            capability = _closed_object(
                capability_value,
                capability_pointer,
                {"service", "kind"},
            )
            service = _string(
                capability["service"],
                f"{capability_pointer}/service",
                MAX_SERVICE_NAME_BYTES,
            )
            if not _valid_service_name(service):
                _fail(
                    f"{capability_pointer}/service",
                    "must use lowercase ASCII namespace segments",
                )
            kind = _string(
                capability["kind"], f"{capability_pointer}/kind", 16
            )
            capability_key = (service, kind)
            if capability_key in seen_capabilities:
                _fail(f"{capability_pointer}/service", "duplicate capability")
            seen_capabilities.add(capability_key)
            if capability_key not in services:
                _fail(
                    capability_pointer,
                    "capability does not match a configured service",
                )
    return fingerprints


def _check_certificate_and_key(
    openssl: str,
    certificate: bytearray,
    key: bytearray,
    trust: bytearray,
) -> None:
    cert_pointer = "/credentials/tls_certificate"
    key_pointer = "/credentials/tls_key"
    trust_pointer = "/credentials/tls_certificate/trust"
    _openssl(
        openssl,
        ["x509", "-noout", "-checkend", "0"],
        cert_pointer,
        input_bytes=certificate,
    )
    _openssl(
        openssl,
        ["x509", "-noout", "-checkend", "0"],
        trust_pointer,
        input_bytes=trust,
    )
    certificate_public = _openssl(
        openssl,
        ["x509", "-pubkey", "-noout"],
        cert_pointer,
        input_bytes=certificate,
    )
    certificate_public_buffer = bytearray(certificate_public)
    try:
        certificate_der = _normalize_public_der(
            openssl, certificate_public_buffer, cert_pointer
        )
    finally:
        certificate_public_buffer[:] = b"\0" * len(certificate_public_buffer)
    if _public_algorithm(openssl, certificate_der, cert_pointer) != "ED25519":
        _fail(cert_pointer, "TLS certificate must use Ed25519")
    key_blocks = _pem_blocks(key, key_pointer, 1)
    try:
        key_der = _public_der_from_private(openssl, key_blocks[0], key_pointer)
    finally:
        key_blocks[0][:] = b"\0" * len(key_blocks[0])
    if _public_algorithm(openssl, key_der, key_pointer) != "ED25519":
        _fail(key_pointer, "TLS key must use Ed25519")
    if not hmac.compare_digest(certificate_der, key_der):
        _fail(key_pointer, "TLS certificate and private key do not match")

    with tempfile.TemporaryDirectory(prefix="yume-doctor-") as temporary:
        directory = Path(temporary)
        certificate_path = directory / "certificate.pem"
        trust_path = directory / "trust.pem"
        for path, payload in (
            (certificate_path, certificate),
            (trust_path, trust),
        ):
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
            )
            try:
                os.fchmod(descriptor, 0o600)
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        _fail(cert_pointer, "could not stage certificate validation")
                    view = view[written:]
            finally:
                os.close(descriptor)
        _openssl(
            openssl,
            ["verify", "-CAfile", str(trust_path), str(certificate_path)],
            cert_pointer,
        )


def _check_trust(openssl: str, payload: bytearray, pointer: str) -> None:
    _openssl(
        openssl,
        ["x509", "-noout", "-checkend", "0"],
        pointer,
        input_bytes=payload,
    )
    public = _openssl(
        openssl,
        ["x509", "-pubkey", "-noout"],
        pointer,
        input_bytes=payload,
    )
    public_buffer = bytearray(public)
    try:
        der = _normalize_public_der(openssl, public_buffer, pointer)
        if _public_algorithm(openssl, der, pointer) != "ED25519":
            _fail(pointer, "trust certificate must use Ed25519")
    finally:
        public_buffer[:] = b"\0" * len(public_buffer)


def _check_cover(base: Path, reference: str, diagnostics: list[DoctorError]) -> None:
    pointer = "/cover/root"
    root = _resolve_reference(base, reference)
    try:
        status = root.lstat()
        if stat.S_ISLNK(status.st_mode):
            _fail(pointer, "cover root must not be a symlink")
        if not stat.S_ISDIR(status.st_mode):
            _fail(pointer, "cover root must be a directory")
        if not os.access(root, os.R_OK | os.X_OK):
            _fail(pointer, "cover root is not readable")
        index = _checked_bytes(
            root / "index.html", f"{pointer}/index.html", private=False
        )
        try:
            try:
                html = index.decode("utf-8").lower()
            except UnicodeDecodeError:
                _fail(f"{pointer}/index.html", "must be UTF-8 HTML")
            if (
                len(html) < 256
                or "<!doctype html>" not in html
                or "<html" not in html
                or "<body" not in html
            ):
                _fail(
                    f"{pointer}/index.html",
                    "must be a complete static HTML cover page",
                )
            if "yume" in html:
                _fail(
                    f"{pointer}/index.html",
                    "must not expose a YUME-specific public marker",
                )
        finally:
            index[:] = b"\0" * len(index)
    except DoctorError as error:
        diagnostics.append(error)


def _read_services(document: dict[str, Any]) -> dict[tuple[str, str], int]:
    return {
        (service["name"], service["kind"]): service["max_concurrent_streams"]
        for service in document["services"]
    }


def diagnose(config_path: Path) -> list[DoctorError]:
    diagnostics: list[DoctorError] = []
    config_payload: bytearray | None = None
    credential_payloads: dict[str, bytearray] = {}
    try:
        try:
            config_payload = _checked_bytes(config_path, "/config")
            document = _load_json_payload(config_payload, "/config")
            role, references, cover_root = _validate_config(document)
        except DoctorError as error:
            return [error]

        base = config_path.parent
        paths = {
            name: _resolve_reference(base, reference)
            for name, reference in references.items()
        }
        for name, path in paths.items():
            pointer = f"/credentials/{name}"
            try:
                credential_payloads[name] = _checked_bytes(path, pointer)
            except DoctorError as error:
                diagnostics.append(error)

        openssl = shutil.which("openssl")
        if openssl is None:
            diagnostics.append(
                DoctorError("/compatibility/crypto_backend", "OpenSSL is unavailable")
            )
            if role == "server" and cover_root is not None:
                _check_cover(base, cover_root, diagnostics)
            return diagnostics

        composite = credential_payloads.get("composite_key")
        if composite is not None:
            try:
                _check_composite_pair(
                    openssl,
                    composite,
                    paths["composite_key"],
                    "/credentials/composite_key",
                    diagnostics,
                )
            except DoctorError as error:
                diagnostics.append(error)

        if role == "client":
            access_psk = credential_payloads.get("access_psk")
            access_psk_digest: bytes | None = None
            if access_psk is not None:
                try:
                    access_psk_digest = _secret_digest(
                        access_psk, "/credentials/access_psk"
                    )
                except DoctorError as error:
                    diagnostics.append(error)
            admission = credential_payloads.get("admission_key")
            if admission is not None:
                try:
                    admission_digest = _secret_digest(
                        admission, "/credentials/admission_key"
                    )
                    if access_psk_digest is not None and hmac.compare_digest(
                        access_psk_digest, admission_digest
                    ):
                        _fail(
                            "/credentials/admission_key",
                            "must differ from the per-identity access PSK",
                        )
                except DoctorError as error:
                    diagnostics.append(error)
            trust = credential_payloads.get("server_trust")
            if trust is not None:
                try:
                    _check_trust(openssl, trust, "/credentials/server_trust")
                except DoctorError as error:
                    diagnostics.append(error)
            server_identity = credential_payloads.get("server_identity")
            if server_identity is not None:
                try:
                    _composite_public_ders(
                        openssl,
                        server_identity,
                        "/credentials/server_identity",
                        False,
                    )
                except DoctorError as error:
                    diagnostics.append(error)
            mlkem = credential_payloads.get("server_mlkem")
            if mlkem is not None:
                try:
                    _single_public_der(
                        openssl,
                        mlkem,
                        "/credentials/server_mlkem",
                        private=False,
                        algorithm="ML-KEM-1024",
                    )
                except DoctorError as error:
                    diagnostics.append(error)
            return diagnostics

        admission_digest: bytes | None = None
        admission = credential_payloads.get("admission_key")
        if admission is not None:
            try:
                admission_digest = _secret_digest(
                    admission, "/credentials/admission_key"
                )
            except DoctorError as error:
                diagnostics.append(error)

        mlkem_private = credential_payloads.get("mlkem_key")
        if mlkem_private is not None:
            public_pointer = "/credentials/mlkem_key/public"
            try:
                private_der = _single_public_der(
                    openssl,
                    mlkem_private,
                    "/credentials/mlkem_key",
                    private=True,
                    algorithm="ML-KEM-1024",
                )
                public_path = paths["mlkem_key"].with_name("server-mlkem.pub.pem")
                public_payload = _checked_bytes(public_path, public_pointer)
                try:
                    public_der = _single_public_der(
                        openssl,
                        public_payload,
                        public_pointer,
                        private=False,
                        algorithm="ML-KEM-1024",
                    )
                    if not hmac.compare_digest(private_der, public_der):
                        _fail(public_pointer, "does not match the ML-KEM private key")
                finally:
                    public_payload[:] = b"\0" * len(public_payload)
            except DoctorError as error:
                diagnostics.append(error)

        certificate = credential_payloads.get("tls_certificate")
        tls_key = credential_payloads.get("tls_key")
        if certificate is not None and tls_key is not None:
            trust_pointer = "/credentials/tls_certificate/trust"
            try:
                trust_path = paths["tls_certificate"].with_name("server-trust.pem")
                trust_payload = _checked_bytes(trust_path, trust_pointer)
                try:
                    _check_certificate_and_key(
                        openssl, certificate, tls_key, trust_payload
                    )
                finally:
                    trust_payload[:] = b"\0" * len(trust_payload)
            except DoctorError as error:
                diagnostics.append(error)

        authorized = credential_payloads.get("authorized_keys")
        authorized_fingerprints: set[str] = set()
        if authorized is not None:
            try:
                authorized_fingerprints = _check_authorized_keys(
                    openssl,
                    authorized,
                    paths["authorized_keys"],
                    _read_services(document),
                    admission_digest,
                    diagnostics,
                )
            except DoctorError as error:
                diagnostics.append(error)

        admin = credential_payloads.get("admin_keys")
        if admin is not None:
            try:
                _check_admin_keys(
                    openssl,
                    admin,
                    paths["admin_keys"],
                    authorized_fingerprints,
                    diagnostics,
                )
            except DoctorError as error:
                diagnostics.append(error)
        if cover_root is not None:
            _check_cover(base, cover_root, diagnostics)
        return diagnostics
    finally:
        if config_payload is not None:
            config_payload[:] = b"\0" * len(config_payload)
        for payload in credential_payloads.values():
            payload[:] = b"\0" * len(payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yume-doctor-ytp1",
        description=(
            "Validate experimental YTP/1 schema-1 configuration and "
            "credentials; this does not qualify the unwired runtime provider."
        ),
    )
    parser.add_argument("--config", required=True, type=Path)
    return parser


def main() -> int:
    os.umask(0o077)
    arguments = build_parser().parse_args()
    try:
        diagnostics = diagnose(arguments.config)
    except (OSError, ValueError):
        diagnostics = [DoctorError("/diagnostic", "validation could not complete")]
    if diagnostics:
        for diagnostic in diagnostics:
            print(
                "yume-doctor-ytp1: invalid "
                f"{diagnostic.pointer}: {diagnostic.detail}",
                file=sys.stderr,
            )
        return 1
    print(
        "yume-doctor-ytp1: configuration and credentials valid; "
        "runtime provider not qualified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
