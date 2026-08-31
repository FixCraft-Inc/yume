#!/usr/bin/env python3
"""Provision a self-contained YUME server kit and safely issue client keys."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile


SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z")


class SetupError(RuntimeError):
    pass


def pinned_node_version() -> str:
    script_dir = Path(__file__).resolve().parent
    candidates = (
        script_dir.parent / "tests/fixtures/chrome151-node24/manifest.json",
        script_dir.parent / "share/yume/cover-profile/manifest.json",
    )
    manifest_path = next((path for path in candidates if path.is_file()), None)
    if manifest_path is None:
        raise SetupError(
            "cover profile manifest not found in the source tree or installed "
            "share/yume/cover-profile directory"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    version = manifest.get("server", {}).get("version")
    if (
        not isinstance(version, str)
        or not re.fullmatch(r"\d+(?:\.\d+){2}", version)
    ):
        raise SetupError(f"invalid Node version in cover profile: {manifest_path}")
    return version


def run(args: list[str], *, input_bytes: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            args, input=input_bytes, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
    except FileNotFoundError as exc:
        raise SetupError(f"required command not found: {args[0]}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise SetupError(f"{' '.join(args)} failed: {detail}")
    return result.stdout


def write_private(path: Path, data: str | bytes) -> None:
    payload = data.encode() if isinstance(data, str) else data
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temp_name, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def write_private_files(path: Path, sources: tuple[Path, ...]) -> None:
    """Atomically concatenate private files without loading their contents."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    buffer = bytearray(64 * 1024)
    try:
        os.fchmod(fd, 0o600)
        for source in sources:
            with source.open("rb", buffering=0) as stream:
                while True:
                    count = stream.readinto(buffer)
                    if not count:
                        break
                    view = memoryview(buffer)[:count]
                    while view:
                        view = view[os.write(fd, view):]
                    del view
                    buffer[:count] = b"\0" * count
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temp_name, path)
    finally:
        buffer[:] = b"\0" * len(buffer)
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def write_json(path: Path, value: object) -> None:
    write_private(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def require_name(value: str, label: str) -> str:
    if not SAFE_NAME.fullmatch(value):
        raise SetupError(f"{label} must use only letters, digits, dot, underscore, or dash")
    return value


def require_common_name(value: str, label: str) -> str:
    if not value or len(value) > 64 or any(ch in value for ch in "/\r\n\0"):
        raise SetupError(f"{label} must be 1..64 characters and must not contain '/', NUL, or a newline")
    return value


def validate_endpoint(host: str, port: int) -> None:
    if not 1 <= port <= 65535:
        raise SetupError("port must be in 1..65535")
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    if len(host) > 253 or not all(SAFE_NAME.fullmatch(part) for part in host.split(".")):
        raise SetupError("host must be an IP literal or a simple DNS name")


def composite_fingerprint(classical_public: bytes, pq_public: bytes) -> str:
    domain = b"yume/2.0/composite-identity/v1"
    encoded = bytearray(domain)
    for pem in (classical_public, pq_public):
        der = run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                  input_bytes=pem)
        encoded.extend(len(der).to_bytes(4, "big"))
        encoded.extend(der)
    return hashlib.sha256(encoded).hexdigest()


def cert_fingerprint(cert: Path) -> str:
    der = run(["openssl", "x509", "-in", str(cert), "-outform", "DER"])
    return hashlib.sha256(der).hexdigest()


def generate_keypair(private_key: Path, public_key: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="yume-composite-") as work:
        work_dir = Path(work)
        classical_private = work_dir / "ed25519.key"
        pq_private = work_dir / "ml-dsa-87.key"
        run(["openssl", "genpkey", "-algorithm", "Ed25519",
             "-out", str(classical_private)])
        run(["openssl", "genpkey", "-algorithm", "ML-DSA-87",
             "-out", str(pq_private)])
        classical_public = run(["openssl", "pkey", "-in", str(classical_private),
                                "-pubout"])
        pq_public = run(["openssl", "pkey", "-in", str(pq_private), "-pubout"])
        write_private_files(private_key, (classical_private, pq_private))
    write_private(public_key, classical_public + pq_public)
    return composite_fingerprint(classical_public, pq_public)


def sign_leaf(*, ca_key: Path, ca_cert: Path, key: Path, cert: Path,
              common_name: str, extensions: str, days: int,
              key_algorithm: str = "Ed25519") -> None:
    with tempfile.TemporaryDirectory(prefix="yume-cert-") as tmp:
        csr = Path(tmp) / "leaf.csr"
        ext = Path(tmp) / "leaf.ext"
        write_private(ext, extensions)
        key_command = ["openssl", "genpkey", "-algorithm", key_algorithm]
        if key_algorithm == "EC":
            key_command += ["-pkeyopt", "ec_paramgen_curve:P-256"]
        run(key_command + ["-out", str(key)])
        run(["openssl", "req", "-new", "-key", str(key), "-out", str(csr),
             "-subj", f"/CN={common_name}"])
        run(["openssl", "x509", "-req", "-in", str(csr),
             "-CA", str(ca_cert), "-CAkey", str(ca_key),
             "-set_serial", "0x" + secrets.token_hex(16), "-days", str(days),
             "-extfile", str(ext), "-out", str(cert)])
    os.chmod(key, 0o600)
    run(["openssl", "verify", "-CAfile", str(ca_cert), str(cert)])


def make_ca(ca_dir: Path, operator_name: str, days: int) -> tuple[Path, Path]:
    key = ca_dir / "operator-ca.key"
    cert = ca_dir / "operator-ca.pem"
    run(["openssl", "genpkey", "-algorithm", "EC",
         "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key)])
    run(["openssl", "req", "-x509", "-new", "-key", str(key), "-out", str(cert),
         "-days", str(days), "-subj", f"/CN={operator_name}",
         "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash"])
    os.chmod(key, 0o600)
    return key, cert


def append_public_key(store: Path, public_key: Path) -> None:
    current = store.read_bytes() if store.exists() else b""
    pem = public_key.read_bytes()
    if pem in current:
        raise SetupError(f"public key is already present in {store}")
    write_private(store, current + pem)


def update_policy(store: Path, fingerprint: str, policy: dict[str, object]) -> None:
    current: dict[str, object] = {}
    if store.exists() and store.stat().st_size:
        loaded = json.loads(store.read_text())
        if not isinstance(loaded, dict):
            raise SetupError(f"metadata is not a JSON object: {store}")
        current = loaded
    if fingerprint in current:
        raise SetupError(f"fingerprint already has metadata in {store}")
    current[fingerprint] = policy
    write_json(store, current)


def copy_client_material(server_dir: Path, client_dir: Path, identity: Path,
                         public_key: Path, *, host: str, port: int,
                         tls_name: str, tls_pin: str, alias: str,
                         operator: bool,
                         admin_identity: Path | None = None,
                         admin_public_key: Path | None = None) -> None:
    client_dir.mkdir(mode=0o700, parents=True)
    for source, dest in (
        (identity, "identity.key"),
        (public_key, "identity.pub"),
        (server_dir / "operator-ca.pem", "operator-ca.pem"),
        (server_dir / "admission.hex", "admission.hex"),
        (server_dir / "inner-psk.hex", "inner-psk.hex"),
    ):
        shutil.copyfile(source, client_dir / dest)
        os.chmod(client_dir / dest, 0o600)
    if (admin_identity is None) != (admin_public_key is None):
        raise SetupError("admin identity must include both private and public files")
    if admin_identity is not None and admin_public_key is not None:
        for source, dest in (
            (admin_identity, "admin-identity.key"),
            (admin_public_key, "admin-identity.pub"),
        ):
            shutil.copyfile(source, client_dir / dest)
            os.chmod(client_dir / dest, 0o600)
    config = {
        "server": host,
        "port": port,
        "identity": "identity.key",
        "obfuscation": True,
        "obfs_secret_file": "admission.hex",
        "inner_psk_file": "inner-psk.hex",
        "inner_crypto": True,
        "inner_heavy": True,
        "tunnels": 1,
        "tls_ca_cert": "operator-ca.pem",
        "tls_server_name": tls_name,
        "tls_pin": tls_pin,
        "anonym_ca_cert": "operator-ca.pem",
        "require_anonym": True,
        "accept_monitoring": False,
        "tls_stealth_profile": "chrome",
        "preferred_name": alias,
    }
    if operator:
        config["allow_outbound_admin"] = True
    if admin_identity is not None:
        config["admin_identity"] = "admin-identity.key"
    write_json(client_dir / "yume.json", config)
    client_runner = """#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ -n "${YUME_BIN:-}" ]]; then
  yume_bin="$YUME_BIN"
elif [[ -x "$HOME/yume/build/bin/yume" ]]; then
  yume_bin="$HOME/yume/build/bin/yume"
elif command -v yume >/dev/null 2>&1; then
  yume_bin="$(command -v yume)"
else
  echo "yume not found; run ~/yume/ezbuild.sh or set YUME_BIN" >&2
  exit 1
fi
exec "$yume_bin" --config yume.json --socks "127.0.0.1:${YUME_SOCKS_PORT:-1080}"
"""
    export_runner = f"""#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ -n "${{YUME_BIN:-}}" ]]; then
  yume_bin="$YUME_BIN"
elif [[ -x "$HOME/yume/build/bin/yume" ]]; then
  yume_bin="$HOME/yume/build/bin/yume"
elif command -v yume >/dev/null 2>&1; then
  yume_bin="$(command -v yume)"
else
  echo "yume not found; run ~/yume/ezbuild.sh or set YUME_BIN" >&2
  exit 1
fi
output_path="${{1:-{alias}.yss}}"
exec "$yume_bin" --config yume.json export "$output_path"
"""
    for name, text in (("start-socks", client_runner), ("export-yss", export_runner)):
        write_private(client_dir / name, text)
        os.chmod(client_dir / name, 0o700)
    guide = f"""YUME device profile: {alias}

Server: {host}
Port: {port}
TLS/SNI name: {tls_name}
TLS certificate SHA-256 pin: {tls_pin}
Operator identity: required
TLS profile: chrome

Android manual fields:
  Admission secret: contents of admission.hex
  Inner PSK: contents of inner-psk.hex
  Auth private key: identity.key
  Operator CA: operator-ca.pem (removable/replacable by the user)

Desktop:
  SOCKS:   ./start-socks
  VPN/TUN: ${{YUME_BIN:-$HOME/yume/build/bin/yume}} --config yume.json --packet-tun yume-client0

Encrypted Android/desktop share file (run from this directory):
  ./export-yss [output.yss]   # BaseFWX requires a 12+ character password
"""
    write_private(client_dir / "DEVICE_SETUP.txt", guide)


def issue_key(*, kit: Path, alias: str, key_type: str, weight: float,
              max_sessions: int) -> Path:
    require_name(alias, "alias")
    manifest_path = kit / "manifest.json"
    if not manifest_path.is_file():
        raise SetupError(f"not a YUME setup directory: {kit}")
    manifest = json.loads(manifest_path.read_text())
    server_dir = kit / "server"
    client_dir = kit / "clients" / alias
    if client_dir.exists():
        raise SetupError(f"client output already exists: {client_dir}")
    if not 0.1 <= weight <= 100.0:
        raise SetupError("weight must be in 0.1..100")
    if not 1 <= max_sessions <= 65535:
        raise SetupError("max-sessions must be in 1..65535")

    with tempfile.TemporaryDirectory(prefix="yume-client-") as tmp:
        private_key = Path(tmp) / "identity.key"
        public_key = Path(tmp) / "identity.pub"
        fingerprint = generate_keypair(private_key, public_key)
        operator = key_type == "admin"
        admin_private_key: Path | None = None
        admin_public_key: Path | None = None
        if operator:
            key_store = server_dir / "operator_keys"
            meta_store = server_dir / "operator_keys.json"
            policy: dict[str, object] = {"alias": alias, "weight": weight}
            admin_private_key = Path(tmp) / "admin-identity.key"
            admin_public_key = Path(tmp) / "admin-identity.pub"
            generate_keypair(admin_private_key, admin_public_key)
            append_public_key(server_dir / "admin_keys", admin_public_key)
        else:
            key_store = server_dir / "authorized_keys"
            meta_store = server_dir / "authorized_keys.json"
            policy = {"alias": alias, "key_type": key_type, "weight": weight}
            if key_type == "bulk":
                policy["max_sessions"] = max_sessions
                policy["permissions"] = {
                    "allow_chat": False, "allow_file": False, "allow_bytes": False,
                }
        append_public_key(key_store, public_key)
        update_policy(meta_store, fingerprint, policy)
        copy_client_material(
            server_dir, client_dir, private_key, public_key,
            host=manifest["host"], port=manifest["port"],
            tls_name=manifest["tls_name"], tls_pin=manifest["tls_pin_sha256"],
            alias=alias, operator=operator,
            admin_identity=admin_private_key,
            admin_public_key=admin_public_key,
        )
    return client_dir


def server_scripts(server_dir: Path, listen_address: str, port: int,
                   allow_from: str, packet_cidr: str, mtu: int) -> None:
    node_version = pinned_node_version()
    start_cover = f"""#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
exec npx --yes node@{node_version} backend.mjs
"""
    start_server = f"""#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ -n "${{YUMED_BIN:-}}" ]]; then
  yumed_bin="$YUMED_BIN"
elif [[ -x "$HOME/yume/build/bin/yumed" ]]; then
  yumed_bin="$HOME/yume/build/bin/yumed"
elif command -v yumed >/dev/null 2>&1; then
  yumed_bin="$(command -v yumed)"
else
  echo "yumed not found; run ~/yume/ezbuild.sh or set YUMED_BIN" >&2
  exit 1
fi
for _ in $(seq 1 100); do
  if (exec 3<>/dev/tcp/127.0.0.1/3000) 2>/dev/null; then exec 3>&-; exec 3<&-; break; fi
  sleep 0.1
done
if ! (exec 3<>/dev/tcp/127.0.0.1/3000) 2>/dev/null; then
  echo "cover backend is not listening; run ./start-cover first" >&2
  exit 1
fi
exec "$yumed_bin" --config yumed.json --listen {listen_address}:{port}
"""
    packet_helper = """if command -v yume-packet-quick >/dev/null 2>&1; then
  packet_helper=("$(command -v yume-packet-quick)")
elif [[ -f "$HOME/yume/tools/yume_packet_quick.py" ]]; then
  packet_helper=(python3 "$HOME/yume/tools/yume_packet_quick.py")
else
  echo "yume-packet-quick not found; install YUME or keep the clone at ~/yume" >&2
  exit 1
fi
"""
    packet_up = ("#!/usr/bin/env bash\nset -euo pipefail\n" + packet_helper +
                 f"exec sudo \"${{packet_helper[@]}}\" up --listen {listen_address}:{port} "
                 f"--allow-from {allow_from} --packet-cidr {packet_cidr} --mtu {mtu}\n")
    packet_down = ("#!/usr/bin/env bash\nset -euo pipefail\n" + packet_helper +
                   "exec sudo \"${packet_helper[@]}\" down\n")
    for name, text in (("start-cover", start_cover), ("start-yumed", start_server),
                       ("packet-up", packet_up), ("packet-down", packet_down)):
        write_private(server_dir / name, text)
        os.chmod(server_dir / name, 0o700)


def init_kit(args: argparse.Namespace) -> None:
    output = args.output.resolve()
    if output.exists():
        raise SetupError(f"refusing to overwrite existing path: {output}")
    validate_endpoint(args.host, args.port)
    listen_address = args.listen_address or args.host
    try:
        if ipaddress.ip_address(listen_address).version != 4:
            raise SetupError("listen address must be IPv4")
    except ValueError as exc:
        raise SetupError("--listen-address is required as a local IPv4 address when --host is DNS") from exc
    require_name(args.tls_name, "TLS name")
    require_common_name(args.operator_name, "operator name")
    require_name(args.client_name, "client name")
    allow_network = ipaddress.ip_network(args.allow_from, strict=False)
    packet_network = ipaddress.ip_network(args.packet_cidr, strict=True)
    dns_address = ipaddress.ip_address(args.dns)
    if allow_network.version != 4 or packet_network.version != 4 or dns_address.version != 4:
        raise SetupError("allow-from, packet CIDR, and DNS must currently be IPv4")
    if not 24 <= packet_network.prefixlen <= 30:
        raise SetupError("packet CIDR prefix must be /24 through /30")
    if not 576 <= args.mtu <= 65535:
        raise SetupError("MTU must be in 576..65535")
    for label, value, maximum in (
        ("CA days", args.ca_days, 36500), ("certificate days", args.cert_days, 36500),
        ("max sessions", args.max_sessions, 1_000_000),
        ("bulk max sessions", args.bulk_max_sessions, 65535),
        ("accept rate", args.accept_rate, 1_000_000),
    ):
        if not 0 < value <= maximum:
            raise SetupError(f"{label} must be in 1..{maximum}")
    if not 0 <= args.egress_mbps <= 4_294_967_295:
        raise SetupError("egress Mbps must be in 0..4294967295")

    staging = output.with_name(output.name + ".tmp-" + secrets.token_hex(4))
    try:
        staging.mkdir(mode=0o700, parents=True)
        server_dir = staging / "server"
        clients_dir = staging / "clients"
        ca_dir = staging / "offline-ca"
        for path in (server_dir, clients_dir, ca_dir):
            path.mkdir(mode=0o700)

        if args.ca_key or args.ca_cert:
            if not args.ca_key or not args.ca_cert:
                raise SetupError("--ca-key and --ca-cert must be used together")
            ca_key, ca_cert = args.ca_key.resolve(), args.ca_cert.resolve()
            if not ca_key.is_file() or not ca_cert.is_file():
                raise SetupError("existing CA key/certificate is not readable")
        else:
            ca_key, ca_cert = make_ca(ca_dir, args.operator_name, args.ca_days)
        shutil.copyfile(ca_cert, server_dir / "operator-ca.pem")
        os.chmod(server_dir / "operator-ca.pem", 0o600)

        san_kind = "IP" if _is_ip(args.host) else "DNS"
        tls_ext = ("basicConstraints=critical,CA:FALSE\n"
                   "keyUsage=critical,digitalSignature\n"
                   "extendedKeyUsage=serverAuth\n"
                   f"subjectAltName={san_kind}:{args.host},DNS:{args.tls_name}\n")
        sign_leaf(ca_key=ca_key, ca_cert=ca_cert,
                  key=server_dir / "server-tls.key", cert=server_dir / "server-tls.pem",
                  common_name=args.tls_name, extensions=tls_ext, days=args.cert_days,
                  key_algorithm="EC")
        identity_ext = ("basicConstraints=critical,CA:FALSE\n"
                        "keyUsage=critical,digitalSignature\n"
                        "subjectKeyIdentifier=hash\n"
                        "authorityKeyIdentifier=keyid,issuer\n")
        sign_leaf(ca_key=ca_key, ca_cert=ca_cert,
                  key=server_dir / "operator-delegated.key",
                  cert=server_dir / "operator-delegated.pem",
                  common_name=args.tls_name, extensions=identity_ext, days=args.cert_days)

        write_private(server_dir / "admission.hex", secrets.token_hex(32))
        write_private(server_dir / "inner-psk.hex", secrets.token_hex(32))
        for name in ("authorized_keys", "operator_keys", "admin_keys"):
            write_private(server_dir / name, b"")
        for name in ("authorized_keys.json", "operator_keys.json"):
            write_json(server_dir / name, {})
        script_dir = Path(__file__).resolve().parent
        backend_candidates = (
            script_dir / "cover-node" / "backend.mjs",
            script_dir.parent / "share" / "yume" / "cover-node" / "backend.mjs",
        )
        backend = next((path for path in backend_candidates if path.is_file()), None)
        if backend is None:
            raise SetupError("cover backend not found beside the clone or under share/yume")
        shutil.copyfile(backend, server_dir / "backend.mjs")
        os.chmod(server_dir / "backend.mjs", 0o600)

        server_cfg = {
            "listen_port": args.port,
            "tls_cert": "server-tls.pem", "tls_key": "server-tls.key",
            "auth_keys": "authorized_keys", "auth_keys_meta": "authorized_keys.json",
            "admin_keys": "admin_keys",
            "operator_keys": "operator_keys", "operator_keys_meta": "operator_keys.json",
            "obfuscation": True, "obfs_secret_file": "admission.hex",
            "inner_psk_file": "inner-psk.hex", "inner_crypto": True,
            "inner_heavy": True,
            "real_backend": "loopback://127.0.0.1:3000",
            "anonym": True, "anonym_proof_mode": "local",
            "anonym_sub_key": "operator-delegated.key",
            "anonym_sub_cert": "operator-delegated.pem",
            "packet_egress": "tun", "packet_tun_name": "yume-pkt0",
            "packet_cidr": args.packet_cidr, "packet_mtu": args.mtu,
            "dns_server": args.dns, "max_sessions": args.max_sessions,
            "bulk_key_max_sessions": args.bulk_max_sessions,
            "accept_rate_limit": args.accept_rate,
            "egress_mbps": args.egress_mbps,
        }
        write_json(server_dir / "yumed.json", server_cfg)
        tls_pin = cert_fingerprint(server_dir / "server-tls.pem")
        manifest = {
            "format": 1, "host": args.host, "port": args.port,
            "tls_name": args.tls_name, "tls_pin_sha256": tls_pin,
            "operator_ca_sha256": cert_fingerprint(server_dir / "operator-ca.pem"),
            "packet_cidr": args.packet_cidr,
        }
        write_json(staging / "manifest.json", manifest)
        server_scripts(server_dir, listen_address, args.port, args.allow_from,
                       args.packet_cidr, args.mtu)
        client_dir = issue_key(kit=staging, alias=args.client_name,
                               key_type=args.key_type, weight=args.weight,
                               max_sessions=args.key_max_sessions)
        output.parent.mkdir(parents=True, exist_ok=True)
        staging.rename(output)
        client_dir = output / client_dir.relative_to(staging)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    print(f"Created secure YUME kit: {output}")
    print(f"Initial device profile: {client_dir}")
    print("\nOn the server:")
    print(f"  cd {output / 'server'}")
    print("  ./packet-up")
    print("  ./start-cover       # terminal 1")
    print("  ./start-yumed       # terminal 2")
    print("\nOn Android, import the files/values described in:")
    print(f"  {client_dir / 'DEVICE_SETUP.txt'}")
    if not args.ca_key:
        print("\nTest CA private key is under offline-ca/. Move it off the server for real deployment.")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yume-setup",
        description="Generate CSPRNG YUME secrets, certificates, configs, and client profiles.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="create a new server kit and first client")
    init.add_argument("--output", type=Path, required=True)
    init.add_argument("--host", required=True, help="server IP or DNS name")
    init.add_argument("--listen-address", help="local IPv4 bind address (defaults to --host)")
    init.add_argument("--port", type=int, default=8443)
    init.add_argument("--tls-name", default="yume-server")
    init.add_argument("--operator-name", default="YUME test operator")
    init.add_argument("--client-name", default="device1")
    init.add_argument("--key-type", choices=("individual", "bulk", "admin"), default="individual")
    init.add_argument("--weight", type=float, default=1.0)
    init.add_argument("--key-max-sessions", type=int, default=64)
    init.add_argument("--ca-key", type=Path)
    init.add_argument("--ca-cert", type=Path)
    init.add_argument("--ca-days", type=int, default=3650)
    init.add_argument("--cert-days", type=int, default=365)
    init.add_argument("--allow-from", default="192.168.0.0/16")
    init.add_argument("--packet-cidr", default="10.89.0.0/24")
    init.add_argument("--mtu", type=int, default=1420)
    init.add_argument("--dns", default="1.1.1.1")
    init.add_argument("--max-sessions", type=int, default=256)
    init.add_argument("--bulk-max-sessions", type=int, default=64)
    init.add_argument("--accept-rate", type=int, default=30)
    init.add_argument("--egress-mbps", type=int, default=0,
                      help="server upload cap; set at/below real uplink (0 disables)")

    key = sub.add_parser("issue-key", help="issue another individual, bulk, or admin key")
    key.add_argument("--kit", type=Path, required=True)
    key.add_argument("--name", required=True)
    key.add_argument("--type", choices=("individual", "bulk", "admin"), default="individual")
    key.add_argument("--weight", type=float, default=1.0)
    key.add_argument("--max-sessions", type=int, default=64)
    return parser


def main() -> int:
    os.umask(0o077)
    args = build_parser().parse_args()
    try:
        if args.command == "init":
            init_kit(args)
        else:
            client = issue_key(kit=args.kit.resolve(), alias=args.name,
                               key_type=args.type, weight=args.weight,
                               max_sessions=args.max_sessions)
            print(f"Issued {args.type} key and device profile: {client}")
        return 0
    except (SetupError, json.JSONDecodeError, OSError, ValueError) as exc:
        print(f"yume-setup: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
