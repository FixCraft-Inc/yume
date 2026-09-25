#!/usr/bin/env python3
"""Drive schema-1 named streams through the public C ABI with real credentials."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


CHILD_ASAN_OPTIONS_ENV = "YUME_TEST_CHILD_ASAN_OPTIONS"
IDENTITY_DOMAIN = b"yume/ytp/1/composite-identity/v1"
STREAM_SERVICES = ("echo", "unregistered", "denied")
# The client identity may open echo and unregistered. The server application
# registers echo and denied, so unregistered is refused by registration and
# denied by the credential grant.
GRANTED_SERVICES = ("echo", "unregistered")


def run_openssl(openssl: Path, arguments: list[str], data: bytes) -> bytes:
    result = subprocess.run(
        [str(openssl), *arguments],
        input=data,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            "openssl failed: " + result.stderr.decode(errors="replace").strip()
        )
    return result.stdout


def public_key_blocks(text: str) -> list[str]:
    begin = "-----BEGIN PUBLIC KEY-----"
    end = "-----END PUBLIC KEY-----"
    blocks: list[str] = []
    position = 0
    while True:
        start = text.find(begin, position)
        if start < 0:
            break
        stop = text.find(end, start)
        if stop < 0:
            raise ValueError("truncated public key block")
        stop += len(end)
        blocks.append(text[start:stop] + "\n")
        position = stop
    if len(blocks) != 2:
        raise ValueError("a composite public identity holds exactly two keys")
    return blocks


def composite_fingerprint(openssl: Path, public_identity: Path) -> str:
    """Hash the identity the way the setup and doctor tools do."""
    digest = hashlib.sha256()
    digest.update(IDENTITY_DOMAIN)
    for block in public_key_blocks(public_identity.read_text(encoding="ascii")):
        der = run_openssl(
            openssl, ["pkey", "-pubin", "-outform", "DER"], block.encode()
        )
        digest.update(len(der).to_bytes(4, "big"))
        digest.update(der)
    return digest.hexdigest()


def configure(kit: Path) -> str:
    services = [
        {"name": name, "kind": "stream", "max_concurrent_streams": 8}
        for name in STREAM_SERVICES
    ]
    for relative in ("server/yumed.json", "client/yume.json"):
        path = kit / relative
        config = json.loads(path.read_text(encoding="utf-8"))
        config["services"] = services
        # The embedding backend composes named services only. Declared
        # adapters would make start fail explicitly.
        config["adapters"] = []
        if config["role"] == "server":
            config["endpoint"]["listen_addresses"] = ["127.0.0.1"]
        path.write_text(json.dumps(config), encoding="utf-8")
    authorization = kit / "server/credentials/authorized-keys.json"
    store = json.loads(authorization.read_text(encoding="utf-8"))
    if len(store["keys"]) != 1:
        raise RuntimeError("the generated kit must authorize one client")
    store["keys"][0]["capabilities"] = [
        {"service": name, "kind": "stream"} for name in GRANTED_SERVICES
    ]
    authorization.write_text(json.dumps(store), encoding="utf-8")
    return str(store["keys"][0]["identity"]["sha256"])


def run(probe: Path, openssl: Path, resolver: Path) -> None:
    probe = probe.resolve(strict=True)
    openssl = openssl.resolve(strict=True)
    resolver = resolver.resolve(strict=True)
    if not probe.is_file() or not openssl.is_file() or not resolver.is_file():
        raise ValueError("probe, OpenSSL and resolver helper must be regular files")
    environment = os.environ.copy()
    child_asan_options = environment.pop(CHILD_ASAN_OPTIONS_ENV, None)
    if child_asan_options is not None:
        # The ASan-preloaded Python host disables only leak detection. The
        # instrumented probe keeps the strict leak policy.
        environment["ASAN_OPTIONS"] = child_asan_options
    # Setup selects openssl by PATH. Generation must use the selected library,
    # and unsupported post-quantum algorithms fail rather than skip this gate.
    environment["PATH"] = str(openssl.parent) + os.pathsep + environment.get("PATH", "")
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="yume-abi-ytp1-") as temporary:
        kit = Path(temporary) / "kit"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        # The reservation closes before the native listener binds. A competing
        # bind fails this test instead of connecting to another peer.
        setup = subprocess.run(
            [sys.executable, str(root / "tools/yume_setup.py"), "init",
             "--host", "localhost", "--port", str(port), "--output", str(kit),
             "--client-name", "abi-client"],
            env=environment, capture_output=True, text=True, timeout=75,
            check=False,
        )
        if setup.returncode:
            raise RuntimeError(
                "schema-1 credential provisioning failed: " + setup.stderr.strip()
            )
        client_fingerprint = configure(kit)
        derived = composite_fingerprint(
            openssl, kit / "client/credentials/client-composite.pub.pem"
        )
        if derived != client_fingerprint:
            raise RuntimeError("fingerprint derivation disagrees with the kit")
        server_fingerprint = composite_fingerprint(
            openssl, kit / "server/credentials/server-composite.pub.pem"
        )
        result = subprocess.run(
            [str(probe), str(kit / "server"), str(kit / "client"),
             client_fingerprint, server_fingerprint, str(resolver)],
            cwd=temporary, env=environment, timeout=150, check=False,
        )
        if result.returncode:
            raise RuntimeError(f"schema-1 ABI probe failed with exit {result.returncode}")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--resolver", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.probe, args.openssl, args.resolver)
    except (OSError, ValueError, RuntimeError, KeyError,
            subprocess.TimeoutExpired) as error:
        print(f"schema-1 ABI stream gate: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
