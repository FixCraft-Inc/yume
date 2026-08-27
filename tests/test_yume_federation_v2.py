#!/usr/bin/env python3
"""End-to-end AUTH v2 federation test using two real yumed processes.

Acceptance: reciprocal links reach ready, both directories carry the other
node's endpoint, and one federated relay channel delivers exact DATA and CLOSE.
The three-node cluster boundary is a separate test; see
test_yume_federation_cluster.py.
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

from yume_federation_fixture import (
    CoverServers,
    FixtureError,
    ManagedProcess,
    PeerLink,
    client_argv,
    dump_logs,
    enroll_node,
    make_node,
    make_temporary_root,
    node_environment,
    pick_port,
    require_ok,
    runtime_request,
    runtime_socket,
    server_argv,
    start_process,
    tcp_ready,
    wait_until,
    write_secret,
)

ALICE_ID = "a" * 32
BOB_ID = "b" * 32


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--yume", type=Path, required=True)
    parser.add_argument("--yumed", type=Path, required=True)
    return parser.parse_args()


def run_fixture(yume: Path, yumed: Path) -> None:
    if not yume.is_file() or not os.access(yume, os.X_OK):
        raise FixtureError(f"yume binary is not executable: {yume}")
    if not yumed.is_file() or not os.access(yumed, os.X_OK):
        raise FixtureError(f"yumed binary is not executable: {yumed}")

    processes: list[ManagedProcess] = []
    covers = CoverServers()
    root = make_temporary_root("yume-federation-v2-")
    try:
        node_a = make_node(yumed, root / "node-a")
        node_b = make_node(yumed, root / "node-b")

        pairwise_psk = root / "pairwise-psk.hex"
        write_secret(pairwise_psk)

        port_a = pick_port()
        port_b = pick_port()
        link_to_a = PeerLink("node-a", node_a, port_a, pairwise_psk)
        link_to_b = PeerLink("node-b", node_b, port_b, pairwise_psk)

        enroll_node(yumed, node_a, [link_to_b])
        enroll_node(yumed, node_b, [link_to_a])

        daemon_b = start_process(
            "node-b-yumed",
            server_argv(yumed, node_b, "2" * 32, "node-b", port_b,
                        covers.start(), [link_to_a]),
            node_b.root,
            node_environment(node_b),
        )
        processes.append(daemon_b)
        wait_until("node-b listener", lambda: tcp_ready(port_b), processes)

        daemon_a = start_process(
            "node-a-yumed",
            server_argv(yumed, node_a, "1" * 32, "node-a", port_a,
                        covers.start(), [link_to_b]),
            node_a.root,
            node_environment(node_a),
        )
        processes.append(daemon_a)
        wait_until("node-a listener", lambda: tcp_ready(port_a), processes)
        wait_until(
            "reciprocal federation links to reach ready",
            lambda: (
                "federation peer ready: node-b" in daemon_a.log_text()
                and "federation peer ready: node-a" in daemon_b.log_text()
            ),
            processes,
        )

        instance_a = "federation-v2-a"
        instance_b = "federation-v2-b"
        client_b = start_process(
            "node-b-yume",
            client_argv(yume, node_b, port_b, pick_port(), instance_b,
                        BOB_ID, "bob"),
            node_b.root,
            node_environment(node_b),
        )
        processes.append(client_b)
        client_a = start_process(
            "node-a-yume",
            client_argv(yume, node_a, port_a, pick_port(), instance_a,
                        ALICE_ID, "alice"),
            node_a.root,
            node_environment(node_a),
        )
        processes.append(client_a)

        socket_a = runtime_socket(node_a, instance_a)
        socket_b = runtime_socket(node_b, instance_b)
        wait_until(
            "both client runtime sockets",
            lambda: socket_a.exists() and socket_b.exists(),
            processes,
        )

        remote_b = f"node-b:{BOB_ID}"
        remote_a = f"node-a:{ALICE_ID}"

        def reciprocal_directory_visible() -> bool:
            directory_a = require_ok(
                runtime_request(socket_a, "directory.list", {}),
                "node-a directory.list",
            )
            directory_b = require_ok(
                runtime_request(socket_b, "directory.list", {}),
                "node-b directory.list",
            )
            ids_a = {entry.get("endpoint_id") for entry in directory_a}
            ids_b = {entry.get("endpoint_id") for entry in directory_b}
            return remote_b in ids_a and remote_a in ids_b

        wait_until(
            "federation.directory to exchange both endpoints",
            reciprocal_directory_visible,
            processes,
            poll_interval=0.5,
        )

        payload = root / "federation-roundtrip.bin"
        payload_bytes = (
            b"YUME federation AUTH v2 DATA/CLOSE integration\x00"
            + secrets.token_bytes(4096)
        )
        payload.write_bytes(payload_bytes)
        relay_password = "federation-v2-integration-password"
        require_ok(
            runtime_request(
                socket_a,
                "bytes.send",
                {
                    "peer": remote_b,
                    "path": str(payload),
                    "password": relay_password,
                },
            ),
            "bytes.send",
        )

        invite: dict[str, object] = {}

        def invite_arrived() -> bool:
            nonlocal invite
            result = require_ok(
                runtime_request(socket_b, "invite.list", {}),
                "invite.list",
            )
            matching = [
                item for item in result if item.get("channel_kind") == "bytes"
            ]
            if not matching:
                return False
            invite = matching[0]
            return True

        wait_until("federated bytes invite", invite_arrived, processes)
        invite_id = invite.get("invite_id")
        if not isinstance(invite_id, str) or not invite_id:
            raise FixtureError(f"invalid invite id: {invite}")
        require_ok(
            runtime_request(
                socket_b,
                "invite.accept",
                {"invite_selector": invite_id, "password": relay_password},
            ),
            "invite.accept",
        )

        received = node_b.relay_receive_dir / payload.name
        wait_until(
            "federated DATA payload",
            lambda: received.is_file() and received.read_bytes() == payload_bytes,
            processes,
        )
        wait_until(
            "federated channel CLOSE",
            lambda: (
                "channel with alice closed: transfer complete"
                in client_b.log_text()
                and require_ok(
                    runtime_request(socket_b, "runtime.status", {}),
                    "node-b runtime.status",
                ).get("active_channels")
                == 0
            ),
            processes,
        )

        # The contacts surface is durable local trust, so an accepted channel
        # must leave the initiator listed as a contact on the responder.
        contacts = require_ok(
            runtime_request(socket_b, "contacts.list", {}), "contacts.list"
        )
        listed = {item.get("endpoint_id") for item in contacts["contacts"]}
        if remote_a not in listed:
            raise FixtureError(
                f"accepted federated peer {remote_a} is not a contact: {contacts}"
            )

        print(
            "PASS: reciprocal AUTH v2 federation ready; directory exchanged; "
            "one federated channel delivered DATA and CLOSE; peer recorded "
            "as a contact"
        )
    except Exception:
        dump_logs(processes)
        raise
    finally:
        for managed in reversed(processes):
            managed.stop()
        covers.stop()
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    args = parse_args()
    try:
        run_fixture(args.yume.resolve(), args.yumed.resolve())
    except (FixtureError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
