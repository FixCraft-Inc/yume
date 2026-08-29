#!/usr/bin/env python3
"""Federation bootstrap and three-node cluster integration regressions.

The first fixture proves that a bootstrap with no outbound peers remains
federation-enabled and reports a joining node's authenticated inbound link.

The second fixture's topology is a line, not a triangle:

    node-a  <-->  node-b  <-->  node-c

node-b peers with both ends; node-a and node-c are not peers of each other.
That shape is what makes the test worth running. It exercises multi-peer link
fan-out, which no other test covers, and it pins the boundary that a federated
endpoint is exactly one authenticated link away: node-a must never learn or
reach node-c's endpoints through node-b.

If federation forwarding is ever implemented, these single-hop assertions are
the ones that must be changed deliberately -- see
docs/protocol/YUME_2_0_FEDERATION_TRANSIT.md.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from yume_federation_fixture import (
    CoverServers,
    FixtureError,
    ManagedProcess,
    NodeFiles,
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
    server_runtime_socket,
    start_process,
    tcp_ready,
    wait_until,
    write_secret,
)

ALICE_ID = "a" * 32
BOB_ID = "b" * 32
CAROL_ID = "c" * 32

SECRET_PATH_KEYS = ("psk_file", "carrier_secret_file")

# A federation link re-requests its peers' directories every five seconds, so
# hold the far-side absence across more than two refresh cycles. Anything
# shorter can pass by sampling before a leak would have propagated.
FAR_SIDE_ABSENCE_SECONDS = 12.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--yume", type=Path, required=True)
    parser.add_argument("--yumed", type=Path, required=True)
    return parser.parse_args()


def check_status_redaction(socket_path: Path, node_name: str) -> None:
    """federation.status must never expose the operator's secret file paths."""
    status = require_ok(
        runtime_request(socket_path, "federation.status", {}),
        f"{node_name} federation.status",
    )
    encoded = json.dumps(status)
    if status.get("schema_version") != 1:
        raise FixtureError(
            f"{node_name} federation.status schema is not version 1: {encoded}"
        )
    for key in SECRET_PATH_KEYS:
        if key in encoded:
            raise FixtureError(
                f"{node_name} federation.status leaked {key}: {encoded}"
            )
    if ".hex" in encoded:
        raise FixtureError(
            f"{node_name} federation.status leaked a secret path: {encoded}"
        )
    if status.get("enabled") is not True:
        raise FixtureError(f"{node_name} did not report federation enabled")


def check_topology(socket_path: Path, node_name: str,
                   expected_peers: set[str]) -> None:
    topology = require_ok(
        runtime_request(socket_path, "federation.topology", {}),
        f"{node_name} federation.topology",
    )

    if topology.get("schema_version") != 1:
        raise FixtureError(
            f"{node_name} federation.topology schema is not version 1"
        )

    if topology["transit"]["supported"] is not False:
        raise FixtureError(
            f"{node_name} claimed transit support that is not implemented"
        )
    if topology["transit"]["max_hops"] != 1:
        raise FixtureError(
            f"{node_name} advertised a hop budget greater than one: {topology}"
        )

    peers = {node["peer_id"] for node in topology["nodes"]}
    if peers != expected_peers:
        raise FixtureError(
            f"{node_name} topology peers {peers} != expected {expected_peers}"
        )
    for node in topology["nodes"]:
        if node["hops"] != 1 or node["route"] != [node["peer_id"]]:
            raise FixtureError(
                f"{node_name} reported a multi-hop route: {node}"
            )
        if node["ready"] is not True:
            raise FixtureError(f"{node_name} peer is not ready: {node}")

    edges = {(edge["from"], edge["to"]) for edge in topology["edges"]}
    expected_edges = {
        (topology["self"]["server_id"], peer) for peer in expected_peers
    }
    if edges != expected_edges:
        raise FixtureError(
            f"{node_name} topology edges {edges} != expected {expected_edges}"
        )


def check_bootstrap_inbound_visibility(
    socket_path: Path,
    inbound_peer_id: str,
) -> None:
    """A bootstrap's inbound-only peer must remain a visible direct link."""
    check_status_redaction(socket_path, "bootstrap")
    status = require_ok(
        runtime_request(socket_path, "federation.status", {}),
        "bootstrap federation.status",
    )
    peers = status.get("peers") if isinstance(status, dict) else None
    if not isinstance(peers, list):
        raise FixtureError(f"bootstrap status has no peer rows: {status}")
    inbound_rows = [
        peer for peer in peers
        if isinstance(peer, dict) and peer.get("peer_id") == inbound_peer_id
    ]
    if len(inbound_rows) != 1:
        raise FixtureError(
            f"bootstrap status did not show exactly one inbound peer "
            f"{inbound_peer_id}: {status}"
        )
    peer = inbound_rows[0]
    if peer.get("configuration") is not None:
        raise FixtureError(
            f"bootstrap inbound peer unexpectedly has outbound configuration: "
            f"{peer}"
        )
    if peer.get("ready") is not True:
        raise FixtureError(f"bootstrap inbound peer is not ready: {peer}")
    if peer.get("outbound_ready") is not False:
        raise FixtureError(
            f"bootstrap inbound peer claimed an outbound-ready link: {peer}"
        )
    inbound_connections = peer.get("inbound_connections")
    if (not isinstance(inbound_connections, int)
            or isinstance(inbound_connections, bool)
            or inbound_connections < 1):
        raise FixtureError(
            f"bootstrap did not count its inbound federation connection: {peer}"
        )

    check_topology(socket_path, "bootstrap", {inbound_peer_id})
    topology = require_ok(
        runtime_request(socket_path, "federation.topology", {}),
        "bootstrap federation.topology",
    )
    self_node = topology.get("self") if isinstance(topology, dict) else None
    if (not isinstance(self_node, dict)
            or self_node.get("federation_enabled") is not True):
        raise FixtureError(
            f"bootstrap topology did not report federation enabled: {topology}"
        )
    node = topology["nodes"][0]
    edge = topology["edges"][0]
    for description, row in (("node", node), ("edge", edge)):
        if row.get("outbound_ready") is not False:
            raise FixtureError(
                f"bootstrap inbound topology {description} claimed an "
                f"outbound-ready link: {row}"
            )
        connection_count = row.get("inbound_connections")
        if (not isinstance(connection_count, int)
                or isinstance(connection_count, bool)
                or connection_count < 1):
            raise FixtureError(
                f"bootstrap inbound topology {description} lost the inbound "
                f"connection count: {row}"
            )


def run_bootstrap_inbound_fixture(yumed: Path) -> None:
    """Start a no-outbound bootstrap and one node that dials into it."""
    processes: list[ManagedProcess] = []
    covers = CoverServers()
    root = make_temporary_root("yume-federation-bootstrap-")
    try:
        bootstrap = make_node(yumed, root / "bootstrap")
        joiner = make_node(yumed, root / "joiner")
        bootstrap_port = pick_port()
        joiner_port = pick_port()
        pairwise_psk = root / "pairwise-psk.hex"
        write_secret(pairwise_psk)

        bootstrap_link = PeerLink(
            "bootstrap", bootstrap, bootstrap_port, pairwise_psk
        )
        joiner_link = PeerLink("joiner", joiner, joiner_port, pairwise_psk)
        # Enrollment controls who may dial a node. Only the joiner receives an
        # outbound peer entry below; the bootstrap merely authorizes that
        # authenticated inbound federation identity.
        enroll_node(yumed, bootstrap, [joiner_link])
        enroll_node(yumed, joiner, [bootstrap_link])

        bootstrap_argv = server_argv(
            yumed, bootstrap, "1" * 32, "bootstrap", bootstrap_port,
            covers.start(), [], cluster_bootstrap=True,
        )
        if "--peer" in bootstrap_argv:
            raise FixtureError("bootstrap fixture accidentally configured a peer")
        bootstrap_daemon = start_process(
            "bootstrap-yumed", bootstrap_argv, bootstrap.root,
            node_environment(bootstrap),
        )
        processes.append(bootstrap_daemon)
        wait_until(
            "bootstrap listener",
            lambda: tcp_ready(bootstrap_port),
            processes,
        )

        joiner_daemon = start_process(
            "joiner-yumed",
            server_argv(
                yumed, joiner, "2" * 32, "joiner", joiner_port,
                covers.start(), [bootstrap_link],
            ),
            joiner.root,
            node_environment(joiner),
        )
        processes.append(joiner_daemon)
        wait_until(
            "joiner federation link to reach ready",
            lambda: "federation peer ready: bootstrap"
            in joiner_daemon.log_text(),
            processes,
            timeout=60.0,
        )

        check_bootstrap_inbound_visibility(
            server_runtime_socket(bootstrap), "joiner"
        )
        print(
            "PASS: bootstrap stayed federation-enabled with no outbound peers "
            "and reported its direct inbound joiner in status and topology"
        )
    except Exception:
        dump_logs(processes)
        raise
    finally:
        for managed in reversed(processes):
            managed.stop()
        covers.stop()
        shutil.rmtree(root, ignore_errors=True)


def directory_ids(socket_path: Path, node_name: str) -> set[str]:
    entries = require_ok(
        runtime_request(socket_path, "directory.list", {}),
        f"{node_name} directory.list",
    )
    return {entry.get("endpoint_id") for entry in entries}


def check_unreachable(socket_path: Path, target: str, payload: Path,
                      description: str) -> None:
    """A target one hop past a peer must be refused, not routed."""
    response = runtime_request(
        socket_path,
        "bytes.send",
        {"peer": target, "path": str(payload), "password": "unused-password"},
    )
    if response.get("ok") is True:
        raise FixtureError(
            f"{description}: bytes.send to {target} was accepted, so traffic "
            f"crossed more than one federation link"
        )


def run_fixture(yume: Path, yumed: Path) -> None:
    for binary in (yume, yumed):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise FixtureError(f"binary is not executable: {binary}")

    processes: list[ManagedProcess] = []
    covers = CoverServers()
    root = make_temporary_root("yume-federation-cluster-")
    try:
        nodes: dict[str, NodeFiles] = {
            name: make_node(yumed, root / name)
            for name in ("node-a", "node-b", "node-c")
        }
        ports = {name: pick_port() for name in nodes}

        psk_ab = root / "pairwise-a-b.psk"
        psk_bc = root / "pairwise-b-c.psk"
        write_secret(psk_ab)
        write_secret(psk_bc)

        # The line: only node-b names both ends as peers. The two adjacencies
        # deliberately use different PSKs so the fixture proves accepting-side
        # selection by authenticated federation identity.
        peers_of = {
            "node-a": [
                PeerLink("node-b", nodes["node-b"], ports["node-b"], psk_ab)
            ],
            "node-b": [
                PeerLink("node-a", nodes["node-a"], ports["node-a"], psk_ab),
                PeerLink("node-c", nodes["node-c"], ports["node-c"], psk_bc),
            ],
            "node-c": [
                PeerLink("node-b", nodes["node-b"], ports["node-b"], psk_bc)
            ],
        }
        for name, node in nodes.items():
            enroll_node(yumed, node, peers_of[name])

        daemons: dict[str, ManagedProcess] = {}
        for index, name in enumerate(("node-c", "node-b", "node-a")):
            daemon = start_process(
                f"{name}-yumed",
                server_argv(
                    yumed, nodes[name], str(index + 1) * 32, name,
                    ports[name], covers.start(), peers_of[name],
                ),
                nodes[name].root,
                node_environment(nodes[name]),
            )
            daemons[name] = daemon
            processes.append(daemon)
            wait_until(f"{name} listener",
                       lambda port=ports[name]: tcp_ready(port), processes)

        # Four links: a->b, b->a, b->c, c->b. Multi-peer fan-out on node-b is
        # the part no other test covers.
        wait_until(
            "every federation link to reach ready",
            lambda: (
                "federation peer ready: node-b" in daemons["node-a"].log_text()
                and "federation peer ready: node-b" in daemons["node-c"].log_text()
                and "federation peer ready: node-a" in daemons["node-b"].log_text()
                and "federation peer ready: node-c" in daemons["node-b"].log_text()
            ),
            processes,
            timeout=60.0,
        )

        server_sockets = {
            name: server_runtime_socket(node) for name, node in nodes.items()
        }
        for name, socket_path in server_sockets.items():
            check_status_redaction(socket_path, name)
        check_topology(server_sockets["node-a"], "node-a", {"node-b"})
        check_topology(server_sockets["node-c"], "node-c", {"node-b"})
        check_topology(server_sockets["node-b"], "node-b",
                       {"node-a", "node-c"})

        client_ids = {
            "node-a": (ALICE_ID, "alice"),
            "node-b": (BOB_ID, "bob"),
            "node-c": (CAROL_ID, "carol"),
        }
        client_sockets: dict[str, Path] = {}
        for name, node in nodes.items():
            instance = f"cluster-{name}"
            endpoint_id, display = client_ids[name]
            processes.append(start_process(
                f"{name}-yume",
                client_argv(yume, node, ports[name], pick_port(), instance,
                            endpoint_id, display),
                node.root,
                node_environment(node),
            ))
            client_sockets[name] = runtime_socket(node, instance)
        wait_until(
            "every client runtime socket",
            lambda: all(path.exists() for path in client_sockets.values()),
            processes,
        )

        # node-b is peered with both ends, so it learns both. node-a and
        # node-c learn only node-b's own endpoints.
        def middle_sees_both_ends() -> bool:
            ids = directory_ids(client_sockets["node-b"], "node-b")
            return (f"node-a:{ALICE_ID}" in ids
                    and f"node-c:{CAROL_ID}" in ids)

        wait_until("node-b to learn both ends", middle_sees_both_ends,
                   processes, poll_interval=0.5)

        def ends_see_the_middle() -> bool:
            return (f"node-b:{BOB_ID}" in directory_ids(
                        client_sockets["node-a"], "node-a")
                    and f"node-b:{BOB_ID}" in directory_ids(
                        client_sockets["node-c"], "node-c"))

        wait_until("both ends to learn node-b", ends_see_the_middle,
                   processes, poll_interval=0.5)

        # The single-hop directory boundary. node-a is two links from carol, so
        # carol must not appear under any name -- neither node-c's raw ID, nor
        # a namespaced one, nor a two-level path.
        #
        # This has to be a sustained absence, not a single sample. node-b
        # re-requests its peers' directories on a timer, so a node that
        # wrongly re-advertised what it learned would leak on a later refresh,
        # and a one-shot check taken right after the positive assertions would
        # pass by racing it. Hold across several refresh cycles instead.
        #
        # Scope of what this proves today. Four independent layers currently
        # enforce single hop:
        #   1. federation.directory emits list_local_endpoints only;
        #   2. directory_policy's IsEndpointCharacter excludes ':', so a raw
        #      federation ID cannot carry a namespace at all;
        #   3. FederationRaw rejects any endpoint carrying remote/peer fields;
        #   4. a client-visible ID admits exactly one ':'.
        # Removing them was tried: the cluster stops working before a far-side
        # name can surface, so this assertion is not what fails first today.
        # It is the guard that matters once forwarding exists -- at that point
        # a leak parses cleanly and only an absence check catches an unbounded
        # hop count. Keep it, and change it deliberately alongside the gates in
        # docs/protocol/YUME_2_0_FEDERATION_TRANSIT.md.
        far_side = {
            "node-a": (CAROL_ID, "node-c"),
            "node-c": (ALICE_ID, "node-a"),
        }

        def far_endpoint_leaked() -> str:
            for near, (far_id, far_peer) in far_side.items():
                visible = directory_ids(client_sockets[near], near)
                forbidden = {
                    far_id,
                    f"{far_peer}:{far_id}",
                    f"node-b:{far_id}",
                    f"node-b:{far_peer}:{far_id}",
                }
                leaked = visible & forbidden
                if leaked:
                    return f"{near} learned an endpoint two links away: {leaked}"
                multi_hop = {
                    identifier for identifier in visible
                    if identifier is not None and identifier.count(":") > 1
                }
                if multi_hop:
                    return (f"{near} directory contains a multi-hop "
                            f"namespace: {multi_hop}")
                # The far end must also stay absent from the near node's own
                # server view, not merely from what its client renders.
                server_ids = {
                    entry.get("endpoint_id") for entry in require_ok(
                        runtime_request(server_sockets[near],
                                        "directory.list", {}),
                        f"{near} server directory.list")
                }
                if server_ids & forbidden:
                    return (f"{near} server directory holds an endpoint two "
                            f"links away: {server_ids & forbidden}")
            return ""

        deadline = time.monotonic() + FAR_SIDE_ABSENCE_SECONDS
        while time.monotonic() < deadline:
            failure = far_endpoint_leaked()
            if failure:
                raise FixtureError(failure)
            time.sleep(0.5)

        # The routing boundary, which the directory boundary alone does not
        # prove: naming a two-link target explicitly must still be refused.
        payload = root / "unroutable.bin"
        payload.write_bytes(b"this transfer must never be admitted\n")
        for near, far_id, far_peer in (
            ("node-a", CAROL_ID, "node-c"),
            ("node-c", ALICE_ID, "node-a"),
        ):
            for target in (f"{far_peer}:{far_id}",
                           f"node-b:{far_peer}:{far_id}"):
                check_unreachable(client_sockets[near], target, payload, near)

        print(
            "PASS: four federation links ready across three nodes; node-b "
            "learned both ends; neither end learned or reached the other "
            "through it; federation.status redacted secret paths"
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
        yume = args.yume.resolve()
        yumed = args.yumed.resolve()
        for binary in (yume, yumed):
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise FixtureError(f"binary is not executable: {binary}")
        run_bootstrap_inbound_fixture(yumed)
        run_fixture(yume, yumed)
    except (FixtureError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
