#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))

import yume_circuit_cable as circuit_cable  # noqa: E402
import yume_circuit_capture as circuit_capture  # noqa: E402
import yume_circuit_wan as circuit_wan  # noqa: E402
import yume_ethernet_smoke as ethernet  # noqa: E402
import yume_ndpi_report as ndpi  # noqa: E402
import yume_wan_emulation as wan  # noqa: E402

READER_TEXT = """
Traffic statistics:
\tEthernet bytes:        177540        (includes ethernet CRC/IFC/trailer)
\tDiscarded bytes:       {discarded}
\tIP packets:            991           of 1214 packets total
\tIP bytes:              153756        (avg pkt size 126 bytes)
\tMax Packet size:       1480

\t1\tTCP 127.0.0.1:41310 <-> 127.0.0.1:443 [proto: 91/TLS][Confidence: DPI][Hostname/SNI: cdn.example.test][JA4: t13d1516h2_8daaf6152771_806a8c22fdea][Plen Bins: 0,14,12]
\t2\tTCP 127.0.0.1:5000 <-> 127.0.0.1:8080 [proto: 7/HTTP][Confidence: DPI]
"""
PIPE_CSV = """#flow_id|protocol|src_ip|src_port|dst_ip|dst_port|ndpi_proto|server_name_sni
0|6|127.0.0.1|41310|127.0.0.1|443|TLS|cdn.example.test
1|6|127.0.0.1|5000|127.0.0.1|8080|HTTP|
"""
COMMA_CSV = """flow_id,protocol,src_ip,src_port,dst_ip,dst_port,ndpi_proto,server_name_sni
0,6,127.0.0.1,41310,127.0.0.1,443,TLS,cdn.example.test
"""
ETHTOOL = """Features for eno1:
rx-checksumming: on
tcp-segmentation-offload: on
\ttx-tcp-segmentation: on
generic-segmentation-offload: off [fixed]
generic-receive-offload: on
large-receive-offload: off [fixed]
"""


class NdpiReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="yume-evaluation-reports-")
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_pipe_delimited_csv_selects_rows_on_the_port(self) -> None:
        rows = ndpi.flows_on_port(self.write("flows.csv", PIPE_CSV), 443)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["server_name_sni"], "cdn.example.test")

    def test_comma_delimited_csv_is_still_read(self) -> None:
        rows = ndpi.flows_on_port(self.write("flows.csv", COMMA_CSV), 443)
        self.assertEqual([row["ndpi_proto"] for row in rows], ["TLS"])

    def test_missing_or_empty_csv_has_no_flows(self) -> None:
        self.assertEqual(ndpi.flows_on_port(self.root / "absent.csv", 443), [])
        self.assertEqual(ndpi.flows_on_port(self.write("empty.csv", ""), 443), [])

    def test_text_report_totals_and_flows_on_the_port(self) -> None:
        report = ndpi.reader_report(self.write("reader.txt", READER_TEXT.format(discarded=0)), 443)
        self.assertEqual((report["ip_bytes"], report["discarded_bytes"], report["max_packet_bytes"]),
                         (153756, 0, 1480))
        self.assertEqual(len(report["flows"]), 1)
        self.assertIn("127.0.0.1:443 ", report["flows"][0])

    def test_discarded_bytes_or_a_missing_flow_fail_the_capture(self) -> None:
        clean = ndpi.reader_report(self.write("clean.txt", READER_TEXT.format(discarded=0)), 443)
        clean["csv_flows"] = [{"dst_port": "443"}]
        self.assertEqual(ndpi.capture_failures("clean", clean, 443), [])
        dropped = ndpi.reader_report(self.write("dropped.txt", READER_TEXT.format(discarded=12632258)), 443)
        dropped["csv_flows"] = []
        failures = ndpi.capture_failures("dropped", dropped, 443)
        self.assertEqual(len(failures), 2)
        self.assertTrue(any("12632258" in failure for failure in failures))

    def test_flow_summary_keeps_classification_without_bins(self) -> None:
        line = ndpi.reader_report(self.write("reader.txt", READER_TEXT.format(discarded=0)), 443)["flows"][0]
        summary = ndpi.flow_summary(line)
        self.assertIn("JA4: t13d1516h2_8daaf6152771_806a8c22fdea", summary)
        self.assertIn("Hostname/SNI: cdn.example.test", summary)
        self.assertNotIn("Plen Bins", summary)


class EthernetReportTest(unittest.TestCase):
    def test_tcpdump_counts(self) -> None:
        counts = ethernet.tcpdump_counts("3823 packets captured\n3823 packets received by filter\n"
                                         "0 packets dropped by kernel\n")
        self.assertEqual(counts, {"captured": 3823, "received_by_filter": 3823, "dropped_by_kernel": 0})
        self.assertEqual(ethernet.tcpdump_counts("tcpdump: eno1: No such device"),
                         {"captured": None, "received_by_filter": None, "dropped_by_kernel": None})

    def test_offloads_ignore_sub_features_and_fixed_markers(self) -> None:
        self.assertEqual(ethernet.parse_offloads(ETHTOOL), {"tso": "on", "gso": "off", "gro": "on"})

    def test_rate_is_decimal_megabits(self) -> None:
        self.assertEqual(ethernet.rate(125_000_000, 1.0), 1000.0)
        self.assertEqual(ethernet.rate(1, 0.0), 0.0)



class WanEmulationTest(unittest.TestCase):
    def test_condition_fields_default_to_an_unshaped_link(self) -> None:
        self.assertEqual(wan.parse_condition("rtt=100,loss=0.5"),
                         {"rtt_ms": 100.0, "loss_percent": 0.5, "rate_mbit": 0.0})
        for text in ("delay=10", "rtt=-1", "rtt=nan", "rtt=10,loss=25", "rtt"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                wan.parse_condition(text)

    def test_each_direction_delays_half_the_round_trip(self) -> None:
        self.assertEqual(wan.netem_arguments(wan.parse_condition("rtt=100,loss=1")),
                         ["netem", "delay", "50ms", "loss", "1%", "limit", str(wan.UNSHAPED_QUEUE_PACKETS)])

    def test_a_rate_limit_sizes_the_queue_from_the_path(self) -> None:
        # 50 Mbit/s at 200 ms holds about 834 full packets in flight.
        self.assertEqual(wan.netem_arguments(wan.parse_condition("rtt=200,rate=50"))[-4:],
                         ["rate", "50mbit", "limit", "3334"])
        self.assertEqual(wan.netem_arguments(wan.parse_condition("rtt=2,rate=10"))[-1], "1000")

    def test_pattern_check_follows_the_cycle_across_chunks(self) -> None:
        check = wan.PatternCheck()
        stream = bytes(range(256)) * 9000
        for start in range(0, len(stream), 70001):
            check.feed(stream[start:start + 70001])
        self.assertEqual(check.offset, len(stream))
        # The stream ended on a whole cycle, so the next byte must be 0x00.
        with self.assertRaises(wan.session.SessionFailure):
            check.feed(b"\x01")

    def test_fairness_is_one_for_equal_streams_and_one_over_n_for_a_hog(self) -> None:
        self.assertAlmostEqual(wan.fairness_index([40.0, 40.0, 40.0, 40.0]), 1.0)
        self.assertAlmostEqual(wan.fairness_index([160.0, 0.0, 0.0, 0.0]), 0.25)
        self.assertAlmostEqual(wan.fairness_index([0.0, 0.0]), 1.0)
        for rates in ([], [1.0, -1.0], [float("nan")]):
            with self.subTest(rates=rates), self.assertRaises(ValueError):
                wan.fairness_index(rates)

    def test_plateau_compares_the_last_quarter_with_the_second(self) -> None:
        # The first quarter is warm-up and may climb freely.
        flat = [10, 50, 100, 101, 100, 102, 101, 103]
        self.assertTrue(wan.plateau(flat, 1.10, 0)["flat"])
        growing = [10, 50, 100, 110, 120, 130, 140, 150]
        check = wan.plateau(growing, 1.10, 0)
        self.assertFalse(check["flat"])
        self.assertEqual((check["baseline_peak"], check["final_peak"]), (110, 150))
        self.assertTrue(wan.plateau([5, 6, 6, 6, 6, 6, 7, 8], 1.0, 2)["flat"])
        with self.assertRaises(ValueError):
            wan.plateau([1, 2, 3], 1.0, 0)

    def test_process_resources_reads_this_process(self) -> None:
        resources = wan.process_resources(os.getpid())
        self.assertGreater(resources["rss_kib"], 0)
        self.assertGreaterEqual(resources["fds"], 3)

    def test_parallel_downloads_run_at_once_and_check_every_byte(self) -> None:
        port = wan.session.free_port()
        server = subprocess.Popen(
            [sys.executable, "-c", wan.PAYLOAD_SERVER, str(wan.STREAM_BYTES), str(wan.SMALL_BYTES), str(port)],
            stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(server.stdout.readline().strip(), "ready")
            started = time.monotonic()
            outcome = wan.parallel_downloads(None, "127.0.0.1", port, 2.0, 3)
            # Three sequential two-second windows would take six seconds.
            self.assertLess(time.monotonic() - started, 5.0)
            self.assertEqual(len(outcome["streams"]), 3)
            self.assertTrue(all(stream["bytes"] > 0 for stream in outcome["streams"]))
            self.assertGreater(outcome["fairness"], 0.0)
            self.assertLessEqual(outcome["fairness"], 1.0)
            self.assertGreater(outcome["aggregate_tail_mbit_s"], 0.0)
        finally:
            server.kill()
            server.wait(timeout=5)
            server.stdout.close()
        with self.assertRaises(wan.session.SessionFailure):
            wan.parallel_downloads(None, "127.0.0.1", port, 2.0, 2)


class CircuitWanTest(unittest.TestCase):
    def test_every_side_has_its_own_network(self) -> None:
        # Distinct /16s give the nodes distinct network tags in the routes
        # view, and each side shares a /30 with its router address.
        sixteens = {circuit_wan.address(side).rsplit(".", 2)[0] for side in circuit_wan.SIDES}
        self.assertEqual(len(sixteens), len(circuit_wan.SIDES))
        for side in circuit_wan.SIDES:
            near, far = circuit_wan.address(side), circuit_wan.router_address(side)
            self.assertEqual(near.rsplit(".", 1)[0], far.rsplit(".", 1)[0])
            self.assertEqual((int(near.rsplit(".", 1)[1]), int(far.rsplit(".", 1)[1])), (1, 2))

    def test_presets_come_from_the_tuning_table(self) -> None:
        table = json.loads((ROOT / "config/tuning_presets.json").read_text())
        self.assertEqual(wan.preset_names(), [item["id"] for item in table["presets"]])
        for item in table["presets"]:
            self.assertEqual(wan.preset_limits(item["id"]), item["limits"])
        with self.assertRaises(ValueError):
            wan.preset_limits("warp")

    def test_summary_compares_every_path_with_the_direct_session(self) -> None:
        downloads = {"direct": [{"tail_mbit_s": 80.0, "first_byte_ms": 400.0},
                                {"tail_mbit_s": 100.0, "first_byte_ms": 500.0}],
                     "three_hops": [{"tail_mbit_s": 20.0, "first_byte_ms": 900.0}]}
        requests = {"direct": [400.0, 402.0, 401.0], "three_hops": [800.0]}
        summary = circuit_wan.summarize(downloads, requests)
        self.assertEqual(summary["median_tail_mbit_s"], {"direct": 90.0, "three_hops": 20.0})
        self.assertEqual(summary["median_first_byte_ms"], {"direct": 450.0, "three_hops": 900.0})
        self.assertEqual(summary["median_request_ms"], {"direct": 401.0, "three_hops": 800.0})
        self.assertEqual(summary["to_direct"], {"three_hops": 0.222})
        stalled = circuit_wan.summarize({"direct": [{"tail_mbit_s": 0.0, "first_byte_ms": 1.0}],
                                         "two_hops": [{"tail_mbit_s": 5.0, "first_byte_ms": 1.0}]},
                                        {"direct": [1.0], "two_hops": [1.0]})
        self.assertEqual(stalled["to_direct"], {"two_hops": None})

    def test_downloads_and_requests_check_the_binary_workload(self) -> None:
        port = circuit_wan.session.free_port()
        server = subprocess.Popen(
            [sys.executable, "-c", circuit_wan.PAYLOAD_SERVER, str(circuit_wan.SMALL_BYTES), str(port)],
            stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(server.stdout.readline().strip(), "ready")
            download = circuit_wan.timed_download(None, "127.0.0.1", port, 2.0)
            self.assertGreater(download["bytes"], 0)
            self.assertGreater(download["tail_mbit_s"], 0.0)
            self.assertGreater(circuit_wan.small_request(None, "127.0.0.1", port), 0.0)
            outcome = circuit_wan.parallel_downloads(None, "127.0.0.1", port, 2.0, 2)
            self.assertEqual(len(outcome["streams"]), 2)
        finally:
            server.kill()
            server.wait(timeout=5)
            server.stdout.close()


class CircuitCableTest(unittest.TestCase):
    def test_the_relays_join_a_connection_and_end_each_direction(self) -> None:
        # Each target answers only after the client's end arrives, so the
        # reply shows both directions and both ends crossed the relays. A
        # TLS handshake byte first reaches the entry, any other byte the
        # destination, through the one served port.
        targets = {}
        for name in ("entry", "destination"):
            target = socket.create_server(("127.0.0.1", 0))
            self.addCleanup(target.close)
            targets[name] = target

            def answer(target: socket.socket = target, tag: bytes = name.encode()) -> None:
                while True:
                    try:
                        connection, _ = target.accept()
                    except OSError:
                        return
                    with connection:
                        received = bytearray()
                        while chunk := connection.recv(65536):
                            received += chunk
                        connection.sendall(tag + bytes(reversed(received)))

            threading.Thread(target=answer, daemon=True).start()
        outside = circuit_wan.HostRelay("127.0.0.1")
        self.addCleanup(outside.close)
        self.assertEqual(outside.ports["entry"], outside.ports["destination"])
        inside = circuit_wan.NamespaceRelay(outside.directory,
                                            {name: target.getsockname() for name, target in targets.items()})
        self.addCleanup(inside.close)
        for first, tag in ((b"\x16", b"entry"), (b"\x01", b"destination")):
            message = first + bytes(range(256)) * 1024
            with socket.create_connection(("127.0.0.1", outside.ports["entry"]), timeout=10) as client:
                client.sendall(message)
                client.shutdown(socket.SHUT_WR)
                reply = bytearray()
                while chunk := client.recv(65536):
                    reply += chunk
            self.assertEqual(bytes(reply), tag + bytes(reversed(message)))

    def test_the_serve_run_detaches_from_a_bash_login(self) -> None:
        # bash keeps a background list's output open until the list ends, so
        # SSH would wait for the whole serve run.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "scripts/yume_circuit_wan.py").write_text("import time\ntime.sleep(3)\n")
            arguments = argparse.Namespace(remote_yumed="yumed", remote_yume="yume", remote_openssl="openssl",
                                           serve_at="127.0.0.1", serve_port=0, serve_seconds=60.0, preset=None,
                                           idle_epoch_rotation=False, tcp_buffer_mib=0)
            command = circuit_cable.serve_command(arguments, str(root / "run"), "rtt=0")
            started = time.monotonic()
            subprocess.run(["bash", "-c", f"cd {temporary} && {command}"], capture_output=True, timeout=10,
                           check=True)
            self.assertLess(time.monotonic() - started, 2.0)
            status = root / "run.status"
            deadline = time.monotonic() + 10
            while not status.exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertEqual(status.read_text().strip(), "0")

    def test_kits_point_at_the_served_entry_with_local_ports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            kits = Path(temporary)
            for path in ("direct", *circuit_wan.CIRCUIT_HOPS):
                config = {"endpoint": {"host": "10.21.0.1", "port": 443},
                          "adapters": [{"kind": "socks5", "listen_port": 1}]}
                if path != "direct":
                    config["control"] = {"socket": "/tmp/elsewhere.sock"}
                (kits / path).mkdir()
                (kits / path / "yume.json").write_text(json.dumps(config))
            served = {"address": "10.77.77.1", "ports": {"entry": 40001, "destination": 40002}}
            configs, socks = circuit_cable.point_kits(kits, served, kits / "sockets")
            self.assertEqual(len(set(socks.values())), 3)
            for path, location in configs.items():
                config = json.loads(location.read_text())
                self.assertEqual(config["endpoint"], {"host": "10.21.0.1", "port": 40001,
                                                      "connect_address": "10.77.77.1"})
                self.assertEqual(config["adapters"][0]["listen_port"], socks[path])
                self.assertEqual(config.get("control"),
                                 None if path == "direct" else {"socket": str(kits / "sockets" / f"{path}.sock")})


def frame(source: str, source_port: int, target: str, target_port: int, sequence: int,
          flags: int, payload: bytes = b"") -> bytes:
    """One Ethernet, IPv4 and TCP frame without checksums."""
    tcp = struct.pack("!HHIIBBHHH", source_port, target_port, sequence, 0, 5 << 4, flags,
                      65535, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     bytes(map(int, source.split("."))), bytes(map(int, target.split("."))))
    return bytes(12) + b"\x08\x00" + ip + tcp


def pcap(frames: list[tuple[float, bytes]]) -> bytes:
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    for when, packet in frames:
        data += struct.pack("<IIII", int(when), round((when % 1) * 1e6), len(packet), len(packet))
        data += packet
    return data


class CircuitCaptureTest(unittest.TestCase):
    CLIENT, SERVER = ("10.20.0.1", 40000), ("10.21.0.1", 443)

    def segment(self, when: float, upward: bool, sequence: int, flags: int,
                payload: bytes = b"") -> tuple[float, bytes]:
        source, target = (self.CLIENT, self.SERVER) if upward else (self.SERVER, self.CLIENT)
        return when, frame(*source, *target, sequence, flags, payload)

    def test_records_are_rebuilt_in_order_across_segments(self) -> None:
        hello = b"\x16\x03\x01\x00\x04abcd"
        data = b"\x17\x03\x03\x00\x06" + b"x" * 6 + b"\x17\x03\x03\x00\x02yz"
        frames = [
            self.segment(1.0, True, 99, 0x02),
            self.segment(1.001, False, 499, 0x12),
            self.segment(1.002, True, 100, 0x10, hello[:3]),
            # Out of order: the rest of the hello arrives after later data,
            # which becomes usable only when the gap fills at 1.004.
            self.segment(1.003, True, 103 + 6, 0x10, data[:7]),
            self.segment(1.004, True, 103, 0x10, hello[3:]),
            # A retransmission that overlaps what was already delivered.
            self.segment(1.005, True, 103 + 6 + 4, 0x10, data[4:]),
            self.segment(1.006, False, 500, 0x18, b"\x17\x03\x03\x00\x01Z"),
            self.segment(1.007, False, 506, 0x11),
        ]
        found = circuit_capture.connections(
            circuit_capture.tcp_segments(circuit_capture.read_pcap(pcap(frames))))
        self.assertEqual(len(found), 1)
        timeline = circuit_capture.record_timeline(found[0])
        up = timeline["client_to_server"]
        self.assertFalse(up["malformed"] or up["truncated"])
        self.assertEqual([record[1:] for record in up["records"]], [[22, 4], [23, 6], [23, 2]])
        # Times never go back, as the gate's feature extraction requires.
        self.assertEqual([record[0] for record in up["records"]], [4000, 4000, 5000])
        self.assertEqual([record[1:] for record in timeline["server_to_client"]["records"]], [[23, 1]])
        self.assertEqual(found[0]["client_to_server"].bytes, len(hello) + len(data))

    def test_a_refused_dial_and_mid_stream_traffic_are_left_out(self) -> None:
        frames = [
            # A connection whose SYN came before the capture.
            self.segment(1.0, True, 5000, 0x18, b"\x17\x03\x03\x00\x01Z"),
            self.segment(2.0, True, 99, 0x02),
            self.segment(2.001, False, 0, 0x14),
        ]
        found = circuit_capture.connections(
            circuit_capture.tcp_segments(circuit_capture.read_pcap(pcap(frames))))
        self.assertEqual(len(found), 1)
        timeline = circuit_capture.record_timeline(found[0])
        self.assertEqual(timeline["client_to_server"]["records"], [])

    def test_a_gap_or_truncated_frame_is_refused(self) -> None:
        frames = [self.segment(1.0, True, 99, 0x02),
                  self.segment(1.1, True, 200, 0x18, b"late")]
        with self.assertRaises(circuit_capture.CaptureError):
            circuit_capture.connections(
                circuit_capture.tcp_segments(circuit_capture.read_pcap(pcap(frames))))
        truncated = bytearray(pcap([self.segment(1.0, True, 99, 0x02)]))
        truncated[24 + 8:24 + 12] = struct.pack("<I", 20)
        with self.assertRaises(circuit_capture.CaptureError):
            list(circuit_capture.read_pcap(bytes(truncated)))


if __name__ == "__main__":
    unittest.main()
