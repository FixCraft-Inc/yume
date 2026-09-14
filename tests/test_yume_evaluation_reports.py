#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))

import yume_ethernet_smoke as ethernet  # noqa: E402
import yume_ndpi_report as ndpi  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
