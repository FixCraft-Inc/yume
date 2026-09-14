#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Read ndpiReader output for one server port.

The loopback nDPI smoke and the direct-link runner both use these parsers, so
one owner decides how the CSV and text reports are read.
"""

from __future__ import annotations

import csv
from pathlib import Path
import re

# ndpiReader opens live captures with this snap length and discards longer frames.
READER_SNAPLEN = 1536
FLOW_FIELDS = ("proto", "confidence", "cat", "breed", "hostname/sni", "(advertised) alpns",
               "tlsv1", "ja4", "ja3s", "ech", "chrome", "firefox", "safari", "cipher",
               "risk", "ndpi cli fingerprint", "tcp fingerprint", "pkt len")


def flows_on_port(csv_path: Path, port: int) -> list[dict[str, str]]:
    if not csv_path.is_file():
        return []
    lines = csv_path.read_text(encoding="utf-8", errors="replace").lstrip("#").splitlines()
    if not lines:
        return []
    # nDPI 6.0 separates CSV fields with '|'.
    delimiter = "|" if "|" in lines[0] else ","
    rows = []
    for row in csv.DictReader(lines, delimiter=delimiter):
        if str(port) in {(row.get("src_port") or "").strip(), (row.get("dst_port") or "").strip()}:
            rows.append({key.strip(): (value or "").strip() for key, value in row.items() if key})
    return rows


def reader_report(path: Path, port: int) -> dict[str, object]:
    """Totals and per-flow lines from the text output, which carries JA4 and risks."""
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""

    def total(label: str) -> int | None:
        match = re.search(rf"^\s*{label}:\s+(\d+)", text, re.MULTILINE)
        return int(match.group(1)) if match else None

    flows = [line.strip() for line in text.splitlines()
             if re.match(r"^\s+\d+\s+(TCP|UDP)\s", line) and f":{port} " in line]
    return {"ip_bytes": total("IP bytes"), "discarded_bytes": total("Discarded bytes"),
            "max_packet_bytes": total("Max Packet size"), "flows": flows}


def flow_summary(line: str) -> str:
    """The classification fields of one flow line, for printing."""
    fields = re.findall(r"\[([^\[\]]*)\]", line)
    return " | ".join(field for field in fields
                      if field.lower().startswith(FLOW_FIELDS) and not field.startswith("Plen Bins"))


def capture_failures(name: str, capture: dict[str, object], port: int) -> list[str]:
    failures = []
    if not capture.get("csv_flows"):
        failures.append(f"{name}: no flow on port {port} was recorded")
    if capture.get("discarded_bytes"):
        failures.append(f"{name}: the reader discarded {capture['discarded_bytes']} bytes")
    return failures
