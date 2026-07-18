#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""
Static HTTP/2 opening-fingerprint comparator for YUME (evidence, not a wire
change).

YUME's `--obfs` carrier emits a fixed, project-defined HTTP/2 opening. This
tool renders that opening in the Akamai HTTP/2 fingerprint format and diffs it,
field by field, against reference fingerprints for real browsers, so the exact
gaps are measured instead of guessed. It changes no bytes; it only reports.

The YUME side is the source of truth: the values below mirror
src/core/stealth/obfs_h2.cpp and must be updated in lockstep if that opening
ever changes. The reference browser values are curated from public captures and
are marked accordingly; re-verify them against a version-pinned capture on the
target platform before making any compatibility decision. A mismatch here is a
known, documented limitation, not proof of blocking.

Akamai H2 fingerprint format (per Akamai's "Passive fingerprinting of HTTP/2"):

    <SETTINGS>|<WINDOW_UPDATE>|<PRIORITY>|<PSEUDO_HEADER_ORDER>

  SETTINGS             id:value pairs joined by ';' in send order
  WINDOW_UPDATE        connection-level increment, or '0' if none
  PRIORITY             priority frames 'streamid:exclusive:dep:weight'
                       joined by ',', or '0' if none
  PSEUDO_HEADER_ORDER  first letters of the :pseudo-headers in send order
                       (m=:method a=:authority s=:scheme p=:path)
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class H2Opening:
    label: str
    # SETTINGS in send order: list of (id, value).
    settings: list[tuple[int, int]]
    window_update: int  # connection-level increment; 0 if none
    priority: list[str]  # 'streamid:exclusive:dep:weight' entries; empty if none
    pseudo_order: str  # e.g. "masp"
    source: str  # citation / provenance
    verified: bool  # True only for values sourced from this repo

    def akamai(self) -> str:
        s = ";".join(f"{i}:{v}" for i, v in self.settings)
        wu = str(self.window_update)
        pr = ",".join(self.priority) if self.priority else "0"
        ps = ",".join(self.pseudo_order)
        return f"{s}|{wu}|{pr}|{ps}"


# --- YUME, mirrored from src/core/stealth/obfs_h2.cpp --------------------------
# SETTINGS + WINDOW_UPDATE: encode_client_handshake(), lines ~391-403.
# Pseudo-header send order: the emit_indexed / emit_literal_with_indexing calls
# at lines ~35-38 emit :method, :scheme, :authority, :path in that order.
YUME = H2Opening(
    label="yume (--obfs client)",
    settings=[(1, 65536), (2, 0), (3, 1000), (4, 6291456), (6, 262144)],
    window_update=15663105,
    priority=[],
    pseudo_order="msap",
    source="src/core/stealth/obfs_h2.cpp encode_client_handshake()",
    verified=True,
)

# --- Reference browser openings (CURATED; re-verify before use) ---------------
# These are the widely-published Akamai H2 fingerprints for recent desktop
# builds. Treat as leads: exact SETTINGS and window sizes drift across versions
# and platforms. The structural traits (pseudo-header order, whether
# MAX_CONCURRENT_STREAMS is sent, whether PRIORITY frames appear) are the stable
# discriminators and the ones worth acting on first.
REFERENCES: dict[str, H2Opening] = {
    "chrome": H2Opening(
        label="Chrome 131 (desktop)",
        settings=[(1, 65536), (2, 0), (4, 6291456), (6, 262144)],
        window_update=15663105,
        priority=[],
        pseudo_order="masp",
        source="public Akamai H2 fingerprint corpus (peet.ws / curl-impersonate)",
        verified=False,
    ),
    "firefox": H2Opening(
        label="Firefox 133 (desktop)",
        settings=[(1, 65536), (4, 131072), (5, 16384)],
        window_update=12517377,
        priority=["3:0:0:201", "5:0:0:101", "7:0:0:1", "9:0:7:1", "11:0:3:1"],
        pseudo_order="mpas",
        source="public Akamai H2 fingerprint corpus (peet.ws / curl-impersonate)",
        verified=False,
    ),
    "safari": H2Opening(
        label="Safari 18 (macOS)",
        settings=[(2, 0), (4, 4194304), (3, 100)],
        window_update=10485760,
        priority=[],
        pseudo_order="masp",
        source="public Akamai H2 fingerprint corpus (peet.ws)",
        verified=False,
    ),
}

SETTINGS_NAMES = {
    1: "HEADER_TABLE_SIZE",
    2: "ENABLE_PUSH",
    3: "MAX_CONCURRENT_STREAMS",
    4: "INITIAL_WINDOW_SIZE",
    5: "MAX_FRAME_SIZE",
    6: "MAX_HEADER_LIST_SIZE",
}

PSEUDO_NAMES = {"m": ":method", "a": ":authority", "s": ":scheme", "p": ":path"}


@dataclass
class Delta:
    field: str
    yume: str
    ref: str

    @property
    def differs(self) -> bool:
        return self.yume != self.ref


def diff(yume: H2Opening, ref: H2Opening) -> list[Delta]:
    deltas: list[Delta] = []
    ids = sorted(set(dict(yume.settings)) | set(dict(ref.settings)))
    ymap, rmap = dict(yume.settings), dict(ref.settings)
    for i in ids:
        name = SETTINGS_NAMES.get(i, f"SETTINGS[{i}]")
        deltas.append(
            Delta(
                name,
                str(ymap[i]) if i in ymap else "(absent)",
                str(rmap[i]) if i in rmap else "(absent)",
            )
        )
    deltas.append(Delta("WINDOW_UPDATE", str(yume.window_update), str(ref.window_update)))
    deltas.append(
        Delta("PRIORITY frames", str(len(yume.priority)), str(len(ref.priority)))
    )
    deltas.append(
        Delta(
            "pseudo-header order",
            ",".join(PSEUDO_NAMES[c] for c in yume.pseudo_order),
            ",".join(PSEUDO_NAMES[c] for c in ref.pseudo_order),
        )
    )
    return deltas


def render(target: str, as_json: bool) -> int:
    names = list(REFERENCES) if target == "all" else [target]
    report: dict[str, object] = {
        "yume": {"akamai": YUME.akamai(), "source": YUME.source},
        "comparisons": {},
    }
    for name in names:
        ref = REFERENCES[name]
        deltas = diff(YUME, ref)
        report["comparisons"][name] = {
            "label": ref.label,
            "akamai": ref.akamai(),
            "source": ref.source,
            "verified": ref.verified,
            "deltas": [
                {"field": d.field, "yume": d.yume, "ref": d.ref, "differs": d.differs}
                for d in deltas
            ],
            "differing_fields": [d.field for d in deltas if d.differs],
        }

    if as_json:
        print(json.dumps(report, indent=2))
        return 0

    print("YUME HTTP/2 opening fingerprint (evidence only; no wire change)\n")
    print(f"  yume   {YUME.akamai()}")
    print(f"         source: {YUME.source}\n")
    for name in names:
        ref = REFERENCES[name]
        deltas = diff(YUME, ref)
        diffs = [d for d in deltas if d.differs]
        print(f"vs {ref.label}  [{'reference; VERIFY' if not ref.verified else 'verified'}]")
        print(f"  ref    {ref.akamai()}")
        print(f"         source: {ref.source}")
        w = max([len("yume"), *(len(d.yume) for d in deltas)]) + 2
        print(f"  {'field':<24}{'yume':<{w}}{ref.label}")
        for d in deltas:
            mark = "  <-- differs" if d.differs else ""
            print(f"  {d.field:<24}{d.yume:<{w}}{d.ref}{mark}")
        if diffs:
            print(f"  => {len(diffs)} differing field(s): "
                  + ", ".join(d.field for d in diffs))
        else:
            print("  => matches this reference")
        print()

    print("Note: reference values are curated from public captures and must be "
          "re-verified\nagainst a version-pinned capture before any wire decision. "
          "This tool measures\nthe gap; it does not prove reachability or blocking.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?", default="all",
                    choices=["all", *REFERENCES],
                    help="reference browser to compare against (default: all)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--check", metavar="BROWSER", choices=list(REFERENCES),
                    help="exit nonzero if YUME's opening does not match BROWSER "
                         "exactly (for tracking the gap in CI)")
    args = ap.parse_args()

    if args.check:
        ref = REFERENCES[args.check]
        diffs = [d for d in diff(YUME, ref) if d.differs]
        if diffs:
            print(f"yume H2 opening differs from {ref.label} in "
                  f"{len(diffs)} field(s): " + ", ".join(d.field for d in diffs),
                  file=sys.stderr)
            return 1
        print(f"yume H2 opening matches {ref.label}")
        return 0

    return render(args.target, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
