#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""
Static HTTP/2 opening-fingerprint comparator for YUME's production nghttp2
carrier (evidence, not a wire change).

The companion `yume_h2_opening_probe` runs the production `H2Carrier`, captures
`TakeOutbound()`, parses its HTTP/2 frames, and decodes the request through the
production server endpoint. This tool compares that independent observation
with browser references. It changes no bytes; it only reports.

Chrome values come from the committed capture fixture. Other browser values
are comparison leads only. A match here covers the reported HTTP/2 fields, not
TLS/Chrome parity or resistance to traffic analysis.

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
import hashlib
import json
import pathlib
import subprocess
import sys
from dataclasses import dataclass


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


# --- Authoritative browser opening -------------------------------------------
# Dev6 supports one coherent identity sourced from the committed five-run
# Chrome capture. Unverified cross-browser comparison leads are intentionally
# absent from the YUME 2.0 path.
_fixture_path = (
    pathlib.Path(__file__).resolve().parents[1]
    / "tests/fixtures/chrome151-node24/chrome_h2_profile.json"
)
with _fixture_path.open(encoding="utf-8") as _fixture_file:
    _chrome_fixture = json.load(_fixture_file)
_chrome_client = _chrome_fixture["client"]
_chrome_headers = _chrome_fixture["priming_get"]["headers_in_order"]
_chrome_settings = [
    (int(setting_id), int(value))
    for setting_id, value, _ in _chrome_fixture["client_settings_in_order"]
]
_chrome_window_update = int(
    _chrome_fixture["client_connection_window_update"]["delta"]
)
_chrome_pseudo_order = "".join(
    name[1] for name, _ in _chrome_headers if name.startswith(":")
)

REFERENCES: dict[str, H2Opening] = {
    "chrome": H2Opening(
        label=(
            f"{_chrome_client['name']} {_chrome_client['version']} "
            f"({_chrome_client['os']})"
        ),
        settings=_chrome_settings,
        window_update=_chrome_window_update,
        priority=[],
        pseudo_order=_chrome_pseudo_order,
        source=str(_fixture_path.relative_to(_fixture_path.parents[3])),
        verified=True,
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


def load_production_opening(emitter: pathlib.Path) -> tuple[H2Opening, dict]:
    try:
        result = subprocess.run(
            [str(emitter)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        raise RuntimeError(
            f"cannot run production opening probe {emitter}: {exc}"
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        raise RuntimeError(f"production opening probe failed: {detail}")
    try:
        observed = json.loads(result.stdout)
        settings = [
            (int(setting_id), int(value))
            for setting_id, value in observed["settings_in_order"]
        ]
        updates = observed["connection_window_updates"]
        priority_frames = [
            (
                f"{int(frame['stream_id'])}:{int(bool(frame['exclusive']))}:"
                f"{int(frame['parent_stream_id'])}:{int(frame['weight'])}"
            )
            for frame in observed["priority_frames"]
        ]
        headers = observed["priming_get"]["headers_in_order"]
        pseudo_order = "".join(
            name[1] for name, _ in headers if name.startswith(":")
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"invalid production opening probe output from {emitter}"
        ) from exc
    if len(updates) != 1:
        raise RuntimeError(
            "production opening must contain exactly one connection WINDOW_UPDATE"
        )
    return (
        H2Opening(
            label="yume (production H2Carrier bytes)",
            settings=settings,
            window_update=int(updates[0]),
            priority=priority_frames,
            pseudo_order=pseudo_order,
            source=str(emitter),
            verified=True,
        ),
        observed,
    )


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


def chrome_profile_diff(observed: dict) -> list[Delta]:
    priming = observed["priming_get"]
    expected = _chrome_fixture["priming_get"]
    observed_headers = json.dumps(
        priming["headers_in_order"], separators=(",", ":")
    ).encode()
    expected_headers = json.dumps(
        expected["headers_in_order"], separators=(",", ":")
    ).encode()
    return [
        Delta(
            "priming parent stream",
            str(priming["parent_stream_id"]),
            str(expected["parent_stream_id"]),
        ),
        Delta(
            "priming exclusive",
            str(bool(priming["exclusive"])).lower(),
            str(bool(expected["exclusive"])).lower(),
        ),
        Delta(
            "priming weight",
            str(priming["weight"]),
            str(expected["weight"]),
        ),
        Delta(
            "priming headers",
            (
                f"{len(priming['headers_in_order'])} fields, "
                f"sha256={hashlib.sha256(observed_headers).hexdigest()}"
            ),
            (
                f"{len(expected['headers_in_order'])} fields, "
                f"sha256={hashlib.sha256(expected_headers).hexdigest()}"
            ),
        ),
    ]


def comparison_deltas(
    name: str,
    yume: H2Opening,
    observed: dict,
) -> list[Delta]:
    deltas = diff(yume, REFERENCES[name])
    if name == "chrome":
        deltas.extend(chrome_profile_diff(observed))
    return deltas


def render(
    target: str,
    as_json: bool,
    yume: H2Opening,
    observed: dict,
) -> int:
    names = list(REFERENCES) if target == "all" else [target]
    report: dict[str, object] = {
        "yume": {
            "akamai": yume.akamai(),
            "source": yume.source,
            "observed": observed,
        },
        "comparisons": {},
    }
    for name in names:
        ref = REFERENCES[name]
        deltas = comparison_deltas(name, yume, observed)
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
    print(f"  yume   {yume.akamai()}")
    print(f"         source: {yume.source}\n")
    for name in names:
        ref = REFERENCES[name]
        deltas = comparison_deltas(name, yume, observed)
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
    ap.add_argument(
        "--emitter",
        type=pathlib.Path,
        required=True,
        help="built yume_h2_opening_probe executable",
    )
    args = ap.parse_args()

    try:
        yume, observed = load_production_opening(args.emitter)
    except RuntimeError as exc:
        ap.error(str(exc))

    if args.check:
        ref = REFERENCES[args.check]
        diffs = [
            d
            for d in comparison_deltas(args.check, yume, observed)
            if d.differs
        ]
        if diffs:
            print(f"yume H2 opening differs from {ref.label} in "
                  f"{len(diffs)} field(s): " + ", ".join(d.field for d in diffs),
                  file=sys.stderr)
            return 1
        print(f"yume H2 opening matches {ref.label}")
        return 0

    return render(args.target, args.json, yume, observed)


if __name__ == "__main__":
    raise SystemExit(main())
