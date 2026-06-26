#!/usr/bin/env python3
"""
draw_pipeline.py - render a vertical pipeline diagram in the EXPLAINED.md
ASCII style. Output is deterministic so the diagrams stay byte-identical
between regenerations.

The reference shape:

    +--------------------------------+
    |  TITLE                         |
    |  subtitle line                 |
    +--------------------------------+
            |
            | optional arrow label
            v
    +--------------------------------+
    |  NEXT TITLE                    |
    |  subtitle line                 |
    +--------------------------------+

Input: a YAML-ish spec on stdin (we don't pull a YAML dep — just key:value
lines and `--` separators between nodes). Example:

    width: 36          # optional, default 36; bumped automatically if a
                       # line doesn't fit
    indent: 0          # leading spaces before the diagram (e.g. for
                       # Markdown nesting)
    --
    title: HUMAN APP
    sub:   browser / curl / game
    --
    arrow: local SOCKS, --run, forward, or VPN capture
    title: YUME CLIENT
    sub:   authenticates and frames
    --
    title: YUMED SERVER
    sub:   opens target sockets

Usage:
    scripts/draw_pipeline.py < spec.txt
    scripts/draw_pipeline.py spec.txt
    scripts/draw_pipeline.py --svg spec.txt > diagram.svg
"""

from __future__ import annotations
import argparse
import html
import sys
from dataclasses import dataclass, field


@dataclass
class Node:
    title: str
    sub: str = ""
    arrow: str = ""  # label for the arrow ENTERING this node (skipped on node 0)


# The project's check_ascii_diagrams.py enforces fixed box widths so a
# manpage-width terminal can render every diagram identically. We only
# emit boxes of these widths; the renderer auto-picks the smaller one
# that still fits the longest title/sub line.
NARROW_WIDTH = 34   # +--------------------------------+ (32 dashes)
WIDE_WIDTH   = 72   # +----------------------------------------------------------------------+


@dataclass
class Spec:
    width: int = 0       # 0 means "auto-pick narrow or wide based on contents"
    indent: int = 0
    nodes: list[Node] = field(default_factory=list)


def parse(text: str) -> Spec:
    spec = Spec()
    current: dict[str, str] | None = None
    in_header = True
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if line.lstrip().startswith("#"):
            continue
        if line.strip() == "--":
            if current is not None:
                spec.nodes.append(_to_node(current))
            current = {}
            in_header = False
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if in_header and current is None:
            if key == "width":
                spec.width = int(value)
            elif key == "indent":
                spec.indent = int(value)
            else:
                raise SystemExit(f"unknown header key '{key}' before any '--'")
            continue
        if current is None:
            raise SystemExit("node fields must come after a '--' separator")
        if key not in ("title", "sub", "arrow"):
            raise SystemExit(f"unknown node key '{key}'")
        current[key] = value
    if current is not None:
        spec.nodes.append(_to_node(current))
    if not spec.nodes:
        raise SystemExit("spec has no nodes")
    return spec


def _to_node(d: dict[str, str]) -> Node:
    if "title" not in d:
        raise SystemExit("node missing 'title'")
    return Node(title=d.get("title", ""), sub=d.get("sub", ""), arrow=d.get("arrow", ""))


def _choose_width(spec: Spec) -> int:
    longest = 0
    for n in spec.nodes:
        longest = max(longest, len(n.title), len(n.sub))
    usable_narrow = NARROW_WIDTH - 4
    if spec.width == 0:
        return NARROW_WIDTH if longest <= usable_narrow else WIDE_WIDTH
    if spec.width in (NARROW_WIDTH, WIDE_WIDTH):
        return spec.width
    raise SystemExit(
        f"width must be {NARROW_WIDTH} or {WIDE_WIDTH} "
        f"(got {spec.width}); these are enforced by "
        "scripts/check_ascii_diagrams.py")


def render(spec: Spec) -> str:
    chosen = _choose_width(spec)
    longest = max(max(len(n.title), len(n.sub)) for n in spec.nodes)
    usable = chosen - 4
    if longest > usable:
        raise SystemExit(
            f"line too long for width {chosen}: longest text is {longest} "
            f"chars but only {usable} fit. Use width: {WIDE_WIDTH} or "
            "shorten the labels.")
    inner = chosen - 2
    horizontal = "+" + "-" * inner + "+"
    pad = " " * spec.indent

    def box(node: Node) -> list[str]:
        lines = [horizontal, _row(node.title, inner), _row(node.sub, inner), horizontal]
        return [pad + line for line in lines]

    arrow_col = 8
    out: list[str] = []
    for i, node in enumerate(spec.nodes):
        if i > 0:
            out.append(pad + " " * arrow_col + "|")
            if node.arrow:
                out.append(pad + " " * arrow_col + "| " + node.arrow)
            out.append(pad + " " * arrow_col + "v")
        out.extend(box(node))
    return "\n".join(out) + "\n"


def _row(text: str, inner: int) -> str:
    body = "  " + text
    body = body.ljust(inner - 1)
    return "|" + body + " |"


def render_svg(spec: Spec) -> str:
    chosen = _choose_width(spec)
    box_w = chosen * 7
    box_h = 52
    gap = 36
    margin = 24
    cx = margin + box_w // 2
    y = margin
    body: list[str] = []

    for i, node in enumerate(spec.nodes):
        if i > 0:
            ay = y
            y += gap // 2
            body.append(
                f'<line x1="{cx}" y1="{ay + box_h}" x2="{cx}" y2="{y}" '
                f'stroke="#ff7eaa" stroke-width="2"/>'
            )
            if node.arrow:
                body.append(
                    f'<text x="{cx}" y="{y - 6}" text-anchor="middle" '
                    f'fill="#b8a6b1" font-size="11">{html.escape(node.arrow)}</text>'
                )
            body.append(
                f'<polygon points="{cx - 5},{y} {cx + 5},{y} {cx},{y + 8}" fill="#ff7eaa"/>'
            )
            y += gap // 2

        body.append(
            f'<rect x="{margin}" y="{y}" width="{box_w}" height="{box_h}" rx="8" '
            f'fill="url(#box)" stroke="#2c2230" stroke-width="1.5"/>'
        )
        body.append(
            f'<text x="{cx}" y="{y + 22}" text-anchor="middle" font-weight="600">'
            f"{html.escape(node.title)}</text>"
        )
        if node.sub:
            body.append(
                f'<text x="{cx}" y="{y + 40}" text-anchor="middle" fill="#b8a6b1" '
                f'font-size="11">{html.escape(node.sub)}</text>'
            )
        y += box_h

    total_h = y + margin
    return "\n".join([
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {box_w + margin * 2} {total_h}" '
        f'font-family="Space Grotesk, system-ui, sans-serif">',
        "<defs>",
        '<linearGradient id="box" x1="0" y1="0" x2="1" y2="1">',
        '<stop offset="0%" stop-color="#1c1620"/>',
        '<stop offset="100%" stop-color="#110d14"/>',
        "</linearGradient>",
        "</defs>",
        f'<g fill="#f4eef2" font-size="13">',
        *body,
        "</g>",
        "</svg>",
        "",
    ])


def main() -> int:
    parser = argparse.ArgumentParser(description="Render YUME pipeline diagrams from .spec files")
    parser.add_argument("spec", nargs="?", help="spec file path, or read stdin when omitted")
    parser.add_argument("--svg", action="store_true", help="emit SVG instead of ASCII")
    args = parser.parse_args()

    if args.spec is None:
        text = sys.stdin.read()
    else:
        text = open(args.spec).read()

    spec = parse(text)
    if args.svg:
        sys.stdout.write(render_svg(spec))
    else:
        sys.stdout.write(render(spec))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
