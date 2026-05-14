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
"""

from __future__ import annotations
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


def render(spec: Spec) -> str:
    # Two-space left gutter inside the box, one-space right gutter, so
    # max usable text is (width - 4). Pick NARROW unless something
    # doesn't fit; explicit `width:` in the spec must be 34 or 72.
    longest = 0
    for n in spec.nodes:
        longest = max(longest, len(n.title), len(n.sub))
    usable_narrow = NARROW_WIDTH - 4  # "|" + " " + text + " " + "|"
    if spec.width == 0:
        chosen = NARROW_WIDTH if longest <= usable_narrow else WIDE_WIDTH
    elif spec.width in (NARROW_WIDTH, WIDE_WIDTH):
        chosen = spec.width
    else:
        raise SystemExit(
            f"width must be {NARROW_WIDTH} or {WIDE_WIDTH} "
            f"(got {spec.width}); these are enforced by "
            "scripts/check_ascii_diagrams.py")
    usable = chosen - 4
    if longest > usable:
        raise SystemExit(
            f"line too long for width {chosen}: longest text is {longest} "
            f"chars but only {usable} fit. Use width: {WIDE_WIDTH} or "
            "shorten the labels.")
    inner = chosen - 2  # everything between the two `+`
    horizontal = "+" + "-" * inner + "+"
    pad = " " * spec.indent

    def box(node: Node) -> list[str]:
        lines = [horizontal, _row(node.title, inner), _row(node.sub, inner), horizontal]
        return [pad + line for line in lines]

    # Arrow gutter aligns under column 8 of the box (matches the
    # EXPLAINED.md spacing of "        |").
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
    # Layout: "|" + " " + (two-space gutter + text) + (right pad) + " " + "|".
    # The trailing single space is required by the checker (right
    # padding). Inner = width - 2, and we hold one of those for the
    # right gutter, so the text body fills `inner - 1`.
    body = "  " + text
    body = body.ljust(inner - 1)
    return "|" + body + " |"


def main() -> int:
    if len(sys.argv) > 2:
        print(__doc__, file=sys.stderr)
        return 2
    text = (
        open(sys.argv[1]).read() if len(sys.argv) == 2 and sys.argv[1] != "-"
        else sys.stdin.read()
    )
    sys.stdout.write(render(parse(text)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
