#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Render a diagram specification as the fixed-width ASCII form.

This is the shape that ships in the man pages and in the Markdown fences, and
scripts/check_ascii_diagrams.py enforces its box widths. The reference shape:

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

Output is deterministic so regeneration is a byte comparison.
"""

from __future__ import annotations

from yume_diagram_spec import Spec

ARROW_COLUMN = 8


def render(spec: Spec) -> str:
    """The complete ASCII block for one diagram, ending in a newline."""
    if spec.type != "route":
        raise ValueError(f"no ASCII renderer for diagram type {spec.type!r}")
    return _render_route(spec)


def _render_route(spec: Spec) -> str:
    width = spec.box_width()
    inner = width - 2
    horizontal = "+" + "-" * inner + "+"
    pad = " " * spec.indent
    stem = pad + " " * ARROW_COLUMN

    lines: list[str] = []
    for index, node in enumerate(spec.nodes):
        edge = spec.edge_into(index)
        if edge is not None:
            lines.append(stem + "|")
            label = edge.ascii_label()
            if label:
                lines.append(stem + "| " + label)
            lines.append(stem + "v")
        lines.append(pad + horizontal)
        lines.append(pad + _row(node.title, inner))
        lines.append(pad + _row(node.sub, inner))
        lines.append(pad + horizontal)
    return "\n".join(lines) + "\n"


def _row(text: str, inner: int) -> str:
    body = ("  " + text).ljust(inner - 1)
    return "|" + body + " |"
