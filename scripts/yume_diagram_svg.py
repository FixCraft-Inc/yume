#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Render a diagram specification as an inline-able animated SVG.

The output is a fragment, not a document. It carries no XML prolog, no width
or height, and no colours of its own. The website inlines it, so the palette
comes from website/assets/tokens.css through class names styled in
website/assets/site.css, and the packet motion is driven there as well. That
keeps one styling source and lets the theme toggle recolour a diagram with no
second palette to maintain.

Every string drawn comes from the specification. The renderer invents no
labels, no extra hops, and no imagery the documentation does not state. An
edge with a channel but no label carries its meaning in the stroke treatment
rather than in invented words.

Geometry is integer or two-decimal and the element order is fixed, so two
runs over the same specification produce identical bytes.
"""

from __future__ import annotations

import html

from yume_diagram_spec import NARROW_WIDTH, Spec

# Vertical layout. The rail on the left mirrors the website's transport
# passage, where a single accent line threads markers down the page.
RAIL_X = 20
CARD_X = 60
CARD_HEIGHT = 72
CARD_GAP = 64
MARGIN_Y = 16
CARD_WIDTH_NARROW = 420
CARD_WIDTH_WIDE = 640

# Horizontal layout, used where a route is the spatial anchor of a page.
H_CARD_WIDTH = 168
H_CARD_HEIGHT = 104
H_CARD_GAP = 84
H_MARGIN_X = 16
H_MARGIN_Y = 34
H_SUB_COLUMNS = 26

SECONDS_PER_HOP = 1.9

# Glyphs are placed with a nested <svg x y>, never a transform attribute. A
# transform would be overridden by any CSS rule that resets transforms, and the
# site has one of those for narrow viewports.
GLYPHS = {
    "app": (
        '<rect x="2.5" y="4.5" width="19" height="15" rx="2.5"/>'
        '<path d="M2.5 9.5h19"/>'
        '<circle cx="5.6" cy="7" r="0.9" class="dgm-glyph-fill"/>'
        '<circle cx="8.4" cy="7" r="0.9" class="dgm-glyph-fill"/>'
    ),
    "client": (
        '<rect x="3.5" y="5.5" width="17" height="11" rx="1.8"/>'
        '<path d="M1.5 19.5h21"/>'
    ),
    "server": (
        '<rect x="3.5" y="3.5" width="17" height="7" rx="1.8"/>'
        '<rect x="3.5" y="13.5" width="17" height="7" rx="1.8"/>'
        '<circle cx="7" cy="7" r="1" class="dgm-glyph-fill"/>'
        '<circle cx="7" cy="17" r="1" class="dgm-glyph-fill"/>'
    ),
    "target": (
        '<circle cx="12" cy="12" r="8.5"/>'
        '<path d="M3.5 12h17"/>'
        '<path d="M12 3.5c4 4.5 4 12.5 0 17c-4-4.5-4-12.5 0-17z"/>'
    ),
    "relay": (
        '<path d="M12 3.2 20 7.6v8.8L12 20.8 4 16.4V7.6z"/>'
        '<circle cx="12" cy="12" r="1.5" class="dgm-glyph-fill"/>'
    ),
    "tor": (
        '<path d="M12 2.8c5.4 4.6 7.2 9.2 5.4 13.2A6.1 6.1 0 0 1 12 21.2'
        'a6.1 6.1 0 0 1-5.4-5.2C4.8 12 6.6 7.4 12 2.8z"/>'
        '<path d="M12 8.2c2.4 2.3 3.2 4.6 2.4 6.6A2.7 2.7 0 0 1 12 16.6'
        'a2.7 2.7 0 0 1-2.4-1.8c-0.8-2 0-4.3 2.4-6.6z"/>'
    ),
    "tun": (
        '<rect x="2.5" y="7" width="19" height="10" rx="5"/>'
        '<path d="M8.6 7.4v9.2M15.4 7.4v9.2" stroke-dasharray="2 2"/>'
    ),
    "cloud": (
        '<path d="M7.4 18.4a4.3 4.3 0 0 1 .3-8.5 5.7 5.7 0 0 1 10.7-1'
        'a3.9 3.9 0 0 1 .4 7.7z"/>'
    ),
}


def render(spec: Spec, layout: str = "vertical") -> str:
    """The inline SVG fragment for one diagram, ending in a newline."""
    if spec.type != "route":
        raise ValueError(f"no SVG renderer for diagram type {spec.type!r}")
    if layout == "horizontal":
        return _render_horizontal(spec)
    if layout != "vertical":
        raise ValueError(f"unknown layout {layout!r}")
    return _render_vertical(spec)


def _render_vertical(spec: Spec) -> str:
    card_width = CARD_WIDTH_NARROW if spec.box_width() == NARROW_WIDTH else CARD_WIDTH_WIDE
    width = CARD_X + card_width + MARGIN_Y
    count = len(spec.nodes)
    height = MARGIN_Y * 2 + count * CARD_HEIGHT + (count - 1) * CARD_GAP

    centres = [
        MARGIN_Y + index * (CARD_HEIGHT + CARD_GAP) + CARD_HEIGHT / 2
        for index in range(count)
    ]

    body: list[str] = []

    body.append('<g class="dgm-links">')
    for index in range(1, count):
        edge = spec.edges[index - 1]
        start = centres[index - 1]
        end = centres[index]
        body.append(
            f'<path class="dgm-link dgm-link-{edge.channel}" '
            f'd="M{RAIL_X} {_n(start)}V{_n(end)}"/>'
        )
        if edge.channel == "tunnel":
            for offset in (-3, 3):
                body.append(
                    f'<path class="dgm-link-rail" '
                    f'd="M{RAIL_X + offset} {_n(start + 9)}V{_n(end - 20)}"/>'
                )
        middle = (start + end) / 2
        tip = end - 12
        body.append(
            f'<path class="dgm-arrow" d="M{RAIL_X - 4.5} {_n(tip - 7.5)}'
            f'H{RAIL_X + 4.5}L{RAIL_X} {_n(tip)}Z"/>'
        )
        label = edge.label
        if label:
            body.append(
                f'<text class="dgm-edge-label" x="{CARD_X}" y="{_n(middle + 3.5)}">'
                f"{html.escape(label)}</text>"
            )
    body.append("</g>")

    body.append('<g class="dgm-nodes">')
    for index, node in enumerate(spec.nodes):
        centre = centres[index]
        top = centre - CARD_HEIGHT / 2
        body.append(f'<circle class="dgm-marker" cx="{RAIL_X}" cy="{_n(centre)}" r="5"/>')
        body.append(
            f'<g class="dgm-node dgm-node-{node.kind}">'
            f'<rect class="dgm-card" x="{CARD_X}" y="{_n(top)}" '
            f'width="{card_width}" height="{CARD_HEIGHT}" rx="14"/>'
            f'<svg class="dgm-glyph" x="{CARD_X + 16}" y="{_n(top + 24)}" '
            f'width="24" height="24" viewBox="0 0 24 24">'
            f"{GLYPHS[node.kind]}</svg>"
            f'<text class="dgm-title" x="{CARD_X + 56}" y="{_n(top + 29)}">'
            f"{html.escape(node.title)}</text>"
        )
        if node.sub:
            body.append(
                f'<text class="dgm-sub" x="{CARD_X + 56}" y="{_n(top + 48)}">'
                f"{html.escape(node.sub)}</text>"
            )
        body.append("</g>")
    body.append("</g>")

    path = f"M {RAIL_X} {_n(centres[0])} L {RAIL_X} {_n(centres[-1])}"
    body.append(_packets(path, count))
    return _document(spec, "vertical", width, height, body)


def _render_horizontal(spec: Spec) -> str:
    count = len(spec.nodes)
    width = H_MARGIN_X * 2 + count * H_CARD_WIDTH + (count - 1) * H_CARD_GAP
    height = H_MARGIN_Y * 2 + H_CARD_HEIGHT
    centre_y = H_MARGIN_Y + H_CARD_HEIGHT / 2
    lefts = [H_MARGIN_X + index * (H_CARD_WIDTH + H_CARD_GAP) for index in range(count)]

    body: list[str] = []

    body.append('<g class="dgm-links">')
    for index in range(1, count):
        edge = spec.edges[index - 1]
        start = lefts[index - 1] + H_CARD_WIDTH
        end = lefts[index]
        body.append(
            f'<path class="dgm-link dgm-link-{edge.channel}" '
            f'd="M{_n(start)} {_n(centre_y)}H{_n(end)}"/>'
        )
        if edge.channel == "tunnel":
            for offset in (-3, 3):
                body.append(
                    f'<path class="dgm-link-rail" '
                    f'd="M{_n(start + 4)} {_n(centre_y + offset)}H{_n(end - 14)}"/>'
                )
        middle = (start + end) / 2
        tip = end - 3
        body.append(
            f'<path class="dgm-arrow" d="M{_n(tip - 7.5)} {_n(centre_y - 4.5)}'
            f'V{_n(centre_y + 4.5)}L{_n(tip)} {_n(centre_y)}Z"/>'
        )
        label = edge.label
        if label:
            body.append(
                f'<text class="dgm-edge-label dgm-edge-label-centred" '
                f'x="{_n(middle)}" y="{_n(centre_y - 14)}">{html.escape(label)}</text>'
            )
    body.append("</g>")

    body.append('<g class="dgm-nodes">')
    for index, node in enumerate(spec.nodes):
        left = lefts[index]
        centre_x = left + H_CARD_WIDTH / 2
        body.append(
            f'<g class="dgm-node dgm-node-{node.kind}">'
            f'<rect class="dgm-card" x="{left}" y="{H_MARGIN_Y}" '
            f'width="{H_CARD_WIDTH}" height="{H_CARD_HEIGHT}" rx="16"/>'
            f'<svg class="dgm-glyph" x="{_n(centre_x - 12)}" y="{H_MARGIN_Y + 14}" '
            f'width="24" height="24" viewBox="0 0 24 24">'
            f"{GLYPHS[node.kind]}</svg>"
            f'<text class="dgm-title dgm-title-centred" x="{_n(centre_x)}" '
            f'y="{H_MARGIN_Y + 58}">{html.escape(node.title)}</text>'
        )
        for line_index, line in enumerate(_wrap(node.sub, H_SUB_COLUMNS)):
            body.append(
                f'<text class="dgm-sub dgm-sub-centred" x="{_n(centre_x)}" '
                f'y="{H_MARGIN_Y + 74 + line_index * 13}">{html.escape(line)}</text>'
            )
        body.append("</g>")
    body.append("</g>")

    path = (
        f"M {_n(lefts[0] + H_CARD_WIDTH / 2)} {_n(centre_y)} "
        f"L {_n(lefts[-1] + H_CARD_WIDTH / 2)} {_n(centre_y)}"
    )
    body.append(_packets(path, count))
    return _document(spec, "horizontal", width, height, body)


def _packets(path: str, count: int) -> str:
    """The travelling packet. Two circles, a glow and a core, on one path."""
    duration = _n(round((count - 1) * SECONDS_PER_HOP, 2))
    style = f"--dgm-path:path('{path}');--dgm-dur:{duration}s"
    return (
        '<g class="dgm-packets" aria-hidden="true">'
        f'<circle class="dgm-packet dgm-packet-glow" cx="0" cy="0" r="9" style="{style}"/>'
        f'<circle class="dgm-packet dgm-packet-core" cx="0" cy="0" r="4" style="{style}"/>'
        "</g>"
    )


def _document(spec: Spec, layout: str, width: float, height: float, body: list[str]) -> str:
    title_id = f"dgm-{spec.name}-{layout}-title"
    desc_id = f"dgm-{spec.name}-{layout}-desc"
    lines = [
        f'<svg class="dgm dgm-{layout}" width="{_n(width)}" height="{_n(height)}" '
        f'viewBox="0 0 {_n(width)} {_n(height)}" '
        f'role="img" aria-labelledby="{title_id} {desc_id}" '
        'xmlns="http://www.w3.org/2000/svg">',
        f'<title id="{title_id}">{html.escape(spec.title)}</title>',
        f'<desc id="{desc_id}">{html.escape(spec.summary)}</desc>',
        *body,
        "</svg>",
        "",
    ]
    return "\n".join(lines)


def _wrap(text: str, columns: int) -> list[str]:
    """Greedy word wrap. Deterministic and stable for identical input."""
    if not text:
        return []
    lines: list[str] = []
    current = ""
    for word in text.split():
        candidate = f"{current} {word}".strip()
        if current and len(candidate) > columns:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def _n(value: float) -> str:
    """Format a coordinate without trailing zeros so output stays stable."""
    rounded = round(float(value) + 0.0, 2)
    if rounded == int(rounded):
        return str(int(rounded))
    return f"{rounded:.2f}".rstrip("0").rstrip(".")
