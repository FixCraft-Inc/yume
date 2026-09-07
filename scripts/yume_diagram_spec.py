#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Parse and validate the diagram specifications in docs/diagrams.

One JSON file describes one diagram. The same file drives the ASCII block in
the man pages and the Markdown documentation and the animated SVG on the
website, so every renderer reads its input through this module.

The key tables are closed. An unknown key, an unknown node kind, an edge that
names a missing node, or a label that cannot fit the fixed ASCII box widths is
a hard error rather than a silently dropped field.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_DIR = REPO_ROOT / "docs" / "diagrams"

# scripts/check_ascii_diagrams.py accepts these two box widths and nothing
# else, so a manpage-width terminal renders every diagram identically.
NARROW_WIDTH = 34
WIDE_WIDTH = 72

NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

DIAGRAM_TYPES = ("route",)

# Both layouts are rendered for every web diagram. A page picks the one that
# suits its shape, so the specification never has to guess where it is used.
LAYOUTS = ("vertical", "horizontal")

# The glyph drawn beside a node in the SVG. The ASCII renderer ignores it.
NODE_KINDS = (
    "app",
    "client",
    "server",
    "target",
    "relay",
    "tor",
    "tun",
    "cloud",
)

# A channel says what kind of link an edge is. It selects the ASCII arrow
# token and the SVG stroke treatment together, so the two renderings cannot
# disagree about the nature of a hop.
CHANNEL_TOKENS = {
    "plain": "",
    "tunnel": "==YUME==>",
    "onion": "...>",
}

SPEC_KEYS = {
    "name",
    "type",
    "title",
    "summary",
    "comment",
    "width",
    "indent",
    "targets",
    "nodes",
    "edges",
}
TARGET_KEYS = {"man", "markdown", "web"}
NODE_KEYS = {"id", "kind", "title", "sub"}
EDGE_KEYS = {"from", "to", "label", "channel"}


class SpecError(ValueError):
    """A specification is malformed. The message names the file."""


@dataclass
class Node:
    id: str
    kind: str
    title: str
    sub: str = ""


@dataclass
class Edge:
    source: str
    target: str
    label: str = ""
    channel: str = "plain"

    def ascii_label(self) -> str:
        """The text printed on the ASCII arrow entering the target node.

        A channel token leads, because ASCII has no stroke treatment to carry
        it. The SVG draws the channel instead and prints only the label.
        """
        return f"{CHANNEL_TOKENS[self.channel]} {self.label}".strip()


@dataclass
class Spec:
    name: str
    type: str
    title: str
    summary: str
    path: Path
    width: int = 0
    indent: int = 0
    comment: list[str] = field(default_factory=list)
    man_targets: list[str] = field(default_factory=list)
    markdown_targets: list[str] = field(default_factory=list)
    web: bool = True
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def box_width(self) -> int:
        """The ASCII box width, either declared or picked from the labels."""
        longest = max(max(len(n.title), len(n.sub)) for n in self.nodes)
        if self.width:
            return self.width
        return NARROW_WIDTH if longest <= NARROW_WIDTH - 4 else WIDE_WIDTH

    def edge_into(self, index: int) -> Edge | None:
        """The edge entering nodes[index], or None for the first node."""
        if index == 0:
            return None
        return self.edges[index - 1]


def _require(condition: bool, path: Path, message: str) -> None:
    if not condition:
        raise SpecError(f"{_relative(path)}: {message}")


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _closed(document: dict, allowed: set[str], path: Path, where: str) -> None:
    unknown = sorted(set(document) - allowed)
    _require(not unknown, path, f"{where} has unknown keys: {', '.join(unknown)}")


def _string(document: dict, key: str, path: Path, where: str, required: bool = True) -> str:
    value = document.get(key, "")
    if required:
        _require(isinstance(value, str) and value.strip() != "", path, f"{where} has no {key}")
    else:
        _require(isinstance(value, str), path, f"{where} field {key} must be a string")
    return value


def parse(path: Path) -> Spec:
    """Read one specification file and return a validated Spec."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SpecError(f"{_relative(path)}: cannot read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SpecError(f"{_relative(path)}: invalid JSON: {exc}") from exc

    _require(isinstance(document, dict), path, "the specification must be a JSON object")
    _closed(document, SPEC_KEYS, path, "the specification")

    name = _string(document, "name", path, "the specification")
    _require(bool(NAME_RE.match(name)), path, f"name {name!r} must be lowercase with underscores")
    _require(name == path.stem, path, f"name {name!r} must match the file name {path.stem!r}")

    diagram_type = _string(document, "type", path, "the specification")
    _require(diagram_type in DIAGRAM_TYPES, path, f"unknown type {diagram_type!r}")

    width = document.get("width", 0)
    _require(isinstance(width, int) and not isinstance(width, bool), path, "width must be an integer")
    _require(
        width in (0, NARROW_WIDTH, WIDE_WIDTH),
        path,
        f"width must be {NARROW_WIDTH} or {WIDE_WIDTH}, got {width}",
    )

    indent = document.get("indent", 0)
    _require(
        isinstance(indent, int) and not isinstance(indent, bool) and 0 <= indent <= 8,
        path,
        "indent must be an integer between 0 and 8",
    )

    comment = document.get("comment", [])
    _require(
        isinstance(comment, list) and all(isinstance(line, str) for line in comment),
        path,
        "comment must be a list of strings",
    )

    spec = Spec(
        name=name,
        type=diagram_type,
        title=_string(document, "title", path, "the specification"),
        summary=_string(document, "summary", path, "the specification"),
        path=path,
        width=width,
        indent=indent,
        comment=list(comment),
    )

    _parse_targets(document, spec, path)
    _parse_nodes(document, spec, path)
    _parse_edges(document, spec, path)
    _check_widths(spec, path)
    return spec


def _parse_targets(document: dict, spec: Spec, path: Path) -> None:
    targets = document.get("targets")
    _require(isinstance(targets, dict), path, "targets must be an object")
    _closed(targets, TARGET_KEYS, path, "targets")

    for key, destination in (("man", spec.man_targets), ("markdown", spec.markdown_targets)):
        listed = targets.get(key, [])
        _require(
            isinstance(listed, list) and all(isinstance(item, str) for item in listed),
            path,
            f"targets.{key} must be a list of repository-relative paths",
        )
        for item in listed:
            target_path = REPO_ROOT / item
            _require(".." not in Path(item).parts, path, f"targets.{key} entry {item!r} escapes the repository")
            _require(target_path.is_file(), path, f"targets.{key} entry {item!r} does not exist")
            destination.append(item)

    web = targets.get("web", True)
    _require(isinstance(web, bool), path, "targets.web must be true or false")
    spec.web = web
    _require(
        bool(spec.man_targets or spec.markdown_targets or spec.web),
        path,
        "the specification has no targets",
    )


def _parse_nodes(document: dict, spec: Spec, path: Path) -> None:
    nodes = document.get("nodes")
    _require(isinstance(nodes, list) and len(nodes) >= 2, path, "nodes must list at least two nodes")
    seen: set[str] = set()
    for index, entry in enumerate(nodes, start=1):
        where = f"node {index}"
        _require(isinstance(entry, dict), path, f"{where} must be an object")
        _closed(entry, NODE_KEYS, path, where)
        node_id = _string(entry, "id", path, where)
        _require(bool(NAME_RE.match(node_id)), path, f"{where} id {node_id!r} must be lowercase with underscores")
        _require(node_id not in seen, path, f"duplicate node id {node_id!r}")
        seen.add(node_id)
        kind = _string(entry, "kind", path, where)
        _require(kind in NODE_KINDS, path, f"{where} has unknown kind {kind!r}")
        spec.nodes.append(
            Node(
                id=node_id,
                kind=kind,
                title=_string(entry, "title", path, where),
                sub=_string(entry, "sub", path, where, required=False),
            )
        )


def _parse_edges(document: dict, spec: Spec, path: Path) -> None:
    edges = document.get("edges")
    _require(isinstance(edges, list), path, "edges must be a list")
    ids = [node.id for node in spec.nodes]
    for index, entry in enumerate(edges, start=1):
        where = f"edge {index}"
        _require(isinstance(entry, dict), path, f"{where} must be an object")
        _closed(entry, EDGE_KEYS, path, where)
        source = _string(entry, "from", path, where)
        target = _string(entry, "to", path, where)
        _require(source in ids, path, f"{where} names unknown node {source!r}")
        _require(target in ids, path, f"{where} names unknown node {target!r}")
        channel = entry.get("channel", "plain")
        _require(channel in CHANNEL_TOKENS, path, f"{where} has unknown channel {channel!r}")
        spec.edges.append(
            Edge(
                source=source,
                target=target,
                label=_string(entry, "label", path, where, required=False),
                channel=channel,
            )
        )

    if spec.type == "route":
        # A route is one ordered chain. The ASCII renderer walks the node list
        # and prints the edge entering each node, so anything else would render
        # a diagram the specification does not describe.
        _require(
            len(spec.edges) == len(spec.nodes) - 1,
            path,
            f"a route needs {len(spec.nodes) - 1} edges for {len(spec.nodes)} nodes, got {len(spec.edges)}",
        )
        for index, edge in enumerate(spec.edges):
            _require(
                edge.source == ids[index] and edge.target == ids[index + 1],
                path,
                f"edge {index + 1} must join {ids[index]!r} to {ids[index + 1]!r} for a route",
            )


def _check_widths(spec: Spec, path: Path) -> None:
    chosen = spec.box_width()
    usable = chosen - 4
    for node in spec.nodes:
        for label in (node.title, node.sub):
            _require(
                len(label) <= usable,
                path,
                f"label {label!r} is {len(label)} characters but only {usable} fit width {chosen}",
            )


def load_all() -> list[Spec]:
    """Every specification in docs/diagrams, ordered by name."""
    specs = [parse(path) for path in sorted(SPEC_DIR.glob("*.json"))]
    names = [spec.name for spec in specs]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise SpecError(f"duplicate diagram names: {', '.join(duplicates)}")
    return specs


def load(name: str) -> Spec:
    path = SPEC_DIR / f"{name}.json"
    if not path.is_file():
        raise SpecError(f"no such diagram: {name}")
    return parse(path)
