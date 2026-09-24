#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Generate the CLI help text and the bash completion script from the manuals.

Each option is an `@opt` entry in the manual source
under `docs/src/<language>/`, and the `@cli` keys on that entry carry what a
terminal needs and a manual does not: how the help line spells the term, the
one-line description, whether the argument completes as a file, and the words
that complete after it. A layout source under `docs/src/<language>/cli/` says
what order the help prints them in and under which headings, because the help
groups options by task while the manual groups them by subject.

The native CLI uses a static help string without an output-stream dependency.
The transport-v2 reference CLI uses stream writers for help and Bash completion.
The generated headers are tracked so a clone builds without Python. `check`
fails when a tracked header no longer matches its source.

    scripts/yume_cli.py list
    scripts/yume_cli.py render yume
    scripts/yume_cli.py sync
    scripts/yume_cli.py check
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yume_doc_spec as spec  # noqa: E402

REPO_ROOT = spec.REPO_ROOT
SOURCE_ROOT = spec.SOURCE_ROOT

MAGIC = "#!yume-cli 1"

# Where a help entry's description starts, and where its later lines start.
# A hand-written help text drifted off these columns in a couple of dozen
# places, so an entry may override them, and every override is one line of
# source rather than an invisible run of spaces.
COLUMN = 27
CONTINUATION = 29
TERM_INDENT = 2

# Header keys, closed for the same reason a `.doc` header's are.
REQUIRED_HEADER_KEYS = {"binary", "manual", "output", "namespace"}
HEADER_KEYS = REQUIRED_HEADER_KEYS | {"output-kind"}

# Layout directives, closed.
DIRECTIVES = ("@usage", "@section", "@note", "@gap", "@end")

# Values a help description may interpolate, and the C++ that produces each.
# The table is closed so a documentation source can name a runtime default
# without being able to name arbitrary C++, and so a constant that moves is
# repaired here rather than in every source that prints it.
INTERPOLATIONS = {
    "reverse-port-min": "yume::policy::kReversePortMinDefault",
    "reverse-port-max": "yume::policy::kReversePortMaxDefault",
}

INTERPOLATION_RE = re.compile(r"\{\{([a-z][a-z0-9-]*)\}\}")

BANNER = "scripts/yume_cli.py"


class CliError(ValueError):
    """A CLI source is malformed, or disagrees with the manual it draws from."""


def _fail(path: Path, line: int, message: str) -> None:
    raise CliError(f"{spec.relative(path)}:{line}: {message}")


def _require(condition: bool, path: Path, line: int, message: str) -> None:
    if not condition:
        _fail(path, line, message)


@dataclass
class Item:
    """One element of the printed help, in the order it prints."""

    kind: str
    line: int
    text: str = ""
    lines: list[str] = field(default_factory=list)


@dataclass
class Layout:
    binary: str
    manual: str
    output: str
    namespace: str
    path: Path
    items: list[Item] = field(default_factory=list)
    output_kind: str = "stream"


def load_layouts(language: str = spec.DEFAULT_LANGUAGE) -> list[Layout]:
    root = SOURCE_ROOT / language / "cli"
    if not root.is_dir():
        return []
    return [parse_layout(path) for path in sorted(root.glob("*.cli"))]


def parse_layout(path: Path) -> Layout:
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    _require(bool(lines) and lines[0] == MAGIC, path, 1, f"the first line must be {MAGIC!r}")

    header: dict[str, tuple[str, int]] = {}
    index = 1
    while index < len(lines):
        raw = lines[index]
        number = index + 1
        if raw.strip() == "---":
            index += 1
            break
        if raw.strip() == "":
            index += 1
            continue
        match = re.match(r"^([a-z][a-z0-9-]*):[ \t]*(.*)$", raw)
        _require(match is not None, path, number, f"expected 'key: value' or '---', got {raw!r}")
        assert match is not None
        key, value = match.group(1), match.group(2).strip()
        _require(key in HEADER_KEYS, path, number, f"unknown header key {key!r}")
        _require(key not in header, path, number, f"duplicate header key {key!r}")
        header[key] = (value, number)
        index += 1
    else:
        _fail(path, len(lines), "the header is not closed by a '---' line")

    missing = sorted(REQUIRED_HEADER_KEYS - set(header))
    _require(not missing, path, 2, f"the header has no {', '.join(missing)}")

    layout = Layout(
        binary=header["binary"][0],
        manual=header["manual"][0],
        output=header["output"][0],
        namespace=header["namespace"][0],
        path=path,
        output_kind=header.get("output-kind", ("stream", 2))[0],
    )
    _require(
        layout.binary == path.stem,
        path,
        header["binary"][1],
        f"binary {layout.binary!r} must match the file name {path.stem!r}",
    )
    _require(
        layout.output.startswith("src/") and layout.output.endswith(".hpp"),
        path,
        header["output"][1],
        f"output {layout.output!r} must be a header under src/",
    )
    _require(
        layout.output_kind in ("stream", "static-help"),
        path,
        header.get("output-kind", ("", 2))[1],
        "output-kind must be stream or static-help",
    )

    layout.items = _parse_body(path, lines, index)
    _require(bool(layout.items), path, index, "the layout prints nothing")
    _require(layout.items[0].kind == "usage", path, index, "a layout opens with @usage")
    return layout


def _parse_body(path: Path, lines: list[str], start: int) -> list[Item]:
    items: list[Item] = []
    index = start
    while index < len(lines):
        raw = lines[index]
        number = index + 1
        if raw.strip() == "":
            index += 1
            continue
        if raw.startswith("@"):
            directive = raw.split(" ", 1)[0].strip()
            _require(directive in DIRECTIVES, path, number, f"unknown directive {directive!r}")
            argument = raw[len(directive):].strip()

            if directive == "@gap":
                _require(not argument, path, number, "@gap takes no argument")
                items.append(Item(kind="gap", line=number))
                index += 1
                continue
            if directive == "@section":
                _require(bool(argument), path, number, "@section needs a heading")
                _require(
                    not argument.endswith(":"),
                    path,
                    number,
                    "@section adds the colon itself",
                )
                items.append(Item(kind="section", line=number, text=argument))
                index += 1
                continue
            if directive == "@end":
                _fail(path, number, "@end closes no open block")

            _require(not argument, path, number, f"{directive} takes no argument")
            body: list[str] = []
            cursor = index + 1
            while cursor < len(lines) and lines[cursor].strip() != "@end":
                body.append(lines[cursor])
                cursor += 1
            _require(cursor < len(lines), path, number, f"{directive} is not closed by @end")
            while body and body[-1].strip() == "":
                body.pop()
            _require(bool(body), path, number, f"{directive} block is empty")
            items.append(Item(kind=directive[1:], line=number, lines=body))
            index = cursor + 1
            continue

        _require(
            raw == raw.strip(),
            path,
            number,
            f"an option reference starts at column zero, got {raw!r}",
        )
        _require(
            bool(spec.CLI_FLAG_RE.match(raw)),
            path,
            number,
            f"{raw!r} is neither a directive nor an option spelling",
        )
        items.append(Item(kind="ref", line=number, text=raw))
        index += 1
    return items


@dataclass
class Entry:
    """One option, as the manual declares it and the terminal prints it."""

    option: spec.Option
    source: Path
    flags: list[str]
    spell: str
    help: list[str]
    file: bool
    values: list[str]
    indent: int
    column: int
    continuation: int


def load_options(manual: str, language: str = spec.DEFAULT_LANGUAGE) -> tuple[list[Entry], list[spec.Option]]:
    """Every option one manual declares that reaches the command line.

    The first list is one element per printed help entry, in declaration
    order. The second is every option that completes, printed or not, which is
    what the completion word list is built from.
    """
    source = SOURCE_ROOT / language / "man" / f"{manual}.doc"
    if not source.is_file():
        raise CliError(f"{spec.relative(source)}: the layout names no such manual")
    doc = spec.parse(source, language)

    completed: list[spec.Option] = []
    printed: list[Entry] = []
    for block in doc.blocks:
        if block.kind != "options":
            continue
        for option in block.options:
            # An option list is also how a manual sets a term list, so an
            # entry only reaches the shell when it names a flag. Membership
            # is automatic rather than opt-in, because an option added to the
            # manual and forgotten in a completion table is the exact drift
            # this generator replaced.
            if not spec.cli_flags(option):
                continue
            completed.append(option)
            for entry in option.cli_print:
                printed.append(
                    Entry(
                        option=option,
                        source=source,
                        flags=sorted(spec.cli_flags(option)),
                        spell=entry["spell"],
                        help=list(entry["help"]),
                        file=spec.BOOLEANS[option.cli["file"]] if "file" in option.cli else False,
                        values=option.cli["values"].split() if "values" in option.cli else [],
                        indent=int(entry.get("indent", TERM_INDENT)),
                        column=int(entry.get("column", COLUMN)),
                        continuation=int(entry.get("continuation", CONTINUATION)),
                    )
                )
    return printed, completed


def resolve(layout: Layout, language: str = spec.DEFAULT_LANGUAGE) -> tuple[list[Entry], list[spec.Option]]:
    """Bind every layout reference to its help entry, and prove the two agree.

    A reference names a flag. An option that prints more than one entry is
    referenced once per entry and hands them out in declaration order, which
    is how yumed(8) prints a port form and an address form of --listen from
    one documented option.
    """
    printed, completed = load_options(layout.manual, language)

    queues: dict[str, list[Entry]] = {}
    for entry in printed:
        for flag in entry.flags:
            queues.setdefault(flag, [])
    for entry in printed:
        for flag in entry.flags:
            queues[flag].append(entry)

    taken: set[int] = set()
    ordered: list[Entry] = []
    for item in layout.items:
        if item.kind != "ref":
            continue
        queue = queues.get(item.text)
        _require(
            bool(queue),
            layout.path,
            item.line,
            f"{item.text} has no @opt carrying '@cli spell' in {layout.manual}",
        )
        assert queue is not None
        entry = next((candidate for candidate in queue if id(candidate) not in taken), None)
        _require(
            entry is not None,
            layout.path,
            item.line,
            f"{item.text} is referenced more often than the manual prints it",
        )
        assert entry is not None
        taken.add(id(entry))
        ordered.append(entry)

    # The other direction. An option that carries help text the layout never
    # places would be documented, completed, and invisible, which is exactly
    # the drift this file exists to stop.
    orphans = [entry.spell for entry in printed if id(entry) not in taken]
    if orphans:
        raise CliError(
            f"{spec.relative(layout.path)}: {len(orphans)} help entr(ies) the "
            f"layout never prints: {', '.join(orphans)}"
        )
    return ordered, completed


def render_help(layout: Layout, ordered: list[Entry]) -> list[str]:
    """The exact lines `--help` prints after the brand header."""
    entries = iter(ordered)
    out: list[str] = []
    for item in layout.items:
        if item.kind == "usage":
            out.append("Usage:")
            out.extend(" " * TERM_INDENT + line for line in item.lines)
        elif item.kind == "section":
            out.append("")
            out.append(f"{item.text}:")
        elif item.kind == "gap":
            out.append("")
        elif item.kind == "note":
            out.extend(item.lines)
        else:
            out.extend(_render_entry(next(entries)))
    return out


def _render_entry(entry: Entry) -> list[str]:
    term = " " * entry.indent + entry.spell
    texts = entry.help
    if not any(text.strip() for text in texts):
        return [term]
    out: list[str] = []
    if len(term) + 1 <= entry.column:
        out.append(term.ljust(entry.column) + texts[0])
    else:
        out.append(term)
        out.append(" " * entry.column + texts[0])
    for text in texts[1:]:
        extra = len(text) - len(text.lstrip(" "))
        out.append(" " * (entry.continuation + extra) + text.strip())
    return out


def _completion_order(flag: str) -> tuple[int, str]:
    """Short flags, then bare subcommands, then long flags, each sorted.

    The hand-written script carried a word order nobody chose deliberately.
    A generated one has to pick a rule, and this is the one a reader can
    verify at a glance. The order has no effect on what completes, because
    `compgen -W` matches on the word rather than its position.
    """
    if flag.startswith("--") and flag != "--":
        return (2, flag)
    if flag.startswith("-"):
        return (0, flag)
    return (1, flag)


def render_completion(layout: Layout, completed: list[spec.Option]) -> list[str]:
    """The exact bash completion script the binary prints."""
    completed = [option for option in completed if option.cli.get("complete") != "no"]
    flags = sorted(
        {
            flag
            for option in completed
            for flag in spec.cli_flags(option)
            # `--` ends the options and is printed in the help, but no shell
            # offers it as a word to complete.
            if flag != "--"
        },
        key=_completion_order,
    )
    files = sorted(
        {
            flag
            for option in completed
            if "file" in option.cli and spec.BOOLEANS[option.cli["file"]]
            for flag in spec.cli_flags(option)
        },
        key=_completion_order,
    )

    cases: list[tuple[list[str], list[str]]] = []
    for option in completed:
        if "values" in option.cli:
            cases.append((sorted(spec.cli_flags(option), key=_completion_order),
                          option.cli["values"].split()))

    binary = layout.binary
    out = [
        f"# bash completion for {binary}",
        f"_{binary}_complete() {{",
        "  local cur prev",
        '  cur="${COMP_WORDS[COMP_CWORD]}"',
        '  prev="${COMP_WORDS[COMP_CWORD-1]}"',
        '  local opts="' + " ".join(flags) + '"',
        '  local file_opts="' + " ".join(files) + '"',
        '  case "$prev" in',
    ]
    for names, words in cases:
        out.append("    " + "|".join(names) + ")")
        out.append('      COMPREPLY=( $(compgen -W "' + " ".join(words) + '" -- "$cur") )')
        out.append("      return 0")
        out.append("      ;;")
    out.extend([
        "  esac",
        "  for opt in $file_opts; do",
        '    if [[ "$prev" == "$opt" ]]; then',
        '      COMPREPLY=( $(compgen -f -- "$cur") )',
        "      return 0",
        "    fi",
        "  done",
        '  if [[ "$cur" == -* ]]; then',
        '    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )',
        "    return 0",
        "  fi",
        "  COMPREPLY=()",
        "}",
        f"complete -F _{binary}_complete {binary}",
    ])
    return out


def _cxx_literal(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}\\n"'


def _stream_line(line: str, layout: Layout) -> list[str]:
    """One printed line as a stream expression, splitting at interpolations."""
    pieces: list[str] = []
    cursor = 0
    for match in INTERPOLATION_RE.finditer(line):
        name = match.group(1)
        if name not in INTERPOLATIONS:
            raise CliError(
                f"{spec.relative(layout.path)}: unknown interpolation {{{{{name}}}}}; "
                f"known values are {', '.join(sorted(INTERPOLATIONS))}"
            )
        head = line[cursor:match.start()]
        if head:
            pieces.append(f'"{head.replace(chr(92), chr(92) * 2)}"')
        pieces.append(INTERPOLATIONS[name])
        cursor = match.end()
    tail = line[cursor:]
    if pieces:
        pieces.append(_cxx_literal(tail))
        return pieces
    return [_cxx_literal(line)]


def render_header(layout: Layout, ordered: list[Entry], completed: list[spec.Option]) -> str:
    help_lines = render_help(layout, ordered)

    needs_policy = any(
        INTERPOLATIONS[name].startswith("yume::policy::")
        for line in help_lines
        for name in INTERPOLATION_RE.findall(line)
        if name in INTERPOLATIONS
    )

    out = [
        f"// Generated by {BANNER} from {spec.relative(layout.path)}. Do not edit.",
        "//",
        "// YUME - Yume Universal Multiprotocol Engine",
        "// Copyright (C) 2020-2026  FixCraft Inc.",
        "// Licensed under the GNU Affero General Public License v3.0 or later.",
        "//",
        f"// The option model lives in the {layout.manual} manual source. Edit the",
        f"// @opt and @cli entries there, then run {BANNER} sync.",
        "",
        "#pragma once",
        "",
    ]
    if layout.output_kind == "static-help":
        if any(INTERPOLATION_RE.search(line) for line in help_lines):
            raise CliError(f"{spec.relative(layout.path)}: static-help cannot interpolate runtime values")
        out.extend([
            f"namespace {layout.namespace} {{",
            "",
            "inline constexpr char kHelpBody[] =",
            *[f"    {_cxx_literal(line)}" for line in help_lines],
        ])
        out[-1] += ";"
        out.extend(["", f"}}  // namespace {layout.namespace}", ""])
        return "\n".join(out)

    completion_lines = render_completion(layout, completed)
    out.append("#include <ostream>")
    if needs_policy:
        out.append("")
        out.append('#include "core/protocol/runtime_policy.hpp"')
    out.extend([
        "",
        f"namespace {layout.namespace} {{",
        "",
        "inline void write_help_body(std::ostream& out) {",
        "    out",
    ])
    for line in help_lines:
        for piece in _stream_line(line, layout):
            out.append(f"        << {piece}")
    out[-1] = out[-1] + ";"
    out.extend([
        "}",
        "",
        "inline void write_bash_completion(std::ostream& out) {",
        "    out << R\"(" + "\n".join(completion_lines),
        ")\";",
        "}",
        "",
        f"}}  // namespace {layout.namespace}",
        "",
    ])
    return "\n".join(out)


def build(layout: Layout, language: str = spec.DEFAULT_LANGUAGE) -> str:
    ordered, completed = resolve(layout, language)
    return render_header(layout, ordered, completed)


def _write(path: Path, text: str) -> bool:
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "command", choices=("list", "render", "sync", "check"), help="what to do"
    )
    parser.add_argument("binary", nargs="?", help="one binary, for render")
    parser.add_argument("--language", default=spec.DEFAULT_LANGUAGE)
    parser.add_argument(
        "--layer",
        choices=("cpp", "help", "completion"),
        default="cpp",
        help="what render prints",
    )
    args = parser.parse_args(argv)

    try:
        layouts = load_layouts(args.language)
    except (CliError, spec.DocError) as exc:
        print(f"cli: {exc}", file=sys.stderr)
        return 1
    if not layouts:
        print(f"cli: no layouts under docs/src/{args.language}/cli", file=sys.stderr)
        return 1

    try:
        if args.command == "list":
            for layout in layouts:
                ordered, completed = resolve(layout, args.language)
                print(
                    f"{layout.binary}: {len(ordered)} printed, "
                    f"{len(completed)} completed -> {layout.output}"
                )
            return 0

        if args.command == "render":
            chosen = [item for item in layouts if item.binary == args.binary]
            if not chosen:
                print(f"cli: unknown binary {args.binary!r}", file=sys.stderr)
                return 1
            layout = chosen[0]
            ordered, completed = resolve(layout, args.language)
            if args.layer == "help":
                print("\n".join(render_help(layout, ordered)))
            elif args.layer == "completion":
                print("\n".join(render_completion(layout, completed)))
            else:
                sys.stdout.write(render_header(layout, ordered, completed))
            return 0

        stale: list[str] = []
        for layout in layouts:
            text = build(layout, args.language)
            target = REPO_ROOT / layout.output
            if args.command == "sync":
                if _write(target, text):
                    print(f"cli: wrote {layout.output}")
            elif not target.is_file() or target.read_text(encoding="utf-8") != text:
                stale.append(layout.output)
    except (CliError, spec.DocError) as exc:
        print(f"cli: {exc}", file=sys.stderr)
        return 1

    if stale if args.command == "check" else False:
        for path in stale:
            print(f"cli: {path} is stale, so run scripts/yume_cli.py sync", file=sys.stderr)
        return 1
    if args.command == "check":
        print(f"cli: {len(layouts)} layouts, {len(layouts)} generated files checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
