#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Prove that first-party code is reachable from a shipped program.

Stale code is found by what the build reaches, never by name or text search.
This runs two exact checks over one built tree:

* Files. Every compile command is preprocessed (``-MM -MG``) and every tracked
  C or C++ file under ``src/`` and ``include/`` must be among the files some
  compile reads.
* Functions. The tree is built at ``-O0`` with one section per function and
  linked with ``--gc-sections``, so a function survives in a linked program
  exactly when something in that program reaches it. Every first-party
  function defined outside test code must survive in a production program.

``config/reachability.json`` names the production programs and the code
kept although no production program reaches it yet, each entry with its
reason. An entry that no longer matches anything fails too, so the list
cannot outlive what it describes.

Test code is ``*_test.cpp``, anything under a ``tests/`` directory and
``src/test_support/``. Test programs with other names are retained entries.

Static and anonymous-namespace functions that share a mangled name across
files are matched by name, so one reachable copy hides an unreachable one.
That can miss dead code but never fails live code.

Usage: python3 scripts/check_reachability.py BUILD_DIR [--report FILE]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "config" / "reachability.json"
SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".h", ".hpp", ".inc")
FUNCTION_TYPES = frozenset({"T", "t", "W"})
# Local C symbols that belong to a library or the toolchain, not to YUME.
FOREIGN_C = re.compile(r"^(sk_|lh_|ossl_|OPENSSL_|ERR_|ASN1_|X509|EVP_|BIO_|SSL_|__|_GLOBAL__)")
DROP_WITH_VALUE = frozenset({"-o", "-MF", "-MT", "-MQ"})
DROP_ALONE = frozenset({"-c", "-MD", "-MMD"})
TOOL_TIMEOUT = 600


class ReachabilityError(Exception):
    """A precondition failed, so no verdict can be given."""


@dataclass(frozen=True)
class Retained:
    path: str
    functions: tuple[str, ...]
    reason: str

    def covers(self, source: str, function: str) -> bool:
        if self.path.endswith("/"):
            if not source.startswith(self.path):
                return False
        elif source != self.path:
            return False
        return not self.functions or any(
            fnmatch.fnmatchcase(function, pattern) for pattern in self.functions)


@dataclass
class Config:
    production: tuple[str, ...]
    retained: tuple[Retained, ...]


@dataclass
class Result:
    unreached_files: list[str] = field(default_factory=list)
    unreachable: list[dict] = field(default_factory=list)
    stale: list[str] = field(default_factory=list)
    counts: dict = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return bool(self.unreached_files or self.stale or any(
            item["retained_by"] is None for item in self.unreachable))


def _run(command: list[str], cwd: Path | None = None, stdin: str | None = None) -> str:
    try:
        result = subprocess.run(command, cwd=cwd, input=stdin, capture_output=True,
                                text=True, timeout=TOOL_TIMEOUT, check=False)
    except subprocess.TimeoutExpired as error:
        raise ReachabilityError(f"{command[0]} timed out after {TOOL_TIMEOUT} s") from error
    except OSError as error:
        raise ReachabilityError(f"cannot run {command[0]}: {error}") from error
    if result.returncode != 0:
        raise ReachabilityError(
            f"{' '.join(command[:3])} ... failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def load_config(path: Path) -> Config:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReachabilityError(f"cannot read {path}: {error}") from error
    if not isinstance(document, dict) or set(document) != {"schema", "production", "retained"}:
        raise ReachabilityError(f"{path}: expected exactly schema, production and retained")
    if document["schema"] != 1:
        raise ReachabilityError(f"{path}: unknown schema {document['schema']!r}")
    production = document["production"]
    if (not isinstance(production, list) or not production
            or not all(isinstance(name, str) and name for name in production)):
        raise ReachabilityError(f"{path}: production must list program file names")
    retained = []
    for index, entry in enumerate(document["retained"]):
        where = f"{path}: retained[{index}]"
        if not isinstance(entry, dict) or not {"path", "reason"} <= set(entry) \
                or not set(entry) <= {"path", "functions", "reason"}:
            raise ReachabilityError(f"{where} needs path and reason, and optionally functions")
        if not isinstance(entry["path"], str) or not entry["path"].startswith(("src/", "include/")):
            raise ReachabilityError(f"{where}: path must be under src/ or include/")
        if not isinstance(entry["reason"], str) or len(entry["reason"].split()) < 3:
            raise ReachabilityError(f"{where}: give the reason in words")
        functions = entry.get("functions", [])
        if not isinstance(functions, list) or not all(
                isinstance(pattern, str) and pattern for pattern in functions):
            raise ReachabilityError(f"{where}: functions must be a list of patterns")
        retained.append(Retained(entry["path"], tuple(functions), entry["reason"]))
    return Config(tuple(production), tuple(retained))


def _cache(build: Path) -> dict[str, str]:
    values = {}
    try:
        text = (build / "CMakeCache.txt").read_text(encoding="utf-8")
    except OSError as error:
        raise ReachabilityError(f"{build} is not a configured CMake tree: {error}") from error
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9_]+):[A-Z]+=(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


def check_build_tree(build: Path) -> None:
    """Refuse a tree whose build could make the answer wrong."""
    cache = _cache(build)
    expected = {
        "CMAKE_BUILD_TYPE": "Debug",
        "YUME_BUILD_NATIVE_APPLICATION": "ON",
        "YUME_BUILD_SHARED_ABI": "ON",
        "YUME_BUILD_BASEFWX_MODULES": "ON",
        "YUME_BUILD_GUI": "ON",
        "YUME_BUILD_TESTING": "ON",
        "YUME_LTO": "OFF",
        "YUME_SANITIZE": "none",
    }
    for key, value in expected.items():
        if cache.get(key) != value:
            raise ReachabilityError(
                f"{build}: {key} is {cache.get(key)!r}, the check needs {value!r}")
    for key in ("CMAKE_C_FLAGS", "CMAKE_CXX_FLAGS"):
        flags = cache.get(key, "").split()
        for flag in ("-ffunction-sections", "-fdata-sections"):
            if flag not in flags:
                raise ReachabilityError(f"{build}: {key} lacks {flag}")
    for key in ("CMAKE_EXE_LINKER_FLAGS", "CMAKE_SHARED_LINKER_FLAGS"):
        if "-Wl,--gc-sections" not in cache.get(key, "").split():
            raise ReachabilityError(f"{build}: {key} lacks -Wl,--gc-sections")


def _arguments(entry: dict) -> list[str]:
    return entry["arguments"] if "arguments" in entry else shlex.split(entry["command"])


def object_path(entry: dict) -> Path:
    """The object the compiler writes: its -o, relative to the directory it
    runs in. CMake's "output" is relative to that directory under Ninja but
    to the top of the build tree under Makefiles, where each source directory
    has its own."""
    arguments = _arguments(entry)
    for index, argument in enumerate(arguments):
        if argument == "-o" and index + 1 < len(arguments):
            return Path(entry["directory"], arguments[index + 1])
        if argument.startswith("-o") and len(argument) > 2:
            return Path(entry["directory"], argument[2:])
    raise ReachabilityError(f"{entry['relative']}: the compile command names no -o output")


def _optimization(arguments: list[str]) -> str:
    level = "-O0"
    for argument in arguments:
        if re.fullmatch(r"-O[0-3sgz]?|-Ofast", argument):
            level = argument if argument != "-O" else "-O1"
    return level


def load_compile_commands(build: Path) -> list[dict]:
    try:
        entries = json.loads((build / "compile_commands.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReachabilityError(
            f"{build}: configure with CMAKE_EXPORT_COMPILE_COMMANDS=ON ({error})") from error
    first_party = []
    for entry in entries:
        source = Path(entry["directory"], entry["file"]).resolve()
        try:
            relative = source.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            continue
        if not relative.startswith(("src/", "include/")):
            continue
        level = _optimization(_arguments(entry))
        if level != "-O0":
            raise ReachabilityError(f"{relative} compiles at {level}, the check needs -O0")
        first_party.append(dict(entry, relative=relative))
    if not first_party:
        raise ReachabilityError(f"{build}: no first-party compile commands")
    return first_party


def tracked_sources() -> set[str]:
    if (REPO_ROOT / ".git").exists():
        listed = _run(["git", "ls-files", "-z", "src", "include"], cwd=REPO_ROOT).split("\0")
    else:
        # A synced build-host workspace holds exactly the Git-visible files.
        print("reachability: no Git checkout, taking every file under src/ and include/")
        listed = [path.relative_to(REPO_ROOT).as_posix()
                  for top in ("src", "include") for path in (REPO_ROOT / top).rglob("*")]
    return {path for path in listed
            if path.endswith(SOURCE_SUFFIXES) and (REPO_ROOT / path).is_file()}


def _preprocessed_files(entry: dict) -> set[str]:
    arguments = []
    skip = False
    for argument in _arguments(entry):
        if skip:
            skip = False
        elif argument in DROP_WITH_VALUE:
            skip = True
        elif argument not in DROP_ALONE:
            arguments.append(argument)
    output = _run(arguments + ["-MM", "-MG"], cwd=Path(entry["directory"]))
    reached = set()
    for token in output.replace("\\\n", " ").split():
        if token.endswith(":"):
            continue
        path = Path(entry["directory"], token).resolve()
        try:
            reached.add(path.relative_to(REPO_ROOT).as_posix())
        except ValueError:
            pass
    return reached


def reached_files(entries: list[dict], jobs: int) -> set[str]:
    reached: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for files in pool.map(_preprocessed_files, entries):
            reached |= files
    return reached


def is_test_source(relative: str) -> bool:
    name = relative.rsplit("/", 1)[-1]
    return (name.endswith(("_test.cpp", "_test.c")) or "/tests/" in relative
            or relative.startswith("src/test_support/"))


def _symbols(path: Path) -> dict[str, str]:
    found = {}
    for line in _run(["nm", "-P", "--defined-only", str(path)]).splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] in FUNCTION_TYPES:
            found[fields[0]] = fields[1]
    return found


def _demangle(names: list[str]) -> dict[str, str]:
    if not names:
        return {}
    lines = _run(["c++filt"], stdin="\n".join(names) + "\n").splitlines()
    if len(lines) != len(names):
        raise ReachabilityError("c++filt returned a different number of names")
    return dict(zip(names, lines))


def _first_party(pretty: str, kind: str) -> bool:
    if pretty.startswith(("yume::", "yume_", "(anonymous namespace)")):
        return True
    return kind == "t" and "::" not in pretty and not FOREIGN_C.match(pretty)


def _is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(4) == b"\x7fELF"
    except OSError:
        return False


def programs(build: Path, names: tuple[str, ...]) -> tuple[list[Path], list[Path]]:
    """The production programs by name, and every other linked ELF file."""
    linked = [path for path in sorted(build.rglob("*"))
              if path.is_file() and not path.is_symlink()
              and path.suffix not in (".a", ".o") and _is_elf(path)
              and "CMakeFiles" not in path.relative_to(build).parts]
    production = []
    for name in names:
        matches = [path for path in linked if path.name == name]
        if len(matches) != 1:
            raise ReachabilityError(
                f"expected one built {name} under {build}, found {len(matches)}")
        production.append(matches[0])
    others = [path for path in linked if path not in production]
    return production, others


def check(build: Path, config: Config, jobs: int) -> Result:
    check_build_tree(build)
    entries = load_compile_commands(build)
    result = Result()

    tracked = tracked_sources()
    reached = reached_files(entries, jobs)
    used: set[Retained] = set()
    for path in sorted(tracked - reached):
        retained_by = next((entry for entry in config.retained
                            if not entry.functions and entry.covers(path, "")), None)
        if retained_by is None:
            result.unreached_files.append(path)
        else:
            used.add(retained_by)

    objects: dict[str, set[Path]] = {}
    for entry in entries:
        if is_test_source(entry["relative"]):
            continue
        output = object_path(entry)
        if not output.is_file():
            raise ReachabilityError(f"{output} is missing, so build the tree first")
        objects.setdefault(entry["relative"], set()).add(output)

    production, others = programs(build, config.production)
    in_production: set[str] = set()
    for program in production:
        in_production |= set(_symbols(program))
    in_other: set[str] = set()
    for program in others:
        in_other |= set(_symbols(program))

    defined: dict[str, tuple[str, set[str]]] = {}
    for source, outputs in sorted(objects.items()):
        for output in sorted(outputs):
            for name, kind in _symbols(output).items():
                defined.setdefault(name, (kind, set()))[1].add(source)
    pretty = _demangle(sorted(defined))

    checked = 0
    for name, (kind, sources) in sorted(defined.items()):
        function = pretty[name]
        if not _first_party(function, kind):
            continue
        checked += 1
        if name in in_production:
            continue
        for source in sorted(sources):
            retained_by = next(
                (entry for entry in config.retained if entry.covers(source, function)), None)
            if retained_by is not None:
                used.add(retained_by)
            result.unreachable.append({
                "source": source,
                "function": function,
                "only_in_tests": name in in_other,
                "retained_by": retained_by.path if retained_by else None,
            })
    for entry in config.retained:
        if entry.functions:
            for pattern in entry.functions:
                if not any(item["source"] == entry.path or (
                        entry.path.endswith("/") and item["source"].startswith(entry.path))
                        for item in result.unreachable
                        if fnmatch.fnmatchcase(item["function"], pattern)):
                    result.stale.append(f"{entry.path}: {pattern}")
        elif entry not in used:
            result.stale.append(entry.path)
    result.counts = {
        "tracked_files": len(tracked),
        "functions_checked": checked,
        "outside_production": len(result.unreachable),
        "production_programs": [path.relative_to(build).as_posix() for path in production],
    }
    return result


def report(result: Result) -> str:
    lines = [f"reachability: {result.counts['functions_checked']} first-party functions, "
             f"{result.counts['outside_production']} outside production programs"]
    for path in result.unreached_files:
        lines.append(f"  unreached file: {path}")
    for item in result.unreachable:
        if item["retained_by"] is None:
            where = "tests only" if item["only_in_tests"] else "no program"
            lines.append(f"  unreachable ({where}): {item['source']}: {item['function']}")
    for entry in result.stale:
        lines.append(f"  stale retention, nothing unreachable matches: {entry}")
    if result.failed:
        lines.append("reachability: remove the unreachable code, or retain it in "
                     "config/reachability.json with its reason")
    else:
        lines.append("reachability: passed")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("build_dir", type=Path)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--report", type=Path, help="write every finding as JSON")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    options = parser.parse_args(argv)
    try:
        result = check(options.build_dir.resolve(), load_config(options.config),
                       max(1, options.jobs))
    except ReachabilityError as error:
        print(f"reachability: {error}", file=sys.stderr)
        return 2
    if options.report:
        options.report.write_text(json.dumps({
            "counts": result.counts, "unreached_files": result.unreached_files,
            "unreachable": result.unreachable, "stale": result.stale,
        }, indent=1) + "\n", encoding="utf-8")
    print(report(result))
    return 1 if result.failed else 0


if __name__ == "__main__":
    sys.exit(main())
