#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""scripts/check_reachability.py finds unreachable code and nothing else.

A small C project stands in for the tree: one production program, one test
program and a library whose functions the programs reach or do not.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_reachability", ROOT / "scripts" / "check_reachability.py")
reachability = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reachability
SPEC.loader.exec_module(reachability)

CACHE = {
    "CMAKE_BUILD_TYPE:STRING": "Debug",
    "YUME_BUILD_NATIVE_APPLICATION:BOOL": "ON",
    "YUME_BUILD_SHARED_ABI:BOOL": "ON",
    "YUME_BUILD_BASEFWX_MODULES:BOOL": "ON",
    "YUME_BUILD_GUI:BOOL": "ON",
    "YUME_BUILD_TESTING:BOOL": "ON",
    "YUME_LTO:BOOL": "OFF",
    "YUME_SANITIZE:STRING": "none",
    "CMAKE_C_FLAGS:STRING": "-ffunction-sections -fdata-sections",
    "CMAKE_CXX_FLAGS:STRING": "-ffunction-sections -fdata-sections",
    "CMAKE_EXE_LINKER_FLAGS:STRING": "-Wl,--gc-sections",
    "CMAKE_SHARED_LINKER_FLAGS:STRING": "-Wl,--gc-sections",
}

SOURCES = {
    "src/lib/library.c": (
        "int yume_used(void) { return 1; }\n"
        "int yume_tests_only(void) { return 2; }\n"
        "int yume_nowhere(void) { return 3; }\n"),
    "src/lib/library.h": (
        "int yume_used(void);\nint yume_tests_only(void);\nint yume_nowhere(void);\n"),
    "src/app/main.c": '#include "lib/library.h"\nint main(void) { return yume_used() - 1; }\n',
    "src/lib/library_test.c": (
        '#include "lib/library.h"\nint main(void) { return yume_tests_only() - 2; }\n'),
    "src/lib/unbuilt.c": "int yume_unbuilt(void) { return 4; }\n",
}


@unittest.skipUnless(shutil.which("cc") and shutil.which("nm") and shutil.which("c++filt"),
                     "needs cc, nm and c++filt")
class Reachability(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.root = Path(self.scratch.name) / "repo"
        self.build = Path(self.scratch.name) / "build"
        for relative, text in SOURCES.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.build.mkdir()
        (self.build / "CMakeCache.txt").write_text(
            "".join(f"{key}={value}\n" for key, value in CACHE.items()), encoding="utf-8")
        commands = []
        objects = {}
        for source in ("src/lib/library.c", "src/app/main.c", "src/lib/library_test.c"):
            output = f"obj/{Path(source).stem}.o"
            arguments = ["cc", "-O0", "-ffunction-sections", "-fdata-sections",
                         f"-I{self.root / 'src'}", "-c", str(self.root / source), "-o", output]
            (self.build / "obj").mkdir(exist_ok=True)
            subprocess.run(arguments, cwd=self.build, check=True)
            commands.append({"directory": str(self.build), "file": str(self.root / source),
                             "arguments": arguments, "output": output})
            objects[source] = self.build / output
        (self.build / "compile_commands.json").write_text(json.dumps(commands), encoding="utf-8")
        (self.build / "bin").mkdir()
        for program, sources in (("yume", ["src/app/main.c", "src/lib/library.c"]),
                                 ("library_test", ["src/lib/library_test.c", "src/lib/library.c"])):
            subprocess.run(["cc", "-Wl,--gc-sections", "-o", str(self.build / "bin" / program)]
                           + [str(objects[source]) for source in sources], check=True)
        self.saved_root = reachability.REPO_ROOT
        reachability.REPO_ROOT = self.root

    def tearDown(self) -> None:
        reachability.REPO_ROOT = self.saved_root
        self.scratch.cleanup()

    def run_check(self, retained: list[dict]) -> reachability.Result:
        path = self.root / "reachability.json"
        path.write_text(json.dumps({"schema": 1, "production": ["yume"],
                                    "retained": retained}), encoding="utf-8")
        return reachability.check(self.build, reachability.load_config(path), 2)

    def unretained(self, result: reachability.Result) -> set[tuple[str, bool]]:
        return {(item["function"], item["only_in_tests"])
                for item in result.unreachable if item["retained_by"] is None}

    def test_unreachable_functions_and_unbuilt_files_are_reported(self) -> None:
        result = self.run_check([])
        self.assertTrue(result.failed)
        self.assertEqual(self.unretained(result),
                         {("yume_tests_only", True), ("yume_nowhere", False)})
        self.assertEqual(result.unreached_files, ["src/lib/unbuilt.c"])

    def test_retained_code_passes_with_its_reason(self) -> None:
        result = self.run_check([
            {"path": "src/lib/library.c", "functions": ["yume_tests_only", "yume_now*"],
             "reason": "kept for the test"},
            {"path": "src/lib/unbuilt.c", "reason": "kept for a planned program"},
        ])
        self.assertFalse(result.failed, reachability.report(result))

    def test_a_whole_directory_can_be_retained(self) -> None:
        result = self.run_check([{"path": "src/lib/", "reason": "a planned module library"}])
        self.assertFalse(result.failed, reachability.report(result))

    def test_a_stale_entry_fails(self) -> None:
        result = self.run_check([
            {"path": "src/lib/library.c", "functions": ["yume_tests_only", "yume_nowhere",
                                                        "yume_used"],
             "reason": "one of these is reachable"},
            {"path": "src/lib/unbuilt.c", "reason": "kept for a planned program"},
            {"path": "src/app/main.c", "reason": "nothing here is unreachable"},
        ])
        self.assertTrue(result.failed)
        self.assertEqual(sorted(result.stale), ["src/app/main.c", "src/lib/library.c: yume_used"])

    def test_a_tree_built_without_gc_sections_is_refused(self) -> None:
        cache = self.build / "CMakeCache.txt"
        cache.write_text(cache.read_text().replace("-Wl,--gc-sections", ""), encoding="utf-8")
        with self.assertRaisesRegex(reachability.ReachabilityError, "gc-sections"):
            self.run_check([])

    def test_an_optimized_compile_is_refused(self) -> None:
        commands = json.loads((self.build / "compile_commands.json").read_text())
        commands[0]["arguments"].append("-O2")
        (self.build / "compile_commands.json").write_text(json.dumps(commands))
        with self.assertRaisesRegex(reachability.ReachabilityError, "-O2"):
            self.run_check([])

    def test_a_missing_production_program_is_refused(self) -> None:
        (self.build / "bin" / "yume").unlink()
        with self.assertRaisesRegex(reachability.ReachabilityError, "one built yume"):
            self.run_check([])


class ConfigValidation(unittest.TestCase):
    def load(self, document: object) -> reachability.Config:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(document, handle)
        try:
            return reachability.load_config(Path(handle.name))
        finally:
            Path(handle.name).unlink()

    def test_the_tracked_config_loads(self) -> None:
        config = reachability.load_config(reachability.DEFAULT_CONFIG)
        self.assertIn("yume", config.production)

    def test_an_entry_needs_a_reason_in_words(self) -> None:
        with self.assertRaisesRegex(reachability.ReachabilityError, "reason"):
            self.load({"schema": 1, "production": ["yume"],
                       "retained": [{"path": "src/a.cpp", "reason": "tests"}]})

    def test_an_entry_outside_the_sources_is_refused(self) -> None:
        with self.assertRaisesRegex(reachability.ReachabilityError, "under src/"):
            self.load({"schema": 1, "production": ["yume"],
                       "retained": [{"path": "tools/a.py", "reason": "kept on purpose here"}]})

    def test_unknown_keys_are_refused(self) -> None:
        with self.assertRaisesRegex(reachability.ReachabilityError, "exactly"):
            self.load({"schema": 1, "production": ["yume"], "retained": [], "extra": 1})


if __name__ == "__main__":
    unittest.main()
