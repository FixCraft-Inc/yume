#!/usr/bin/env python3
"""Exercise the SDK install gate's capability selection without a compiler."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "cmake/check_yume_abi_install.cmake"
FIXTURE = Path(__file__).resolve().parent / "abi/install_consumer"


class InstallGateTest(unittest.TestCase):
    def check_gate(self, applications: bool, tools: bool) -> tuple[str, list[str], str]:
        with tempfile.TemporaryDirectory(prefix="yume-install-gate-") as temporary:
            root = Path(temporary)
            build = root / "configured"
            build.mkdir()
            (build / "CMakeCache.txt").write_text(
                f"YUME_BUILD_NATIVE_APPLICATION:BOOL={'ON' if applications else 'OFF'}\n")
            installer = '''
file(APPEND "${CMAKE_INSTALL_PREFIX}/components.txt" "${CMAKE_INSTALL_COMPONENT}\\n")
file(MAKE_DIRECTORY "${CMAKE_INSTALL_PREFIX}/include/yume" "${CMAKE_INSTALL_PREFIX}/lib" "${CMAKE_INSTALL_PREFIX}/bin")
file(WRITE "${CMAKE_INSTALL_PREFIX}/include/yume/yume.h" "fixture")
file(WRITE "${CMAKE_INSTALL_PREFIX}/lib/libyume.so" "fixture")
file(WRITE "${CMAKE_INSTALL_PREFIX}/lib/yume.pc" "fixture")
file(WRITE "${CMAKE_INSTALL_PREFIX}/lib/yumeConfig.cmake" "fixture")
'''
            if tools:
                installer += '''
foreach(tool IN ITEMS yume-setup yume-doctor)
 file(WRITE "${CMAKE_INSTALL_PREFIX}/bin/${tool}" "#!/bin/sh\\nexit 0\\n")
 file(CHMOD "${CMAKE_INSTALL_PREFIX}/bin/${tool}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
endforeach()
'''
            (build / "cmake_install.cmake").write_text(installer)
            programs = root / "programs"
            programs.mkdir()
            pkg = programs / "pkg-config"
            pkg.write_text("#!/bin/sh\necho 'fixture reached SDK metadata' >&2\nexit 71\n")
            pkg.chmod(0o700)
            result = subprocess.run(
                ["cmake", f"-DYUME_BUILD_DIR={build}", f"-DYUME_TEST_PREFIX={build / 'stage'}",
                 f"-DYUME_CONSUMER_SOURCE_DIR={FIXTURE}", "-P", str(SCRIPT)],
                env={**os.environ, "PATH": str(programs) + os.pathsep + os.environ["PATH"]},
                text=True, capture_output=True, timeout=15, check=False)
            self.assertNotEqual(result.returncode, 0, "fixture must stop before real SDK compilation")
            prefix, = build.glob("stage-*")
            stages = list((prefix / "sdk-stage-records").glob("*.json"))
            return (result.stdout + result.stderr,
                    (prefix / "components.txt").read_text().splitlines(),
                    " ".join(stage.name for stage in stages))

    def test_sdk_only_does_not_require_native_tools(self) -> None:
        output, components, stages = self.check_gate(False, False)
        self.assertIn("fixture reached SDK metadata", output)
        self.assertEqual(components, ["libyume_runtime", "libyume_development"])
        self.assertNotIn("installed-yume-setup", stages)

    def test_native_application_install_requires_its_tools(self) -> None:
        output, components, _ = self.check_gate(True, False)
        self.assertIn("staged install omitted yume-setup", output)
        self.assertIn("yume_cli", components)

    def test_native_application_tools_are_executed(self) -> None:
        output, _, stages = self.check_gate(True, True)
        self.assertIn("fixture reached SDK metadata", output)
        self.assertIn("installed-yume-setup", stages)
        self.assertIn("installed-yume-doctor", stages)


if __name__ == "__main__":
    unittest.main()
