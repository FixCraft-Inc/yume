#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026  FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""scripts/ensure-node.sh accepts only the pinned, verified Node build.

A fake curl on PATH stands in for the download, so nothing leaves the host.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "ensure-node.sh"


def executable(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class EnsureNode(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.root = Path(self.scratch.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.cache = self.root / "cache"
        self.calls = self.root / "curl-calls"

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def run_helper(self) -> subprocess.CompletedProcess:
        environment = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                           YUME_CACHE_ROOT=str(self.cache))
        return subprocess.run(["bash", str(HELPER)], env=environment, capture_output=True,
                              text=True, timeout=60)

    def fake_curl(self, archive_bytes: bytes) -> None:
        payload = self.root / "payload"
        payload.write_bytes(archive_bytes)
        executable(self.bin / "curl", f'''
echo called >> "{self.calls}"
while [[ $# -gt 0 ]]
do
    if [[ "$1" == "--output" ]]
    then
        cp "{payload}" "$2"
    fi
    shift
done
''')

    def test_a_checksum_mismatch_fails_and_keeps_nothing(self) -> None:
        self.fake_curl(b"not the pinned archive")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertEqual([path.name for path in self.cache.iterdir()], [])

    def test_a_failed_download_fails(self) -> None:
        executable(self.bin / "curl", "exit 22\n")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Could not download", result.stderr)

    def test_a_verified_cache_is_used_without_a_download(self) -> None:
        prefix = self.cache / "node-v24.18.0-linux-x64"
        (prefix / "bin").mkdir(parents=True)
        executable(prefix / "bin" / "node", 'echo v24.18.0\n')
        (prefix / ".yume-verified").touch()
        self.fake_curl(b"unused")
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(prefix / "bin" / "node"))
        self.assertFalse(self.calls.exists())

    def test_an_unverified_or_wrong_cache_is_not_trusted(self) -> None:
        prefix = self.cache / "node-v24.18.0-linux-x64"
        (prefix / "bin").mkdir(parents=True)
        executable(prefix / "bin" / "node", 'echo v24.18.0\n')
        self.fake_curl(b"not the pinned archive")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.calls.exists())

    def test_the_pin_matches_the_cover_tools(self) -> None:
        text = HELPER.read_text(encoding="utf-8")
        package = json.loads(
            (ROOT / "tools" / "cover-node" / "package.json").read_text(encoding="utf-8"))
        engine = package["engines"]["node"]
        self.assertTrue(engine.endswith(".x"), engine)
        version = re.search(r'^YUME_NODE_VERSION="([0-9.]+)"$', text, re.M).group(1)
        self.assertTrue(version.startswith(engine[:-1]), (version, engine))


if __name__ == "__main__":
    unittest.main()
