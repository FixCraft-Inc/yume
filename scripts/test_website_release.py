#!/usr/bin/env python3
# YUME - Yume Universal Multiprotocol Engine
# Copyright (C) 2026 FixCraft Inc.
# Licensed under the GNU Affero General Public License v3.0 or later.
"""Exercise the checksums page with the release publisher's inventory and an offline GitHub fixture."""

import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from release_integrity import PUBLISHED_FILES


SITE = Path(__file__).resolve().parents[1] / "website"
REPOSITORY = "https://github.com/FixCraft-Inc/yume"
LATEST = "https://api.github.com/repos/FixCraft-Inc/yume/releases/latest"
DIGEST = "f" * 64


def release(tag="v0.3.0"):
    return {
        "tag_name": tag, "draft": False, "prerelease": False,
        "published_at": "2026-01-01T00:00:00Z",
        "assets": [
            {"name": name, "state": "uploaded", "size": 128,
             "browser_download_url": f"{REPOSITORY}/releases/download/{tag}/{name}"}
            for name in PUBLISHED_FILES
        ],
    }


class WebsiteReleaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.browser = shutil.which("google-chrome") or shutil.which("chromium")
        if not cls.browser:
            raise RuntimeError("The release page test needs Chrome or Chromium")
        temporary = tempfile.TemporaryDirectory(prefix="yume-website-release-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.page = (SITE / "hashes/index.html").read_text().split("---", 2)[2]
        shutil.copyfile(SITE / "assets/site.js", cls.directory / "site.js")

    def visit(self, status=200, data=None, *, scripts=True):
        # Substitute fetch before the production script runs. Record the rendered
        # status and links after its HTTP promises have settled.
        fixture = json.dumps({"status": status, "release": data, "latest": LATEST})
        script = '<script src="site.js" defer></script>' if scripts else ""
        page = self.directory / "index.html"
        page.write_text(f"""<!doctype html><meta charset="utf-8"><script>
            const fixture = {fixture};
            const requests = [];
            window.fetch = async (url) => {{
              requests.push(url);
              if (url === fixture.latest)
                return {{status: fixture.status, ok: fixture.status === 200, json: async () => fixture.release}};
              if (fixture.release?.assets.some(a => a.browser_download_url === url && a.name.endsWith(".sha256")))
                return {{ok: true, text: async () => "{DIGEST}  filename"}};
              throw new Error("unexpected request");
            }};
            </script>{script}<body>{self.page}
            <script>
            window.addEventListener("load", () => setTimeout(() => {{
              const links = Array.from(document.querySelectorAll("[data-download], [data-asset], [data-asset-link]"));
              const result = {{
                requests, version: document.querySelector("#release-version").textContent,
                status: document.querySelector("#release-date").textContent,
                links: links.map(a => a.getAttribute("href")),
                enabled: links.filter(a => !a.hasAttribute("aria-disabled")).length,
                hashes: Array.from(document.querySelectorAll("[data-hash-file]"), e => e.dataset.fullHash || e.textContent)
              }};
              document.body.textContent = "OBSERVED=" + JSON.stringify(result);
            }}, 0));
            </script>""")
        run = subprocess.run([
            self.browser, "--headless", "--disable-background-networking",
            "--host-resolver-rules=MAP * ~NOTFOUND", "--no-first-run",
            f"--user-data-dir={self.directory / 'browser'}", "--virtual-time-budget=1000",
            "--dump-dom", page.as_uri(),
        ], capture_output=True, text=True, check=True, timeout=30)
        observed = re.search(r"<body>OBSERVED=(.+)</body>", run.stdout)
        self.assertIsNotNone(observed, "browser did not report the release page state")
        return json.loads(observed[1])

    def assert_disabled(self, result, status):
        self.assertEqual(result["status"], status)
        self.assertEqual(result["hashes"], [status, status])
        self.assertEqual(result["enabled"], 0)
        self.assertTrue(result["links"])
        self.assertTrue(all(link is None for link in result["links"]))
        self.assertEqual(result["requests"], [LATEST])

    def test_complete_stable_release(self):
        data = release()
        result = self.visit(data=data)
        self.assertEqual(result["version"], data["tag_name"])
        self.assertEqual(result["enabled"], len(result["links"]))
        self.assertEqual(result["hashes"], [DIGEST, DIGEST])
        urls = {asset["browser_download_url"] for asset in data["assets"]}
        self.assertTrue(set(result["links"]) <= urls)
        self.assertCountEqual(result["requests"], [LATEST, *(url for url in urls if url.endswith(".sha256"))])

    def test_partial_publication(self):
        for missing in PUBLISHED_FILES:
            with self.subTest(missing=missing):
                data = release()
                data["assets"] = [a for a in data["assets"] if a["name"] != missing]
                self.assert_disabled(self.visit(data=data), "Stable release files unavailable")

    def test_unpublished_files_and_prereleases(self):
        for changes in ({"prerelease": True}, {"draft": True}):
            with self.subTest(changes=changes):
                self.assert_disabled(self.visit(data=release() | changes), "Stable release files unavailable")
        data = release()
        data["assets"][-1]["state"] = "starter"
        self.assert_disabled(self.visit(data=data), "Stable release files unavailable")
        self.assert_disabled(self.visit(data=release("v0.3.0-rc1")), "Stable release files unavailable")

    def test_empty_and_unavailable_are_distinct(self):
        self.assert_disabled(self.visit(404), "No stable release published")
        self.assert_disabled(self.visit(503), "Release information unavailable")

    def test_without_site_script(self):
        result = self.visit(scripts=False)
        self.assertEqual(result["requests"], [])
        self.assertEqual(result["status"], "See GitHub Releases for availability")
        self.assertEqual(result["enabled"], 0)
        self.assertTrue(all(link is None for link in result["links"]))


if __name__ == "__main__":
    unittest.main()
