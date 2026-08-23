#!/usr/bin/env python3
"""Guard: hot-path sources must not read a clock for diagnostics-only values.

`YUME_TIMING_LOG` compiles away in Release, but a bare `util::now_ms()` feeding
it does not: the call still happens and the result is discarded. Diagnostics
must cost a normal user nothing, so stream-lifecycle stamps go through
`diagnostics::timing_now_ms()` / `diagnostics::elapsed_ms_since()`, which are
constexpr 0 when YUME_ENABLE_DEV_DIAGNOSTICS is 0 and read no clock even in an
instrumented build until collection is enabled.

Functional timestamps -- chat message times, key derivation input, protocol
fields, anything a peer or user observes -- must keep using `util::now_ms()`.
They are not diagnostics and must not silently become 0. That is why this guard
covers the connection hot path only, rather than banning the call outright.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT / "src"

# Per-connection and per-stream sources. A clock read here is on the path of
# every session, so it must be diagnostics-gated.
HOT_PATH = (
    "server/session/session.cpp",
    "server/session/streams.cpp",
    "server/session/open_transport.cpp",
    "server/session/codecs.cpp",
    "server/session/ext.cpp",
    "server/session/reverse_listener.cpp",
    "server/session/internal.hpp",
    "client/proxy/socks.cpp",
    "client/proxy/forward.cpp",
    "client/transport/write.cpp",
    "client/transport/core.cpp",
)

CLOCK = re.compile(r"\butil::now_ms\s*\(")


def code_only(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


class ReleaseDiagnosticsCostTest(unittest.TestCase):
    def test_hot_path_takes_no_ungated_timestamps(self) -> None:
        offenders = []
        for rel in HOT_PATH:
            path = SCAN_ROOT / rel
            if not path.is_file():
                offenders.append(f"src/{rel}: listed source is missing")
                continue
            if CLOCK.search(code_only(path.read_text(encoding="utf-8"))):
                offenders.append(
                    f"src/{rel} calls util::now_ms() on the connection hot "
                    f"path. If the value only feeds YUME_TIMING_LOG, use "
                    f"diagnostics::timing_now_ms() / "
                    f"diagnostics::elapsed_ms_since(). If it is functional, "
                    f"move it off this path or narrow HOT_PATH with a reason.")
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_helpers_are_zero_cost_when_compiled_out(self) -> None:
        header = (SCAN_ROOT / "core/diagnostics/timing.hpp").read_text(
            encoding="utf-8")
        # The disabled form must fold to a constant, not call anything.
        self.assertIn(
            "inline constexpr std::int64_t timing_now_ms() noexcept "
            "{ return 0; }",
            header)
        # And the header itself must never reach the clock: the one real read
        # lives in timing.cpp, which is only compiled when diagnostics are on.
        self.assertNotIn("util::now_ms", code_only(header))

    def test_the_single_clock_read_is_runtime_gated(self) -> None:
        impl = (SCAN_ROOT / "core/diagnostics/timing.cpp").read_text(
            encoding="utf-8")
        body = code_only(impl)
        self.assertEqual(body.count("util::now_ms"), 1, body)
        # It must be guarded by timing_enabled(), so an instrumented build that
        # is not collecting costs the same as Release.
        fn = body.split("std::int64_t timing_now_ms() noexcept", 1)[1]
        fn = fn.split("}", 1)[0]
        self.assertIn("timing_enabled()", fn)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
