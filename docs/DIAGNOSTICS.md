# Developer diagnostics

YUME keeps precise in-process timing available for diagnosis without carrying
it in production executables. The build configuration, not a runtime flag,
defines that boundary.

| CMake configuration | Timing code | Runtime default |
|---|---:|---:|
| `Release`, `MinSizeRel` | compiled out | unavailable |
| `RelWithDebInfo`, `Debug` | compiled in | off |

`./ezbuild.sh` produces a portable, `-O3`/LTO `Release` build by default.
Use `./ezbuild.sh --native` for the fastest binary on the current CPU; that
binary must not be copied to an older/different CPU. Use `./ezbuild.sh --dev`
for an optimized `RelWithDebInfo` build with diagnostic hooks. Self-test builds
are also developer builds so endpoint profiling can opt in to the same hooks.
Fast-math stays disabled in every mode.

In a developer build, pass `--timing` to `yume` and `yumed`, or set
`YUME_TIMING=1`. `YUME_TRACE_TIMING=1` and `YUME_PROFILE=1` are compatibility
aliases. A production binary warns that `--timing` is unavailable; timing
environment variables have no activation path in that binary.

## One implementation, bounded hook points

The shared API is `src/core/diagnostics/timing.hpp`. It provides:

- `Stopwatch` for one synchronous operation;
- `SampleAccumulator` for batched hot-path counts and nanoseconds;
- `IntervalTimer` for asynchronous spans such as `REKEY_INIT` to `REKEY_ACK`;
- `YUME_TIMING_LOG` and `YUME_TIMING_SINK`, which remove the whole event and
  its detail-building expression from production preprocessing.

The current low-level hooks cover connection setup, TLS and H2 carrier setup,
AUTH hybrid work, SOCKS/open lifecycle, write selection/queue depth, ratchet
seal/open batches, rekey waits, TLS write completion, and H2/WebSocket
encode/decode/flush totals. These are the state and I/O boundaries needed to
locate stalls; logging every function would add noise and make traces harder to
use.

New timing work should use the shared types instead of open-coding
`steady_clock::now()` pairs or adding per-file enable flags. Detail strings must
stay inside a timing macro. For an asynchronous callback, guard a diagnostic
timer and its lambda capture with `#if YUME_ENABLE_DEV_DIAGNOSTICS` so a Release
closure has no diagnostic member. Never log keys, nonces, plaintext, auth
responses, secret paths, or full peer-controlled payloads.

## Verification

```bash
# Production: optimized, no timing implementation/event strings.
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release \
  -DYUME_BUILD_TESTING=ON -DYUME_LTO=ON
cmake --build build-release -j"$(nproc)"
ctest --test-dir build-release --output-on-failure
nm -C build-release/src/libyume_core.a | grep 'diagnostics::log_timing'  # no match
strings build-release/bin/yume | grep 'timing component='               # no match

# Developer: optimized hooks, runtime opt-in.
cmake -S . -B build-dev -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DYUME_BUILD_TESTING=ON -DYUME_BUILD_SELFTEST=ON
cmake --build build-dev -j"$(nproc)"
ctest --test-dir build-dev --output-on-failure
./build-dev/bin/yume --timing --help
```

Benchmark comparisons must state whether timing was enabled. Do not compare an
instrumented run with an uninstrumented one as if they were identical builds.
