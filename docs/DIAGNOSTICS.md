# Developer diagnostics

> **Runnable transport-v2 path:** these diagnostics apply to the current
> product. Replacement typed diagnostics and `yume-doctor-ytp1` are documented
> in the [YTP/1 foundation page](development/ytp1/README.md#diagnostics-and-evidence).

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

## Compiler warnings

| Option | Default | Effect |
|---|---|---|
| `YUME_WARNINGS` | `ON` | Project warning set on first-party targets |
| `YUME_WARNINGS_AS_ERRORS` | `OFF` (`ON` in CI) | Promote those warnings to errors |

The set is `-Wall -Wextra -Wformat-security -Wvla -Wnon-virtual-dtor` on
GCC/Clang and `/W4 /permissive-` on MSVC, applied through
`yume_apply_warnings()` in `src/CMakeLists.txt`. Most first-party targets pick
it up via the existing `yume_apply_perf_opts()` hook; the installed shared
library (`yume_abi`) calls `yume_apply_warnings()` directly, so its
optimisation settings stay a separate decision from its warning settings.

Coverage is enforced, not assumed: a configure-time audit at the end of
`src/CMakeLists.txt` fails the build if any target that compiles first-party
code never received the set. Add a genuinely exempt target to
`YUME_WARNING_EXEMPT_TARGETS` with a reason.

Both the Release and the sanitizer CI jobs build with `-Werror`. That is
deliberate duplication: warnings whose analysis depends on optimization level
(`-Wformat-truncation` among them) fire in only one of the two configurations,
so gating a single job leaves part of the set unenforced.

Bundled dependencies (BaseFWX, Dear ImGui, ImPlot, nanosvg, stb) are separate
targets or `SYSTEM` includes and never receive it, so any warning printed here
is about code this tree owns and can fix. Do not silence one with a blanket
`-Wno-`; either fix it or add a narrowly scoped, commented suppression.

The deliberately disabled flags are `-Wconversion`, `-Wsign-conversion`,
`-Wshadow`, `-Wcast-qual`, and `-Wold-style-cast`. Each needs a dedicated
cleanup pass instead of a suppression and is enabled as that work is done.

Two diagnostics are demoted from errors rather than disabled, so they still
print. Both are limitations of a specific toolchain reported against a system
or third-party header, where an in-source pragma does not apply:

| Demoted | Where | Why |
| --- | --- | --- |
| `-Wstringop-overread` | GCC 11 only | GCC 11 propagates an exact string length proved at the call site into libstdc++'s `std::string` move assignment, then warns about the short-string branch a string of that length can never take. GCC 12 and later do not emit it. |
| `-Wtsan` | GCC, ThreadSanitizer lane | GCC reports that Boost.Asio's atomic fences are not modeled by TSan. |

Neither is a licence to ignore the warning elsewhere. The release toolchain is
GCC 11 because `release.yml` builds on `ubuntu-22.04`, so a real overread on
that compiler still appears in the log.

## Sanitizers

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DYUME_BUILD_TESTING=ON -DYUME_SANITIZE=address+undefined
cmake --build build-asan -j"$(nproc)"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
  ctest --test-dir build-asan --output-on-failure
```

`YUME_SANITIZE` accepts `none` (default), `address`, `undefined`,
`address+undefined`, or `thread`. It instruments every source-built target
added by this tree, including bundled BaseFWX sources. Prebuilt vendor
archives and system libraries are not instrumented.

The option forces `YUME_LTO=OFF`, because link-time optimization inlines and
reorders across exactly the boundaries a sanitizer reports against. It refuses
to combine with `YUME_STATIC` (the sanitizer runtime must stay dynamic) and
with compilers other than GCC/Clang. UBSan builds add
`-fno-sanitize-recover=all` so a violation aborts instead of printing and
continuing, which is what makes it usable as a CI gate.

`address` and `thread` are mutually exclusive by construction. Run them as
separate configurations. Never distribute a sanitized binary.

## Fuzzing

```bash
cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DYUME_BUILD_TESTING=ON -DYUME_BUILD_FUZZERS=ON
cmake --build build-fuzz -j"$(nproc)" \
  --target yume_fuzz_h2_probe_decoder yume_fuzz_client_config \
           yume_fuzz_server_config
bash tests/fuzz/run_fuzzers.sh build-fuzz/bin 600 fuzz-out
```

`tests/fuzz/run_fuzzers.sh` seeds the corpora, runs each harness for the given
per-target budget, and exits nonzero if libFuzzer writes any artifact. CI runs
the same script with a short budget as a regression gate. A longer campaign is
the same invocation with a larger budget and a corpus carried over from the
previous run. Seeds come from `tests/fuzz/make_seeds.py`, which generates them
as code rather than checking in opaque binaries, and includes the hostile HPACK
encodings the decoder regressions pin.

`YUME_BUILD_FUZZERS` builds libFuzzer harnesses for the parsers that consume
input from outside a trust boundary, and requires Clang. Each harness carries
its own ASan and UBSan instrumentation, so it does not combine with
`YUME_SANITIZE`, and it forces `YUME_LTO=OFF` for the same reason a sanitizer
build does. The harnesses are never installed.

| Harness | Parser | Reached by |
| --- | --- | --- |
| `yume_fuzz_h2_probe_decoder` | `obfs::H2InboundDecoder` | an unauthenticated peer, before any admission check |
| `yume_fuzz_client_config` | `facade::config_io::parse_client_json` | a configuration file, the GUI, and the C ABI |
| `yume_fuzz_server_config` | `facade::config_io::parse_server_json` | a configuration file and the GUI |

The decoder harness asserts a stronger contract than "does not crash": the
decoder must reject malformed input rather than throw, because a throw would
unwind into the Asio worker instead of the session that owns the connection.
Both configuration harnesses assert the same for their loaders. Corpora live
outside the tree; a crashing input is evidence and does not belong in Git.

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
Sanitized builds are never valid benchmark subjects.
