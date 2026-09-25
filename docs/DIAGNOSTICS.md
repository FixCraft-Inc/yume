<!-- Generated from docs/src/en_US/pages/diagnostics.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# Developer diagnostics

Operators check a configuration with `--validate` and `yume-doctor`, which
[operations](OPERATIONS.md#troubleshooting) describes, and the
[native guide](development/ytp1/README.md#diagnostics-and-evidence) covers
typed runtime diagnostics and evidence. This page is for developers: the
timing helpers, the warning set, sanitizers and fuzzing.

## Timing helpers

`src/common/timing.hpp` holds the shared timing types. `Stopwatch` times one
synchronous operation, `SampleAccumulator` batches counts and nanoseconds, and
`IntervalTimer` tracks an asynchronous span. `YUME_TIMING_SINK` hands an event
to a sink, and in builds without diagnostics it removes the event together
with the expression that builds its details.

The build configuration, not a runtime flag, decides whether any of this
exists:

| CMake configuration | Timing code |
|---|---|
| `Release`, `MinSizeRel` | compiled out, no clock reads |
| `RelWithDebInfo`, `Debug` | compiled in, off until a caller turns it on |

Today only the HTTP/2 carrier uses the helpers. With `set_timing_enabled(true)`
it records feed, flush, WebSocket encode and decode time next to its credit and
window counters, and only its tests turn that on. `yume` and `yumed` have no
timing switch.

`./ezbuild.sh` builds `Release`. `./ezbuild.sh --dev` builds an optimized
`RelWithDebInfo` with the helpers compiled in. `./ezbuild.sh --native` tunes
for the current CPU, so that binary must not be copied to an older or
different CPU. Fast-math stays off in every mode.

New timing work should use these types instead of pairs of
`steady_clock::now()` calls or per-file switches. Keep detail strings inside
`YUME_TIMING_SINK`. Guard a diagnostic timer that an asynchronous callback
captures with `#if YUME_ENABLE_DEV_DIAGNOSTICS`, so a Release closure carries
no diagnostic member. Never log keys, nonces, plaintext, authentication
material, secret paths or full peer-controlled payloads.

## Compiler warnings

| Option | Default | Effect |
|---|---|---|
| `YUME_WARNINGS` | `ON` | Project warning set on first-party targets |
| `YUME_WARNINGS_AS_ERRORS` | `OFF` (`ON` in CI) | Promote those warnings to errors |

The set is `-Wall -Wextra -Wformat-security -Wvla -Wnon-virtual-dtor` on
GCC and Clang and `/W4 /permissive-` on MSVC, applied through
`yume_apply_warnings()` in `src/CMakeLists.txt`. Most first-party targets get
it from `yume_apply_perf_opts()`. The shared library `yume_abi` calls
`yume_apply_warnings()` directly, so its optimization settings stay a
separate decision from its warnings.

A configure-time audit at the end of `src/CMakeLists.txt` fails the build if
any target that compiles first-party code never received the set. Add an
exempt target to `YUME_WARNING_EXEMPT_TARGETS` with a reason.

The CI test lanes build with `-Werror` at different optimization levels on
purpose. Warnings whose analysis depends on optimization, such as
`-Wformat-truncation`, fire in only some configurations, so gating one lane
would leave part of the set unenforced.

Bundled dependencies such as BaseFWX are separate targets or `SYSTEM`
includes and never receive the set, so any warning printed here is about code
this tree owns and can fix. Do not silence one with a blanket `-Wno-`. Fix it
or add a narrowly scoped, commented suppression.

The deliberately disabled flags are `-Wconversion`, `-Wsign-conversion`,
`-Wshadow`, `-Wcast-qual` and `-Wold-style-cast`. Each needs its own cleanup
pass instead of a suppression and is enabled when that work is done.

Two diagnostics are demoted from errors rather than disabled, so they still
print. Both are limitations of a specific toolchain reported against a system
or third-party header, where an in-source pragma does not apply:

| Demoted | Where | Why |
| --- | --- | --- |
| `-Wstringop-overread` | GCC 11 only | GCC 11 propagates an exact string length proved at the call site into libstdc++'s `std::string` move assignment, then warns about the short-string branch a string of that length can never take. GCC 12 and later do not emit it. |
| `-Wtsan` | GCC, ThreadSanitizer lane | GCC reports that Boost.Asio's atomic fences are not modeled by TSan. |

Neither is permission to ignore the warning elsewhere. The release toolchain
is GCC 13 on `ubuntu-24.04`, and a source build with GCC 11 still prints a real
overread in its log.

## Sanitizers

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DYUME_BUILD_TESTING=ON -DYUME_SANITIZE=address+undefined
cmake --build build-asan -j"$(nproc)"
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
  ctest --test-dir build-asan --output-on-failure
```

`YUME_SANITIZE` accepts `none` (the default), `address`, `undefined`,
`address+undefined` or `thread`. It instruments every source-built target in
this tree, including bundled BaseFWX sources when the modules are on. Prebuilt
vendor archives and system libraries are not instrumented.

The option forces `YUME_LTO=OFF`, because link-time optimization inlines and
reorders across exactly the boundaries a sanitizer reports against. It refuses
to combine with `YUME_STATIC`, since the sanitizer runtime must stay dynamic,
and with compilers other than GCC and Clang. UBSan builds add
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
  --target yume_fuzz_ytp1_protocol yume_fuzz_ytp1_auth yume_fuzz_config_v1
bash tests/fuzz/run_fuzzers.sh build-fuzz/bin 600 fuzz-out
```

`tests/fuzz/run_fuzzers.sh` seeds the corpora, runs each harness for the given
per-target budget with a bounded input size, and exits nonzero if libFuzzer
writes any artifact. CI runs the same script with a short budget as a
regression gate. A longer campaign is the same invocation with a larger budget
and a corpus carried over from the previous run. `tests/fuzz/make_seeds.py`
generates the seeds as code rather than checking in opaque binaries, and
derives the configuration seeds from the schema-1 examples in `config/`.

`YUME_BUILD_FUZZERS` builds libFuzzer harnesses for the parsers that consume
input from outside a trust boundary, and requires Clang. It selects
`YUME_SANITIZE=address+undefined` and `YUME_LTO=OFF`, with coverage and
ASan/UBSan checks in the source-built parser libraries as well as the
harnesses. Only the harness executables link libFuzzer's main function. Other
sanitizer selections need a separate build. Prebuilt dependencies stay outside
this instrumentation, and the harnesses are never installed. Verify parser
compile commands and object instrumentation when you keep qualification
evidence.

| Harness | Parser | Checks |
| --- | --- | --- |
| `yume_fuzz_ytp1_protocol` | YTP/1 frame, OPEN, destination and capability codecs in `ytp/protocol.*` | Every accepted encoding is canonical and re-encodes to the same bytes |
| `yume_fuzz_ytp1_auth` | AUTH TLV records in `ytp/security.*` | Unknown critical fields, duplicate IDs, reordered TLVs and wrong suite values are refused, and unknown noncritical fields survive |
| `yume_fuzz_config_v1` | The schema-1 parser in `config/v1/` | Typed rejection is the expected failure, and any other exception is a finding. It opens no credential file |

Corpora live outside the tree. A crashing input is evidence and does not
belong in Git.

## Verification

```bash
# Production: optimized, no timing code.
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release \
  -DYUME_BUILD_TESTING=ON -DYUME_LTO=ON
cmake --build build-release -j"$(nproc)"
ctest --test-dir build-release --output-on-failure

# Developer: the same tests with the timing helpers compiled in.
cmake -S . -B build-dev -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DYUME_BUILD_TESTING=ON
cmake --build build-dev -j"$(nproc)"
ctest --test-dir build-dev --output-on-failure
```

`yume_h2_carrier_test` asserts at compile time that the timing helpers exist
exactly when the configuration says they do, so either run above fails if the
switch and the build disagree.

Native test executables keep their checks in optimized builds. Most define
their own `CHECK` macro, which `NDEBUG` does not remove, and a test that calls
`assert()` is compiled with `-UNDEBUG`. Keep it that way: a Release or
RelWithDebInfo test run must not pass because CMake defined `NDEBUG` and
compiled the checks away.

Benchmark comparisons must state whether timing was enabled. Do not compare an
instrumented run with an uninstrumented one as if they were identical builds.
Sanitized builds are never valid benchmark subjects.
