# YUME 0.3 verification and evidence

The current development gates are intentionally split by layer. Passing a
foundation test does not qualify an end-to-end tunnel.

## Focused local checks

```bash
cmake -S . -B build-test \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DYUME_BUILD_TESTING=ON \
  -DYUME_BUILD_SHARED_ABI=ON \
  -DYUME_INSTALL_EXPERIMENTAL_YTP1_TOOLS=ON \
  -DYUME_WARNINGS_AS_ERRORS=ON
cmake --build build-test -j"$(nproc)"
ctest --test-dir build-test --output-on-failure
python3 -m unittest \
  tests.test_yume_setup_transport_v2 \
  tests.test_yume_setup_ytp1 \
  tests.test_yume_doctor_ytp1
python3 tests/test_project_metadata.py
python3 scripts/generate_transport_profiles.py --check
python3 scripts/check_website_catalog.py
python3 scripts/check_dependency_sbom.py --check
git diff --check
```

These cover the dependency-clean engine contracts, YTP/1 codecs and vectors,
strict config parser, build-tree ABI and strict C/C++ consumers, source
layering, setup/doctor, metadata, documentation catalog, and source SBOM. The
clean-prefix install consumers remain future freeze fixtures because the ABI
has no install rules yet.

## Security-provider gates

The opt-in OpenSSL security provider has focused tests for:

- both Ed25519 and ML-DSA-87 signatures being required;
- X25519, ML-KEM-1024, per-identity access PSK, TLS exporter, role, transcript,
  identities, parameters, and both capability manifests being bound;
- component stripping and mutation, role confusion, replay, and exporter
  mismatch;
- directional one-use keys, nonce uniqueness, wrong-direction failure,
  bounded pending epochs, rekey races, and secure cancellation.

Known-answer vectors use only new `yume/ytp/1/...` domains. Transport-v2
vectors are not renamed or edited into YTP/1 vectors.

The separate TLS 1.3, H2 carrier, TCP ByteChannel, and direct-route provider
candidates have focused fake-channel or loopback coverage. Their composition,
real public ingress, failure injection, and production resource qualification
remain runtime gates.

## Runtime gates

Before the tunnel can be described as usable, tests must exercise the real
TLS 1.3 front door, genuine HTTP/2 cover behavior, replay-protected admission,
duplex carrier flow control, direct TCP/UDP routes, SOCKS5, named services,
packet batches, and the public ABI data path. Invalid admission must receive
the same website or reverse-proxy behavior as ordinary traffic, never a
YUME-shaped public response.

Clean Linux environments must run setup through the first authenticated stream
and include permission failures and a normal non-YUME browser request.

## Resource and failure qualification

Exercise slow consumers, stalled front doors, handshake and stream floods,
malformed lengths, queue pressure, packet batches, rekey pressure, cancellation,
and teardown at every asynchronous boundary. Broad ASan, UBSan, TSan, soak,
failure-injection, and fuzz suites belong on the configured remote build host,
with explicit detached jobs and retained result paths.

## Performance baseline and claims

Keep the signed 0.2 baseline runnable and capture matched evidence before any
switch-over removes it from the default build.
Compare throughput, p50/p99 latency, CPU per byte, allocations, peak memory,
and fairness at 1, 32, and 256 streams over at least five runs. Report the
environment, raw runs, summary method, and uncertainty. Do not claim a speedup
without published evidence supporting it.

Ingress claims must name the exact qualified profile and environment and link
immutable captures, TLS/H2 semantic gates, active-probe cover results, and a
held-out classifier evaluation. YUME does not claim universal
indistinguishability or DPI resistance.

## Freeze gate

`0.3.0-rc1` requires clean cross-platform builds, protocol vectors,
sanitizer/fuzz evidence, installed ABI consumers, setup smoke, documentation
drift checks, ingress evidence, and an external protocol/cryptography review.
Final validation ends with `git diff --check`.
