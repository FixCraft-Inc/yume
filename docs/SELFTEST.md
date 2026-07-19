# YUME benchmarks

YUME has three separate benchmark paths. They answer different questions and
their numbers should not be compared as if they measured the same layer.

## Local transport benchmark

`yume --full-bench` starts temporary `yume` and `yumed` processes, routes data
through SOCKS on loopback, and prints MiB/s for:

- `base-direct`: the host/kernel TCP floor.
- `yume-v2`: the mandatory 2.0 TLS + H2 + WebSocket + hybrid-ratchet path.

There are no raw, no-inner, light, heavy, hop, persistent-PQ, or Argon2
variants in the 2.0 benchmark. Those were 1.x transports and their results are
not comparable with 2.0.

Build the optional tools with an optimized configuration:

```bash
cmake -S . -B build-selftest \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DYUME_BUILD_SELFTEST=ON \
  -DYUME_FEATURE_LAN_BRIDGE=ON
cmake --build build-selftest --target \
  yume yumed yume-selftest yume-basefwx-bench
```

Run a short smoke or the full profile:

```bash
build-selftest/bin/yume --quick-bench
build-selftest/bin/yume --full-bench
build-selftest/bin/yume --full-bench --duration-sec 120
build-selftest/bin/yume --full-bench --dev --json selftest.json
```

The standalone entry point accepts the same benchmark options:

```bash
build-selftest/bin/yume-selftest --list-configs
build-selftest/bin/yume-selftest --full --no-color
```

The normal result table always shows median/p95 latency, MiB/s, and Mbit/s.
`--dev` adds hot-path rows, startup timing, backpressure timing, repeat detail,
and score components. JSON schema 2 records the 2.0 workload without retired
Argon2/PQ-file fields.

The harness creates temporary Ed25519 identity material plus separate 32-byte
admission and inner PSK files. Both secret files contain exactly 64 lowercase
hex characters and have owner-only permissions. A small bounded loopback HTTP
fixture satisfies `yumed`'s required cover-backend health check; it is not used
as evidence of Node fingerprint parity. Chrome/Node fingerprint work uses the
committed reference fixture.

`YUME_FEATURE_LAN_BRIDGE=ON` is required because the temporary server must
reach the loopback echo target. The generated authorization grants
`allow_local_ip` only to the temporary benchmark identity.

## Real endpoint benchmark

`yume --bench` measures authenticated upload and download streams against a
deployed `yumed`. `yume --bench-full` uses the longer 1024 MiB / 64-stream
profile. This path includes the live YUME 2.0 carrier, server, and network, but
does not include a browser, SOCKS application, public cover site, or CDN.

Enable the server endpoint:

```bash
yumed --config config/yumed.json --bench
```

Run from the client:

```bash
yume --config config/yume.json --bench
yume --config config/yume.json --bench-full
yume --config config/yume.json --bench \
  --bench-mib 1024 --bench-streams 32 --bench-chunk-kib 256
```

The server rejects synthetic benchmark streams unless `--bench`, its
`--full-bench` compatibility alias, or `"benchmark_enable": true` is enabled.
The client prints total, upload, download, and server-drain rates in MiB/s and
Mbit/s.

Keep release binaries portable for cross-machine tests. `YUME_NATIVE_OPT` is
off by default; a binary built with `-DYUME_NATIVE_OPT=ON` may use instructions
that do not exist on the destination CPU.

## Crypto microbenchmark

`yume-basefwx-bench` runs the production 2.0 crypto schedule in memory:

- ML-KEM-1024 + X25519 + random-PSK salted-HKDF establishment.
- Directional ML-KEM-1024 + X25519 epoch rekey.
- Per-message AES-256-GCM ratchet transfer with real 256 KiB rekey boundaries.

```bash
build-selftest/bin/yume-basefwx-bench
build-selftest/bin/yume-basefwx-bench \
  --bytes-mib 256 --chunk-kib 64 \
  --establishment-samples 50 --rekey-samples 50
```

This is a crypto-only ceiling. It excludes TLS, H2, WebSocket, socket I/O,
SOCKS, process startup, and scheduling between `yume` and `yumed`. Use the
local transport benchmark to find carrier/process overhead, then use the real
endpoint benchmark to measure the deployed path.

## Reading results

- Use payloads large enough that setup noise does not dominate `base-direct`.
- `send%` near 100 means the local writer is backpressured for most of the
  transfer. A low value points toward receive, carrier, proxy, or scheduling
  limits instead.
- A fast crypto microbenchmark with a slower `yume-v2` row usually means the
  bottleneck is outside the ratchet primitive.
- Quick mode is a smoke test. Use a stable, approved machine for full scores,
  sustained throughput, sanitizers, or WAN capture.
