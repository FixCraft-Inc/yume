# Local Self-Test Benchmark

`yume-selftest` is an optional desktop developer tool. It starts temporary
local `yumed` and `yume` processes, routes SOCKS traffic to a loopback echo
server, and reports protocol-only latency and throughput against direct
loopback.

Build it explicitly:

```bash
cmake -B build-selftest \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DYUME_BUILD_SELFTEST=ON \
  -DYUME_FEATURE_LAN_BRIDGE=ON
cmake --build build-selftest --target yume-selftest yume-basefwx-bench yume yumed
```

`YUME_BUILD_SELFTEST=ON` defaults an otherwise unset single-config CMake build
to `RelWithDebInfo`. Benchmark numbers from an empty `CMAKE_BUILD_TYPE` are not
meaningful because the transport/proxy path is then built without optimization.

Run a quick local benchmark:

```bash
build-selftest/bin/yume-selftest --configs base-direct,heavy-hop-2hz
```

Useful options:

```bash
build-selftest/bin/yume-selftest --list-configs
build-selftest/bin/yume-selftest --latency-iters 200 --bulk-mib 64
build-selftest/bin/yume-selftest --json selftest.json
build-selftest/bin/yume-selftest --keep-workdir
```

Useful isolation configs:

```bash
build-selftest/bin/yume-selftest \
  --configs base-direct,no-inner-raw,no-inner-obfs,light-no-hop,light-hop-2hz \
  --latency-iters 40 --bulk-mib 8
```

Interpret the comparisons this way:

- `base-direct`: kernel/host TCP echo floor. Very small `--bulk-mib` values can
  under-report this baseline because setup noise dominates the transfer.
- `no-inner-raw`: SOCKS + YUME framing over TLS without the H2 disguise.
- `no-inner-obfs`: adds the browser-shaped H2 carrier handshake and obfs TLS
  profile path; compare to `no-inner-raw` to estimate stealth-path cost.
- `light-no-hop` and `light-hop-2hz`: compare these to estimate live hopping
  cost after inner crypto is enabled.
- `heavy-hop-2hz` and `heavy-no-hop`: include the heavy KDF setup path, still
  bounded by the local Argon2 caps below.

The self-test prints a second phase-breakdown table:

- `srv ms`: time until temporary `yumed` accepts TCP.
- `pq ms`: extra wait for the generated PQ public key when inner crypto is used.
- `cli ms`: time until temporary `yume` starts the local SOCKS listener.
- `conn ms`: direct TCP connect or TCP+SOCKS connect to the echo target.
- `warm ms`: first echo round trip before sampled latency begins.
- `bulk s`: total bulk echo transfer time.
- `send s` and `send%`: how long the benchmark writer was blocked sending.
  `send%` near 100 means the upstream write path is backpressured for most of
  the transfer; a much lower value points at the return/read path instead.

The routed benchmark requires `YUME_FEATURE_LAN_BRIDGE=ON` because the server
must connect to a loopback echo target. The tool creates a temporary
`authorized_keys.json` and grants `allow_local_ip` only to the generated test
key.

## Client Shortcut

When `yume-selftest` is built next to `yume`, the client exposes the same local
benchmark without requiring any config:

```bash
yume --quickbench
yume --fullbench
yume --fullbench --duration-sec 120
```

`--fullbench` is local and scored. It does not contact a server, read the
normal client config, or require `--auth`.

## Real Endpoint Benchmark

`yume --bench` measures an authenticated YUME stream against a real `yumed`
endpoint without Chromium, curl, SOCKS apps, or an external echo server.
Use `yume --bench-full` when you want the longer authenticated endpoint profile
with larger payloads and more streams. Endpoint benchmarks always require the
normal server and identity configuration.

Use portable binaries for real endpoints. `YUME_NATIVE_OPT` is off by default;
only turn it on for same-machine experiments. A binary configured with
`-DYUME_NATIVE_OPT=ON` can crash with `Illegal instruction` when copied to a
different x86_64 CPU that lacks the builder's AVX/BMI/AES-class features.

Enable the virtual benchmark endpoint on the server:

```bash
yumed --bench --config config/yumed.json
```

Run from the client:

```bash
yume --config config/yume.json --bench
yume --config config/yume.json --bench-full
yume --config config/yume.json --bench --bench-mib 1024
yume --config config/yume.json --bench --bench-mib 1024 --bench-chunk-kib 256
```

The server rejects benchmark streams unless `--bench`, the compatibility alias
`--fullbench`, or `"benchmark_enable": true` is set. The benchmark uses the
current TLS profile,
obfs carrier, inner crypto, and hopping settings, then opens two synthetic
streams: one upload sink and one download source. It does not include browser,
local SOCKS client, remote website, CDN, or provider routing behavior beyond
the path between `yume` and `yumed`.

Inner-crypto configs let the temporary `yumed` generate a throwaway PQ keypair
and pass the generated public key to the temporary client. The harness also
passes `--accept-monitoring`, because this is an explicit local benchmark
rather than an anonym-mode trust test.

Heavy mode is still bounded by default: `YUME_ARGON2_MEM` and server caps are
set to 32768 KiB with parallelism 2 for the child processes. Use
`--argon-mem-kib` and `--argon-parallelism` when intentionally profiling
larger KDF settings on a suitable machine.

## Inner Crypto Microbench

`yume-basefwx-bench` measures the same YUME `inner_crypto` API used by the
transport, but without TLS, H2 obfs, SOCKS, loopback routing, or child process
startup:

```bash
build-selftest/bin/yume-basefwx-bench
build-selftest/bin/yume-basefwx-bench --bytes-mib 256 --light-iters 100 --no-heavy
build-selftest/bin/yume-basefwx-bench --heavy-iters 5 --argon-mem-kib 65536
```

Use it with `yume-selftest` to localize bottlenecks:

- If `inner-aead-encrypt`/`inner-aead-decrypt` are far faster than
  `yume-selftest` throughput, steady-state payload crypto is not the main cap.
- If `pq-client-heavy` or `pq-server-heavy` are large but the payload rows are
  fast, the slowdown is handshake/KDF setup rather than transfer speed.
- If `no-inner-raw` is already slow compared with BaseFWX AEAD, inspect SOCKS,
  stream framing, TLS writes, and process scheduling.
- If `no-inner-obfs` is much slower than `no-inner-raw`, inspect the H2 carrier,
  padding, flush behavior, and stealth shaping.

Current desktop interpretation:

- BaseFWX AEAD in the same process should be several GiB/s on a normal desktop
  CPU. If `yume-selftest` is hundreds of MiB/s while `yume-basefwx-bench` is
  multiple GiB/s, inspect the proxy/carrier path first.
- Heavy Argon2 is visible in `cli ms` because the client prepares inner crypto
  before the SOCKS listener becomes ready. It should not materially change
  steady-state throughput after the tunnel is authenticated.
- Low `send%` during bulk means the benchmark writer is not waiting on local
  `send()` for most of the transfer. The limiter is then downstream receive,
  carrier parsing, proxy forwarding, or scheduling rather than the local upload
  syscall path.
- The desktop `--obfs` path performs an H2-shaped carrier handshake, then
  carries normal YUME frames over the established TLS session. Treat
  `no-inner-raw` vs `no-inner-obfs` as a whole-carrier/profile comparison, not
  as per-payload HTTP/2 DATA frame cost.
