# YUME benchmarks

Native CTest executables keep `assert()` enabled even in Release and
RelWithDebInfo builds. A test configuration must not report success merely
because CMake defined `NDEBUG` and compiled its checks away.

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
build-selftest/bin/yume-selftest --full --rekey-window 1
```

The full preset's four-tunnel fixture is fail-closed and independently
authenticated. It generates one composite individual identity per tunnel,
enrolls every public identity with the same narrowly scoped loopback permission,
passes tunnels 2..N through repeated `--secondary-auth`, and refuses to start
the SOCKS measurement if any secondary authentication fails. Before measuring,
the harness queries `runtime.status` and requires `requested_tunnels`,
`authenticated_tunnels`, and `live_tunnels` to equal the requested count. Those
three values are also retained in each JSON result's `breakdown` object.

The normal result table always shows median/p95 latency, MiB/s, and Mbit/s.
`--dev` adds hot-path rows, startup timing, backpressure timing, repeat detail,
and score components. JSON schema 2 records the 2.0 workload without retired
Argon2/PQ-file fields. `--rekey-window` passes the same validated depth
(1..64) to both spawned binaries so high-RTT runs can compare the negotiated
epoch window without changing per-epoch security limits.

The harness creates temporary composite Ed25519 + ML-DSA-87 identity material
(one identity for each requested tunnel)
plus separate 32-byte
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
profile. Its default 64 KiB upload DATA size is taken from
`YUME_RELAY_READ_BUF`, as are client SOCKS and forward reads. Server target and
benchmark-source reads are capped at 32 KiB so one 256 KiB directional epoch
is delivered incrementally instead of becoming one head-of-line-blocking DATA
record. This path includes the live YUME transport v2 carrier, server, and network, but
does not include the local SOCKS socket, the server target TCP socket, a
browser, public cover site, or CDN.

Enable the server endpoint:

```bash
yumed --config config/yumed.json --bench
```

Run from the client:

```bash
yume --config config/yume.json --bench
yume --config config/yume.json --bench-full
yume --config config/yume.json --bench \
  --bench-mib 1024 --bench-streams 32

# Explicit transport-max diagnostic; do not label this SOCKS-equivalent.
yume --config config/yume.json --bench \
  --bench-mib 1024 --bench-streams 32 --bench-chunk-kib 256
```

The server rejects synthetic benchmark streams unless `--bench` or
`"benchmark_enable": true` is enabled. `--full-bench` is a client flag; `yumed`
does not accept it.
The client prints total, upload, download, and server-drain rates in MiB/s and
Mbit/s. It also prints the measured boundary, frame profile, and immutable
security/carrier features so a custom 256 KiB run cannot be mistaken for a
production-shaped result.

### Fair comparison contract

No one synthetic number is valid for every adapter. Use the benchmark that
actually crosses the boundary being claimed:

| Claim | Required benchmark | Included boundary |
|---|---|---|
| Deployed tunnel core | `yume --bench` | DATA, ratchet, H2, WebSocket, TLS, network, server |
| SOCKS end to end | `yume --full-bench --configs yume-v2` | Actual SOCKS socket and target TCP socket on loopback |
| Custom tunnel maximum | `yume --bench --bench-chunk-kib 256` | Same core with non-production DATA geometry |
| Packet C ABI | `yume-abi-tun` plus `iperf3` through a configured server TUN | Public ABI copies, packet batching, tunnel, and TUN egress |

The endpoint benchmark deliberately records `adapter=authenticated-stream-core`
and lists SOCKS, target TCP, and packet ABI as exclusions. The packet codec
rows in `--full-bench --dev` are component ceilings, not packet-ABI network
throughput. A packet result is publishable only after a live
`yume-abi-tun`/`iperf3` test uses the public `yume_packet_*` symbols and the
real `packet-bulk-v1`/TUN path; see `PACKET_NATIVE_BULK.md`.

Security layers are not benchmark toggles in YUME transport v2. The hybrid
ML-KEM-1024/X25519/PSK ratchet, AES-256-GCM, TLS 1.3, H2, and WebSocket carrier
remain enabled. Legacy time-key hopping is absent (therefore already off), and
padding/jitter are off in the pinned Chrome profile. Change workload size,
direction, stream count, DATA geometry, capture, timing counters, or benchmark
boundary; use the crypto/carrier component rows to isolate cost without
creating an insecure network mode.

Keep release binaries portable for cross-machine tests. `YUME_NATIVE_OPT` is
off by default; a binary built with `-DYUME_NATIVE_OPT=ON` may use instructions
that do not exist on the destination CPU.

### One-machine virtual WAN

The virtual-WAN helper creates isolated client and server network namespaces,
applies a `tc netem` profile in both directions, provisions temporary 2.0
identity and secret files, starts the real loopback Node cover, enables the
authenticated endpoint benchmark, and retains the outer captures and logs.

The helper requires util-linux and Bubblewrap so the loopback Node cover runs
with a minimal read-only filesystem in both modes. Build first, then run it as
root on a benchmark host:

```bash
./ezbuild.sh --selftest --tests
sudo python3 scripts/yume_bench_wan.py --profile mobile-4g
```

On Linux hosts that allow unprivileged user namespaces, the endpoint-only arm
can instead confine the named namespaces, veths, and netem qdiscs to a
throwaway user/mount/PID/network wrapper. Run this mode as an unprivileged
user with util-linux and Bubblewrap installed; it intentionally rejects the
browser arm:

```bash
python3 scripts/yume_bench_wan.py \
  --isolated-userns --no-browser --profile mobile-4g \
  --tls-backend openssl-chrome151
```

The wrapper validates an exact single-ID user/group mapping, a private mount
tree, PID-1 ownership, and a fresh outer network namespace before mounting a
private `/run/netns`; it kills all namespace children if the wrapper exits.
Node runs in a nested Bubblewrap sandbox with only `/usr` and the exact pinned
Node, cover backend, and capability guard visible, so it cannot read the
generated YUME keys or evidence directory. Node, `yumed`, and `yume` all fail
closed unless the kernel reports zero capabilities and `NoNewPrivs: 1`. The
isolated endpoint uses internal port 8443 because these workloads cannot bind a
privileged port after the capability drop; the existing root/browser mode
continues to use port 443. The JSON report records those runtime security
assertions, exact executable hashes, namespace inodes, and mutation scope. It
also records the Git commit, tree, full dirty-state status, and exact hashes of
every runtime harness/config input before and after the run; any change during
the measurement makes the run fail. This is still a synthetic virtual-WAN
measurement, not a deployed-network soak or external hosting/IP-metadata
result.

The default workload transfers 128 MiB per direction over eight streams with
the production relay DATA shape (64 KiB unless `YUME_RELAY_READ_BUF` is set).
It also loads the public cover through an installed Chrome/Chromium binary.
Useful variants are:

```bash
# Short carrier smoke; 32 MiB, four streams, no browser arm
sudo python3 scripts/yume_bench_wan.py --quick --profile broadband \
  --tls-backend openssl-chrome151

# Sustained endpoint run
sudo python3 scripts/yume_bench_wan.py --full --profile mobile-4g

# Reproduce a custom path
sudo python3 scripts/yume_bench_wan.py \
  --rtt 120 --jitter 30 --loss 2 --bandwidth 20 \
  --bench-mib 256 --bench-streams 16 \
  --tls-backend openssl-chrome151
```

Results are written under `yume-bench-results/<UTC timestamp>/` by default:

- `endpoint.pcap` contains the authenticated YUME transport v2 carrier.
- `cover-chromium.pcap` contains a real browser page load through `yumed` to
  the loopback Node site.
- `endpoint.log`, `yumed.log`, and `node.log` retain the corresponding output.
- `report.json` records versions, network settings, commands, exit codes,
  parsed MiB/s and Mbit/s rows, host capacity, and client/server CPU and RAM.
- `yumed-resources.jsonl` and `node-resources.jsonl` retain the external server
  process-group samples used by the summary.

The WAN harness defaults to `openssl-chrome151`, which requires the pinned
patched OpenSSL and does not launch the helper. Pass `--tls-backend chrome151`
only to reproduce the older helper measurements, or
`--tls-backend openssl-diagnostic` for the stock negative control. The selected
backend is recorded in `report.json`; never combine backend results in one
median, and do not transfer the helper's qualification evidence to the native
backend.

The cover profile requires the Node version named by the active registry entry.
When the system Node is older and `npx` is available, it resolves the pinned
runtime in the invoking user's npm cache automatically. Pass
`--no-node-bootstrap` to
forbid that download, or `--allow-node-version-mismatch` for a functional-only
run with the system Node.
Likewise, the browser version recorded in `report.json` must match the pinned
Chrome fixture before its PCAP is used as fingerprint evidence.

`scripts/yume_bench_localhost.py` is now only a convenience wrapper for the
canonical built-in local benchmark. It also samples the benchmark
process from the outside and writes a resource report under
`yume-bench-results/local-<UTC>/resources.json`:

```bash
python3 scripts/yume_bench_localhost.py
python3 scripts/yume_bench_localhost.py --full --duration-sec 120 --dev
```

The report records CPU user/system/core-seconds, core-hours, average cores,
single-core and whole-machine percentages, average/peak RSS in MiB, peak
threads/processes, CPU model/topology/frequency, affinity, and host RAM. These
absolute fields make results comparable across machines without relying on an
ambiguous percentage alone. Use `--resource-json PATH` to select the artifact,
`--resource-sample-ms 500` to lower sampling frequency, or
`--no-resource-sampling` for a measurement with no external sampler.

### Two-host LAN or WAN

Do not reuse the generic example JSON for a two-host endpoint benchmark: it
does not contain a matching server identity, admission secret, PSK, or TLS
trust anchor. Generate a minimal matching bundle on the client instead:

```bash
# local-workstation
scripts/yume_bench_lan.py prepare \
  --server build-host.example \
  --output ~/yume-lan-kit

scp -r ~/yume-lan-kit/server \
  operator@build-host.example:~/yume-lan-server
```

The existing `~/yume` checkout on remote-builder may contain benchmark work or
other local changes. Use a clean sibling checkout instead of resetting it:

```bash
# remote-builder
git clone https://github.com/FixCraft-Inc/yume.git ~/yume-main
cd ~/yume-main
./ezbuild.sh

sudo scripts/yume_bench_lan.py server \
  --bundle ~/yume-lan-server
```

Then run the client and capture its physical LAN flow:

```bash
# local-workstation
cd ~/yume
sudo scripts/yume_bench_lan.py client \
  --bundle ~/yume-lan-kit/client \
  --full --capture --cover --tls-backend openssl-chrome151
```

The LAN harness defaults to `openssl-chrome151`. Use `chrome151` only for an
explicit helper-comparison run and `openssl-diagnostic` only for the stock
negative control. The backend is recorded in the endpoint report; keep each
comparative series on one backend.

LAN client `report.json` records the client process resources. When the server
is stopped, its result directory receives `resources.json` plus bounded
`yumed-resources.jsonl` and `node-resources.jsonl` sample streams. The JSONL
timeline is useful because a two-host server may sit idle before or after the
actual client load; lifetime CPU percentages alone would dilute the busy
window. Match its UTC samples to `endpoint.started_utc` and
`endpoint.finished_utc` in the client report when comparing concurrency steps.

For an explicitly bounded server-scaling run, start the server as above and
launch several independent authenticated client processes:

```bash
# 4 GiB aggregate payload: 16 clients * 128 MiB * two directions.
scripts/yume_bench_lan.py client \
  --bundle ~/yume-lan-kit/client \
  --bench-mib 128 --bench-streams 16 \
  --clients 16 --client-stagger-ms 25

# Deliberate high-concurrency run on a host with capacity for 100 processes.
scripts/yume_bench_lan.py client \
  --bundle ~/yume-lan-kit/client \
  --bench-mib 32 --bench-streams 4 \
  --clients 100 --client-stagger-ms 10 --allow-high-client-count
```

The default remains one client. More than 64 clients requires the explicit
`--allow-high-client-count` acknowledgement, the hard limit is 128, and more
than 16 GiB of aggregate payload separately requires `--allow-large-workload`.
Cancellation stops every client process group. For a new machine, ramp through
`--clients 1`, `2`, `4`, `8`, and `16` while watching the server JSONL rather
than starting at the maximum. `wall_throughput` in the client report is total
application payload divided by full ramp wall time; `rates` separately retains
the sum of each client's own reported rates. Use server `--threads N` to compare
worker counts without editing the bundle; this changes scheduling only, not the
cryptographic protocol.

Resource sampling is implemented only in the Python benchmark harness through
Linux `/proc`; it adds no counters, logging, timer calls, branches, or threads
to normal `yume` and `yumed` execution. The default 250 ms sampler is external
to the measured process group. `--timing` is separate, opt-in in-process
diagnostics compiled only in Debug/RelWithDebInfo developer builds. Pass it to
both server and client only for profiling, not for an uninstrumented throughput
comparison. Release/MinSizeRel builds contain no timing hooks. See
[DIAGNOSTICS.md](DIAGNOSTICS.md).
Multi-client peak RSS is intentionally reported as an upper bound: it sums
each process group's independently observed peak, so the peaks may not coincide
and shared pages can be counted once per process. Use proportional-set-size
tooling for a dedicated memory study rather than interpreting that upper bound
as exact simultaneous physical RAM.
The client refuses a capture before startup when the selected payload plus
packet overhead would leave too little filesystem space for the final logs and
`report.json`. Uncaptured endpoint runs remain the preferred throughput sweep.

Use `--quick` on the client for the 32 MiB/four-stream smoke before committing
to the full 1024 MiB/64-stream run. `--cover` follows the endpoint test with a
real Chrome/Chromium page load and records it separately from the tunnel PCAP.
Client artifacts are written under `yume-bench-results/lan-<UTC timestamp>/`.
A full bidirectional capture can exceed 2 GiB. The server command stays in the
foreground and should be stopped with Ctrl-C after the client finishes.
Client output is streamed while the benchmark runs; non-interactive progress
updates appear every five seconds. Ctrl-C stops the endpoint and capture
cleanly, returns status 130, and retains a partial `endpoint.log` and
`report.json` instead of printing a Python traceback.

The endpoint run always exercises the 2.0 ML-KEM-1024 + X25519 + PSK suite,
directional ratchets, H2/WebSocket carrier, and Node masquerade. `--cover` is a
separate real-browser request to the same public endpoint. There is no hop mode
to exercise -- the time-derived hop layer was removed, see
`docs/SECURITY_MODES.md` -- and nginx is absent because it is not part of the
focused 2.0 wire path.

The bundle contains shared high-entropy admission and inner PSK files. Treat
the SCP step as out-of-band secret distribution: do not publish or commit the
bundle, and delete it when the benchmark is finished.

### Manually configured endpoint

For a physical endpoint, provision the identity, admission secret, inner PSK,
TLS certificate, and real Node service as described in
[QUICKSTART.md](QUICKSTART.md). Enable the benchmark only for the test window:

```bash
# Server; Node is already bound to 127.0.0.1:3000
sudo ./build/bin/yumed \
  --listen 0.0.0.0:443 \
  --cert /etc/yume/server.crt \
  --key /etc/yume/server.key \
  --auth-keys /etc/yume/authorized_keys \
  --obfs-secret-file /etc/yume/secrets/admission.hex \
  --inner-psk-file /etc/yume/secrets/inner.hex \
  --real-backend loopback://127.0.0.1:3000 \
  --bench
```

Run a moderate measurement from the client:

```bash
./build/bin/yume \
  --server edge.example.net --port 443 \
  --tls-ca ~/.config/yume/server-ca.crt \
  --auth ~/.config/yume/client.key \
  --obfs-secret-file ~/.config/yume/admission.hex \
  --inner-psk-file ~/.config/yume/inner.hex \
  --profile chrome \
  --transport-profile chrome151-node24-v1 \
  --tls-backend openssl-chrome151 \
  --bench --bench-mib 128 --bench-streams 8 \
  --bench-direction both \
  --boring --no-color
```

Add `--bench-chunk-kib 256` only for a separately labelled transport-max run.

Capture the public interface at either end:

```bash
sudo tcpdump -i eth0 -n -s 0 -U \
  -w yume-2-endpoint.pcap \
  'host CLIENT_OR_SERVER_IP and tcp port 443'
```

For the cover baseline, start a second capture and open
`https://edge.example.net/` in the pinned Chrome build. That request travels
through public `yumed` and the loopback Node backend, but it is intentionally a
separate workload from `yume --bench`. nginx is not part of this carrier or
cover path.

To capture an application-like browser session instead of synthetic benchmark
streams, start the normal client SOCKS listener:

```bash
./build/bin/yume \
  --server edge.example.net --port 443 \
  --tls-ca ~/.config/yume/server-ca.crt \
  --auth ~/.config/yume/client.key \
  --obfs-secret-file ~/.config/yume/admission.hex \
  --inner-psk-file ~/.config/yume/inner.hex \
  --profile chrome \
  --transport-profile chrome151-node24-v1 \
  --tls-backend openssl-chrome151 \
  --socks 127.0.0.1:1080 \
  --non-interactive --accept-monitoring

chromium \
  --user-data-dir=/tmp/yume-browser-profile \
  --proxy-server=socks5://127.0.0.1:1080 \
  --host-resolver-rules='MAP * ~NOTFOUND, EXCLUDE localhost' \
  https://example.com/
```

Capture only the client-to-`yumed` address and port. The destination browser
traffic then appears inside the encrypted YUME carrier rather than as extra
public flows in the same PCAP. Use a disposable browser profile so extensions,
sync, and an existing service worker do not add unrelated traffic.

There is no `--pq`, hop, or masquerade switch. ML-KEM-1024 + X25519,
per-message encryption, the default Extreme 256 KiB / 512-frame / 500 ms
directional epochs,
the Chrome-shaped H2 carrier, and the Node cover routing are mandatory in every
accepted 2.0 endpoint benchmark. The capture verifies on-wire behavior; the
benchmark output reports application throughput, not protocol overhead.

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
