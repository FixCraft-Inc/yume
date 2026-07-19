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

### One-machine virtual WAN

The virtual-WAN helper creates isolated client and server network namespaces,
applies a `tc netem` profile in both directions, provisions temporary 2.0
identity and secret files, starts the real loopback Node cover, enables the
authenticated endpoint benchmark, and retains the outer captures and logs.

Build first, then run it as root on a benchmark host:

```bash
./ezbuild.sh --selftest --tests
sudo python3 scripts/yume_bench_wan.py --profile mobile-4g
```

The default workload transfers 128 MiB per direction over eight streams with
256 KiB application chunks. It also loads the public cover through an installed
Chrome/Chromium binary. Useful variants are:

```bash
# Short carrier smoke; 32 MiB, four streams, no browser arm
sudo python3 scripts/yume_bench_wan.py --quick --profile broadband

# Sustained endpoint run
sudo python3 scripts/yume_bench_wan.py --full --profile mobile-4g

# Reproduce a custom path
sudo python3 scripts/yume_bench_wan.py \
  --rtt 120 --jitter 30 --loss 2 --bandwidth 20 \
  --bench-mib 256 --bench-streams 16
```

Results are written under `yume-bench-results/<UTC timestamp>/` by default:

- `endpoint.pcap` contains the authenticated YUME 2.0 carrier.
- `cover-chromium.pcap` contains a real browser page load through `yumed` to
  the loopback Node site.
- `endpoint.log`, `yumed.log`, and `node.log` retain the corresponding output.
- `report.json` records versions, network settings, commands, exit codes, and
  parsed MiB/s and Mbit/s rows.

The helper requires Node 24.18.x for the pinned cover profile. When the system
Node is older and `npx` is available, it resolves the exact pinned runtime in
the invoking user's npm cache automatically. Pass `--no-node-bootstrap` to
forbid that download, or `--allow-node-version-mismatch` for a functional-only
run with the system Node.
Likewise, the browser version recorded in `report.json` must match the pinned
Chrome fixture before its PCAP is used as fingerprint evidence.

`scripts/yume_bench_localhost.py` is now only a convenience wrapper for the
canonical built-in local benchmark:

```bash
python3 scripts/yume_bench_localhost.py
python3 scripts/yume_bench_localhost.py --full --duration-sec 120 --dev
```

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
  f1xgod@build-host.example:~/yume-lan-server
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
  --full --capture --cover
```

Use `--quick` on the client for the 32 MiB/four-stream smoke before committing
to the full 1024 MiB/64-stream run. `--cover` follows the endpoint test with a
real Chrome/Chromium page load and records it separately from the tunnel PCAP.
Client artifacts are written under `yume-bench-results/lan-<UTC timestamp>/`.
A full bidirectional capture can exceed 2 GiB. The server command stays in the
foreground and should be stopped with Ctrl-C after the client finishes.

The endpoint run always exercises the 2.0 ML-KEM-1024 + X25519 + PSK suite,
directional ratchets, H2/WebSocket carrier, and Node masquerade. `--cover` is a
separate real-browser request to the same public endpoint. Hop mode and nginx
are intentionally absent because neither is part of the focused 2.0 wire path.

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
  --bench --bench-mib 128 --bench-streams 8 \
  --bench-chunk-kib 256 --bench-direction both \
  --boring --no-color
```

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
  --profile chrome --socks 127.0.0.1:1080 \
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

No `--pq`, `--hop`, or masquerade switch is needed. ML-KEM-1024 + X25519,
per-message encryption, the 256 KiB / 512-frame / 500 ms directional epochs,
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
