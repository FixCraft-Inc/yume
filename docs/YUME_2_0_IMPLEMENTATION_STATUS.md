# YUME 2.0 desktop implementation status

Status: `2.0-dev1` vertical slice implemented; release gates incomplete.

This is a truthful inventory of the focused Linux x86-64 client/server work. It
does not claim Android, GUI, nginx, alternate browser profiles, H3, federation,
or admin/control validation.

## Implemented

- Version-pinned Chrome `150.0.7871.114` / Node `24.18.0` reference fixture,
  manifest, and sanitized HTTP/2 profile.
- Persistent nghttp2 carrier with priming page and asset requests, RFC 8441
  extended CONNECT, WebSocket masking/fragmentation/control frames, flow
  control, serialized writes, backpressure, and graceful H2 shutdown.
- Loopback-IP-literal-only Node backend proxy with startup health check, bounded
  headers/body/timeouts, hop-by-hop header removal, and no tunnel-data routing
  to Node.
- Strict file-only admission and inner PSK configuration. Both files are
  mandatory 32-byte random secrets encoded as exactly 64 lowercase hex
  characters and protected from group/world access.
- Version/SNI/hour/nonce HMAC admission, authority matching, bounded replay
  cache, and ordinary cover behavior before AUTH on rejection.
- Canonical AUTH v2 transcript with strict parsing and Ed25519 authorization
  before ML-KEM work.
- ML-KEM-1024 + X25519 + high-entropy PSK salted-HKDF root derivation. Argon2 is
  absent at connection establishment and per epoch.
- AES-256-GCM one-use message keys with version/direction/epoch/sequence/type/
  stream/flags AAD binding.
- Independent directional hybrid rekeys before 256 KiB, 512 encrypted data
  frames, or 500 ms of active epoch time; idle silence, bounded rekey barrier,
  timeout close, simultaneous rekeys, old receiving-chain retirement, and
  independent receiver enforcement of byte/frame usage boundaries.
- Exact `2.0-dev1` admission/AUTH-version equality and no accepted 1.x
  downgrade path. Legacy
  inner/light/heavy/dual/hop/no-inner/raw-carrier and literal-secret CLI choices
  are rejected.

## Local evidence completed

- Exact Chrome loaded `/`, CSS, and JavaScript through `yumed` backed by exact
  Node `24.18.0`; the page completed its expected DOM readiness marker.
- Ordinary HTTP/1.1 and HTTP/2 GET/HEAD requests returned the same loopback
  Node site through `yumed`. After the backend was stopped, both paths returned
  bounded Node-shaped 502 responses without exposing a YUME marker.
- A persistent H2 benchmark transferred 1 MiB in each direction while crossing
  multiple 256 KiB rekey boundaries. Repeated short loopback runs reported
  about 217-240 Mbit/s combined throughput after capture-sized WebSocket
  shaping. These are smoke results, not sustained WAN or release throughput
  evidence.
- Wrong admission did not emit AUTH. Wrong PSK reached no usable plaintext
  session and failed inner AEAD authentication.
- Focused unit/KAT coverage exercises AUTH parsing/transcripts, initial roots,
  directional keys/AAD/ciphertext, threshold transitions, idle behavior,
  simultaneous rekeys, rekey timeout, secret files, WebSocket framing, HTTP/2
  header/stream shape, and admission handling.
- The local benchmark harness now starts only `base-direct` and the mandatory
  `yume-v2` stack. Its 1.x raw/light/heavy/hop and Argon2/PQ-file rows were
  removed. Short development-laptop smokes measured about 79-96 MiB/s for
  `yume-v2`, depending on payload and concurrency; these are functional
  datapoints, not the pending full or sustained release benchmark.
- The crypto microbenchmark now uses the production SessionRatchet. A 2 MiB
  per-direction smoke with 64 KiB DATA frames measured about 415-440 MiB/s and
  performed seven authenticated hybrid rekeys per direction.
- The full profile passed on an approved 32-core Debian 13 host using liboqs
  0.16.0 and the pinned nghttp2 1.69.0 fallback. Across three 8 GiB, 64-stream,
  four-tunnel trials, `yume-v2` measured 226.19 MiB/s (1,897.44 Mbit/s) median
  with 0.709 ms median loopback RTT. Hybrid establishment measured 0.175 ms
  median and directional rekey 0.219 ms median. This proves ample local
  throughput, not WAN performance, Chrome TLS parity, or the pending bulk-wire
  overhead gate.
- A sustained direct-Ethernet authenticated stream-core matrix completed 1 GiB
  upload plus 1 GiB download at 1, 4, 16, and 64 logical streams without a
  queue overrun, replay failure, crash, timeout, or byte mismatch. With a
  production 256 KiB relay buffer, upload measured 311.9-362.8 Mbit/s and
  download 149.0-158.3 Mbit/s. This validates the DATA/ratchet/H2/WebSocket/TLS
  boundary on that single-tunnel LAN path; it excludes local SOCKS and target
  sockets, the packet ABI/TUN path, WAN behavior, and Android. The persistent
  download asymmetry in that historical build became the next profiling target.
- Receive-path profiling found that one maximum-size 256 KiB server DATA record
  consumed an entire byte epoch and delayed client delivery until the whole
  H2/WebSocket/AEAD record had arrived. Server target and benchmark-source reads
  are now capped at 32 KiB records; the 256 KiB / 512-frame / 500 ms ratchet
  limits and wire format are unchanged. In a controlled three-run loopback
  comparison with both processes configured with `YUME_RELAY_READ_BUF=256`,
  128 MiB per direction, and 16 streams, uncapped download measured 284.9
  Mbit/s median and capped download measured 1,077.7 Mbit/s median, a 278%
  increase. The capped upload median was 1,267.9 Mbit/s. This local functional
  run used Node 20.19.2 rather than the pinned Node 24 fixture; the direct
  Ethernet matrix must still be rerun before claiming the hardware asymmetry is
  closed.
- The external `/proc` benchmark sampler and bounded multi-client LAN harness
  passed a 1/2/4/8/16-process loopback ramp on a 24-core/32-thread x86-64 desktop
  host with 64 MiB per direction and 16 streams per client. At 16 clients the
  full-wall application rate was 9,023.5 Mbit/s; clients used 14.65 core-seconds
  (7.695 average cores, 24.046% of the machine) with a conservative 494.83 MiB
  summed peak-RSS bound. Over the matching sampled window, `yumed` averaged
  12.001 cores (37.502% of the machine), 70.34 MiB RSS, and 101.18 MiB peak
  RSS. All stages completed normally. This is same-host scaling evidence, not
  physical-LAN or WAN throughput evidence.
- Authorization keys and per-key policies are now loaded together into an
  immutable server snapshot at startup/reload instead of reparsing the metadata
  file in every session. A 50-client burst previously lost one authentication
  when a concurrent `last_seen` update overlapped a policy-file read; the same
  run passed 50/50 after the snapshot fix. A single bounded 100-client run then
  passed 100/100 with full ML-KEM-1024/X25519 authentication and ratcheted
  traffic. With 24 server workers, the 10.98-Gbit/s load window used 14.48
  average `yumed` cores (45.25% of the 32-thread host), 155.1 MiB average RSS,
  and 233.1 MiB peak RSS. This validates 100 same-host active clients; it is not
  an idle-connection soak or a physical-network result.
- On the same 50-client workload, 24 server workers slightly improved full-wall
  throughput over the 32-worker default (11.30 versus 11.21 Gbit/s) while
  reducing sampled `yumed` CPU from 15.51 to 14.65 average cores. Sixteen
  workers used 13.21 cores and 161.35 MiB peak RSS at 10.95 Gbit/s. This supports
  deployment-specific worker tuning; it does not justify a universal thread cap
  from one hybrid-CPU host.
- Server capacity policy now has an operator-facing bounded model: 256 live
  sessions by default, configurable bulk-key concurrency (64 by default),
  weighted fair egress through decimal per-key `weight`, and separate physical
  `operator_keys` authentication. Individual and operator keys admit one
  authenticated session; explicitly marked bulk-key sessions are counted and
  shaped separately. Bulk policies fail closed if they request exec, LAN,
  full-control, codecs/services, admin, or federation privileges. Process-wide hard CPU/RSS
  ceilings remain the job of systemd/cgroups; `threads`, accept/session limits,
  and filter memory bounds constrain YUME-owned work.
- A focused live policy smoke passed two simultaneous clients using one bulk
  key. Under a 64-Mbit/s egress cap their download shares were 30.8 and 32.6
  Mbit/s (63.4 Mbit/s combined). A separate smoke with an empty regular store
  authenticated through `operator_keys` and logged the explicit outbound-admin
  policy. These prove standard authenticated benchmark traffic and the physical
  operator store; they do not constitute a full GUI admin-attach workflow test.

## Required before `2.0-rc1`

- Run an actual desktop tunnel bidirectionally across multiple epochs and
  reconnect cleanly in the intended deployment environment.
- Complete external HTTP/2/WebSocket conformance checks, not only project tests
  and Chrome interoperability.
- Exercise partial socket writes, sustained flow-control stalls, malformed
  carrier paths, backend timeout/failure, and bounded backpressure under load.
- Decide whether receiver-verifiable active-time enforcement justifies a wire
  timestamp in a later protocol revision. Dev1 independently enforces inbound
  byte/frame usage; its 500 ms boundary remains sender-local because network
  delivery may be delayed after sealing.
- Fuzz WebSocket reassembly across mid-record splits, multi-fragment binary
  messages, and interleaved PING/PONG control frames. Strict inner-record
  sequencing makes this carrier boundary security-critical.
- Capture and compare the live YUME connection against the committed fixture;
  record every remaining classifier-visible TLS/H2 difference.

## Required before exact version `2.0`

- A valid tunnel lasting at least 30 minutes.
- Sanitizer coverage and a longer concurrency/rekey soak on an approved machine.
- WAN capture and throughput validation with at least 10 Mbit/s sustained
  application throughput.
- Bulk overhead measurement at or below 5% using the committed capture-derived
  shaping policy.
- Security-negative coverage for counter wrap and all malformed/tampered cases
  in the acceptance list, plus independent review of key erasure and failure
  paths.
- Directly affected CLI, wire, stealth, threat-model, and deployment docs
  reconciled with the final capture and commands.

## Known residual

YUME dev1 uses OpenSSL while the captured Chrome uses BoringSSL. OpenSSL cannot
reproduce Chrome’s ClientHello/GREASE ordering byte-for-byte, so TLS remains a
classifier-visible difference upstream of the full-session H2 carrier. Matching
ALPN or a coarse JA4 classification is not enough to claim Chrome
indistinguishability. BoringSSL is the likely follow-up if the release threat
model requires closer TLS parity.
