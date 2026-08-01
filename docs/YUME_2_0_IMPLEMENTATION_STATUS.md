# YUME 2.0 desktop implementation status

Status: `2.0-dev6` vertical slice implemented; release gates incomplete.

This is a truthful inventory of the focused Linux x86-64 client/server work. It
does not claim Android, GUI, nginx, alternate browser profiles, H3, federation,
or admin/control validation.

## Implemented

- Version-pinned Chrome `151.0.7922.71` / Node `24.18.0` reference fixture,
  manifest, and sanitized HTTP/2 profile. One immutable Chrome 151/Debian 13 +
  Node 24 profile supplies the TLS selection, User-Agent/client hints, H2
  settings/priorities/header order, assets, and cover-server identity.
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
- Independent directional hybrid rekeys under an authenticated bounded policy.
  Extreme remains the default at 256 KiB, 512 encrypted data frames, or 500 ms
  of active epoch time; Normal, Soft, and exact bounded Ultimate profiles widen
  all three budgets without changing the mandatory algorithms or one-use
  message keys. The next epoch is prepared while
  bounded current-epoch traffic remains, hiding the exchange latency without
  increasing any hard usage limit. Idle silence, bounded boundary waits,
  timeout close, simultaneous rekeys, old receiving-chain retirement, and
  independent receiver enforcement remain fail closed. Server
  rekey/control frames are scheduled ahead of saturated DATA queues so normal
  throughput cannot turn congestion into a rekey timeout.
- Encrypted `.yss` migration uses the BaseFWX 12-character minimum and carries
  separate TLS/operator CA material, TLS/SNI name, admission secret, inner PSK,
  tunnel count, and operator-proof policy. Legacy v1 files that carried only
  the shared private CA remain importable.
- Exact `2.0-dev6` admission/AUTH-version equality and no accepted older-dev
  downgrade path. Legacy
  inner/light/heavy/dual/hop/no-inner/raw-carrier and literal-secret CLI choices
  are rejected. The unreachable client-side 1.x AUTH response, Argon2 challenge
  metadata, and long-lived PQ auto-trust/reconnect implementation have been
  removed; the unvalidated federation path still retains its separate legacy
  AUTH and inner-key flow.

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
- A local real-SOCKS regression transferred 33 MiB continuously for 16 seconds
  across many rekey epochs, then completed a follow-up request on the same
  connection. This covers the prior server-side rekey-starvation disconnect;
  it is not an Android background-lifecycle or WAN throughput result.
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
  Ethernet result was still limited by the dev1 stop-and-wait epoch exchange.
- Matched `2.0-dev2` client/server binaries pipelined that exchange without
  changing the 256 KiB, 512-frame, or 500 ms limits. On the direct
  10.77.77.2-to-10.77.77.1 one-gigabit link (940-941 Mbit/s raw iperf3), three
  256 MiB-per-direction one-stream trials measured 930.6 Mbit/s upload and
  930.6 Mbit/s download median. A final exact 1 GiB-per-direction one-stream
  run sustained 931.2/930.0 Mbit/s, while the requested 16-stream run sustained
  931.1/926.9 Mbit/s. Same-host one-stream endpoint traffic measured
  1,894.5/1,910.2 Mbit/s. These runs cover the authenticated
  DATA/ratchet/H2/WebSocket/TLS benchmark path, not SOCKS target sockets,
  packet ABI/TUN, WAN, Android, or a release soak. The generated benchmark
  bundle was retired during the 2026-07-28 machine cleanup; this document
  preserves the reviewed result, not a claim that raw artifacts remain in the
  checkout.
- Dev2 had only one pending future epoch, so exhausting 256 KiB before its ACK
  returned reintroduced a hard-boundary wait on a saturated high-BDP path: a
  model of about 35/21/10 Mbit/s at 60/100/210 ms RTT.
- Dev3 replaces that with a negotiated bounded window of authenticated,
  strictly contiguous future epochs (`--rekey-window`, default 8, range 1..64),
  raising the same model to `window * 256 KiB` per rekey round trip — about
  419/280 Mbit/s at 40/60 ms at the default depth. Every per-epoch limit is
  unchanged and the depth bounds both the ML-KEM work a peer can request and
  the number of prepared future epochs an endpoint compromise exposes. Unit
  coverage is in `src/core/security/session_ratchet_test.cpp` (window budget,
  progress pacing, inbound overflow, non-contiguous offer) and
  `src/core/security/auth_v2_test.cpp` (record vectors, range rejection).
  These are unit and model results, not measured WAN results: the 100 ms time
  lead and 64-frame lead can still run out on continuous or small-frame
  traffic, and H2/TCP bandwidth-delay-product work is still required before any
  WAN line-rate claim. See `docs/YUME_2_0_WAN_BEHAVIOR.md`.
- Timing instrumentation now uses one shared diagnostics layer. It is compiled
  only into Debug/RelWithDebInfo builds and remains runtime opt-in; Release and
  MinSizeRel contain no timing clocks, counters, handlers, event strings, or
  environment activation path.
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
- The current 2.0 carrier diagnostic provisions protected admission/inner
  secret files and the real loopback Node cover. An unprivileged local audit
  passed Chromium-through-SOCKS, H2 ALPN, and ordinary cover probing. Raw packet
  capture was unavailable on that host, so this adds functional evidence but no
  new ClientHello or Chrome-parity claim. The diagnostic emits JA3, JA4, and
  JA4_r evidence when `dumpcap` or `tcpdump` access is available.

## Required before `2.0-rc1`

- Run an actual desktop tunnel bidirectionally across multiple epochs and
  reconnect cleanly in the intended deployment environment.
- Complete external HTTP/2/WebSocket conformance checks, not only project tests
  and Chrome interoperability.
- Exercise partial socket writes, sustained flow-control stalls, malformed
  carrier paths, backend timeout/failure, and bounded backpressure under load.
- Decide the time-limit threat model explicitly. Today the receiver
  independently enforces inbound byte/frame usage while the configured active-time boundary is
  sender-local. A signed timestamp does not make a malicious sender's clock
  truthful. Alternatives are to retain and document the honest-sender rule, or
  enforce a receiver-local lifetime from first authenticated arrival and accept
  its delay/availability tradeoff. Any wire timestamp needs explicit semantics,
  a version/AAD change, and a leakage analysis.
- Fuzz WebSocket reassembly across mid-record splits, multi-fragment binary
  messages, and interleaved PING/PONG control frames. Strict inner-record
  sequencing makes this carrier boundary security-critical.
- Capture and compare the live YUME connection against the committed fixture;
  record every remaining classifier-visible TLS/H2 difference.
- Preserve fixture-backed coherence between the TLS selection, HTTP headers,
  H2 shape, assets, and cover server while closing the remaining OpenSSL
  ClientHello differences.

## Required before exact version `2.0`

- A valid tunnel lasting at least 30 minutes.
- Sanitizer coverage and a longer concurrency/rekey soak on an approved machine.
- Validate the implemented bounded future-epoch window with matched one-tunnel
  WAN upload/download/both matrices at 60, 100, and 210 ms, 100 Mbit/s and
  approximately 1 Gbit/s, plus controlled loss and a 30-minute soak. Diagnose
  the separate measured ceiling near 25 Mbit/s before tuning the ratchet
  further. The LAN result is not this gate.
- Bulk overhead measurement at or below 5% using the committed capture-derived
  shaping policy.
- Security-negative coverage for counter wrap and all malformed/tampered cases
  in the acceptance list, plus independent review of key erasure and failure
  paths.
- Directly affected CLI, wire, stealth, threat-model, and deployment docs
  reconciled with the final capture and commands.

## Known residual

The former Chrome 131/150 and Windows/Linux identity mismatch is fixed behind
one immutable Chrome 151/Debian 13 + Node 24 profile. OpenSSL still cannot
reproduce Chrome/BoringSSL ClientHello/GREASE ordering, so TLS remains a
classifier-visible difference upstream of the full-session H2 carrier.
Matching ALPN or a coarse JA4 classification is not enough to claim Chrome
indistinguishability. BoringSSL is a likely experiment, not a sufficient fix by
itself; Chrome-specific behavior and entropy-normalized on-wire comparison
against one pinned build are required. Traffic padding is likewise an
evidence-driven option, not an automatic improvement.

Client AUTH sends an Ed25519 public key and a signature over the complete
canonical challenge/response transcript; it never sends the private key. As of
`2.0-dev4` the signature input also covers a 32-byte RFC 8446 exporter that
each endpoint derives from its own live TLS object and never transmits, and the
same value is folded into the establishment root. A malicious terminating
endpoint with compatible admission/PSK access can no longer relay a live AUTH
exchange to a second server: the forwarded signature is over a different
connection's exporter. Both endpoints require TLS 1.3 and a finished handshake;
there is no unbound mode and no way to negotiate the binding away.

Identity-file safety is now a creation and loading invariant rather than
operator hygiene. `generate_ed25519_keypair()` serializes to memory and creates
both files through the exclusive owner-only writer, wipes the private PEM, and
refuses to replace an existing path. `crypto::load_keypair()` reads the private
key through an already-validated descriptor: regular non-symlink file, owned by
the effective user, no group/world bits, bounded size. Windows has no equivalent
enforcement and fails closed, which remains open work alongside protected
secret loading there.

The hybrid ephemeral establishment/rekeys provide a forward-secrecy design
against later long-term-file compromise, not secrecy from `yumed` itself.
`yumed` terminates the ratchet and handles decrypted stream bytes. Historical
secrecy still depends on honest non-retention, ephemeral erasure, primitive/RNG
security, and the absence of live endpoint compromise.
