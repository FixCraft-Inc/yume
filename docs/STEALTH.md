<!-- Generated from docs/src/en_US/pages/stealth.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# YUME stealth transport

This page describes the transport profile, carrier, admission and cover that
`yume` and `yumed` use, and the evidence behind them. The runtimes and the
schema-1 ABI backend compose TLS 1.3, the HTTP/2 front door and carrier,
exporter-bound replay-protected admission and hybrid session security. Their
complete-session stealth qualification remains open. See the current
[implementation status](IMPLEMENTATION_STATUS.md).

YUME keeps its admitted tunnel inside a TLS 1.3, HTTP/2, and WebSocket
connection. The same public listener answers ordinary requests from a static
cover site that `yumed` loads at start. This makes the session less like a
proprietary tunnel and raises the cost of casual active probing.

It does not make YUME identical to a browser, hide connection timing or volume,
or guarantee that a classifier cannot distinguish it.

## One captured profile

The active client and cover identity comes from the immutable registry in
`config/transport_profiles.json` and `src/stealth/cover_profile.*`. The
registry selects a committed browser and cover-server fixture under
`tests/fixtures/`. It owns the TLS choice, request headers, HTTP/2 settings and
priorities, asset order, WebSocket behavior, and cover-server identity.

Tests compare production consumers with that fixture. A new browser or server
identity needs a new capture, registry entry, wire tests, and end-to-end
evidence. Changing only a User-Agent string or rotating profiles per connection
is not supported.

Recent nghttp2 versions no longer emit the legacy priority bytes captured from
the target browser. YUME's narrow wire-profile adapter inserts or verifies those
captured bytes while nghttp2 continues to own HPACK, stream state, flow control,
and the rest of the framing.

## Carrier lifecycle

The connection remains valid HTTP/2 for its full lifetime:

1. The client loads the captured cover page and assets.
2. It opens an RFC 8441 extended `CONNECT` stream with
   `:protocol = websocket`.
3. Encrypted YUME records travel as WebSocket binary messages inside HTTP/2
   DATA frames.
4. HTTP/2 and WebSocket control frames close the session without switching to a
   proprietary outer syntax.

Client WebSocket frames are masked and server frames are not. SETTINGS, ACK,
WINDOW_UPDATE, fragmentation, PING/PONG, CLOSE, RST_STREAM, GOAWAY, partial
writes, and backpressure have explicit handling and bounded state.

Both roles use manual receive credit for the admitted carrier. Control and
cover bytes are credited when parsed. Tunnel bytes retain their matching credit
until the destination or local sink consumes them. This preserves bounded
backpressure without changing the captured opening SETTINGS.

Idle carriers do not invent periodic traffic. Any active PING, close sequence,
padding, or future cadence must come from a committed target capture.

## Admission and failure behavior

Every client holds two independent 32-byte random secrets:

- the admission key, which the server shares with its clients, lets a request
  reach AUTH
- the client's own access PSK contributes to its session keys

Each is a file of exactly 32 raw bytes, not all zero, read through the
owner-only secret-file reader, and both are distributed out of band. The
server refuses an access PSK equal to the admission key. There is no
public-key-only or empty-secret public-node mode.

Admission is an HMAC-SHA256 token in the extended CONNECT path over the
canonical TLS SNI, an exporter from this TLS connection and a random nonce
([YTP admission](protocol/YTP_1.md#h2-admission-v1)). Wall-clock time and the
evidence profile are not part of it, and one TLS connection can promote at
most one carrier. The nonce enters a replay cache that every listener in the
process shares. It keeps at most 4096 nonces for two hours of monotonic time
and refuses new admissions when full rather than dropping live entries. A
restart loses that state. TLS SNI and HTTP/2 `:authority` must agree.

A missing, malformed, wrong-key, replayed or cache-saturated proof, or a
request beyond promotion capacity, gets the cover site and never an AUTH
message. A later PSK or transcript failure closes the admitted carrier without
a plaintext YUME marker or downgrade response.

## Cover site

`yumed` terminates public TLS and HTTP/2 and serves cover from an immutable
static site it loads from a confined directory at start. The site must hold the
assets the active browser profile loads, or startup fails. Requests select
preloaded routes, so serving cover reads no file and resolves no name. By
default a file is at most 1 MiB and the whole site at most 16 MiB.

Tunnel payloads, client identities, admission values and session secrets never
reach cover handling. One connection may hold at most 64 open cover streams
and make 256 requests, and a response is served only while it fits under
4 MiB of queued output. One 30-second deadline covers the TLS handshake,
requests and cover drain until a carrier is promoted.

Those are availability bounds. They are not proof that overload looks exactly
like the target cover server. A reverse-proxy cover in front of a real website
can be written in schema 1 but is not implemented yet, and a server configured
with one refuses to start.

## What observers can still see

A passive network observer can see the destination IP, ClientHello (including
SNI), TLS record sizes, timing, duration, and transferred volume. TLS 1.3
encrypts the certificate exchange, although an active peer can inspect the
certificate by connecting. A hosting provider
can also see the daemon's outbound destinations. The terminating daemon sees
authenticated client identities, requested targets, and decrypted YUME stream
bytes unless an application protocol such as HTTPS protects them end to end.

Valid HTTP/2 removes a proprietary post-handshake grammar. Keyed admission and
the cover path make simple probes less informative. Neither property provides
anonymity or prevents statistical traffic analysis.

## Native TLS evidence

YUME keeps two separate native TLS contracts:

- the diagnostic backend is the stock-library negative control
- the normal backend enables the default-off capability in YUME's pinned
  OpenSSL source

The normal backend passes the pinned ClientHello structure rows for the active
fixture. The diagnostic backend must remain unchanged when linked to the same
patched library. This proves the intended capability is opt-in and does not
alter unrelated TLS contexts.

The structure gate covers the fields recorded by the fixture. It does not
qualify certificate validation, exporter behavior, hello retry, resumption,
reconnect, full-session timing, build reproducibility, or classifier parity.
A matching ALPN, JA3, or JA4 value is narrower still.

The Go helper backend that transport v2 compared against has been removed.
The native backend's full handshake, resumption, soak, same-session and
classifier gates remain open in the
[implementation status](IMPLEMENTATION_STATUS.md).

## Reproducible checks

Compare the production HTTP/2 opening with the committed fixture:

```bash
python3 scripts/yume_h2_fingerprint.py chrome \
  --check chrome \
  --emitter build/bin/yume_h2_opening_probe
```

Observe one real YTP/1 session with nDPI inside a rootless network namespace:

```bash
python3 scripts/yume_ndpi_smoke.py \
  --yumed build/bin/yumed --yume build/bin/yume \
  --ndpi-reader /path/to/ndpiReader --openssl /path/to/openssl \
  --output yume-ndpi-smoke
```

The script runs the session under `unshare -rn`, so it needs no host
privileges, and writes the raw reader output and a summary to a new directory.
It observes one loopback session and is not a classifier result. Packet
capture outside such a namespace should run only on an approved evidence host
with deliberately granted capture access. Do not give the YUME binaries root
or capture privileges to make a check pass.

The classifier-evidence validator accepts bounded, checksummed, sanitized
artifacts and requires matched normal-browser and YUME arms. Raw NetLogs,
packet captures, credentials, and keys remain outside Git.

## Classifier gate

Freeze the target profile, workload, feature extraction, overhead budget, and
acceptance threshold before evaluating a candidate. Split data by complete
session and hold out capture day, host, network, and provider. A packet-random
split leaks session identity into both sets.

Report sample counts, confidence intervals, ROC-AUC, PR-AUC, and true-positive
rate at low false-positive rates across more than one classifier family. Include
active probes and simple metadata-only baselines. A finite campaign can bound
measured advantage against one named cover distribution. It cannot prove that
future DPI cannot learn YUME.

Do not add random padding, a fixed keepalive, or host-specific jitter because it
sounds browser-like. Add a bounded, versioned traffic-shape policy only when a
captured workload and held-out comparison show that it reduces
distinguishability within the release overhead budget.

## Claim language

YUME uses hybrid post-quantum key establishment. “Quantum-proof,”
“uncrackable,” “identical to Chrome,” “DPI-proof,” and guaranteed
future-proof are not supported claims.

Compromise claims must name the exposed material. A one-use message key, the
current chain or root, a prepared future root, the deployment PSK, and live
process memory have different consequences. Recovery requires fresh
uncompromised contributions. It is not correct to say that every key becomes
useless after a fixed number of milliseconds.

The [relay channel contract](protocol/RELAY_CHANNEL.md) records the relay
module's handshake and ratchet formulas. The
[YTP/1 kernel contract](protocol/YTP_1.md) records YTP/1's canonical
encodings, fixed security constants, and exact unfinished cryptographic/runtime
boundary. The [implementation status](IMPLEMENTATION_STATUS.md) records the
current release and evidence boundary.
