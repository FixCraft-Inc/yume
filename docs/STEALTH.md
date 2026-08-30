# YUME stealth transport

YUME keeps its admitted tunnel inside a TLS 1.3, HTTP/2, and WebSocket
connection. The same public listener sends ordinary requests to a separate
cover site on loopback. This makes the session less like a proprietary tunnel
and raises the cost of casual active probing.

It does not make YUME identical to a browser, hide connection timing or volume,
or guarantee that a classifier cannot distinguish it.

## One captured profile

The active client and cover identity comes from the immutable registry in
`config/transport_profiles.json` and `src/core/stealth/cover_profile.*`. The
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

Every client needs two independent 32-byte random secrets:

- the admission secret lets a request reach AUTH
- the inner pre-shared key contributes to session establishment

Each file contains exactly 64 lowercase hexadecimal characters and has no group
or world permission bits. Both are distributed out of band. The current
transport has no public-key-only or empty-secret public-node mode.

Admission binds the transport version, normalized SNI, an hour bucket, and a
random nonce with HMAC-SHA256. The nonce enters a bounded replay cache. TLS SNI
and HTTP/2 `:authority` must agree.

Malformed, expired, replayed, wrong-secret, or authority-mismatched requests do
not receive an AUTH message. They take a bounded ordinary cover path. A later
PSK or transcript failure closes the admitted carrier without a plaintext YUME
marker or downgrade response.

## Loopback cover server

`yumed` terminates public TLS and HTTP/2. A separately supervised cover process
listens on a configured loopback IP literal. YUME performs no DNS lookup for
that backend, follows no redirect, and accepts no peer-selected backend.

Ordinary GET and HEAD requests can reach the cover process. Tunnel payloads,
client identities, admission values, and session secrets cannot. Hop-by-hop
headers are removed and request, response, body, and timeout limits are
enforced.

Cover work is admitted for at most four streams per public connection and 32
across the process. Each response body is capped at 8 MiB. Backend response
state and serialized TLS-write state have separate bounded budgets. Saturation
uses retryable `REFUSED_STREAM`, and reset or connection close cancels the
loopback work and releases its admission.

Those are availability bounds. They are not proof that overload looks exactly
like the target cover server.

## What observers can still see

A passive network observer can see the destination IP, certificate, ClientHello,
TLS record sizes, timing, duration, and transferred volume. A hosting provider
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

The older helper backend remains comparison evidence. Its tests do not qualify
the native default. Remove it only after the native backend passes its own full
handshake, validation, exporter, lifecycle, resumption, soak, build,
same-session, classifier, and review gates.

## Reproducible checks

Compare the production HTTP/2 opening with the committed fixture:

```bash
python3 scripts/yume_h2_fingerprint.py chrome \
  --check chrome \
  --emitter build/bin/yume_h2_opening_probe
```

Run a local functional carrier and cover check without packet capture:

```bash
python3 scripts/yume_carrier_diagnose.py \
  --local-server \
  --capture-tool none \
  --out yume-dpi-functional
```

This proves the exercised functional path, not ClientHello or classifier
parity. Packet capture should run only on an approved evidence host with
deliberately granted capture access. Do not give the YUME binaries root or
capture privileges to make a check pass.

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

The normative record and ratchet rules are in
[the transport wire specification](protocol/YUME_2_0_WIRE.md). The
[implementation status](IMPLEMENTATION_STATUS.md) records the current release
and evidence boundary.
