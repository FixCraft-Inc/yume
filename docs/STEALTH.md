# YUME 2.0 desktop stealth transport

This document covers only the first YUME 2.0 Linux desktop slice. The fixed
cover stack is a Chrome-shaped `yume` client, a public `yumed` TLS/HTTP/2
endpoint, and a separately supervised Node.js process on loopback. Android,
nginx, alternate browser profiles, HTTP/3, and the retired 1.x carriers are
outside this slice.

## Target identity and current implementation

- Target client fixture: Chrome `151.0.7922.71` on Debian 13.
- Cover server fixture: Node.js `24.18.x` LTS HTTP/2.
- TLS: TLS 1.3 with ALPN `h2`; `--profile chrome` is mandatory.
- Public endpoint: `yumed`; Node is never exposed directly.
- Cover backend: `loopback://<IP-literal>:<port>` only.

The sanitized capture and version manifest are committed under
`tests/fixtures/chrome151-node24/`. They, rather than invented timing or frame
constants, define the target profile.

The current client selects one immutable profile in
`src/core/stealth/cover_profile.*`. It supplies the Chrome 151/Debian 13 TLS
profile selection, User-Agent/client hints, H2 settings/priorities/header
order, asset sequence, WebSocket message size, and Node 24 server settings.
The HTTP registry, TLS preset, and production `H2Carrier` consume that profile,
and tests compare it to the committed capture fixture.

nghttp2 1.69 removed its RFC 7540 priority scheduler and ignores the legacy
priority argument on request submission. Chrome's captured HEADERS still
contains those five priority bytes. The private `h2_wire_profile` adapter
therefore inserts the captured fields when a new nghttp2 omits them, or
validates them when an older supported nghttp2 emits them itself. nghttp2
continues to own HPACK, stream state, flow control, and all other framing. The
opening diagnostic parses the resulting production bytes and decodes them
through the production server endpoint.

This fixes the former Chrome 131/150 and Windows/Linux contradiction. It does
not mean the emitted TLS ClientHello has achieved Chrome/BoringSSL parity.
Profile rotation remains rejected in 2.0.

## Full-session HTTP/2 carrier

YUME no longer switches to raw proprietary frames after an HTTP-looking
opening. The connection remains valid HTTP/2 for its entire life:

1. The client opens `GET /` on stream 1.
2. It requests the captured CSS and JavaScript assets on streams 3 and 5.
3. It opens RFC 8441 extended `CONNECT` with `:protocol = websocket` on stream
   7 after the priming requests complete.
4. Encrypted YUME records travel as WebSocket binary messages inside HTTP/2
   DATA frames. Client WebSocket frames are masked; server frames are not.

The carrier handles SETTINGS/ACK, flow control, WINDOW_UPDATE, WebSocket
fragmentation, PING/PONG, CLOSE, RST_STREAM, GOAWAY, partial socket writes, and
bounded backpressure. It uses one serialized output path and never drops or
truncates tunnel data.

Idle connections originate no keepalive or rekey traffic. “Idle silent” does
not mean “never originate a protocol frame”: the captured active Chrome/Node
fixture shows Chrome originating an HTTP/2 PING immediately before its
WebSocket close, with Node acknowledging it, so YUME mirrors those roles. Any
future active-session cadence must come from a committed capture; it must not
be invented. At the WebSocket layer, the Node fixture sends one 12-byte PING
after the first client binary message and Chrome replies with a masked PONG;
the profile reproduces that active exchange once per carrier.

## Admission and failure camouflage

Every client needs two different 32-byte random secrets delivered out of band:

- `--obfs-secret-file <path>` admits the carrier before AUTH.
- `--inner-psk-file <path>` contributes to the encrypted inner channel.

Each file contains exactly 64 lowercase hexadecimal characters with no newline
and must have no group/world permission bits. There is deliberately no
public-key-only or empty-secret mode in YUME 2.0.

Admission binds the exact transport version, normalized SNI, hour bucket, and a
32-byte random nonce with HMAC-SHA256. The nonce is authenticated and inserted
into a bounded replay cache. SNI and HTTP/2 `:authority` must agree.

Missing, malformed, expired, replayed, wrong-secret, or authority-mismatched
attempts never receive AUTH. They take the ordinary captured Node cover path.
PSK mismatch, transcript failure, or inner authentication failure closes the
accepted carrier without a plaintext YUME marker or downgrade response.

## Genuine loopback Node cover

`yumed` terminates public TLS and HTTP/2, while a separate Node process provides
the genuine website behavior:

```text
yumed --real-backend loopback://127.0.0.1:3000 \
      --obfs-secret-file /run/secrets/yume-obfs.hex \
      --inner-psk-file /run/secrets/yume-inner.hex ...
```

Only a configured loopback IP literal is accepted. YUME performs no DNS lookup,
follows no redirect, accepts no peer-selected host, and forwards no proxy
authorization. Ordinary GET/HEAD requests may reach Node; authenticated carrier
bytes, identities, PSKs, and tunnel data never do.

The proxy bounds request headers to 32 KiB, response headers to 64 KiB, response
bodies to 8 MiB, and applies bounded connection/response timeouts. Hop-by-hop
headers are stripped. Backend health is checked at startup. A later outage uses
an ordinary Node-shaped 502/close path, not a YUME-specific error.

The old static responder may remain an emergency fallback in the wider codebase,
but it is not the evidence-backed YUME 2.0 cover and must not be described as
native Node behavior.

## What this helps against today

- Custom-protocol signatures after TLS: the whole session remains H2/WebSocket.
- Casual active probing: ordinary non-admitted GET/HEAD traffic sees the real
  Node site. Invalid carrier attempts remain outside AUTH and receive a bounded
  cover response; this is not a claim that every malformed H2 request renders
  a complete website.
- Replay of captured carrier URLs: admission nonces are cached until expiry.
- Some retained-chain compromise: independent directions rekey before crossing
  the authenticated ratchet policy; Extreme defaults to 256 KiB, 512 encrypted
  data frames, or 500 ms of active epoch time.

These are reductions in distinguishability and compromise radius, not claims of
anonymity, browser identity, or immunity to statistical traffic analysis.
Passive observers see the ClientHello, certificate and endpoint metadata, TLS
record sizes, timing, and volume. They do not see plaintext H2 frames unless
they also terminate or decrypt TLS. Valid H2 primarily removes a proprietary
post-handshake syntax and improves behavior under probing; it does not make a
tunnel look specifically like “reading a news article.”

## Reproducible checks

Compare the production H2 opening against the committed Chrome fixture:

```bash
python3 scripts/yume_h2_fingerprint.py chrome \
  --check chrome \
  --emitter build/bin/yume_h2_opening_probe
```

Run the current client, daemon, real Node cover, and Chromium without privileged
packet capture:

```bash
python3 scripts/yume_carrier_diagnose.py \
  --local-server \
  --capture-tool none \
  --out yume-dpi-functional
```

That checks transport functionality, H2 negotiation, browser traffic through
SOCKS, and the ordinary cover path. It deliberately reports stealth as
unproven because it cannot see the ClientHello.

Where the operator has deliberately granted `dumpcap` or `tcpdump` capture
access, collect both the YUME flow and a direct Chromium baseline:

```bash
python3 scripts/yume_carrier_diagnose.py \
  --local-server \
  --capture-tool auto \
  --out yume-dpi-capture
```

The resulting `SUMMARY.md`, pcaps, logs, JA3, JA4, and JA4_r values are review
artifacts, not an automatic parity verdict. Never grant the YUME binaries root
or packet-capture privileges merely to make this diagnostic pass.

## Known classifier-visible residuals

TLS remains the weakest classifier-visible layer. Stock OpenSSL does not expose
enough control to reproduce Chrome/BoringSSL extension and GREASE ordering. It
therefore remains available only as the explicitly named
`openssl-diagnostic` backend and is not a Chrome-parity fallback.

The experimental Linux `chrome151` backend isolates pinned uTLS `v1.8.2` in a
per-connection helper built with exact Go `1.26.5`. The C++ parent establishes
the routed TCP socket, the helper emits the custom Chrome 151 first flight and
returns authenticated certificate metadata plus the mandatory TLS exporter
over a private socketpair. It is implemented but deliberately not the default:
five-run normalized on-wire parity and the local handshake/throughput gates now
pass. The bounded negative certificate/exporter and process-lifecycle matrix,
process ramps, reconnect storm, and segmented full-speed loopback soak also
pass. Matched WAN, one uninterrupted deployed-network soak, exact-Chrome
same-session capture, classifier/active-probe evidence, and independent review
remain incomplete.
The helper name or a matching JA3/JA4 value is not evidence of parity.

YUME also does not currently disguise traffic volume and timing beyond the
capture-derived H2/WebSocket framing. Blanket random padding, fixed-rate cover
traffic, or periodic keepalives can create a new fingerprint and waste
bandwidth. Add padding or timing shaping only when captured workloads and an
external classifier comparison show that a bounded policy improves the target
distribution. Idle silence remains the current contract.

## Goal state and measurable gates

The “ordinary sedan outside, hardened vault inside” description is a design
goal, not a current security claim. Move toward it in this order:

1. **One profile source (implemented).** The immutable Chrome 151/Debian 13 +
   Node 24 profile supplies the target identity and capture-shaped H2 values;
   fixture-backed tests keep its consumers coherent.
2. **Capture-normalized TLS parity (structural gate passed).** Five complete
   authenticated helper flows match the Chrome 151/Node 24 structural profile,
   with five distinct extension orders and three allowed ECH lengths. The gate
   in `scripts/yume_tls_wire.py` preserves
   extension order, GREASE positions, cipher/group/signature order, ALPN,
   key-share geometry, padding, and lengths while normalizing only documented
   entropy. A fresh same-session normal-Chrome NetLog plus wire recapture is
   still required for release evidence quality. A matching JA3/JA4 label is
   insufficient.
3. **End-to-end profile coherence.** Capture a real YUME connection and reject
   any TLS, HTTP header, client-hint, H2 setting/priority, WebSocket, certificate,
   cover-site, or server-header contradiction. Validate both admitted and
   ordinary/probe paths with external H2 tooling.
4. **Evidence-driven traffic shape.** Record representative page-load,
   interactive, upload, download, bidirectional, idle, close, loss, and WAN
   traces. Compare TLS-record size/timing distributions against the chosen
   cover workload. Introduce bounded padding/jitter only if it measurably lowers
   distinguishability and remains within the release overhead budget.
5. **Adversarial validation.** Test passive classification, active TLS/H1/H2
   probes, malformed extended CONNECT, replay, backend outage, certificate/site
   consistency, and common hosting/IP metadata. Record what still
   distinguishes YUME; do not turn a passed fixture test into a DPI-immunity
   claim.

Changing the TLS stack, adding padding, or changing wire fields is not complete
until these gates have repeatable artifacts. Any TLS-stack migration must also
preserve certificate validation, pinning, ALPN, error handling, packaging, and
sanitizer/build coverage.

## Cryptographic claim vocabulary

YUME 2.0 uses hybrid ML-KEM-1024 + X25519 + a uniformly random 32-byte PSK for
establishment and fresh hybrid material for directional epochs. It is accurate
to call this **hybrid post-quantum key establishment**. It is not accurate to
call YUME “quantum-proof,” “uncrackable,” or guaranteed future-proof: Ed25519
client authentication and the public TLS certificate remain classical, the PSK
is a deployment secret, endpoint compromise exposes live plaintext/state, and
the complete construction has not received an independent formal proof or
security audit.

The Extreme profile's 500 ms constant is a maximum **sender-active epoch age**, starting with the
first application frame. Byte or frame use may rotate an epoch sooner; an idle
connection does not rotate at all. Receivers independently enforce byte/frame
limits, but the time rule currently assumes a conforming sender. An
authenticated wire timestamp would not make a malicious sender's clock
truthful, would expose/change timing semantics, and would require a versioned
wire/AAD decision. A future design may instead keep the honest sender-local
contract or enforce a receiver-local lifetime from first authenticated
arrival, with its availability tradeoff.

Compromise claims must name the material. Exposure of one erased, one-use
message key is much narrower than exposure of the current chain/root or process
memory. The negotiated window also retains up to `w` authenticated future
roots. Recovery occurs only after uncompromised fresh rekey contributions; a
key does not become “instantly useless after 500 ms” under every compromise
model.

## Release evidence

The exact wire contract is in `docs/protocol/YUME_2_0_WIRE.md`. Current evidence
and remaining gates are in `docs/YUME_2_0_IMPLEMENTATION_STATUS.md`. The version
must remain a development/RC label until external H2 conformance, a 30-minute
tunnel, WAN/soak validation, and the stated throughput/overhead gates pass.
