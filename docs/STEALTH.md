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

Before feeding two five-run arms to a passive classifier, validate that they
actually share one frozen comparison contract:

```bash
python3 scripts/yume_classifier_evidence.py \
  --normal /private/evidence/normal-chrome \
  --yume /private/evidence/yume
```

The validator parses only sanitized JSON, normalized TLS-wire reports, the
public certificate, and their environment/completion manifests. It hashes raw
NetLogs opaquely without parsing or displaying them. It requires a final
`complete.json`, verifies portable per-run, runtime-source, and top-level
checksums, rejects symlinks and unbounded inputs, requires exact Chrome/Node
identities and five runs per arm, rejects a normal/YUME arm relabel, requires a
user-namespace Chrome sandbox, and compares source cleanliness, certificate,
SNI, ALPN, profile, the exact `tools/cover-node/workload-v1.json` hash,
workload, and stable H2/WebSocket behavior. The stable projection includes the
ordered request stream/method/path classes (including Chrome's stream-9
`/favicon.ico` request) and the compressed WebSocket frame order, so a missing
favicon lifecycle or an early server PING cannot be hidden by matching aggregate
counts. `PARITY` means only that the inputs are matched enough for later external
classifier and active-probe work.
`KNOWN_GAP` means required evidence is absent; `DRIFT` means an observed value
differs. The existing carrier diagnostic's public-URL baseline is useful
functional evidence but is not a same-certificate, same-server classifier
baseline and therefore cannot satisfy this contract.

The direct HTTP/2 capture target and classifier-input validator consume that
one workload file through `tools/cover-node/workload.mjs`. The reference page,
CSS, generated browser script, asset order, 64 by 16-KiB bidirectional
WebSocket transfer, first server fragmentation, 12-byte ping/pong, and close
payload therefore no longer have independent definitions. The installed
production HTTP/1 cover backend intentionally remains a bounded GET/HEAD site:
ordinary public RFC 8441 CONNECT is not an admitted YUME carrier and must not
be forwarded to a new unauthenticated echo service merely to force parity.
Driving the same workload through production YUME uses the opt-in live carrier
observer and exact one-shot lifecycle described below. It observes the outer
production carrier directly; it does not infer behavior from SOCKS counters.

For a normal-Chrome arm, run from a clean exact-commit checkout and place the
fresh output outside the checkout. A matched campaign may supply one private
certificate/key pair and DNS SNI to the existing runner:

```bash
YUME_CAPTURE_TLS_CERT=/private/session/server.crt \
YUME_CAPTURE_TLS_KEY=/private/session/server.key \
YUME_CAPTURE_SNI=cover.test \
YUME_CAPTURE_TLS_WIRE=1 \
YUME_CHROME_LAUNCHER=/isolated/chrome/google-chrome \
YUME_CHROME_BINARY=/isolated/chrome/chrome \
tools/cover-node/capture_chrome151_runs.sh \
  /private/session/normal-chrome /isolated/node-v24.18.0/bin/node 5 42000
```

The key must be mode `0600` or stricter and the certificate must cover the
declared SNI. The runner still supports generating a standalone ephemeral
certificate when both variables are absent, but that arm cannot be called
same-certificate evidence until the YUME arm actually uses it. Before any
browser starts, the runner binds a clean commit/tree and copies every reopened
Node/Python/fixture input into a private checksummed runtime-source snapshot.
All five runs use only that snapshot; the source, snapshot, runtimes,
certificate, and key are rechecked before portable relative checksum manifests
and mode-0600 `complete.json` are written. Failed or partial captures have no
completion marker and are rejected by the validator. Raw NetLogs and all
private material remain outside Git.

The first real five-plus-five campaign on 2026-08-13 failed closed during
normal run 3 after two completed normal runs. Its driver could issue the
fixture evaluation against the old `about:blank` execution context immediately
after navigation; the YUME arm and matched validator did not run. That partial
root is diagnosis-only evidence and no run from it may be reused. The corrected
driver enables lifecycle events before its single navigation, requires the
returned frame and loader to reach `load`, and then checks the exact fixture URL
and readiness marker with short synchronous polls. CDP commands, DevTools HTTP
requests, and socket transitions are bounded, and the runner passively confirms
the exact loopback Node listener before starting the TLS relay. A fresh exact-
commit five-plus-five campaign is still required.

For the YUME arm, use the checked-in runner from a clean exact-commit checkout.
It creates the owner-only output, runs five separate production connections
through an unprivileged TCP relay that records TLS-wire structure, invokes the
exact capture mode, seals per-run and top-level checksums, snapshots every
runtime input, and writes `complete.json` only after all runs verify:

```bash
tools/cover-node/capture_yume151_runs.sh \
  /private/session/yume-arm \
  /exact/build/bin/yume \
  /private/session/release/yume-amd64-linux.tar.xz \
  /private/session/yume-client.json \
  /private/session/server.crt \
  cover.example \
  192.0.2.10:443 \
  /exact/chrome/google-chrome \
  /exact/chrome/chrome \
  /exact/node-v24.18.0/bin/node \
  5
```

The target must terminate with the supplied certificate and the config must
contain the campaign's external admission/inner credentials. The runner hashes
the config but never copies it or any referenced secret. It separately records
the certificate PEM-file checksum and passes the X.509 DER leaf fingerprint as
the helper pin. It fails closed unless the YUME binary, adjacent helper, exact
Chrome launcher/binary, exact Node binary, source commit/tree, certificate,
runtime snapshot, and user-namespace capability remain unchanged. The supplied
client and its adjacent helper must byte-match the validated prepared Linux
bundle, whose manifest must name the clean capture source commit. The direct
CLI flag is intentionally incompatible with SOCKS/forwarding, packet-TUN,
proxy, multi-tunnel, full-benchmark, padding, and jitter modes.

Each run sends 64 ordered 16-KiB application messages and requires the server
to echo each parsed message byte-for-byte, for exactly 1 MiB in each direction.
This capture-only transaction stays open while the authenticated carrier is
quiet for 42 seconds; the ordinary throughput benchmark remains sequential
upload/download and closes its logical streams normally. Capture then sends
the terminal H2 PING/WebSocket CLOSE/GOAWAY and waits at most 750 ms for the
peer close before shutdown.

The report is reserved before networking, remains mode `0600`, is durably
written once, and records only bounded sanitized metadata from actual live
nghttp2/WebSocket events. It never records payloads, admission secrets,
carrier URLs, peer addresses, TLS secrets, or H2 PING opaque bytes. Collection
failure does not alter the carrier, but the report is marked incomplete and the
capture command fails. The stable summaries are reconstructed from the event
stream; the classifier rejects placeholder, malformed, mismatched PING/ACK,
and aggregate-inconsistent event evidence.

Do not synthesize `behavior.json` from the committed fixture,
`cover_profile::active()`, aggregate timing counters, or the H2 opening probe.
The observer supplies the missing production input, but authenticated YUME
framing/ratchet overhead is intentionally reported in the outer WebSocket
geometry and may yield a truthful `DRIFT`; it is never rewritten into the
normal-Chrome aggregate. The current carrier also has no browser favicon stream,
and its server PING is triggered by the first decoded carrier data rather than
the reference workload's first complete application message. Those lifecycle
differences are retained and must produce `DRIFT`, not be repaired by capture-only
wire mutations. Gate B remains open
until five real YUME runs and five normal-Chrome runs are sealed into matched
same-session arms and accepted before external classifier/active-probe work.

## Known classifier-visible residuals

TLS remains the weakest classifier-visible layer, but the shape of that weakness
changed and the earlier description here was wrong. It claimed stock OpenSSL
could not be driven close to Chrome at all. Measured against OpenSSL 3.5.6, the
`openssl-diagnostic` backend now emits the captured browser's **exact non-GREASE
cipher list, in order**, its **exact signature algorithm list, in order**
(ML-DSA `0x0904`/`0x0905`/`0x0906` included — OpenSSL 3.5 emits all three), and
its **full extension set**. `0x0012`, `0x44cd` (ALPS) and `0xfe0d` (GREASE ECH)
are injected through `SSL_CTX_add_custom_ext`, which accepts any extension
number OpenSSL does not own internally; `0x0005` comes from
`SSL_CTX_set_tlsext_status_type`, which is required because `add_custom_ext`
refuses internally-owned numbers; and `0x0016`, which OpenSSL offers and the
browser does not, is suppressed with `SSL_OP_NO_ENCRYPT_THEN_MAC`.

Those three lists are what JA4 hashes, and the measured result is an exact
match against the committed capture:

```
capture JA4:  t13d1516h2_8daaf6152771_806a8c22fdea
native  JA4:  t13d1516h2_8daaf6152771_806a8c22fdea
```

`tests/test_yume_native_tls_wire.py` gates this on emitted bytes — it renders a
ClientHello through the production `StealthContext` and compares against the
fixture, rather than comparing configuration to configuration. Extension
*order* is deliberately not claimed: Chrome has permuted its own extension order
on every connection since v110, which is what broke JA3 as a Chrome
discriminator and motivated JA4's sorted, GREASE-excluding construction. There
is no stable order to match.

What stock OpenSSL still cannot do, and what patching its internals would be
required to fix: GREASE is absent from the cipher list, `supported_groups`,
`supported_versions` and `key_share`; both injected GREASE extensions land at
the front rather than first-and-last, because `add_custom_ext` prepends; and
`compress_certificate` advertises OpenSSL's zlib+zstd rather than the browser's
brotli. The two GREASE extension types are also fixed per `SSL_CTX` rather than
redrawn per connection, because `SSL_CTX_add_custom_ext` binds the extension
number at registration time; the starting point is drawn from the CSPRNG so the
values vary across installs and restarts, but one long-lived context reuses
them. JA4 excludes GREASE, so those do not move JA4 — but they are
real, they are visible to anything that inspects the raw ClientHello, and they
are why this backend is still not a parity claim. The exact gap is recorded in
`known_tls_divergence` in `config/transport_profiles.json` and re-derived from
emitted bytes by the same test, so it cannot widen unnoticed.

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
call YUME “quantum-proof,” “uncrackable,” or guaranteed future-proof: the
composite client identity still depends on its classical Ed25519 half as well
as ML-DSA-87, the public TLS certificate remains classical, the PSK is a
deployment secret, endpoint compromise exposes live plaintext/state, and the
complete construction has not received an independent formal proof or security
audit.

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
