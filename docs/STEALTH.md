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

Both HTTP/2 roles use manual receive credit for the carrier stream. WebSocket
framing and control bytes are credited immediately, while decoded tunnel bytes
retain their matching credit until the owning downstream path reports them
consumed. Ordinary cover-response DATA is credited immediately because it has
no tunnel sink. This changes credit ownership, not the captured HTTP/2 SETTINGS
or normal opening wire.

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

Unauthenticated H2 cover work also has lifetime admission: at most four
GET/HEAD streams per public connection and 32 across the process may own a
backend fetch or flow-controlled cover response. With the 8-MiB body limit,
that bounds this response state to 32 MiB per connection and 256 MiB
process-wide; the carrier's separate 32-MiB output ceiling still applies. Bytes
already serialized out of the carrier retain a second 32-MiB-per-connection,
256-MiB-process-wide budget until their TLS write completes, so repeated
WINDOW_UPDATE/RST cycles cannot bypass the carrier cap through its downstream
write queue. Backend/response state and already-serialized wire can coexist for
different requests, making the conservative combined maxima 64 MiB per
connection and 512 MiB process-wide before protocol/TLS overhead.
Overload uses retryable H2 `REFUSED_STREAM` rather than allocating another
response. `RST_STREAM` and connection shutdown cancel the loopback operation
and release admission before its late callback can respond. These are
availability bounds, not proof of normal-cover parity during overload.

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
exact capture mode, seals per-run and top-level checksums, snapshots its
client-side runtime inputs, and writes `complete.json` only after all runs
verify:

```bash
tools/cover-node/capture_yume151_runs.sh \
  /private/session/yume-arm \
  /exact/build/bin/yume \
  /private/session/release/yume-amd64-linux.tar.xz \
  /private/session/yume-client.json \
  /private/session/server.crt \
  cover.example \
  127.0.0.1:443 \
  /exact/chrome/google-chrome \
  /exact/chrome/chrome \
  /exact/node-v24.18.0/bin/node \
  5
```

The target must be reachable from the loopback-only capture namespace (run the
campaign `yumed` inside that namespace), terminate with the supplied
certificate, and use the campaign's external admission/inner credentials. The
runner records the config hash but never copies it or any referenced secret. It separately records
the certificate PEM-file checksum and passes the X.509 DER leaf fingerprint as
the TLS pin. It fails closed unless the YUME binary, exact
Chrome launcher/binary, exact Node binary, source commit/tree, certificate,
client-side runtime snapshot, and user-namespace capability remain unchanged. The supplied
client must byte-match the validated prepared Linux bundle, whose manifest must
name the clean capture source commit. The runner selects the in-process
`openssl-chrome151` backend and never launches the helper. The current release
bundle validator still expects the separately optional comparison-helper
artifact to be present in the bundle. The direct
CLI flag is intentionally incompatible with SOCKS/forwarding, packet-TUN,
proxy, multi-tunnel, full-benchmark, padding, and jitter modes.

This arm does not yet attest the target `yumed` binary, its configuration, or
the production Node backend it launches. Seal those server-side identities in a
separate campaign attestation before treating the pair as matched same-server
classifier evidence; until then this artifact proves only the client-side arm.
Each YUME process is bounded by a 180-second deadline and a 16-MiB log limit.

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

There are now two deliberately separate native OpenSSL contracts:

- `openssl-diagnostic` is the stock/default-off negative control. It retains
  the measured two-of-six result below and must not change when linked to the
  patched library. This protects BaseFWX and every unconfigured `SSL_CTX`.
- `openssl-chrome151` is the normal client selection. It enables YUME's
  additive patch on the checksum-pinned OpenSSL 3.5.7 tree through
  `SSL_CTX_ctrl`. It fails closed if that capability or Brotli is absent. The
  patch emits independent per-connection cipher/group/version/extension
  GREASE (with the group value shared by `supported_groups` and `key_share`),
  brackets a shuffled middle block with distinct GREASE extensions, shuffles
  custom SCT/ALPS/ECH blocks together with built-ins, and emits only
  uncompressed EC point format. Padding and PSK are excluded from the shuffle
  and constructed on the final packet, preserving length and binder semantics.

The positive wire gate renders 12 fresh SSL objects from one long-lived
context and checks the six rows, GREASE value relationships, custom-extension
interleaving, varying JA3 order, and exact JA4. This is a ClientHello structure
gate, not proof that an entire YUME session is indistinguishable from Chrome.

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

Those three lists, and only those three lists, are what JA4 hashes — so the
measured result is an exact JA4 match against the committed capture, and an
exact match on nothing wider than that:

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

**Matching JA4 is not matching the ClientHello, and the difference is not
academic.** JA4 hashes three sorted, GREASE-excluding lists. Everything else in
the first flight is outside what it can see, and measured against the same
capture the following are all still different on the wire:

| Residual | Capture | `openssl-diagnostic` | |
| --- | --- | --- | --- |
| GREASE in `cipher_suites` / `supported_groups` / `supported_versions` / `key_share` | present | absent | open |
| GREASE extension placement | first and last | both at the front — `add_custom_ext` prepends | open |
| Extension emission order | permuted per connection | fixed | open |
| `ec_point_formats` (`0x000b`) | `[0]` | `[0, 1, 2]` | open |
| `key_share` entries | GREASE, `0x11ec` (1216 B), `0x001d` (32 B) | GREASE absent; both real shares offered | **closed** |
| `compress_certificate` (`0x001b`) | one algorithm, 3-byte body | brotli alone, 3-byte body | **closed\*** |

For the stock `openssl-diagnostic` control, two rows are closed and the other
four are unreachable without patching OpenSSL. Each verdict below was probed
against the library rather than reasoned about:

- **`key_share` — closed.** `SSL_CTX_set1_groups_list` emits a share for every
  group whose name carries a `*` prefix.
  `openssl_selection.key_share_groups` now names both real groups, which grew
  the extension body from 1222 to 1258 bytes. The capture is 1263; the
  remaining five bytes are the GREASE share, which stock OpenSSL cannot
  express.
- **`compress_certificate` — closed\*, and build-dependent.** This is a
  build-flag limit, not an API limit: `SSL_CTX_set1_cert_comp_preference`
  returns 0 for brotli and 1 for zstd on a `-DZLIB -DZSTD` build.
  `scripts/ensure-openssl.sh` now configures `enable-brotli`, and against such
  a build the backend emits `020002` — brotli alone, a 3-byte body, exactly the
  length the capture records. The diagnostic backend records a visible
  degradation when Brotli is absent; `openssl-chrome151` refuses to start, and
  the patched source build fails closed without the Brotli development files.

  \* The asterisk is real. The committed fixture records only the *length* of
  `0x001b`, not the algorithm value, so "brotli" comes from Chrome's documented
  behaviour rather than our own capture. **Recapture the value before treating
  this row as genuinely matched.**
- **GREASE code points — rejected by the API.** `SSL_CTX_set1_groups_list`
  returns 0 for `0x0a0a`, `GREASE`, `0x2a2a` and any other unnamed code point,
  and `SSL_CTX_set_cipher_list` / `SSL_CTX_set_ciphersuites` likewise refuse
  one. OpenSSL will not carry a code point it does not implement, which is what
  makes GREASE in the cipher list, `supported_groups`, `supported_versions` and
  `key_share` unreachable.
- **GREASE extension placement — structurally impossible.** Registering two
  custom extensions emits both at the very front; the last extension is always
  an OpenSSL built-in. A custom extension cannot be last, so the browser's
  first-and-last GREASE pair cannot be built.
- **Extension order — no setter exists.** OpenSSL has
  `SSL_client_hello_get_extension_order`, a server-side getter for inspecting
  someone else's hello. There is no client-side ordering control, and therefore
  no way to permute per connection the way Chrome has since v110.
- **`ec_point_formats` — no setter exists.** Only `SSL_CTRL_GET_EC_POINT_FORMATS`
  is defined; every context tested emitted `[0, 1, 2]`.

The two GREASE extension types are likewise fixed per `SSL_CTX` rather than
redrawn per connection, because `SSL_CTX_add_custom_ext` binds the extension
number at registration time; the starting point is drawn from the CSPRNG so the
values vary across installs and restarts, but one long-lived context reuses
them.

So the honest stock bound remains: **stock OpenSSL closes two of six.** The
new default-off patch implements the other four for `openssl-chrome151`; it
does not rewrite or relax this negative control.

**JA3 does not match, and the way it fails is worse than a mismatch.** JA3
preserves extension emission order and hashes `ec_point_formats`, so this
backend produces a stable
`771,…,18-17613-65037-65281-0-11-10-35-5-16-23-13-43-45-51-27,…,0-1-2` string
that is not any Chrome ordering. Because the order is fixed, that JA3 is
*constant across every connection this backend makes*, where a real Chrome
client emits a fresh JA3 each time. A stable Chrome-labelled JA3 is a signal in
its own right, not a step toward parity. Do not report JA3 agreement as
evidence for this backend, and do not report the JA4 match as byte parity: the
two claims are not the same size.

The exact stock gap is recorded in `known_tls_divergence` in
`config/transport_profiles.json`. `tests/test_yume_native_tls_wire.py`
re-derives every diagnostic row from emitted bytes, then separately gates the
patched backend across multiple SSL objects sharing one context.

The legacy Linux `chrome151` backend isolates pinned uTLS `v1.8.2` in a
per-connection helper built with exact Go `1.26.5`. The C++ parent establishes
the routed TCP socket, the helper emits the custom Chrome 151 first flight and
returns authenticated certificate metadata plus the mandatory TLS exporter
over a private socketpair. It is implemented but no longer the default:
five-run normalized on-wire parity and the local handshake/throughput gates now
pass. The bounded negative certificate/exporter and process-lifecycle matrix,
process ramps, reconnect storm, and segmented full-speed loopback soak also
pass. Matched WAN, one uninterrupted deployed-network soak, exact-Chrome
same-session capture, classifier/active-probe evidence, and independent review
remain incomplete.

The Go helper is therefore **retained as temporary qualification evidence**,
but normal runtime selects `openssl-chrome151` and does not launch it. Existing
helper results do not qualify the replacement. Remove the helper only after the
native backend passes complete handshake/transcript, certificate, hostname,
pin, ALPN, 32-byte exporter, cancellation, reconnect storm, resumed/PSK
ordering, soak, sanitizer, reproducible-build, same-session, classifier, and
independent-review gates. Removal must update the registry, generated
consumers, tests, packaging, capture tools, and evidence together.

Each helper connection currently creates fresh uTLS state without a session
cache, so reconnects always exercise a full TLS 1.3 handshake. The committed
fixture and present structural gate cover that fresh-session arm only; ordinary
Chrome also uses resumed/PSK handshakes. Add explicit reconnect/resumption
classifier arms, or design persistent ticket state and requalify exporter,
pinning, process lifecycle, and failure behavior before claiming that population.
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
   insufficient. Separately, the native `openssl-chrome151` byte gate closes
   all six pinned ClientHello structure rows across 12 SSL objects sharing one
   context. That native gate has not inherited the helper's handshake,
   exporter, validation, lifecycle, reconnect, soak, or reproducibility
   evidence; those remain open.
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

For the classifier gate, a packet-random train/test split is invalid because
packets from one session share the same network and implementation artifacts.
Group by complete session and hold out capture day, client/server host, network
and provider. Use multiple classifier families and an untouched final set;
freeze feature extraction, overhead budget and acceptance thresholds before
examining candidate labels. Report sample counts, confidence intervals,
ROC-AUC, PR-AUC and true-positive rate at operationally low false-positive
rates, alongside a matched real-Chrome baseline and simple metadata-only
baselines. Active-probe success/failure and response shape are part of the same
evidence, not a separate marketing claim.

No finite capture campaign can prove that a future DPI or neural classifier
“cannot learn YUME.” An observer can also classify endpoint/IP reputation,
certificate reuse, connection timing and transferred volume even when the TLS
and H2 bytes are excellent. The defensible target is a pre-declared, low
measured distinguishing advantage against a named cover distribution under
held-out conditions, plus an honest list of residual features.

Changing the TLS stack, adding padding, or changing wire fields is not complete
until these gates have repeatable artifacts. Any TLS-stack migration must also
preserve certificate validation, pinning, ALPN, error handling, packaging, and
sanitizer/build coverage.

Likewise, do not introduce a generic “randomish millisecond” cadence. If a
captured cover workload supports early rotation or timing shaping, use a
bounded versioned distribution derived from that capture, retain the hard
ratchet maxima, and require a held-out classifier improvement. Independent
per-host jitter or uniform random delay is an implementation feature a model
can learn, not evidence of camouflage.

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
