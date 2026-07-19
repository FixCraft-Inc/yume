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
  timeout close, simultaneous rekeys, and old receiving-chain retirement.
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

## Required before `2.0-rc1`

- Run an actual desktop tunnel bidirectionally across multiple epochs and
  reconnect cleanly in the intended deployment environment.
- Complete external HTTP/2/WebSocket conformance checks, not only project tests
  and Chrome interoperability.
- Exercise partial socket writes, sustained flow-control stalls, malformed
  carrier paths, backend timeout/failure, and bounded backpressure under load.
- Enforce the 256 KiB / 512-frame / 500 ms thresholds independently on
  inbound epochs. Dev1 currently authenticates epoch/sequence transitions but
  relies on the sender to initiate each boundary on time.
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
