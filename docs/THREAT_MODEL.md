# YUME threat model

This page states what YUME defends against, what it does not claim, and
where operator configuration matters. Read it alongside
`docs/PERMISSIONS.md` and `docs/STEALTH.md`.

## Actors

| Actor | Typical capability | What they can see without extra routing |
| --- | --- | --- |
| Path observer (ISP, Wi‑Fi, hotel gateway) | Passive or shallow DPI on the carrier | TLS ClientHello/server metadata, encrypted-record sizes, timing, and volume; the HTTP/2 opening is encrypted inside TLS |
| Active prober | HTTPS probe to the same host:port | Real HTML facade when `--real` is configured, or a coherent static site under `--real-root <dir>` (correct MIME/`ETag`/`Last-Modified`, one identity across HTTP/1.1 and the H2 decoy); otherwise a synthetic profile-driven response (`yumed` by default, `nginx` under `--public-node`) |
| YUME server operator | Runs `yumed`, holds TLS cert, sees auth keys | Authenticated client identity, requested targets, byte counts unless anonym mode strips logs |
| Client host | Runs `yume`, holds client private key | All local app traffic before it enters the carrier |
| Target site | Receives outbound TCP/UDP from server egress | Server IP (or Tor exit IP when server-side Tor is configured) |

YUME is a stealth transport and relay. It is not an anonymity system.
Tor, VPN overlays, or multi-hop federation change who sees what; they are
routing choices, not properties baked into the carrier alone.

## What the carrier protects

When inner crypto is negotiated and a deployment PQ key is configured or
securely bootstrapped (enabled by default in full builds, but only mandatory
when the server uses `--inner-required`):

- **Confidentiality and integrity** of multiplexed stream payloads via
  ML-KEM-768-derived keys and AES-256-GCM frame encryption.
- **Authentication** of the client to the server via Ed25519-signed
  handshake material bound to `authorized_keys`.
- **Per-window key separation** when live key hopping is enabled (1–4 Hz
  derivation on the inner channel). This is not forward secrecy: the retained
  base key can derive every hop key.
- **Masquerade against simple active probes** via keyed HTTP/2 carrier
  admission and complete benign responses for missing, malformed, or wrong
  tokens, plus optional HTTP disguise for ordinary non-YUME probes.
- **Passive feature reduction** via browser-oriented TLS presets and optional
  padding/jitter. These are mimicry layers, not ML/DPI immunity claims.

The outer TLS session is real TLS 1.3 and avoids a custom UDP/WireGuard
handshake signature. Browser-profile shaping is partial; it should not be
treated as proof that every observer sees a byte-identical browser connection.
The HTTP/2 opening uses valid frame/HPACK ordering in focused project tests,
but the authenticated stream is not a full-session HTTP/2 tunnel and the
opening has not yet been certified against a version-pinned external browser
or conformance suite. Synthetic nginx/Apache/etc. templates are not native
server implementations.

## What YUME does not protect

- **Hiding the target from the server operator** on a direct route. The
  client sends `OPEN` requests with host/port (or packet batches with
  destination metadata). Server-side Tor egress changes what the target
  sees, not what `yumed` learns.
- **Client-side leaks outside the tunnel.** SOCKS-aware apps can still
  bypass a local proxy. See `docs/LEAK_TIGHT.md`.
- **Endpoint compromise.** A rooted client or server defeats transport
  crypto. YUME does not harden the host OS.
- **Traffic-analysis resistance.** Packet sizes and timing are not padded
  to constant rate by default. `--obfs-pad-multiple` and jitter exist on
  the client but are opt-in and peer-dependent.
- **Denial of service on the server.** Argon2 admission, session caps, service
  queue caps, and close deadlines bound specific resources; they do not make
  authorized or explicitly preauth-enabled peers harmless.

## Masquerade admission boundary

With obfs enabled, yumed does not emit YUME `AUTH` for a raw frame-looking
prefix, a partial prefix that times out, a malformed HTTP/2 request, an
authority/SNI/listener-port mismatch, a missing server-SETTINGS ACK, or a wrong
keyed token. These paths stay outside AUTH. The successful opening is server
`SETTINGS`, ACK of the client settings, bodyless accepted response headers; the
client ACKs the server settings before the transport switches to YUME framing.

`--public-node` requires obfs plus a nonempty `--obfs-secret`. An empty secret
is retained only for non-public development and performs a structural path
check, not authentication. The hourly token verifier accepts a +/-1-hour
window and does not store nonce reuse, so a captured valid path can be replayed
within an accepted window to reach the separate Ed25519 challenge. It cannot
authenticate or decrypt the inner channel by itself.

## Argon2 gate (DoS boundary)

After signature/key authorization (or admission to an explicitly configured
preauth service lane), peers can advertise Argon2id KDF parameters on the wire. The server
**must** call `argon2_params_exceed_limits` before honoring them. Params
above the compiled limits are rejected; the handshake fails instead of
allocating multi-gigabyte memory from a peer-controlled request.

The default per-derivation memory ceiling is 512 MiB. Positive
`YUME_ARGON2_*_MAX` values can deliberately lower or raise the corresponding
time, memory, and parallelism ceilings; invalid or zero values retain the
compiled defaults.

Before Argon2 allocation, the server also acquires a manager-owned RAII
reservation. By default, all concurrent authorized/preauth handshakes share a
512 MiB aggregate budget and at most four admitted Argon2 jobs. Operators can
set lower or higher positive values with `--argon2-memory-budget-kib` and
`--argon2-max-jobs` (or the matching JSON fields). Requests that cannot reserve
both limits fail immediately, and every success, exception, cancellation, or
early return releases its reservation. These controls bound admitted Argon2
work; they do not make compromised authorized keys or intentionally enabled
preauth lanes harmless, and connection/session caps remain separate controls.

## Preauth service boundary and queue limits

A self-signed Ed25519 key admitted by `preauth_services` is persisted as
`PreauthServiceOnly`. A central dispatcher gate permits only named
`service.v1` OPEN, DATA/CLOSE on accepted service streams, and PING/PONG.
It cannot enter control, relay/admin, generic egress, codec, benchmark, or
packet paths. Pending service opens are capped at 64 per service and 256 total;
the limits bound queue ownership but are not a substitute for application-level
rate limits inside the registered service implementation.

## Dangerous features and permission gates

Server-side command execution, LAN/private-IP bridging, unrestricted
address bridging, and privileged application codecs are gated by **all
three** of:

1. Compile-time feature switches (`YUME_FEATURE_EXEC`, `_LAN_BRIDGE`,
   `_FULL_CONTROL`).
2. Server runtime flags (`--allow-exec`, `--allow-local-ip`,
   `--control-full`, `--codec-allow`).
3. Per-key entries in `auth_keys.meta`.

Stock builds ship with compile-time gates OFF. A mis-set server flag
cannot grant `allow_exec` to a key whose metadata denies it.

Application codecs (`monero-rpc-v1`, future registry entries) are **not**
raw TCP forwards. They parse local app protocols, carry typed envelopes
over normal `DATA` frames, and reconstruct only to a narrow loopback
backend on the server. Grant them with `allow_codecs`, not
`allow_local_ip`.

Relayed admin attach is directional: the caller must be a trusted relay with
server-capped plus runtime `allow_outbound_admin`, and the target must have
server-capped plus runtime `allow_inbound_admin`. The legacy attach form uses
the same predicate and also requires the target's `--server-in-charge` opt-in.
For federation, the source server enforces the caller half and the target
server enforces the target half; the current wire trusts the authenticated
source server rather than carrying a separate caller-policy proof.

## Lifetime and concurrency bounds

Session shutdown has a five-second whole-close deadline, pending named
service queues are bounded as above, and client EXEC dispatch admits at most
four concurrent workers. Sensitive byte buffers are best-effort overwritten
before release on the principal shutdown paths. This is not a locked allocator
or a guarantee that prior copies were erased, and detached EXEC workers are
bounded but are not yet cancellable/joined during shutdown. These changes have
focused build/unit coverage; sanitizer and long-running race/soak validation
remain outstanding.

## Anonym mode limits

`--anonym` on the server reduces identifying log fields where supported.
It does not erase in-memory session state while connections are active,
does not stop the operator from patching the binary, and does not remove
the server's ability to open outbound sockets for authorized clients.

Client-side `--require-anonym` refuses servers that do not advertise
anonym support; verify the deployment policy out of band.

## Trust summary

| Route | Client ISP sees | Server operator sees | Target sees |
| --- | --- | --- | --- |
| Direct YUME | YUME server as HTTPS peer | Client key + targets | Server egress IP |
| Client Tor → YUME | Tor entry path | Tor circuit metadata only if Tor fails; else same as direct from server's view of the SOCKS hop | Server egress IP |
| Server Tor egress | YUME server as HTTPS peer | Targets (unless client only opens local Tor ports) | Tor exit IP |
| Federated cluster | Entry peer as HTTPS peer | Entry peer policy; remote peer sees forwarded metadata per federation rules | Final egress peer's IP |

Pick the route to match who must not learn which fact. The transport
stack stays the same; the trust boundary moves with routing.
