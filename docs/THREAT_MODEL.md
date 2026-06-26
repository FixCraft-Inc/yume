# YUME threat model

This page states what YUME defends against, what it does not claim, and
where operator configuration matters. Read it alongside
`docs/PERMISSIONS.md` and `docs/STEALTH.md`.

## Actors

| Actor | Typical capability | What they can see without extra routing |
| --- | --- | --- |
| Path observer (ISP, Wi‑Fi, hotel gateway) | Passive or shallow DPI on the carrier | TLS metadata, timing, volume; with obfs enabled, cleartext bytes look like Chrome → CDN gRPC-web |
| Active prober | HTTPS probe to the same host:port | Real HTML facade when `--real` is configured; otherwise a closed or minimal response |
| YUME server operator | Runs `yumed`, holds TLS cert, sees auth keys | Authenticated client identity, requested targets, byte counts unless anonym mode strips logs |
| Client host | Runs `yume`, holds client private key | All local app traffic before it enters the carrier |
| Target site | Receives outbound TCP/UDP from server egress | Server IP (or Tor exit IP when server-side Tor is configured) |

YUME is a stealth transport and relay. It is not an anonymity system.
Tor, VPN overlays, or multi-hop federation change who sees what; they are
routing choices, not properties baked into the carrier alone.

## What the carrier protects

When inner crypto is negotiated (default on current builds):

- **Confidentiality and integrity** of multiplexed stream payloads via
  hybrid ML-KEM-768 key agreement and AES-256-GCM frame encryption.
- **Authentication** of the client to the server via Ed25519-signed
  handshake material bound to `authorized_keys`.
- **Forward secrecy within a session** when live key hopping is enabled
  (1–4 Hz rekey on the inner channel).
- **Stealth against many classifiers** via real TLS 1.3 with browser
  fingerprint profiles, optional HTTP/2 carrier camouflage, and optional
  HTTP disguise for non-YUME probes.

The outer TLS session is also real. A passive observer sees a normal
HTTPS connection shape, not a custom UDP or WireGuard signature.

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
- **Denial of service on the server** from unauthenticated peers when
  Argon2 heavy KDF is enabled — see below.

## Argon2 gate (DoS boundary)

Peers can advertise Argon2id KDF parameters on the wire. The server
**must** call `argon2_params_exceed_limits` before honoring them. Params
above the compiled limits are rejected; the handshake fails instead of
allocating multi-gigabyte memory for an unauthenticated remote.

Operators should keep default limits in production. Raising them is a
deliberate capacity decision, not a client convenience knob.

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
