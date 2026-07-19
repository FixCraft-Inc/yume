# YUME 2.0 desktop stealth transport

This document covers only the first YUME 2.0 Linux desktop slice. The fixed
cover stack is a Chrome-shaped `yume` client, a public `yumed` TLS/HTTP/2
endpoint, and a separately supervised Node.js process on loopback. Android,
nginx, alternate browser profiles, HTTP/3, and the retired 1.x carriers are
outside this slice.

## Fixed identity

- Client fixture: Chrome `150.0.7871.114` on Debian 13.
- Cover server fixture: Node.js `24.18.x` LTS HTTP/2.
- TLS: TLS 1.3 with ALPN `h2`; `--profile chrome` is mandatory.
- Public endpoint: `yumed`; Node is never exposed directly.
- Cover backend: `loopback://<IP-literal>:<port>` only.

The sanitized capture and version manifest are committed under
`tests/fixtures/chrome150-node24/`. They, rather than invented timing or frame
constants, define the first profile.

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

## What this helps against

- Custom-protocol signatures after TLS: the whole session remains H2/WebSocket.
- Casual active probing: non-admitted traffic sees the real Node site or its
  captured rejection path.
- Replay of captured carrier URLs: admission nonces are cached until expiry.
- Long-lived inner-key compromise: independent directions rekey before crossing
  256 KiB, 512 encrypted data frames, or 500 ms of active epoch time.

These are reductions in distinguishability and compromise radius, not claims of
anonymity or immunity to statistical traffic analysis.

## Known TLS residual

TLS is the weakest classifier-visible layer. Stock OpenSSL cannot reproduce
Chrome 150 ClientHello extension and GREASE ordering byte-for-byte. A censor can
therefore distinguish YUME before inspecting HTTP/2 even when ALPN, suites,
groups, signatures, and a coarse JA4 classification align.

The release must document this residual and must not call the connection
“TLS-indistinguishable from Chrome.” BoringSSL is the likely follow-up if exact
capture comparison shows that the residual is unacceptable.

## Release evidence

The exact wire contract is in `docs/protocol/YUME_2_0_WIRE.md`. Current evidence
and remaining gates are in `docs/YUME_2_0_IMPLEMENTATION_STATUS.md`. The version
must remain a development/RC label until external H2 conformance, a 30-minute
tunnel, WAN/soak validation, and the stated throughput/overhead gates pass.
