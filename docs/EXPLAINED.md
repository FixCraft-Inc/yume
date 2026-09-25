<!-- Generated from docs/src/en_US/pages/explained.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# YUME explained

YUME is two programs. `yume` runs on your device and collects traffic from your
applications. `yumed` runs on a server you control. The traffic travels between
them inside one long-lived connection that looks like a browser visiting a
website. The server authenticates the client, checks what it may reach, makes
the real connection and sends the answer back the same way.

```text
app --SOCKS5 or TUN--> yume ==TLS 1.3 + HTTP/2==> yumed front door
                                                      |
                                   valid admission?  no --> cover website
                                                      | yes
                                           YTP/1 session (authenticated)
                                                      |
                                           policy check --> destination
```

This page describes the default programs, which speak YTP/1 (YUME Transport
Protocol 1). The [glossary](GLOSSARY.md) defines the terms, and the
[YTP/1 reference](protocol/YTP_1.md) has the exact wire format.

## Setting up

`yume-setup init` writes a server directory and a client bundle. Each side gets
a composite identity, an Ed25519 key paired with an ML-DSA-87 key. The server
also gets an ML-KEM-1024 key, a TLS certificate and a 32-byte admission key.
Each client gets its own access PSK. The client bundle carries the server's
public keys, so the client knows exactly which server it must reach.
`add-client` issues more bundles for the same server.

## How a connection opens

1. `yume` opens TCP to the server. A server name is looked up in a small
   helper process, so a hung DNS lookup never blocks shutdown.
2. It starts TLS 1.3 with the ClientHello of a pinned Chrome release and asks
   for HTTP/2, the way that browser would.
3. Over HTTP/2 it first requests the site's page with that browser's headers,
   then sends an extended CONNECT request carrying an admission proof. The proof is
   derived from the admission key and bound to this TLS connection, so it
   cannot be replayed on another one.
4. `yumed` checks the proof. Anything without a valid proof, including a
   scanner or a curious visitor, gets the static website and nothing else. A
   valid proof turns that HTTP/2 stream into the YUME carrier. One TLS
   connection can be promoted once.
5. Inside the carrier both sides run YTP/1 authentication, described next.

## Keys

Authentication proves both identities with both signature algorithms. Key
establishment combines X25519, ML-KEM-1024, the client's access PSK and a
secret exported from the live TLS connection. Breaking one of these is not
enough. The transcript binds the suite, both identities, both service lists and
the security parameters, so neither side can be talked into a weaker setup.
There is one suite and no negotiation or fallback.

After authentication every record is sealed with AES-256-GCM under a key that
is used once. Each direction has its own key epoch and rotates it on its own
after one MiB of data, 512 records or 500 ms, whichever comes first.

## Streams and policy

The client opens streams by service name, `tcp` or `udp` in a default kit, and
names a destination when the service routes to one. Stream numbers are 31-bit,
odd for the client and even for the server. Every stream and the connection as
a whole have flow credit, so a slow reader cannot make the other side buffer
without limit. UDP and TUN traffic travel as whole packets.

For each open, `yumed` checks that the client's identity is granted the
service, that the destination is inside the adapter's configured networks, and
that every address a destination name resolves to is allowed, before it opens a
socket. A refusal closes that stream only. The operator lists clients in
`authorized-keys.json`, can limit how many sessions each may hold, and applies
changes with a reload that ends revoked clients' sessions.

If the connection drops, `yume` reconnects with backoff and its SOCKS5
listener and TUN routes stay in place.

## Embedding

Applications can embed the same endpoint through the [C ABI](ABI.md): named
byte streams, packet channels and routed TCP/UDP, with the application
deciding where traffic comes from. The ABI is experimental and not yet frozen.

## What stays visible

| Who | Still sees |
| --- | --- |
| A network observer | The server's IP address, the TLS ClientHello including the site name, and the timing, sizes, duration and volume of encrypted traffic |
| The server operator | Authenticated client identities, requested destinations, and any bytes the application did not encrypt itself |
| The hosting provider | The server's outbound connections |
| The destination | The server's address and the application's own traffic |

`yumed` is a single-hop proxy that ends the tunnel. Use TLS inside the tunnel,
as browsers do, to keep content private from the server. YUME cannot help when
the server's address itself is blocked, and it makes no claim to be
undetectable. The [threat model](THREAT_MODEL.md) and
[stealth transport](STEALTH.md) cover these limits.

## Where to start reading

| Question | Start at |
| --- | --- |
| How do the programs start? | `src/runtime/yume_main.cpp`, `src/runtime/native_cli.cpp` |
| How does a client keep its session? | `src/runtime/native_client_runtime.cpp`, `src/runtime/native_endpoint.cpp` |
| How are streams, records and keys handled? | `src/engine/session_engine.cpp`, `src/providers/ytp1_security_provider.cpp` |
| What does the server show a visitor? | `src/providers/ytp1_front_door.cpp`, `src/providers/ytp1_cover_site.cpp` |
| How does the TLS look like Chrome? | `src/providers/ytp1_tls13_secure_channel.cpp`, [transport profiles](TRANSPORT_PROFILES.md) |
| Which folder owns what? | [Source map](SOURCE_MAP.md) |
| What works today? | [Implementation status](IMPLEMENTATION_STATUS.md) |
