# YUME explained

YUME carries several local connections through one authenticated connection to
a YUME server. This page explains that path, the trust it creates, and the
common ways to route it.

YUME can make a connection look less like a custom tunnel and can move the
visible exit away from the client. It does not provide anonymity by itself.

## The basic route

```text
+--------------------------------+
|  APPLICATION                   |
|  browser, CLI, or service      |
+--------------------------------+
                |
                | SOCKS, forward, packet path, or C API
                v
+--------------------------------+
|  YUME CLIENT                   |
|  authenticates and multiplexes |
+--------------------------------+
                |
                | TLS 1.3 + HTTP/2 + WebSocket
                v
+--------------------------------+
|  YUMED SERVER                  |
|  checks policy and opens exits |
+--------------------------------+
                |
                | TCP or UDP
                v
+--------------------------------+
|  DESTINATION                   |
|  sees the server's exit IP     |
+--------------------------------+
```

The application connects to a local YUME entry point. Each application socket
becomes a logical stream. Opening another website or forward does not require a
new TLS connection or client login.

The daemon authenticates the client, checks its permissions, decrypts YUME
records, and opens the destination socket. The destination normally sees the
daemon's exit address. The daemon can see destination metadata and any payload
that is not protected by an application protocol such as HTTPS.

## What appears on the network

The outer connection is TLS 1.3 with an HTTP/2 and WebSocket carrier. A normal
browser request on the same listener is sent to a separate cover site on
loopback. A request must pass keyed admission before it can reach YUME
authentication.

The current profile comes from one committed browser and cover-server capture.
It centralizes the TLS choice, request headers, HTTP/2 settings, and cover
identity. Some behavior is still distinguishable, especially full
session timing and volume. Read [stealth transport](STEALTH.md) for the tested
scope and remaining residuals.

## Session security

AUTH v2 uses a composite Ed25519 and ML-DSA-87 client identity. Key
establishment combines ML-KEM-1024, X25519, a random pre-shared key, and the
TLS exporter. The session then uses independent send and receive epochs with a
one-use AES-256-GCM key for each message.

Rekey policies change how much data or active time one epoch can cover. They do
not remove the hybrid algorithms or per-message keys. See
[security modes](SECURITY_MODES.md).

The admission secret and inner pre-shared key solve different problems. Both
are required for the current public-node mode and both must be distributed out
of band.

## Routing choices

### Direct

The client connects directly to `yumed`, and `yumed` connects directly to the
destination. This has the fewest network hops. The client's network sees a
connection to the YUME server. The destination sees the YUME server.

### Outer proxy or Tor

The client can reach `yumed` through a SOCKS5 proxy or Tor:

```text
application -> yume -> SOCKS/Tor -> yumed -> destination
```

Hostnames are sent to the proxy as domain names, so an onion address or remote
DNS lookup does not need a direct client-side query. The proxy can see that the
client connected to the YUME server. The YUME server still terminates the
YUME session and sees its exit traffic.

### Server-side egress

An operator can route the daemon's outbound sockets through a separate egress
network:

```text
application -> yume -> yumed -> Tor or VPN -> destination
```

This changes which IP address the destination sees. It does not hide the
destination from `yumed`, because the daemon chooses and opens that connection.
The operator is responsible for making sure DNS and fallback routes use the
same egress policy.

### Federation

YUME servers can exchange a directory and relay eligible channels across a
direct authenticated federation link. The implemented boundary is one hop.
The three-node regression intentionally proves that a far endpoint is not
routable through the middle node.

Multi-hop relay-channel transit has a public design document, but it is not an
implemented feature. Exit traffic such as SOCKS, forwarding, and packet routing
remains local to the terminating daemon. See the
[federation transit design](protocol/YUME_2_0_FEDERATION_TRANSIT.md).

## Local entry points

The command-line client supports SOCKS, local and reverse forwards, attached
commands, packet paths, services, and application codecs. Availability depends
on the client key's permissions and the selected build. The stable C ABI offers
the same in-process client runtime to native applications.

The optional desktop GUI uses that shared runtime. It is a development preview,
not a separate transport implementation. The Android application and browser
are separate repositories and are not qualified by the native Linux build.

## Decide what to trust

Before choosing a route, answer these questions:

1. Who may learn the client's network address?
2. Who may learn the destination?
3. Is the application payload protected end to end?
4. Which component can fall back to a direct route?
5. Which keys and shared secrets must be distributed or stored?

Use the [threat model](THREAT_MODEL.md) for attacker-specific analysis and the
[operations guide](OPERATIONS.md) for deployment controls. The
[implementation status](IMPLEMENTATION_STATUS.md) lists unqualified paths and
open release gates.
