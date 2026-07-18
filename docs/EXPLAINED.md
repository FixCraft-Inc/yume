# YUME Explained

This document explains how YUME traffic is carried, where it can be
routed, and what each protection layer does. The diagrams are plain ASCII
so they can be reused in `man yume`.

YUME is a stealth transport and relay. It does not provide anonymity by
itself. The route you choose decides who can see the client, who can see
the target, and how much trust is placed in the YUME server.

## Diagram Style

Every diagram uses the same fixed-width box shape. The format is stable
in terminals, Markdown, and man pages.

```text
+--------------------------------+
|  PROCESS                       |
|  detail                        |
+--------------------------------+

--->   local or normal outbound traffic
===>   YUME carrier: TLS 1.3, optional HTTP/2 obfs, YUME frames
...>   external anonymity or egress network, such as Tor or VPN
```

## Basic Mental Model

Most YUME sessions have four visible parts:

```text
+--------------------------------+
|  HUMAN APP                     |
|  browser / curl / game         |
+--------------------------------+
        |
        | local SOCKS, --run, forward, or VPN capture
        v
+--------------------------------+
|  YUME CLIENT                   |
|  authenticates and frames      |
+--------------------------------+
        |
        | YUME carrier over public internet
        v
+--------------------------------+
|  YUMED SERVER                  |
|  opens target sockets          |
+--------------------------------+
        |
        | outbound TCP/UDP
        v
+--------------------------------+
|  TARGET SITE                   |
|  website / API / service       |
+--------------------------------+
```

The local program talks to the YUME client through SOCKS, a local
forward, `--run`, or an Android VPN capture path. The YUME client turns
that traffic into authenticated YUME streams and sends them through one
long-lived encrypted carrier to `yumed`.

The server receives an `OPEN` request for a target, opens the outbound
connection, then moves bytes in both directions until either side closes.
The target normally sees the YUME server's egress IP address.

## Typical Direct Route

This is the default shape for SOCKS, local forward, `--run`, and Android
VPN mode.

```text
+--------------------------------+
|  HUMAN APP                     |
|  browser / curl                |
+--------------------------------+
        |
        v
+--------------------------------+
|  YUME CLIENT                   |
|  TLS / H2 / YUME frames        |
+--------------------------------+
        |
        | ==YUME==>
        v
+--------------------------------+
|  YUMED SERVER                  |
|  direct egress                 |
+--------------------------------+
        |
        v
+--------------------------------+
|  TARGET SITE                   |
|  sees server IP                |
+--------------------------------+
```

What observers normally see:

- Client LAN / ISP: the client connects to the YUME server over
  HTTPS-looking traffic.
- Target site: the YUME server's IP address.
- Server network / hosting provider: the server connects to the target.
- YUME server process: authenticated client, requested targets, and
  relayed byte counts unless anonym/log policy removes them.

This route is fastest because it has one YUME carrier and one server
egress connection. It gives stealth against many network classifiers, but
it still trusts the YUME server with target metadata.

## Connection Lifecycle

The high-level handshake looks like this:

```text
yume client                         yumed server                         target
     |                                    |                                  |
     |-- TCP connect + TLS 1.3 ---------->|                                  |
     |-- HTTP/2 obfs preface + HEADERS -->|                                  |
     |<------------ SETTINGS + 200 -------|                                  |
     |<------------ AUTH challenge -------|                                  |
     |-- signed AUTH + inner setup ------>|                                  |
     |<-- server info, caps, proof -------|                                  |
     |                                    |                                  |
     |-- OPEN stream 7 example.com:443 -->|-- connect example.com:443 ------>|
     |-- DATA stream 7 ------------------>|-- bytes ------------------------>|
     |<------------------ DATA stream 7 --|<------------------------ bytes --|
     |-- CLOSE stream 7 ----------------->|-- close ------------------------>|
```

The carrier can stay open while many streams come and go. A new website,
TCP connection, or forwarded socket becomes a new YUME stream, not a new
TLS login.

## YUME Frame Flow

Inside the carrier, YUME multiplexes streams:

```text
+----------------------------------------------------------------------+
|  ONE AUTHENTICATED CARRIER                                           |
|                                                                      |
|  stream 1  OPEN ifconfig.me:80  -> DATA -> DATA <- CLOSE             |
|  stream 2  OPEN 1.1.1.1:443   -> app TLS bytes <-> target bytes      |
|  stream 3  OPEN api.site:443  -> another independent connection      |
+----------------------------------------------------------------------+
```

The TCP/TLS connection between `yume` and `yumed` is the carrier. The
application connections are independent logical streams inside it.

## Android Routes

On Android, apps usually do not speak SOCKS directly. YUME captures app
traffic through Android `VpnService`, then hands the captured packets to
one of the routing backends.

```text
+--------------------------------+
|  ANDROID APP                   |
|  Chrome / Termux / apps        |
+--------------------------------+
        |
        v
+--------------------------------+
|  VPNSERVICE TUN                |
|  packets + DNS mapping         |
+--------------------------------+
        |
        v
+--------------------------------+
|  ROUTE BACKEND                 |
|  tun2socks or native direct    |
+--------------------------------+
        |
        | ==YUME==>
        v
+--------------------------------+
|  YUMED SERVER                  |
|  target relay                  |
+--------------------------------+
```

In tun2socks mode, the backend behaves like a small TCP/IP stack that
connects to the local YUME SOCKS gateway. In native direct mode, the
Android path tries to turn captured flows directly into YUME streams with
less Java and SOCKS overhead.

## Server-Side Tor Egress

The server can send its outbound traffic through Tor, optionally through
obfs4 bridges.

```text
+--------------------------------+
|  HUMAN APP                     |
|  normal app                    |
+--------------------------------+
        |
        v
+--------------------------------+
|  YUME CLIENT                   |
|  YUME carrier                  |
+--------------------------------+
        |
        | ==YUME==>
        v
+--------------------------------+
|  YUMED SERVER                  |
|  receives target request       |
+--------------------------------+
        |
        v
+--------------------------------+
|  SERVER TOR                    |
|  SOCKS / transparent route     |
+--------------------------------+
        |
        | ...>
        v
+--------------------------------+
|  TOR ENTRY                     |
|  obfs4 bridge or guard         |
+--------------------------------+
        |
        v
+--------------------------------+
|  TOR MIDDLE                    |
|  relay nodes                   |
+--------------------------------+
        |
        v
+--------------------------------+
|  TOR EXIT                      |
|  target sees this IP           |
+--------------------------------+
        |
        v
+--------------------------------+
|  TARGET SITE                   |
|  website / API                 |
+--------------------------------+
```

This makes the target see a Tor exit instead of the YUME server. It also
hides the final target from the server's local network and hosting
provider.

Important limit: the `yumed` process still receives the requested target
from the YUME client unless the client is only asking the server to
connect to a Tor bridge, guard, or local Tor endpoint. Server-side Tor is
useful, but it does not by itself hide the target from the YUME server
operator.

## Client-Side Tor Over YUME

For stronger target anonymity from the YUME server operator, run Tor on
the client side and make Tor use YUME as the path to its Tor entry.

```text
+--------------------------------+
|  TOR BROWSER                   |
|  or app configured for Tor     |
+--------------------------------+
        |
        v
+--------------------------------+
|  LOCAL TOR                     |
|  builds circuit                |
+--------------------------------+
        |
        v
+--------------------------------+
|  YUME CLIENT                   |
|  relays Tor TCP                |
+--------------------------------+
        |
        | ==YUME==>
        v
+--------------------------------+
|  YUMED SERVER                  |
|  opens Tor entry only          |
+--------------------------------+
        |
        v
+--------------------------------+
|  TOR ENTRY                     |
|  guard or obfs4 bridge         |
+--------------------------------+
        |
        v
+--------------------------------+
|  TOR NETWORK                   |
|  middle relays + exit          |
+--------------------------------+
        |
        v
+--------------------------------+
|  TARGET SITE                   |
|  sees Tor exit                 |
+--------------------------------+
```

In this route, the YUME server usually sees only a Tor guard or bridge as
the requested target. The final website sees the Tor exit. This is slower
than direct YUME, but it hides more from the YUME server itself.

## YUME Over Tor

YUME can also be reached through Tor first. In this route, the YUME
carrier itself is sent through a local Tor client before it reaches the
YUME server.

```text
+--------------------------------+
|  HUMAN APP                     |
|  normal app                    |
+--------------------------------+
        |
        v
+--------------------------------+
|  YUME CLIENT                   |
|  carrier source                |
+--------------------------------+
        |
        v
+--------------------------------+
|  CLIENT TOR                    |
|  carries YUME carrier          |
+--------------------------------+
        |
        | ...>
        v
+--------------------------------+
|  TOR EXIT                      |
|  client-side edge              |
+--------------------------------+
        |
        v
+--------------------------------+
|  YUMED SERVER                  |
|  sees Tor exit                 |
+--------------------------------+
        |
        v
+--------------------------------+
|  TARGET SITE                   |
|  sees server IP                |
+--------------------------------+
```

This hides the client's real IP from the YUME server, but the Tor exit can
see a connection to the YUME server and performance is usually worse.

## Tor -> YUME -> Tor

YUME can be set up with Tor on both sides:

- the client reaches `yumed` through Tor, hiding the client IP from the
  YUME server
- the server sends egress through Tor, hiding the YUME server IP from the
  target

```text
+--------------------------------+
|  HUMAN APP                     |
|  normal app                    |
+--------------------------------+
        |
        v
+--------------------------------+
|  YUME CLIENT                   |
|  carrier source                |
+--------------------------------+
        |
        | YUME carrier is sent through client Tor
        v
+--------------------------------+
|  CLIENT TOR                    |
|  obfs4 optional                |
+--------------------------------+
        |
        v
+--------------------------------+
|  TOR EXIT A                    |
|  client-side edge              |
+--------------------------------+
        |
        | YUME carrier reaches the server
        v
+--------------------------------+
|  YUMED SERVER                  |
|  sees Tor exit A               |
+--------------------------------+
        |
        | target stream is sent through server Tor
        v
+--------------------------------+
|  SERVER TOR                    |
|  obfs4 optional                |
+--------------------------------+
        |
        v
+--------------------------------+
|  TOR EXIT B                    |
|  target-side edge              |
+--------------------------------+
        |
        v
+--------------------------------+
|  TARGET SITE                   |
|  sees exit B                   |
+--------------------------------+
```

This can be less linkable for passive observers because neither edge sees
both the real client and the final target. It is also much slower and more
complex. It does not automatically hide the requested target from the
`yumed` process; for that, the application itself should use Tor over
YUME so the server only opens a Tor guard or bridge.

## VPN Or Proxy After YUME

The server can also send traffic through another VPN, datacenter proxy, or
firewall policy route.

```text
+--------------------------------+
|  HUMAN APP                     |
|  normal app                    |
+--------------------------------+
        |
        v
+--------------------------------+
|  YUME CLIENT                   |
|  YUME carrier                  |
+--------------------------------+
        |
        | ==YUME==>
        v
+--------------------------------+
|  YUMED SERVER                  |
|  policy route                  |
+--------------------------------+
        |
        v
+--------------------------------+
|  VPN / PROXY                   |
|  exit layer                    |
+--------------------------------+
        |
        v
+--------------------------------+
|  TARGET SITE                   |
|  sees VPN / proxy              |
+--------------------------------+
```

This changes the exit IP and can help with compartmentalization. It is
not the same as Tor: the proxy or VPN provider becomes another party that
can observe egress traffic.

## Inner Crypto And BaseFWX

YUME has an outer TLS carrier. It can also encrypt YUME frame payloads
inside that carrier using BaseFWX-backed inner crypto.

```text
+----------------------------------------------------------------------+
|  OUTER TLS 1.3 CARRIER                                               |
|                                                                      |
|  YUME frame header                                                   |
|    type, flags, stream id                                            |
|                                                                      |
|  INNER PAYLOAD                                                       |
|    encrypted with BaseFWX / AES-256-GCM                              |
|    authenticated with frame context                                  |
+----------------------------------------------------------------------+
```

Simplified key setup:

```text
+--------------------------------+
|  CLIENT INPUTS                 |
|  server PQ public key          |
+--------------------------------+
        |
        | ML-KEM encapsulates to the server public key
        v
+--------------------------------+
|  KEM CIPHERTEXT                |
|  sent during inner setup       |
+--------------------------------+
        |
        | server decapsulates with private key
        v
+--------------------------------+
|  SERVER INPUTS                 |
|  server PQ private key         |
+--------------------------------+
        |
        v
+--------------------------------+
|  SHARED SECRET                 |
|  both sides compute same value |
+--------------------------------+
        |
        | optional Argon2id work factor or HKDF
        v
+--------------------------------+
|  BASE KEY                      |
|  used directly or hopped       |
+--------------------------------+
```

The inner layer is client-to-YUME-server protection, not browser-to-target
end-to-end encryption. The server still has to know enough to open the
requested target connection. HTTPS inside the application remains the
browser-to-target encryption layer.

Use your own PQ key files for production. The embedded BaseFWX master key
is for explicit test/dev use only and must not become the trust root for a
real deployment.

## Live Key Hopping

When hopping is enabled, the base inner key is not used directly forever.
Both sides derive a time-based hop key and use it for frame encryption.

```text
+--------------------------------+
|  WINDOW 0                      |
|  0 - 499 ms -> hop key K0      |
|  encrypts DATA frames          |
+--------------------------------+

+--------------------------------+
|  WINDOW 1                      |
|  500 - 999 ms -> hop key K1    |
|  encrypts DATA frames          |
+--------------------------------+

+--------------------------------+
|  WINDOW 2                      |
|  1000 - 1499 ms -> hop key K2  |
|  encrypts DATA frames          |
+--------------------------------+
```

The default interval is 500 ms. Hopping limits how long any one derived
key is useful and adds churn inside the already encrypted carrier. It can
cost a little latency, so performance tests should compare hopping on and
off on the same route.

This is derived-key separation, not forward secrecy. Both endpoints retain
the base inner key for the session; compromise of that base key permits
deriving every time-window key.

## HTTP/2 Obfs

With `--obfs` enabled, the bytes after TLS form a standards-conformant HTTP/2
opening exchange before YUME frames begin. The settings and headers are YUME
project templates, not byte-identical output from a named browser.

```text
+--------------------------------+
|  TLS HANDSHAKE                 |
|  real TLS 1.3                  |
+--------------------------------+
        |
        v
+--------------------------------+
|  HTTP/2 PREFACE                |
|  PRI * HTTP/2.0                |
+--------------------------------+
        |
        v
+--------------------------------+
|  PROJECT H2 SETTINGS           |
|  SETTINGS + WINDOW_UPDATE      |
+--------------------------------+
        |
        v
+--------------------------------+
|  OBFUSCATED REQUEST            |
|  POST /token/nonce HEADERS     |
+--------------------------------+
        |
        v
+--------------------------------+
|  YUME FRAMES                   |
|  carrier data begins           |
+--------------------------------+
```

With a nonempty `--obfs-secret`, the token is bound to that shared secret,
SNI, and an accepted hourly time window. `--public-node` requires this keyed
mode. Empty-secret structural admission remains available only in non-public
development mode and does not authenticate the probe. The opening can reject
casual probes, but the subsequent carrier is not a full-session HTTP/2 tunnel;
packet timing and sizes can still distinguish it.

## Real HTTPS Facade

`--real` lets the same port answer normal browser requests with a real
HTML page while YUME clients use the obfs path.

```text
                         SAME PORT, USUALLY 443

+--------------------------------+
|  NORMAL BROWSER                |
|  or active probe               |
+--------------------------------+
        |
        v
+--------------------------------+
|  HTTP/1.1 REQUEST              |
|  GET / facade path             |
+--------------------------------+
        |
        v
+--------------------------------+
|  REAL HTML PAGE                |
|  normal public site            |
+--------------------------------+

+--------------------------------+
|  YUME CLIENT                   |
|  authorized peer               |
+--------------------------------+
        |
        v
+--------------------------------+
|  HTTP/2 PREFACE                |
|  token HEADERS                 |
+--------------------------------+
        |
        v
+--------------------------------+
|  YUME OBFS PATH                |
|  tunnel starts                 |
+--------------------------------+
```

This is mainly for active probes and normal browser visits. It is not a
replacement for correct TLS certificates, private obfs secrets, or server
hardening.

## What Each Layer Protects

- SOCKS, `--run`, Android VPN capture:
  gets app traffic into YUME. It does not fix browser fingerprinting,
  logged-in accounts, or malware on the client.
- TLS 1.3 carrier:
  protects against passive network reading and many middlebox checks. It
  does not protect against a malicious or compromised endpoint.
- HTTP/2 obfs:
  gives active probes a benign HTTP response and, in keyed mode, gates AUTH
  behind the shared admission token. It does not defeat traffic analysis,
  full-session HTTP/2 validation, or endpoint compromise.
- AUTH:
  keeps unauthorized clients off the server. It does not help if the auth
  key is stolen.
- Inner BaseFWX crypto:
  adds frame confidentiality and integrity inside TLS. It does not remove
  the relay's need to know enough target metadata to connect.
- Key hopping:
  limits long-lived derived key exposure. It does not protect against
  endpoint compromise.
- Anonym mode/proof:
  signals server-side log minimization policy. It does not erase hosting
  logs, payment identity, browser identity, or target-side tracking.
- Tor in the route:
  hides different links depending on placement. It adds latency and does
  not fix target-side browser fingerprinting or bad operational security.

## Common Routing Choices

```text
Fastest common route:

  app -> yume client ==YUME==> yumed server -> target


Target sees Tor exit:

  app -> yume client ==YUME==> yumed server -> server Tor ...> target


YUME server sees only Tor entry:

  app -> local Tor -> yume client ==YUME==> yumed server -> Tor entry ...> target


Hide client IP from YUME server:

  app -> yume client -> client Tor ...> Tor exit -> yumed server -> target


Tor -> YUME -> Tor:

  app -> yume client -> client Tor ...> yumed server -> server Tor ...> target


Change exit IP without Tor:

  app -> yume client ==YUME==> yumed server -> VPN/proxy -> target
```

## Max Anonymity Setup

For target anonymity from the YUME server, the cleanest general shape is
Tor over YUME:

```text
+--------------------------------+
|  TOR BROWSER                   |
|  no login / no reused cookies  |
+--------------------------------+
        |
        v
+--------------------------------+
|  LOCAL TOR                     |
|  owns target selection         |
+--------------------------------+
        |
        v
+--------------------------------+
|  YUME CLIENT                   |
|  carries Tor traffic           |
+--------------------------------+
        |
        | ==YUME==>
        v
+--------------------------------+
|  YUMED SERVER                  |
|  sees Tor entry only           |
+--------------------------------+
        |
        v
+--------------------------------+
|  TOR NETWORK                   |
|  target hidden from YUME       |
+--------------------------------+
        |
        v
+--------------------------------+
|  TARGET SITE                   |
|  sees Tor exit                 |
+--------------------------------+
```

For edge unlinkability, Tor -> YUME -> Tor can be used, but it should be a
deliberate high-latency mode rather than the default. Multiple Tor layers
can create unusual timing and reliability behavior, and they do not fix
browser identity leaks.

Operational checklist:

- Run `yumed` with `--anonym` when the server is meant to be privacy
  preserving.
- Configure clients with `require_anonym: true` and the expected anonym
  CA when relying on anonym proof.
- Keep `--obfs` enabled and set the same private `--obfs-secret` on both
  ends for keyed carrier admission. A nonempty value is mandatory under
  `--public-node`.
- Use your own PQ keypair with `--pq-pub` and `--pq-key`; avoid
  `--use-embedded-master` outside explicit tests.
- Keep inner crypto, heavy KDF, and hopping enabled unless performance
  testing proves a specific route needs different settings.
- Use remote DNS through the tunnel. For SOCKS, prefer `socks5h://` so
  hostnames are resolved through the proxy path.
- Remember that server-side Tor hides egress from the server's network,
  but not necessarily from the `yumed` process itself.
- Use a separate browser profile or Tor Browser style compartment. A
  logged-in account, stable fingerprint, or reused cookies can identify
  the user even if the network path is strong.
- Harden the server host: disable unrelated logs, avoid reverse proxies
  that terminate TLS, protect auth keys, and keep system package logs in
  mind.
- Treat hosting, payment, SSH access, DNS registration, and time
  correlation as part of the threat model.

## Performance Setup

The fastest practical route is usually direct YUME:

```text
app -> yume client ==YUME==> yumed server -> target
```

For speed testing, keep the route fixed and compare one variable at a
time:

- direct internet from the server to the target
- desktop YUME SOCKS to the same target
- Android tun2socks to the same target
- Android native direct to the same target
- hopping on versus hopping off
- obfs on versus obfs off only as a diagnostic

Tor, extra VPN egress, bad DNS, remote cellular jitter, and overloaded
mobile routing backends can dominate the result. A slower anonymous route
can still be the right route, but it should be chosen deliberately.

## Short Version

```text
YUME hides the transport shape from the client network.
YUME moves app streams through an authenticated TLS/H2 carrier.
The server opens the target unless another egress layer is configured.
Tor/VPN placement decides who sees the target and who sees the client.
Inner BaseFWX crypto and hopping protect YUME frames inside the carrier.
Anonym mode reduces server-side logging, but does not replace good OPSEC.
```
