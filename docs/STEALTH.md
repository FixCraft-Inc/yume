# YUME stealth and obfuscation

YUME stacks three independent layers of byte-shape camouflage on top of TLS 1.3. Each one defends against a different kind of observer; they're orthogonal and can be enabled or disabled independently. All three are on by default.

## Layer 1: real TLS 1.3 with a browser fingerprint

The TLS handshake is real, not forged. OpenSSL emits a genuine ClientHello, but its cipher suites, supported groups, signature algorithms, and ALPN list are configured to match a specific browser profile. JA3 / JA4 hashes fall in the browser cluster, and a passive TLS-fingerprint observer sees the same handshake shape they'd see from the configured browser.

Source: [src/core/tls_stealth.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/tls_stealth.cpp), [src/core/tls_fingerprint.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/tls_fingerprint.cpp).

| Profile flag | Mimics |
| --- | --- |
| `--profile chrome` (default) | Chrome 135 |
| `--profile firefox` | Firefox 126 |
| `--profile safari` | Safari 17 |
| `--no-stealth` | Bare OpenSSL defaults; distinguishable as YUME, not recommended in hostile networks |

Profile rotation per N connections is available via `--tls-stealth-rotate` and `--tls-stealth-rotation-interval <N>`.

## Layer 2: HTTP/2 carrier handshake (`--obfs`)

After TLS handshake, the client emits the bytes a real Chrome would: an HTTP/2 connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), Chrome-shaped `SETTINGS`, a `WINDOW_UPDATE`, and a `HEADERS` frame opening stream 1 with a `POST` request. The path is `/<token>/<nonce>` where `<token>` = `HMAC-SHA256(K, sni || hour_epoch || "yume-obfs-v2")` truncated to 16 bytes hex, and `K` is HKDF-derived from `--obfs-secret`. The server replies with canned `SETTINGS` + `SETTINGS-ACK` + `HEADERS :status=200 content-type=application/grpc-web+proto`.

To a stateless DPI box, the first ~150 cleartext bytes of every YUME connection look exactly like a Chrome → CDN gRPC-web request.

Source: [src/core/obfs_h2.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/obfs_h2.cpp), [src/core/obfs_signal.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/obfs_signal.cpp).

| Flag | Effect |
| --- | --- |
| `--obfs` (default on) | enable HTTP/2 carrier handshake |
| `--no-obfs` | disable; tunnel goes raw YUME after TLS |
| `--obfs-secret <string>` | shared secret used to bind the path token to a peer; client and server must agree |

If `--obfs-secret` is unset on either side, the server falls back to a structural check (path matches `/<32hex>/<16hex>`). That defeats casual probes but doesn't pin the tunnel to a specific authorised peer; set `--obfs-secret` on both ends for strict pinning.

The token rotates every hour. The verifier accepts ±1 hour of clock skew. A captured token cannot be replayed beyond that window and cannot decrypt the inner stream regardless.

## Layer 3: real HTML facade (`--real`)

A browser that hits the same hostname and port with `GET / HTTP/1.1` is served the configured HTML page (or a Wikipedia redirect by default). YUME clients and browsers cohabit on port 443. An active prober that completes TLS and sends a normal browser request gets a normal-looking web page back.

| Flag | Effect |
| --- | --- |
| `--real` | serve a real HTML page to non-YUME requests |
| `--real-index <path>` | HTML file to serve for `GET /` |
| `--real-secret <string>` | embed an HMAC-derived hidden blob in the HTML (used for downstream identification by other YUME tools, unrelated to `--obfs-secret`) |
| `--real-secret-file <path>` | load (or auto-generate) the secret from a file |

`--real` and `--obfs` are independent and can both be on. They're demuxed by the first cleartext bytes after TLS: a `PRI * HTTP/2.0` preface goes to the `--obfs` validator; an HTTP/1.1 method-line goes to the `--real` HTML server.

## What this defends against, what it doesn't

**Defends well against:**

- Stateless DPI that classifies traffic by the first N cleartext bytes after TLS
- ML classifiers trained on TLS-handshake fingerprints (JA3 / JA4)
- Active probes that complete TLS and inspect the application layer for non-HTTP traffic
- ISP-level "OpenVPN/WireGuard signature" filters that block known VPN protocols

**Does not defend against:**

- Stateful HTTP/2 middleboxes that fully track stream and HPACK dynamic-table state. The HPACK encoder is intentionally stateless and SETTINGS changes from the peer are ignored, so a fully-conformant H2 parser will desync within seconds.
- ML traffic classifiers trained on joint inter-arrival × packet-size distributions over the full session.
- Active probers that send arbitrary HTTP/2 requests to the server: any path that doesn't match the structural / token check gets the `--real` HTML page back, distinguishable from a real CDN by content (the page is configured by you, not generated dynamically).
- TLS-fingerprint regressions if OpenSSL is upgraded to a version whose default extension order drifts from the compiled-in browser profiles.

## Quick recipes

**Strict per-peer pinning.** Both ends have an out-of-band shared secret:

```bash
# server
yumed --listen 443 --cert … --key … --auth-keys … --obfs --obfs-secret 'shared-string'

# client
yume --server fixcraft.net --auth id_ed25519 --socks 1080 --obfs --obfs-secret 'shared-string'
```

**Coexisting with a real website.** Port 443 serves both browsers and YUME clients:

```bash
yumed --listen 443 --cert … --key … --auth-keys … \
      --obfs --obfs-secret … \
      --real --real-index ./www/index.html --real-secret-file ./.secrets/html_secret
```

**Profile-rotating client.** A different browser fingerprint every N connections:

```bash
yume --server … --auth … --socks 1080 --tls-stealth-rotate --tls-stealth-rotation-interval 50
```

**Disable obfs entirely.** Fastest, but recognisable as a YUME server to anything that probes:

```bash
yume --server … --auth … --socks 1080 --no-obfs
```

## Inspecting what's on the wire

Run a local-loopback yumed and capture with `tcpdump`:

```bash
sudo tcpdump -A -i lo -s 0 'port 18443'
```

The TLS handshake and ciphertext are encrypted, but the plaintext bytes that the local TLS code writes can be observed in the application's own logs. With `--obfs` on, the post-handshake plaintext should begin with `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` followed by a `SETTINGS` frame; that's the byte-shape DPI sees after decryption (or that any active TLS-MITM probe would see if the network can do TLS interception).
