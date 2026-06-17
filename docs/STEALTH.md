# YUME stealth and obfuscation

YUME stacks four independent layers of byte-shape camouflage on top of TLS 1.3. Each one defends against a different kind of observer; they're orthogonal and can be enabled or disabled independently.

## Layer 1: real TLS 1.3 with a browser fingerprint

The TLS handshake is real, not forged. OpenSSL emits a genuine ClientHello, but its cipher suites, supported groups, signature algorithms, and ALPN list are configured to match a specific browser profile. JA3 / JA4 hashes fall in the browser cluster, and a passive TLS-fingerprint observer sees the same handshake shape they'd see from the configured browser.

Source: [src/core/stealth/tls_stealth.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/stealth/tls_stealth.cpp), [src/core/stealth/tls_fingerprint.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/stealth/tls_fingerprint.cpp).

| Profile flag | Mimics |
| --- | --- |
| `--profile chrome` (default) | Chrome 131 |
| `--profile firefox` | Firefox 133 |
| `--profile safari` | Safari 18 |
| `--no-stealth` | Bare OpenSSL defaults; distinguishable as YUME, not recommended in hostile networks |

Profile rotation per N connections is available via `--tls-stealth-rotate` and `--tls-stealth-rotation-interval <N>`.

## Layer 2: HTTP/2 carrier handshake (`--obfs`)

After TLS handshake, the client emits the bytes a real Chrome would: an HTTP/2 connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), Chrome-shaped `SETTINGS`, a `WINDOW_UPDATE`, and a `HEADERS` frame opening stream 1 with a `POST` request. The path is `/<token>/<nonce>` where `<token>` = `HMAC-SHA256(K, sni || hour_epoch || "yume-obfs-v2")` truncated to 16 bytes hex, and `K` is HKDF-derived from `--obfs-secret`. The server replies with canned `SETTINGS` + `SETTINGS-ACK` + `HEADERS :status=200 content-type=application/grpc-web+proto`.

To a stateless DPI box, the first ~150 cleartext bytes of every YUME connection look exactly like a Chrome → CDN gRPC-web request.

Source: [src/core/stealth/obfs_h2.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/stealth/obfs_h2.cpp), [src/core/stealth/obfs_signal.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/stealth/obfs_signal.cpp).

| Flag | Effect |
| --- | --- |
| `--obfs` (default on) | enable HTTP/2 carrier handshake |
| `--no-obfs` | disable; tunnel goes raw YUME after TLS |
| `--obfs-secret <string>` | shared secret used to bind the path token to a peer; client and server must agree |

If `--obfs-secret` is unset on either side, the server falls back to a structural check (path matches `/<32hex>/<16hex>`). That defeats casual probes but doesn't pin the tunnel to a specific authorised peer; set `--obfs-secret` on both ends for strict pinning.

The token rotates every hour. The verifier accepts ±1 hour of clock skew. A captured token cannot be replayed beyond that window and cannot decrypt the inner stream regardless.

## Layer 3: HTTP-layer server disguise (`--hide-in-the-crowd`)

The TLS-fingerprint layer fools a passive JA3 / JA4 inspector. The HTTP/2 carrier fools a stateless cleartext-byte-shape DPI. But an active prober that just sends a regular `curl https://yumed.example.com/` got — before 1.0 — TLS handshake plus immediate TCP close. **Real web servers don't do that.** They answer 404 / 503 / something. The close-on-probe was itself a strong DPI fingerprint.

`--hide-in-the-crowd <profile>` makes yumed serve a profile-driven 404 to non-YUME probes, with the EXACT header order, charset, and body shape that the chosen real-server software emits. Captured from upstream source — not just the Server header — so a header-level DPI inspector sees what nginx/Apache/Caddy/etc would send.

Server profiles:

| Profile | What it mimics |
| --- | --- |
| `nginx` (default under `--public-node`) | `Server: nginx/1.24.0`, `Content-Type: text/html; charset=utf-8`, nginx's `<hr><center>nginx/1.24.0</center>` 404 body |
| `nginx-stable` | `Server: nginx` (no version), same body shape |
| `apache` | `Date:` BEFORE `Server:` (httpd build order), `iso-8859-1` charset, Apache's `<address>` 404 footer with `Server at <host> Port 443` |
| `caddy` | `Alt-Svc: h3=":443"; ma=2592000` (real Caddy 2 always advertises HTTP/3), `Server: Caddy`, empty body |
| `cloudflare` | Full CF header set: `Strict-Transport-Security` / `Server: cloudflare` / `CF-RAY: <16hex>-<POP>` (uppercase, matches real CF) / `alt-svc: h3=":443"` (lowercase, matches real CF) |
| `express` | `X-Powered-By: Express` / `Content-Security-Policy: default-src 'none'` / `X-Content-Type-Options: nosniff` / no Server header (Express default) / Express's `<pre>Cannot GET /</pre>` body |
| `gunicorn` | `Server: gunicorn` (no version, current default) + werkzeug's 404 body |
| `none` | No `Server` header at all |
| `yumed` | Pre-1.0 default: `Server: yumed`. Not stealthy; for operators who explicitly want the brand. |

Client profiles select the User-Agent in stealth probes (and any other HTTP-layer code the client runs): `chrome`, `firefox`, `safari`, `edge`, `curl`, `wget`, `yume`. When unset, the UA is derived from `--profile` so the JA3 and the UA stay consistent.

Source: [src/core/stealth/http_profile.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/stealth/http_profile.cpp). Automated fidelity test (verifies header order, charset, body length, profile-specific extras): [scripts/yume_disguise_check.py](https://github.com/FixCraft-Inc/yume/blob/main/scripts/yume_disguise_check.py).

| Flag | Effect |
| --- | --- |
| `--hide-in-the-crowd <p>` (server or client) | Pick a disguise profile |
| `--public-node` (server) | Implicitly sets `--hide-in-the-crowd nginx` if no profile is otherwise selected |

## Layer 4: real HTML facade (`--real`)

A browser that hits the same hostname and port with `GET / HTTP/1.1` is served the configured HTML page (or a Wikipedia redirect by default). YUME clients and browsers cohabit on port 443. An active prober that completes TLS and sends a normal browser request gets a normal-looking web page back.

| Flag | Effect |
| --- | --- |
| `--real` | serve a real HTML page to non-YUME requests |
| `--real-index <path>` | HTML file to serve for `GET /` |
| `--real-secret <string>` | embed an HMAC-derived hidden blob in the HTML (used for downstream identification by other YUME tools, unrelated to `--obfs-secret`) |
| `--real-secret-file <path>` | load (or auto-generate) the secret from a file |

`--real`, `--obfs`, and `--hide-in-the-crowd` are independent and combine. They're demuxed by the first cleartext bytes after TLS: a `PRI * HTTP/2.0` preface goes to the `--obfs` validator; an HTTP/1.1 method-line gets the `--real` HTML page for `GET /` or the `--hide-in-the-crowd` 404 for anything else.

## What this defends against, what it doesn't

**Defends well against:**

- Stateless DPI that classifies traffic by the first N cleartext bytes after TLS
- ML classifiers trained on TLS-handshake fingerprints (JA3 / JA4)
- Active probes that complete TLS and inspect the application layer for non-HTTP traffic
- ISP-level "OpenVPN/WireGuard signature" filters that block known VPN protocols

**Partial defense (depends on the depth of the attack):**

- **Stateful HTTP/2 middleboxes** that fully track stream and HPACK dynamic-table state. SETTINGS frame ACKs and PING ACKs are emitted with the right payload echo. Peer SETTINGS are parsed (not just ACKed): the decoder tracks `SETTINGS_HEADER_TABLE_SIZE`, `SETTINGS_MAX_CONCURRENT_STREAMS`, `SETTINGS_INITIAL_WINDOW_SIZE`, `SETTINGS_MAX_FRAME_SIZE` (clamped to RFC 7540 §6.5.2's [16384, 16777215] range), and `SETTINGS_MAX_HEADER_LIST_SIZE`. Connection-level and per-stream flow control (§6.9) are tracked: `WINDOW_UPDATE` increments propagate to the send-window state, `SETTINGS_INITIAL_WINDOW_SIZE` deltas apply to every existing per-stream window per §6.9.2, and `Session::serve_fake_h2_real_index` consults the budget before emitting DATA so a peer-advertised window isn't exceeded. HPACK is stateful: the encoder uses the "Literal Header Field with Incremental Indexing" opcode (§6.2.1, 0x40 prefix) — the same opcode real Chrome / Firefox emit — and maintains the dynamic table per §4 with size accounting (§4.1), eviction on shrink (§4.2 + §4.4), and the §6.3 dynamic-table-size-update opcode when the peer changes `SETTINGS_HEADER_TABLE_SIZE`. The remaining tell is that the carrier only ever emits one HEADERS frame per connection — that's a fingerprint of the carrier's purpose (one-shot fake gRPC-web request), not a protocol bug. Replacing the byte-shape-preserving static-table indices in `encode_client_handshake` with their semantically-correct counterparts (16=`accept-encoding`, 17=`accept-language`, 31=`content-type`) is a post-1.x change since it alters HEADERS-frame size.
- **ML traffic classifiers** trained on joint inter-arrival × packet-size distributions over the full session. Mitigations are opt-in (both knobs default to 0 because they need a matching-version peer / cost latency):
    - `--obfs-pad-multiple <N>` (0..256) — rounds every outbound frame payload up to a multiple of N bytes via trailing pad + a 1-byte length (`kFlagPadded`). Both ends must run a yume that knows `kFlagPadded`; enable it on both sides or leave it off.
    - `--obfs-jitter-ms <ms>` — defers each batched TLS write by a uniform random 0..ms delay. Strand-serialised, so the cadence offset propagates and the inter-arrival ML feature stops being constant. Adds latency.
    - `YUME_AUTH_JITTER_MS=<ms>` env — server-side jitter on the single AUTH challenge frame, separate from `--obfs-jitter-ms`. Cheap because it only fires once per session.
    
    None of these close the gap against arbitrarily sensitive classifiers; they raise the training cost.
- **Active probers** that send arbitrary HTTP/1.1 requests to the server: served a profile-driven 404 by `--hide-in-the-crowd <profile>` (see [Layer 3](#layer-3-http-layer-server-disguise---hide-in-the-crowd)) whose header order, charset, body shape, and profile-specific extras (`Alt-Svc` for Caddy, `CF-RAY` + `alt-svc` for Cloudflare, `Content-Security-Policy` + `nosniff` + `X-Powered-By` for Express, etc.) match the real-server bytes captured from upstream source. For byte-identical replay of a real captured response, use `--upstream-response <file>` (single capture, replayed verbatim every probe) or `--upstream-response-dir <dir>` + optional `--upstream-response-ttl <s>` (loads every `*.http` / `*.response` in the directory and rotates one per probe; TTL reloads the directory periodically so operators can refresh captures without restarting). Rotation defeats the "probe twice, get byte-identical Date / ETag / body" tell that single-capture replay leaves behind.
- **TLS-fingerprint regressions** if OpenSSL is upgraded to a version whose default extension order drifts from the compiled-in browser profiles. Mitigated: yumed runs a startup JA3 self-check that hashes its own ClientHello via the configured profile and compares to a pinned per-profile baseline. Drift is logged loudly with the observed vs expected JA3.
- **Real-browser GREASE values** (RFC 8701) in the ClientHello. **Extensions slot: closed.** `apply_stealth_profile` registers a custom extension via `SSL_CTX_add_custom_ext` at a GREASE-range type (one of `{0x0A0A, 0x1A1A, …, 0xFAFA}`, rotated per-connection through a process-local seed so each ClientHello picks a different value) with an empty payload. Verified against OpenSSL 3.5.6 by hex-dumping the rendered ClientHello: the extension appears at the front of the extensions block (`7a 7a 00 00`, `8a 8a 00 00`, …) — exactly the shape real Chrome emits. The JA3 parser correctly normalizes GREASE values out of the hash, so the pinned baselines in `main_server.cpp` continue to match. **Still partial:** Chrome additionally puts GREASE values at index 0 of the cipher_suites list, the supported_groups list, and the ALPN list. Stock OpenSSL's `SSL_CTX_set_cipher_list` / `SSL_CTX_set_ciphersuites` / `SSL_CTX_set_alpn_protos` reject unknown names, and `SSL_CTX_set1_groups` (uint16-array form) silently drops unknown IDs and falls back to defaults (observed: it injected `0x11ec` X25519MLKEM768 instead). Closing those three slots needs either a BoringSSL backend (days, link-layer swap) or a custom BIO wrapper that rewrites the cipher/groups/ALPN lists post-construction (~400-700 LOC). The extensions-slot win alone defeats DPI engines that key on "GREASE present somewhere in the ClientHello" without checking position; a classifier that specifically tracks GREASE-at-cipher-index-0 will still see the difference.

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

**Per-frame padding + send-side jitter.** Defeats ML classifiers that fingerprint by inter-arrival × packet-size joints. Enable on BOTH ends — `--obfs-pad-multiple` flips on `kFlagPadded` and an old peer can't parse the stream:

```bash
# server
yumed --listen 443 --cert … --key … --auth-keys … \
      --obfs --obfs-pad-multiple 32 --obfs-jitter-ms 25

# client
yume --server … --auth … --socks 1080 \
     --obfs --obfs-pad-multiple 32 --obfs-jitter-ms 25
```

**Rotating real-server replay for probes.** Capture N real upstream responses once and let yumed rotate one per probe; refresh the cache every 30 min without restarting:

```bash
# Capture once (one-time setup)
for i in 1 2 3 4; do
  curl -i "https://real-cdn.example.com/notfound-$i" > ./captures/$i.http
done

# Server
yumed --listen 443 --cert … --key … --auth-keys … \
      --upstream-response-dir ./captures --upstream-response-ttl 1800
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
