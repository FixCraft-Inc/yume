# YUME stealth and obfuscation

YUME stacks four independent layers of byte-shape camouflage on top of TLS 1.3. Each one defends against a different kind of observer; they're orthogonal and can be enabled or disabled independently.

## Layer 1: real TLS 1.3 with browser-oriented presets

The TLS handshake is real, not forged. OpenSSL emits a genuine ClientHello whose cipher suites, supported groups, signature algorithms, and ALPN list are configured toward a browser profile. The project checks the resulting JA3 against pinned build-host baselines and computes [canonical JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md) for diagnostics. This is browser-oriented shaping, not a byte-identical browser ClientHello: stock OpenSSL and the partial GREASE support leave observable differences described below.

Source: [src/core/stealth/tls_stealth.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/stealth/tls_stealth.cpp), [src/core/stealth/tls_fingerprint.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/stealth/tls_fingerprint.cpp).

| Profile flag | Preset orientation |
| --- | --- |
| `--profile chrome` (default) | Project baseline labelled Chrome 131 |
| `--profile firefox` | Project baseline labelled Firefox 126 |
| `--profile safari` | Project baseline labelled Safari 18 |
| `--no-stealth` | Bare OpenSSL defaults; distinguishable as YUME, not recommended in hostile networks |

Profile rotation is available via `--tls-stealth-rotate` and `--tls-stealth-rotation-interval <N>`. The configured starting profile advances through chrome/firefox/safari after every N successful TLS connections. Unless `--hide-in-the-crowd` explicitly selects a client HTTP profile, the carrier User-Agent follows the active TLS preset.

## Layer 2: HTTP/2 carrier handshake (`--obfs`)

After TLS handshake, the client emits an HTTP/2 connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), a project-defined browser-oriented `SETTINGS` block, a `WINDOW_UPDATE`, and a `HEADERS` frame opening stream 1 with a `POST` request. The request uses valid HPACK static-table indexes, carries `END_HEADERS|END_STREAM`, and requires `:authority` to match the TLS SNI after canonical host normalization. If `:authority` supplies a port, it must be decimal, in range, and equal to the accepted listener port. The path is `/<token>/<nonce>` where `<token>` = `HMAC-SHA256(K, sni || hour_epoch || "yume-obfs-v2")` truncated to 16 bytes hex, and `K` is HKDF-derived from `--obfs-secret`.

On an accepted request the server writes one ordered sequence: server `SETTINGS`, an ACK for the client's `SETTINGS`, and bodyless `:status=200` response `HEADERS` with `content-type: application/grpc-web+proto`. The current client ACKs the server settings before the server emits YUME `AUTH`; a client that omits that ACK is closed without AUTH. Missing, malformed, or wrong admission data stays in the masquerade path and receives a complete benign HTTP/2 response with `END_STREAM`; yumed uses a captured upstream response when configured, then the real HTML/profile identity, then its synthetic profile fallback. The client classifies this as an ordinary HTTPS decoy before attempting to parse YUME framing.

This is a standards-conformant opening exchange covered by the project decoder tests, not a claim of exact Chrome/Firefox bytes or native nginx/Apache output. It has not yet been validated against a version-pinned external browser or HTTP/2 conformance capture. The exact gap is measurable: `scripts/yume_h2_fingerprint.py` renders YUME's opening in the Akamai HTTP/2 fingerprint format and diffs it, field by field, against reference browser fingerprints (SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order). It reports deltas only and changes no bytes; use it to decide whether a future opt-in per-profile opening is worth a wire change. A passive path observer does not see these plaintext bytes; it sees the TLS handshake plus encrypted record sizes and timing. After this opening exchange, the authenticated tunnel carries YUME frames rather than maintaining a fully conformant long-lived HTTP/2 stream.

Source: [src/core/stealth/obfs_h2.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/stealth/obfs_h2.cpp), [src/core/stealth/obfs_signal.cpp](https://github.com/FixCraft-Inc/yume/blob/main/src/core/stealth/obfs_signal.cpp).

| Flag | Effect |
| --- | --- |
| `--obfs` (default on) | enable HTTP/2 carrier handshake |
| `--no-obfs` | disable; tunnel goes raw YUME after TLS |
| `--obfs-secret <string>` | shared secret used to bind the path token to a peer; client and server must agree; required by `--public-node` |

In non-public development mode, an empty secret permits only a structural admission check (`/<32hex>/<16hex>`). This is not probe authentication and must not be described as strict masquerade. `--public-node` rejects startup unless obfs is enabled with a nonempty secret. There is no separate dual-key wire format: clients connecting to a keyed server must use the same secret.

The token rotates every hour and the verifier accepts ±1 hour of clock skew. There is no nonce-reuse database, so a captured valid path can be replayed during an accepted time window to reach the separate Ed25519 challenge. It cannot authenticate the client or decrypt the inner stream by itself.

## Layer 3: HTTP-layer server disguise (`--hide-in-the-crowd`)

The TLS-fingerprint layer is intended to reduce coarse JA3-based blocking, while the HTTP/2-shaped opening makes an endpoint probe less obviously proprietary. Neither is a guarantee against a current JA4 implementation or a stateful classifier. An active prober that just sends a regular `curl https://yumed.example.com/` got — before 1.0 — TLS handshake plus immediate TCP close. **Real web servers don't do that.** They answer 404 / 503 / something. The close-on-probe was itself a strong DPI fingerprint.

`--hide-in-the-crowd <profile>` makes yumed serve a synthetic profile-driven 404 to non-YUME probes, with header order, charset, and body templates based on the chosen server software. This is higher fidelity than changing only the `Server` header, but generated fields and repeated behaviour can still differ from a real deployment. Use `--upstream-response` or `--upstream-response-dir` when replay of operator-captured responses is required.

Server profiles:

| Profile | Synthetic response identity |
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

Client profiles select the User-Agent in stealth probes (and any other HTTP-layer code the client runs): `chrome`, `firefox`, `safari`, `edge`, `curl`, `wget`, `yume`. When unset, the UA is derived from the active `--profile` preset so profile rotation updates both layers. These are project templates, not proof that a native browser or server produced the exchange.

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
| `--real-index <path>` | HTML file to serve for `GET /` (single-page mode) |
| `--real-root <dir>` | serve GET/HEAD static files under `<dir>` (implies `--real`) |
| `--real-secret <string>` | embed an HMAC-derived hidden blob in the HTML (used for downstream identification by other YUME tools, unrelated to `--obfs-secret`) |
| `--real-secret-file <path>` | load (or auto-generate) the secret from a file |

`--real-root <dir>` upgrades the facade from a single page to a coherent static site: `GET`/`HEAD` for any real file under `<dir>` is served with the correct MIME type, `Content-Length`, `Last-Modified`, an nginx-style `ETag` (`"<hex-mtime>-<hex-len>"`), and `Accept-Ranges: bytes`. `/` and directory paths serve `index.html`; misses and non-GET/HEAD methods fall through to the profile 404, exactly as a real server behaves for an unrouted path. This matters because a single page that returns `200` for `/` but `404` for every asset is itself a tell to any prober that walks more than one URL. The same root/index is presented on both HTTP/1.1 probes and the H2 decoy so an active probe sees one web identity, not two different sites. Path resolution rejects traversal (`..`), percent-encoded slash/backslash, control bytes, over-length targets, and symlinks that escape the root (enforced by canonicalization); a per-response size cap bounds a single cover reply. Static 200s currently use nginx-shaped header framing, so pair `--real-root` with `--hide-in-the-crowd nginx` (the default under `--public-node`) for the closest fit. HTTP/1.1 keep-alive is honored: a browser pulls the page and its assets over one connection (bounded by a per-connection request cap and an idle timeout), with `Connection: keep-alive` on 200 responses and `Connection: close` on HTTP/1.0, a client-requested close, or a 404. Only bodyless GET/HEAD keep the connection open; a request with a body or a non-GET/HEAD method is answered and closed so the byte stream never desyncs.

`--real`, `--obfs`, and `--hide-in-the-crowd` are independent and combine. They're demuxed by the first cleartext bytes after TLS: a `PRI * HTTP/2.0` preface goes to the `--obfs` validator; an HTTP/1.1 method-line gets the `--real`/`--real-root` page for `GET /` (or the resolved static file) and the `--hide-in-the-crowd` 404 for anything else.

## What this defends against, what it doesn't

**Designed to help against:**

- Simple blocking based on known VPN wire signatures or coarse TLS fingerprints
- TLS-terminating inspection that checks only the first application exchange
- Casual active probes that complete TLS and expect an immediate non-HTTP close
- ISP-level "OpenVPN/WireGuard signature" filters that block known VPN protocols

**Partial defense (depends on the depth of the attack):**

- **Stateful HTTP/2 middleboxes.** The opening decoder parses peer SETTINGS, answers SETTINGS/PING frames, tracks send windows for fake HTTP responses, and has stateful HPACK helpers. Those pieces improve the handshake and decoy response, but the authenticated carrier deliberately switches to YUME framing after the initial HEADERS exchange. A TLS-terminating middlebox that requires valid HTTP/2 for the full connection can therefore distinguish or reject it. Per-payload HTTP/2 DATA carriage is not enabled in the current transport path.
- **ML traffic classifiers** trained on joint inter-arrival × packet-size distributions over the full session. Mitigations are opt-in (both knobs default to 0 because they need a matching-version peer / cost latency):
    - `--obfs-pad-multiple <N>` (0..256) — rounds every outbound frame payload up to a multiple of N bytes via trailing pad + a 1-byte length (`kFlagPadded`). Both ends must run a yume that knows `kFlagPadded`; enable it on both sides or leave it off.
    - `--obfs-jitter-ms <ms>` — defers each batched TLS write by a uniform random 0..ms delay. Strand-serialised, so it adds bounded cadence variation and latency.
    - `YUME_AUTH_JITTER_MS=<ms>` env — server-side jitter on the single AUTH challenge frame, separate from `--obfs-jitter-ms`. Cheap because it only fires once per session.
    
    These use ordinary pseudo-random scheduling rather than a claimed TRNG, and none establishes ML/DPI immunity.
- **Active probers** that send arbitrary HTTP/1.1 requests to the server: served a profile-driven 404 by `--hide-in-the-crowd <profile>` (see [Layer 3](#layer-3-http-layer-server-disguise---hide-in-the-crowd)) whose header order, charset, body shape, and profile-specific extras (`Alt-Svc` for Caddy, `CF-RAY` + `alt-svc` for Cloudflare, `Content-Security-Policy` + `nosniff` + `X-Powered-By` for Express, etc.) are based on captured upstream behaviour. For higher-fidelity replay, use `--upstream-response <file>` (single capture, normalized to valid HTTP line endings and replayed every probe) or `--upstream-response-dir <dir>` + optional `--upstream-response-ttl <s>` (loads every `*.http` / `*.response` in the directory and rotates one per probe; TTL reloads the directory periodically). Rotation avoids the simplest "every probe returns the same capture" tell, but it is not proof against a stateful prober.
- **TLS-fingerprint regressions** if OpenSSL is upgraded to a version whose emitted ClientHello drifts from the compiled profiles. Mitigation is diagnostic: yumed generates a local ClientHello at startup and compares its JA3 with a pinned project baseline. A mismatch is logged but does not fail startup, and a match proves consistency with that baseline rather than equivalence to a current browser release.
- **Real-browser GREASE values** (RFC 8701) in the ClientHello. **Extension slot implemented, overall support partial.** `apply_stealth_profile` registers an empty custom extension at a GREASE-range type and rotates the selected value. Chrome also places GREASE values in the cipher-suite and supported-group lists; stock OpenSSL's public configuration APIs do not preserve those unknown values. A classifier that tracks GREASE position or the complete ClientHello can still distinguish YUME's OpenSSL-generated shape.

## Quick recipes

**Strict per-peer pinning.** Both ends have an out-of-band shared secret:

```bash
# server
yumed --listen 443 --cert … --key … --auth-keys … --obfs --obfs-secret 'shared-string'

# client
yume --server yume.example.com --auth id_ed25519 --socks 1080 --obfs --obfs-secret 'shared-string'
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

**Per-frame padding + send-side jitter.** Reduces stable features available to classifiers that use inter-arrival × packet-size joints. Enable on BOTH ends — `--obfs-pad-multiple` flips on `kFlagPadded` and an old peer can't parse the stream:

```bash
# server
yumed --listen 443 --cert … --key … --auth-keys … \
      --obfs --obfs-secret 'shared-string' \
      --obfs-pad-multiple 32 --obfs-jitter-ms 25

# client
yume --server … --auth … --socks 1080 \
     --obfs --obfs-secret 'shared-string' \
     --obfs-pad-multiple 32 --obfs-jitter-ms 25
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

The ClientHello is visible on the wire, while application data is encrypted after the TLS handshake. With `--obfs` on, the local plaintext passed into TLS begins with `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` followed by a `SETTINGS` frame. A passive capture sees only the resulting TLS records; inspecting the HTTP/2 bytes requires endpoint instrumentation or TLS termination/interception.
