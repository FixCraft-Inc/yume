# Filtering, robots, and self-DPI

> **Transport-v2 surface:** this document records probe, cover, and diagnostic
> behavior in the runnable 0.2 product. Its evidence does not automatically
> qualify the unwired YTP/1 front door.

## Stealth boundary

`--robots-deny`, IP filtering, and self-DPI do not change the TLS profile,
ALPN, HTTP/2 carrier preface, obfs token, or YUME frame format. Robots is a
normal HTTP-facade response for `GET`/`HEAD /robots.txt`; packet and stream
traffic still rides inside the existing encrypted YUME `DATA` frames.

### There is no default cover page

`yumed` ships no built-in cover page. One compiled into the daemon would be
byte-identical on every deployment, so a single HTTP/2 request would identify
the server as YUME no matter what the HTTP/1.1 cover backend serves.

Startup therefore requires two separate things and refuses without either:

- `real_backend`, a real local HTTP server that answers unauthenticated
  HTTP/1.1 requests and is health-checked at start; and
- a source for the HTTP/2 decoy: `upstream_response_dir` or
  `upstream_response` (captured real responses, the closest fit),
  `real_root` (a static site, whose `index.html` is also the decoy page), or
  `real_index_path` (a single page).

If a configured source disappears at run time, the daemon answers with the
profile's ordinary 404 rather than substituting a page of its own.

## Server filters

Two independent planes are available:

- `client`: source IPs are checked immediately after accept and refused before
  the TLS handshake.
- `egress`: resolved TCP/UDP destinations and packet-native IPv4 destinations
  are checked before the server connects or writes packets to the TUN.

Use:

```bash
yumed --filter-list egress:deny:/etc/yume/vpn_db.tar.xz \
      --filter-list egress:allow:/etc/yume/allow.json \
      --filter-geolite /etc/yume/GeoLiteCountry.tar.xz
```

JSON lists use:

```json
{ "ips": ["1.2.3.4", "1.2.3.0/24"], "countries": ["US"] }
```

Most-specific match wins. If two rules have the same specificity, deny wins.
This lets exact allow rules override broad country or VPN-provider denies
while keeping ambiguous equal matches fail-closed.

Archives are extracted once at startup into a private temp directory, validated
for path traversal, loaded into memory, then removed on shutdown. No archive
extraction or disk parsing is done in the hot path.

`vpn_db.tar.xz` is private/operator-supplied and remains untracked.
`GeoLiteCountry.tar.xz` may contain a compact `geoip_country_ipv4.db` or a
GeoLite2-Country `.mmdb`; both are loaded into memory without a runtime
MaxMind library dependency. Committing a copy requires a deliberate license
review and `.gitignore` exception.

## Client self-DPI

The native client option `--self-dpi` enables warning-only checks of local
carrier metadata. The separate Android packet client does not expose this
switch; its diagnostics report packet-session facts instead.

Self-DPI v1 inspects local configuration and runtime metadata only. The
desktop client logs the TLS stealth switch, the resolved profile name, the
HTTP/2 carrier state, the server port, the TLS handshake time, and the frame
padding and jitter settings. It warns when TLS stealth or HTTPS masking is
off, when the port is not 443, and when the selected profile does not resolve
to a known browser fingerprint locally. It does not inspect application
payloads, packet-native batch settings, or throughput, and it does not
auto-tune the connection.
