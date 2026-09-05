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

`yumed` ships no built-in cover page. A shared compiled-in page would give
probes that reach it a common response across deployments.

Startup therefore requires two separate things and refuses without either:

- `real_backend`, a real local HTTP server that receives ordinary
  unauthenticated HTTP/1.1 and HTTP/2 GET/HEAD requests through the daemon's
  structured proxy and is health-checked at start; and
- a source for the separate probe-response path: `upstream_response_dir` or
  `upstream_response` (captured responses),
  `real_root` (a static site, whose `index.html` is also the decoy page), or
  `real_index_path` (a single page).

Recognized HTTP/2 openings with client admission enabled reach the live
backend. Partial or malformed openings, and the HTTP/2 path with
`accept_yume_clients=false`, can reach the static/captured decoy instead.
These paths need separate probe and failure comparisons. It is incorrect to
describe `real_backend` as HTTP/1.1-only or ordinary HTTP/2 GET/HEAD as always
serving another origin. The additional cover-source requirement remains in
the current `real_http` startup policy.

Cover files are bounded operational input. A single static asset, index, or
captured response may be at most 8 MiB. A response directory may contain at
most 256 matching captures among at most 4,096 entries, and the daemon retains
at most 64 MiB of normalized captures. A reload that exceeds the entry or file
count keeps the previous snapshot; an aggregate limit stops adding later files
in sorted order. Oversize captures and final-component symlinks are refused.
POSIX reads open nonblocking, then refuse nonregular files from the opened
descriptor, so a FIFO does not wait for a writer.

Static-root reads walk the root and child directories through owned POSIX
descriptors and refuse symlinks in every component. Renaming an opened
directory cannot redirect the subsequent read through a replacement symlink.
Bytes and modification time come from the same opened file. This is path
confinement, not a snapshot of contents another process can still modify.
Use a root path without symlinked ancestors. Platforms without confined
directory access, including Windows, refuse static-root reads.

Captured responses must contain one complete HTTP/1.0 or HTTP/1.1 final
response, with headers bounded to 64 KiB. Header LF endings are normalized to
CRLF; body bytes and chunk framing are preserved. Invalid, conflicting,
truncated, or trailing framing is refused. Capture with
`curl --http1.1 --raw -i https://real-site/notfound > resp.http` so curl retains
the response's transfer framing. HTTP/2 conversion removes chunk framing
before emitting DATA. These checks do not establish equivalence to a live
upstream or a complete-session fidelity claim.

A missing static page falls through to the profile response. Capture reloads
can retain the prior snapshot. A live-backend failure on ordinary HTTP/2
requests produces a 502. Those failure paths are not a single shared cover
response.

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

At startup, each archive is copied into a newly created owner-only temporary
directory so validation and extraction consume one private snapshot. Archive
members must have relative, traversal-free names without backslashes or control
escapes and be regular files or directories; links and special files are
refused. Extracted data is loaded into memory and removed on shutdown, while a
partial failed extraction is removed immediately. No archive extraction or
disk parsing is done in the hot path.

Archive extraction is supported only on Linux and depends on a shell and GNU
tar. Other platforms refuse archives; use unpacked lists or databases there.
Compressed size, member count, expanded bytes, disk use, and
decompression time have no complete extraction budget. Use only trusted
operator archives on the tested Linux/GNU-tar path.

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
