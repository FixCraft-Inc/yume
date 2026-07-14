# YUME implementation status

This page is the current engineering status snapshot for features that are easy
to overstate. It should stay conservative: implemented means code exists in this
tree; tested means it has a specific validation path; planned means no supported
runtime contract should rely on it yet.

YUME raises the cost of blocking and can reduce metadata exposure depending on
the route. It should not be described as impossible to block, impossible to
trace, or a replacement for a full anonymity network by itself.

## Host controller

Status: implemented, lightly validated.

- `host_mode`, `accept_yume_clients`, `client_deny_action`, HTTPS routes,
  extra listeners, runtime info, runtime filter reload, runtime session kill,
  and exposure checks are present in code and configuration.
- Current implemented host-controller backend scheme is
  `loopback://<ip-literal>:<port>` only.
- `tls_terminate`, `tcp_passthrough`, and `starttls_mail` listener modes exist.
- Validation so far is lightweight: shell syntax checks, diff whitespace checks,
  focused C++ syntax checks, and `host_types_test`.

Not done / not fully tested:

- Full WAN cutover test with only `yumed` bound to `:443`.
- Browser-level HTTPS ingress smoke against a real certificate, SNI route, and
  loopback backend.
- Cloudflare Spectrum / non-Cloudflare TCP passthrough exposure checks from an
  external network.
- Long-lived reverse-proxy soak, backend failure behavior, and real mail
  STARTTLS interop.
- Kernel/firewall-level packet blackhole behavior. `client_deny_action=drop` is
  a userspace close after accept, not a true pre-accept network drop.

## Public host mode

Status: config/API present; production cutover needs real deployment testing.

- `host_mode=private` is intended for a WAN-facing host that serves configured
  backends and rejects YUME clients.
- `host_mode=relay` is intended for host routing plus authenticated YUME
  clients on the same daemon.
- Private host mode avoids HTTP/2 ALPN when YUME clients are disabled because
  the current host reverse proxy is HTTP/1.x.

Not done / not fully tested:

- Real browser compatibility matrix for common Linux/Windows/macOS browsers.
- Direct public IP vs TCP proxy vs HTTP proxy deployment matrix.
- Certificate renewal, hot reload, and operational runbook coverage.
- Performance and memory measurements under public probe/load traffic.

## Application codecs

Status: registry-driven built-ins exist; external plugin codecs do not.

- `monero-rpc-v1` is the first built-in application codec.
- Codec enablement flows through `--codec-allow <name>` / `allow_codecs` plus
  per-key `permissions.allow_codecs`.
- Codec streams use typed app-codec envelopes over normal YUME frames instead of
  raw TCP forwarding.

Not done / not fully tested:

- Live `monero-wallet-cli` / `monerod` smoke against a real daemon.
- Regression tests for allowed/denied RPC paths and backend failures.
- Dynamic `.so` / DLL codec loader.
- Stable external plugin ABI/SPI for third-party codecs.
- Sandboxed out-of-process plugin runner.

## Host-controller backend schemes

Status: loopback TCP only.

- Implemented: `loopback://127.0.0.1:PORT`, `loopback://127.x.x.x:PORT`, and
  `loopback://[::1]:PORT`.
- Not implemented: `service://`, `codec://`, and `unix://`.

Those schemes must stay rejected until runtime drivers exist and have their own
validation, timeout, permission, and test coverage.

## Federation and multi-hop privacy

Status: cluster federation exists; onion-style routing does not.

- Current federation connects `yumed` peers and can route endpoint invites /
  channels through cluster links.
- It is not a Tor-like onion-routing anonymity layer.

Planned but not implemented:

- Client-selected guard/middle/service or exit paths.
- Per-hop layered encryption where each server knows only adjacent hops.
- Signed node and service descriptors for path selection.
- Browser-safe circuit telemetry.
- Tests proving no single non-client node sees the whole route and plaintext.

## Browser

Status: separate repo scaffolded; no production browser exists in this
tree.

- The separate Linux-first browser repository is not part of this tree.
- It currently contains a Qt Quick / Qt WebEngine scaffold, renderer adapter
  interfaces, a `libyume` wrapper boundary, and a placeholder `yume://` scheme
  handler.
- The intended first renderer is Qt WebEngine behind a renderer adapter so
  WebKitGTK or Servo can be added later.
- The intended transport integration is `libyume`, not launching the `yume`
  CLI as a sidecar.
- The intended first visible feature is loading a `yume://name.xxx:port`
  hidden-service page from a signed YUME directory.

Not done:

- Hidden-service descriptor format and signature verification.
- Browser-grade `libyume` ABI for descriptor resolution, circuit creation,
  `yume://` streams, trust roots, and safe circuit telemetry.
- 3-hop onion routing.
- Browser profile isolation tests.
- End-to-end `yume://` page rendering without normal DNS.

## Tor positioning

YUME can be useful as an additional stealth transport or bridge path for Tor in
restricted networks, and Tor-over-YUME is a valid route choice. Tor already has
its own pluggable transports and bridge ecosystem, so YUME documentation should
avoid claiming that Tor has no stealth. The accurate claim is that YUME provides
a different HTTPS-shaped transport and can be combined with Tor depending on
which party must not learn which fact.
