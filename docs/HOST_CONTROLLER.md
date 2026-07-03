# YUME host controller

`yumed` can act as the single WAN-facing host on a machine. Backends bind
loopback TCP only; `yumed` terminates TLS and dials inward. This
avoids double-listen stacks (`node:443` plus `yume:443`).

Current implementation and testing status is tracked in
`docs/IMPLEMENTATION_STATUS.md`. The host-controller code exists, but a full
public WAN cutover matrix still needs real deployment testing.

## Modes

| `host_mode` | YUME clients | Typical use |
| --- | --- | --- |
| `off` | yes (default) | Legacy tunnel daemon only |
| `private` | no | WAN HTTPS/TCP shield; disguise for probes |
| `relay` | yes | Host routing plus YUME client tunnel/relay |

Set in `yumed.json` or via CLI:

```bash
yumed --config /etc/yume/yumed.json \
  --host-mode private \
  --client-deny-action reset \
  --exposure-check example.com
```

## HTTPS ingress (routes)

Move your public service to loopback and route through `yumed`:

```json
{
  "host_mode": "private",
  "accept_yume_clients": false,
  "client_deny_action": "reset",
  "routes": [
    { "sni": "api.example.com", "backend": "loopback://127.0.0.1:8080" }
  ]
}
```

Only `loopback://<ip-literal>:<port>` backends are implemented today. Use
`127.0.0.1`, `127.0.0.0/8`, or `[::1]`; `localhost`, `unix://`, `codec://`,
and `service://` are rejected until those backend drivers exist.

The HTTP reverse proxy is HTTP/1.x. In `host_mode=private` with YUME clients
disabled, `yumed` avoids HTTP/2 ALPN so ordinary browsers use HTTP/1.1. In
`host_mode=relay`, HTTP/2 remains reserved for the YUME carrier.

## Extra listeners (mail / TCP)

```json
{
  "listeners": [
    {
      "bind": ":8443",
      "mode": "tls_terminate",
      "backend": "loopback://127.0.0.1:8080"
    },
    {
      "bind": ":587",
      "mode": "starttls_mail",
      "backend": "loopback://127.0.0.1:2525"
    },
    {
      "bind": ":25",
      "mode": "tcp_passthrough",
      "backend": "loopback://127.0.0.1:2525"
    }
  ]
}
```

Modes: `tls_terminate`, `tcp_passthrough`, `starttls_mail`.

Every listener requires a loopback backend. `tls_terminate` accepts TLS,
reads a bounded HTTP/1.x request, and proxies it to the backend.

## IP policy

Use existing filter lists plus `client_deny_action`:

- `close` — graceful FIN (default)
- `reset` — TCP RST via `SO_LINGER`
- `drop` — immediate close without response body

Reload filters without restart:

```json
{"op":"runtime.rules.reload","args":{}}
```

Kill sessions by session id, endpoint id, or client IP:

```json
{"op":"runtime.sessions.kill","args":{"ip":"203.0.113.50"}}
```

`drop` is a userspace close after accept. A true packet blackhole before TCP
accept requires firewall/eBPF/nftables integration outside the daemon.

## Exposure self-check

`exposure_check_hostname` (or `--exposure-check`) probes whether the hostname
is direct TCP or behind a Cloudflare HTTP proxy. `runtime.info` includes
`host.exposure` with `direct_tcp`, `cf_http_proxy`, `blocked`, or `unknown`.

YUME stealth requires true TCP passthrough (e.g. Cloudflare Spectrum), not
orange-cloud HTTP mode.

## Node as library

Do not bind backends on `0.0.0.0`. Prefer:

1. **App codecs** — typed protocol shims (`monero-rpc-v1`, future mail codecs)
2. **`service.v1`** — in-process registration via `yume_server_register_service`
3. **Loopback TCP** — `loopback://127.0.0.1:PORT` host-controller routes

See `docs/APP_CODECS.md` for the Monero pattern. Host-controller route
backends currently use loopback TCP; direct `service://` and `codec://`
route targets are not wired yet.

## Migration checklist

1. Move backend from `0.0.0.0:443` to `127.0.0.1:<port>`.
2. Configure `yumed` with `host_mode` and `routes`.
3. Grant `cap_net_bind_service` to `yumed` only.
4. Run `--exposure-check` and confirm `direct_tcp` if clients use YUME stealth.
