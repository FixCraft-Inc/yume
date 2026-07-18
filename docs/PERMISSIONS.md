# YUME permission model

YUME splits authentication from authorization the way SSH does:

- `authorized_keys` lists the Ed25519 public keys that may **connect**. Holding one of these is the audience-with-the-king; you get past the door.
- `auth_keys.meta` (a JSON file) lists what each connected key is **allowed to do** once inside. Without an entry here, a normally authorized key can use unprivileged transport features but cannot exec, cannot reach LAN addresses, cannot use privileged application codecs, and cannot administer other clients.

The current revision uses one Ed25519 key per identity. A second physical key (the "noble's seal" for stronger permission control) is a planned wire-protocol change for a post-1.1 release; in the meantime, the SSH-style split below gives you the same operational separation: connection rights vs. action rights live in different files, can be edited independently, and can be revoked independently.

## The three-layer gate for dangerous features

Any of these features (server-side command execution, LAN/private-IP bridging, unrestricted address bridging) is gated by **all three** of:

1. **Build switch.** `cmake -DYUME_FEATURE_EXEC=ON` (or `_LAN_BRIDGE`, `_FULL_CONTROL`). Stock builds ship with all three OFF. The runtime CLI flag still parses but logs a warning and stays disabled.
2. **Server flag.** `--allow-exec`, `--allow-local-ip`, `--control-full` (or the equivalent JSON config field). This is the global "feature is allowed on this server" upper bound.
3. **Per-key meta entry.** `"allow_exec": true` (or `"allow_local_ip"`, `"control_full"`) in `auth_keys.meta`. Default is deny. The server flag never grants permission to a key that does not opt in.

A request is allowed only when all three layers say yes. Removing the build switch is the cleanest way to make a server physically incapable of running shell commands for clients, regardless of any operator misconfiguration later.

## File layout

```
/etc/yume/
  authorized_keys           # one PEM-encoded public key per block; "who may connect"
  auth_keys.meta            # JSON mapping fingerprint → permissions; "what each may do"
```

A typical layout:

```text
$ cat /etc/yume/authorized_keys
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA...alice...
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA...bob...
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA...visitor...
-----END PUBLIC KEY-----
```

```jsonc
// /etc/yume/auth_keys.meta
{
  "0d4f3a...alice-fingerprint...": {
    "alias": "alice",
    "permissions": {
      "allow_exec": true,
      "allow_local_ip": true,
      "allow_codecs": ["monero-rpc"],
      "allow_services": ["example-service-v1"],
      "control_full": false,
      "allow_inbound_admin": true,
      "allow_outbound_admin": false,
      "allow_chat": true,
      "allow_file": true,
      "allow_bytes": true
    }
  },
  "9b21e8...bob-fingerprint...": {
    "alias": "bob",
    "permissions": {
      "allow_local_ip": true,
      "allow_chat": true,
      "allow_file": true
    }
  }
  // visitor key omitted (connects only, no extra permissions)
}
```

Generate fingerprints with `yumed --auth-keys /etc/yume/authorized_keys --keys-list`. Any field you omit defaults to the safe choice (deny for admin/exec/LAN; allow for the relay-side `chat` / `file` / `bytes` channels which never carry server-side actions).

## Permission fields

| Field | Default | What it grants | Server flag required |
| --- | --- | --- | --- |
| `allow_exec` | deny | Permit the EXEC control feature. The active runtime forwards the request to an opted-in client; yumed does not execute arbitrary shell commands locally. | `--allow-exec` and `YUME_FEATURE_EXEC=ON` |
| `allow_local_ip` | deny | Open TCP/UDP streams to RFC1918 / loopback addresses through the server | `--allow-local-ip` and `YUME_FEATURE_LAN_BRIDGE=ON` |
| `control_full` | deny | Open TCP/UDP streams to *any* address (superset of `allow_local_ip`) | `--control-full` and `YUME_FEATURE_FULL_CONTROL=ON` |
| `allow_codecs` | deny | Use named application codecs, for example `["monero-rpc"]` | `--codec-allow <name>` |
| `allow_services` | deny | Use native embed named-service streams, for example `["example-service-v1"]` | server config `allow_services` plus `yume_server_register_service` |
| `allow_monero_rpc` | deny | Compatibility alias for the built-in Monero RPC application codec against the server's loopback monerod backend | `--codec-allow monero-rpc` |
| `allow_inbound_admin` | deny | Other clients on this server can attach to admin THIS client | none (always honoured) |
| `allow_outbound_admin` | deny | This client can attach to admin OTHER clients on the server | none (always honoured) |
| `allow_chat` | allow | This key can use the chat relay | none |
| `allow_file` | allow | This key can use the file relay | none |
| `allow_bytes` | allow | This key can use the raw-bytes relay | none |

`alias` is a free-form label used in logs.

## Bridge / admin modes: the four quadrants

Two relationships are independent:

- **server-controls-client** (S → C): the server sends the client commands or open requests, and the client executes them.
- **client-controls-server** (C → S): the client opens streams through the server (SOCKS, port-forward, exec) or attaches to administer other clients.

| Mode | Server side | Client side | Use case |
| --- | --- | --- | --- |
| **S→C, C→S (full bridge)** | `--allow-exec` (with key `allow_exec`) plus directional admin policy as described below | `--server-in-charge` AND open SOCKS/forward | Operator's own laptop tunnelling through their own server, with the server able to dispatch opted-in control requests |
| **S→C only** | `--allow-exec` (with key `allow_exec`) | `--server-in-charge`, no `--socks`/`-L`/`-R` | Server dispatches control requests to an opted-in client; the client doesn't tunnel anything outbound |
| **C→S only** | normal flags, key `allow_local_ip` etc. as needed | `--socks` / `-L` / `-R` (no `--server-in-charge`) | Most common: user wants a SOCKS proxy / port forward, server cannot push requests back |
| **neither (pure transport)** | no `--allow-exec`, no `--control-full`, no `--allow-local-ip`; key has no per-key permissions | no `--server-in-charge`, no SOCKS | Probe / handshake test only; useful for smoke-testing the tunnel without exposing either side |

The implemented client flag is `--server-in-charge`; there is no `--accept-server-control` alias in this release.

An admin channel between relayed clients is admitted only when all of these are true:

1. the caller registered `relay_mode=trusted`;
2. the caller key's server-capped `allow_outbound_admin` policy and the caller's runtime opt-in are both true; and
3. the target key's server-capped `allow_inbound_admin` policy and the target's runtime opt-in are both true.

Modern `admin.attach` also requires the target to accept the signed invite. The legacy attach message is retained for compatibility but is no longer caller-blind: it applies the same caller/target predicate and additionally requires the target's `--server-in-charge` opt-in. In federation, the authenticated source server enforces the caller half and the target server rechecks the target half; the current wire format does not carry an independently verifiable caller-policy proof across servers.

## Pre-authenticated service-only tier

`preauth_services` is a deliberately narrower admission path for embedded named services. A peer with any valid self-signed Ed25519 key may enter it only when the server explicitly configures at least one preauth service. That peer is persisted as `PreauthServiceOnly`, not promoted to the normal authorized dispatcher.

The central post-auth gate permits only:

- `OPEN` for `proto=service.v1` when the requested service is in the configured preauth list and registered by the embedder;
- `DATA` and `CLOSE` on an already accepted named-service stream; and
- `PING` / `PONG` connection liveness frames.

Control, relay, admin, generic TCP/UDP opens, codecs, benchmark streams, packet egress, and every other frame family are rejected for this tier. Normal `allow_services` metadata still applies to keys admitted through `authorized_keys`; it does not broaden a preauth session.

## Operational tips

- **Editing auth_keys.meta is the recommended way to manage permissions.** The server's interactive `--ui` mode is brittle around per-key permissions; it's documented but you'll have a smoother time with a JSON editor.
- **Reload after edits.** The meta file is read at server startup. Changes take effect on `systemctl restart yumed`. Hot reload is on the post-1.1 roadmap.
- **Application codecs.** Codec permissions are intentionally narrower than `allow_local_ip`: they only enable named protocol-aware codecs listed in `allow_codecs`. The Monero built-in validates allowed wallet RPC paths/methods and reconstructs HTTP only to a loopback backend configured by `--monero-rpc-backend`.
- **Native service streams.** `allow_services` is for embedded C ABI users and is intentionally separate from `allow_local_ip`, `control_full`, `allow_codecs`, and exec. For a normally authorized key, a service stream opens only when the server config lists the service, the key metadata lists the same service, and the embedding process registered it with `yume_server_register_service`. The separately configured preauth tier follows the narrower rules above.
- **Revoke a key.** Remove the public-key block from `authorized_keys`. The meta entry can stay; it'll be ignored.
- **Audit.** Startup logs `auth policy <permissions summary>` for any key that has a non-empty meta entry. Run `yumed --auth-keys ... --keys-list` to dump all configured keys with their aliases.
- **CI/scripted setup.** Generate fingerprints with `openssl pkey -pubin -in user.pub -outform DER | sha256sum | cut -d' ' -f1`. The same fingerprint format is used by `yumed --keys-list`.

## Security posture summary

- A server built without `YUME_FEATURE_EXEC` cannot run user commands even if every other layer is misconfigured.
- A server built with `YUME_FEATURE_EXEC=ON` but without `--allow-exec` cannot run user commands.
- A server with `--allow-exec` but no `auth_keys.meta` entry granting `allow_exec` cannot run user commands.
- The same applies to LAN bridging and unrestricted bridging.
- Admin (inbound/outbound) defaults to deny and is checked directionally for both caller and target; chat/file/bytes default to allow.
- AUTH imports only Ed25519 public keys and verifies the challenge signature with OpenSSL before either normal or preauth admission.
