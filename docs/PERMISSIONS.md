# YUME permission model

YUME splits authentication from authorization the way SSH does:

- `authorized_keys` lists the Ed25519 public keys that may **connect**. Holding one of these is the audience-with-the-king; you get past the door.
- `auth_keys.meta` (a JSON file) lists what each connected key is **allowed to do** once inside. Without an entry here, a key can talk to the server but cannot exec, cannot reach LAN addresses, cannot administer other clients.

The current revision uses one Ed25519 key per identity. A second physical key (the "noble's seal" for stronger permission control) is a planned wire-protocol change for a post-1.0 release; in the meantime, the SSH-style split below gives you the same operational separation: connection rights vs. action rights live in different files, can be edited independently, and can be revoked independently.

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
| `allow_exec` | deny | Run shell commands on the server (server-issued via control channel) | `--allow-exec` and `YUME_FEATURE_EXEC=ON` |
| `allow_local_ip` | deny | Open TCP/UDP streams to RFC1918 / loopback addresses through the server | `--allow-local-ip` and `YUME_FEATURE_LAN_BRIDGE=ON` |
| `control_full` | deny | Open TCP/UDP streams to *any* address (superset of `allow_local_ip`) | `--control-full` and `YUME_FEATURE_FULL_CONTROL=ON` |
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
| **S→C, C→S (full bridge)** | `--allow-exec` (with key `allow_exec` and `allow_inbound_admin`) | `--accept-server-control` AND open SOCKS/forward | Operator's own laptop tunnelling through their own server, with the server able to dispatch local commands |
| **S→C only** | `--allow-exec` (with key `allow_exec`) | `--accept-server-control`, no `--socks`/`-L`/`-R` | Server sends remote-admin commands to a client; the client doesn't tunnel anything outbound |
| **C→S only** | normal flags, key `allow_local_ip` etc. as needed | `--socks` / `-L` / `-R` (no `--accept-server-control`) | Most common: user wants a SOCKS proxy / port forward, server cannot push commands back |
| **neither (pure transport)** | no `--allow-exec`, no `--control-full`, no `--allow-local-ip`; key has no per-key permissions | no `--accept-server-control`, no SOCKS | Probe / handshake test only; useful for smoke-testing the tunnel without exposing either side |

`--accept-server-control` is the new, intuitive name for what was previously `--server-in-charge` (the old name still works as a deprecated alias). The "admin attach" channel between two relayed clients is governed independently by `allow_inbound_admin` / `allow_outbound_admin` on the per-key meta. Neither of these ever defaults to true.

## Operational tips

- **Editing auth_keys.meta is the recommended way to manage permissions.** The server's interactive `--ui` mode is brittle around per-key permissions; it's documented but you'll have a smoother time with a JSON editor.
- **Reload after edits.** The meta file is read at server startup. Changes take effect on `systemctl restart yumed`. Hot reload is on the post-1.0 roadmap.
- **Revoke a key.** Remove the public-key block from `authorized_keys`. The meta entry can stay; it'll be ignored.
- **Audit.** Startup logs `auth policy <permissions summary>` for any key that has a non-empty meta entry. Run `yumed --auth-keys ... --keys-list` to dump all configured keys with their aliases.
- **CI/scripted setup.** Generate fingerprints with `openssl pkey -pubin -in user.pub -outform DER | sha256sum | cut -d' ' -f1`. The same fingerprint format is used by `yumed --keys-list`.

## Security posture summary

- A server built without `YUME_FEATURE_EXEC` cannot run user commands even if every other layer is misconfigured.
- A server built with `YUME_FEATURE_EXEC=ON` but without `--allow-exec` cannot run user commands.
- A server with `--allow-exec` but no `auth_keys.meta` entry granting `allow_exec` cannot run user commands.
- The same applies to LAN bridging and unrestricted bridging.
- Admin (inbound/outbound) defaults to deny; chat/file/bytes default to allow.
- All key signatures are verified with constant-time `EVP_DigestVerify`. The `auth_keys` file is loaded once at startup; the `auth_keys.meta` file is parsed once at startup.
