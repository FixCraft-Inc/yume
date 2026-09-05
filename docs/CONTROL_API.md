# YUME JSON control API

> **Transport-v2 surface:** this is the command-oriented facade contract used
> by the runnable 0.2 product and optional GUI. The experimental role-neutral
> YTP/1 ABI does not expose a JSON operation bus.

This document defines the JSON operation envelope used by local runtime IPC and
by the in-process embedder entry points `client::RuntimeController::request` and
`server::RuntimeController::request`. The replacement role-neutral ABI exposes
typed lifecycle calls instead of this JSON operation bus. This contract is
independent of transport v2 and of `YUME_ABI_VERSION`.

## Envelope and error layers

Every well-formed operation returns one JSON object:

```json
{"ok": true, "result": {}}
```

or:

```json
{"ok": false, "error": "human-readable reason"}
```

`result` may be an object, array, Boolean, or another operation-specific JSON
value. `error` is diagnostic text and must never be parsed to recover a status.

These C++ entry points accept a nonempty operation name and a JSON argument
object. Pass `{}` for no arguments. Local IPC receives one newline-delimited
JSON request with `op` and optional object `args`; received messages are capped
at 1 MiB. There is no generic C request function or response-sizing cache in
the current ABI.

The client controller reports IPC/connect/read/parse failures through its
`std::string* error` and returns an empty object. The embedded server controller
also exposes `runtime::OperationStatus`: invalid input, an unavailable runtime,
and an internal failure have distinct statuses. A handled operation returns
`Success` even when the envelope contains `ok=false`. Check the outer failure
channel before interpreting the envelope. The replacement ABI's typed lifecycle
and stream contract is documented separately in [ABI.md](ABI.md).

## Authority and deadlines

The client request entry point runs as the connected local client identity.
Its timeout configures socket send/receive timeouts after connecting; it is not
an overall operation deadline and does not cancel a queued or running handler.
An operation can complete a mutation after its caller stops waiting. A timeout
is therefore not a rollback result and callers must not blindly retry a
mutating operation.
Remote `admin.*` operations also have an independent internal 8-second
request deadline and depend on an authenticated admin relay channel plus
remote authorization.

The owner-only local IPC socket exposes its process's complete local operation
set. Socket filesystem permissions are therefore part of the authorization
boundary.

The embedded server request entry point does not require IPC, but deliberately
exposes only bounded read operations. It has no timeout parameter. Mutating
admin-socket operations such as `runtime.stop`, `runtime.disconnect`, session
killing, and rules reload return a handled `ok=false` envelope here. Use typed
lifecycle and facade methods for embedded mutations.

Embedded server startup rejects `anonym=true` with an invalid-argument result.
Operator-proof generation, refresh, and associated logging policy belong to
standalone `yumed`.

Embedded server stop preserves graceful drain when cancellation succeeds. If a
teardown step throws, the controller stops executor progress before joining its
workers and records the first failed stage in its status message. This
diagnostic is not a typed teardown result or a guarantee that all session work
settled gracefully; the embedding stop seam remains `void noexcept`.
Local IPC shutdown wakes the listener and keeps its descriptor open until the
serving thread has joined, preventing concurrent descriptor mutation or reuse.

## Client operations

Unless a row says otherwise, `{}` means exactly an empty object, listed string
fields are required and nonempty, and unknown fields are rejected. `text` and
`reason` may be empty strings. `peer` and `invite_selector` accept the same
exact-id-or-unambiguous-display-name selectors as the CLI.

| Operation | Args | Result |
| --- | --- | --- |
| `runtime.info`, `runtime.status` | `{}` | runtime/self/server/tunnel status object |
| `runtime.stop` | `{}` | `true` after local stop is requested |
| `directory.list` | `{}` | array of endpoint objects |
| `contacts.list` | `{}` | contact/presence document below |
| `contacts.forget` | exactly `{"endpoint_id": string}` | `{"removed": boolean}` |
| `history.list` | object containing only optional nonempty string `peer_id` and optional integer `limit` in `1..1000` (default `200`) | bounded history document below |
| `history.delete` | exactly one of `{"peer_id": nonempty string}` or `{"all": true}` | `true` after durable deletion/no-op |
| `invite.list` | `{}` | array of pending relay invites |
| `invite.accept` | `{"invite_selector": string}` plus optional one-of string `relay_secret`/`password` | `true` |
| `invite.reject` | `{"invite_selector": string}` plus optional string `reason` | `true` |
| `chat.open` | `{"peer": string}` plus optional one-of string `relay_secret`/`password` | `{"channel_id": string, "peer_id": string}` |
| `chat.send` | exactly `{"channel_id": string, "text": string}` | `true` |
| `chat.close` | exactly `{"channel_id": string}` | `true` |
| `file.send`, `bytes.send` | `{"peer": string, "path": string}` plus optional one-of string `relay_secret`/`password` | `true` once the outgoing invite is queued |
| `admin.attach` | exactly `{"peer": string}` | `true` after the request is sent |
| `admin.status` | `{}` | `{self, server_id, server_name, directory_size, pending_invites, active_channels}` from the administered peer |
| `admin.sessions` | `{}` | `{channels[], pending_invites[]}`, each channel `{stream_id, channel_id, channel_kind, peer_id, peer_name}` |
| `admin.stop` | `{}` | `{"stopping": true}` |

The three `admin.*` operations above are answered by the remote peer, so their
`result` is peer-controlled JSON and carries a second failure layer. A local
transport or internal remote-admin deadline failure gives `ok=false` as usual,
but an operation the remote peer does not implement returns `ok=true` with
`{"error": "unsupported op"}` inside `result`. Before use, require `result` to
be an object, check for an `error` member, and validate every required field and
element type against the shapes above. The outer C ABI caller deadline remains
a typed `YUME_STATUS_TIMEOUT`, not a JSON operation failure.

Operations that use a relay secret accept either `relay_secret` (the canonical
base64 encoding of a 32-byte derived secret) or `password` (which the local
runtime derives), never both members in one request. Either may be omitted when
the target operation does not require a password. Admin channels do not accept
a relay secret. Relay-secret/password inputs are sensitive even though the
response is not. Callers must minimize their lifetime and wipe mutable storage
after the call.

`contacts.list` returns durable trust even when live directory refresh fails:

```json
{
  "ok": true,
  "result": {
    "schema_version": 1,
    "directory_available": true,
    "directory_error": "",
    "contacts": [{
      "endpoint_id": "peer-id",
      "fingerprint": "composite-sha256",
      "trust_source": "tofu",
      "explicit_marker": false,
      "configured_mismatch": false,
      "in_directory": true,
      "online": true,
      "display_name": "Peer"
    }]
  }
}
```

`contacts.forget` removes only learned TOFU trust. Configured pins and durable
explicit authorization are refused rather than silently weakened.
Presence fields such as `online`, `display_name`, and the advertised relay
permissions are present only when `in_directory` is true.

`history.list` reports storage availability separately from an empty history:

```json
{
  "ok": true,
  "result": {
    "schema_version": 1,
    "available": true,
    "error": "",
    "truncated": false,
    "items": [{
      "ts_ms": 1780000000000,
      "peer_id": "peer-id",
      "peer_name": "Peer",
      "direction": "in",
      "text": "hello"
    }]
  }
}
```

Rows are ordered oldest-to-newest and contain at most `limit` items. A response
also retains at most 512 KiB of serialized record plaintext, and one operation
scans at most 64 MiB of protected history logs. The newest items are retained
and `truncated` is true when either the item or plaintext-response bound is hit.
Every current item contains the five required fields shown above: integer
`ts_ms` within the signed 64-bit range, nonempty string `peer_id`, string
`peer_name`, `direction` equal to `in` or `out`, and string `text`. The
protected on-disk record is a closed internal schema with exactly those five
fields. That storage rule does not close the public response schema: facade callers read the documented result fields and ignore additional fields.
Protection, I/O, protected-scan, directory-scan, or record-integrity failure
yields `available:false`, a nonempty diagnostic, and an empty `items` array; it
is never silently reported as empty history.

History persistence is deliberately best-effort: a protection or I/O failure
does not tear down an otherwise valid relay channel. Consequently `available`
describes readability when `history.list` runs; it is not an acknowledgement
that every earlier chat append reached durable storage. An entry whose
serialized plaintext would exceed the 512 KiB result budget is dropped before
the history key or log is created, so the store does not write a record that it
must refuse to list.

`history.delete {"all":true}` validates and bounds the complete directory scan
before unlinking anything. Separate directory entries cannot be removed as one
filesystem transaction, however, so an unlink or directory-sync failure can
return `ok:false` after an earlier entry was removed. After such a failure,
callers should re-list before deciding whether to retry.

`runtime.info` and `runtime.status` return the same client object. Its
required fields are `self` (endpoint object), string `server_id` and
`server_name`, non-negative integer `directory_size`,
`pending_invites`, `active_channels`, `requested_tunnels`,
`authenticated_tunnels`, `live_tunnels`, `tunnel_sessions`,
`bytes_in`, and `bytes_out`. `active_chat_stream`,
`active_chat`, `active_admin_stream`, and `latest_lifecycle` are
present only when applicable.

Endpoint objects returned by `self` and `directory.list` always contain
string `endpoint_id`, `endpoint_kind`, `display_name`, `hostname`,
`client_platform`, `client_variant`, `client_version`,
`server_id`, and `relay_mode`; Boolean `allow_inbound_admin`,
`allow_outbound_admin`, `allow_chat`, `allow_file`,
`allow_bytes`, and `online`; and string arrays `controller_ids` and
`controlled_target_ids`. `server_name` and `auth_pubkey_b64` are
optional. A direct-federation row also has `remote:true` plus string
`federation_peer_id` and `remote_endpoint_id`.

`invite.list` rows always contain integer `relay_protocol_version` and
`created_ms`; string `invite_id`, `from_id`, `to_id`,
`channel_kind`, `metadata_json`, `handshake_request_b64`, and
`from_display_name`; and Boolean `requires_password` and `accepted`.
Identity/response fields are present only when supplied by that invite.

## Embedded-server read operations

The embedded server read allowlist is:

| Operation | Args | Result |
| --- | --- | --- |
| `runtime.info`, `runtime.status` | `{}` | server identity/configuration and endpoint-status snapshot |
| `runtime.sessions` | `{}` | active relay-channel rows |
| `runtime.events` | optional `{"limit": integer in 0..512}` (default `200`) | oldest-to-newest recent lifecycle-event rows |
| `directory.list` | `{}` | local and directly federated endpoint rows |
| `federation.status` | `{}` | redacted configuration/link document |
| `federation.topology` | `{}` | single-hop topology document |

Unknown arguments are rejected. The owner-only server IPC socket also
exposes these mutations. None is available through the embedded server read
entry point:

| Operation | Exact args | Result |
| --- | --- | --- |
| `runtime.stop` | `{}` | `true` only after a stop callback accepts the request |
| `runtime.disconnect` | `{"endpoint_id": nonempty string}` | `true` |
| `runtime.sessions.kill` | exactly one nonempty string member: `session_id`, `endpoint_id`, or `ip` | `true` |
| `runtime.rules.reload` | `{}` | `true` |

Selectors are typed: a `session_id` value is compared only with the canonical
decimal session id, an `endpoint_id` only with the exact endpoint id, and
`ip` only with the client address. Coincidentally equal text in another
field is not a match.

`runtime.info` and `runtime.status` return the same server object. Its required
fields are string `server_id` and `server_name`; integer `listen_port`;
Boolean `relay_enable` and `directory_enable`; non-negative integer
`endpoints` and `channels`; object `host`; and array `endpoint_statuses`.
Each endpoint-status row contains an `endpoint` object in the shape documented
above and an optional `latest_lifecycle` object.

`runtime.sessions` rows require string `channel_id`, `channel_kind`,
`left_endpoint_id`, and `right_endpoint_id`; non-negative integer
`left_stream_id` and `right_stream_id`; Boolean `e2ee_required`, `pending`, and
`federated`; and integer `route_hops`.

`runtime.events` rows require string `endpoint_id`, `display_name`, `state`,
`message`, `detail`, `client_platform`, `client_variant`, `client_version`,
`effective_protection`, `exit_ip`, and `error_code`; Boolean
`traffic_verified`; and integer `server_time_ms`.

Both federation documents currently carry `schema_version: 1`.
`federation.status` never returns raw peer JSON, PSK paths, carrier-secret
paths, or secret contents. Each peer row includes `peer_id`, redacted dial
configuration/presence flags, overall `state`/`ready`, separate
`outbound_state`/`outbound_ready`, `inbound_connections`,
`last_handshake_ms` as a Unix-epoch millisecond count (`0` before the first
handshake), and the canonical active-channel count. `last_error` is a maximum
of 512 printable ASCII bytes; configured federation key/CA/peer-secret paths
are replaced with `[redacted-path]`, and control or non-ASCII bytes are
replaced with `?`.
Configured peers remain visible as `not-started` rows even when federation
itself is disabled. An authenticated, hello-complete inbound-only peer appears
with `configuration:null`, `ready:true`,
`outbound_ready:false`, and `inbound_connections` greater than zero.
Entries that cannot be represented as a unique accepted peer are counted only
by `invalid_peer_entries`, because the raw text may contain secret paths.

The exact federation status shape is:

| Location | Required fields and types |
| --- | --- |
| top level | `schema_version` integer `1`; `enabled` Boolean; `self` object; `invalid_peer_entries` non-negative integer; `peers` array |
| `self` | string `server_id`/`server_name`; integer `listen_port`; non-negative integer `local_endpoints`; Boolean `federation_enabled` |
| peer row | string `peer_id`, `state`, `outbound_state`, `last_error`; Boolean `ready`/`outbound_ready`; non-negative integer `inbound_connections`/`channels_active`; integer `last_handshake_ms`; nullable `configuration` |
| peer `configuration` | string `host`; integer `port`; Boolean `tls_pin_present`, `psk_present`, `carrier_secret_present` |

`federation.topology` contains:

- `self`: reporting server identity, port, local endpoint count, and enablement;
- `nodes`: directly configured/observed peers with link state, redacted
  configuration, endpoint counts, `route`, and `hops`;
- `edges`: the reporting node's direct federation links;
- `channels`: active relay-channel metadata;
- `transit`: currently `{ "supported": false, "max_hops": 1 }`.

Topology repeats the exact `self` and peer link fields above. Each node also
requires non-negative integer `endpoints`, string-array `route`, and
integer `hops` (currently `1`). Each edge requires string `from`,
`to`, `kind`, and `state`; Boolean `ready` and
`outbound_ready`; and non-negative integer `inbound_connections`.
Each channel requires string `channel_id`, `channel_kind`,
`left_endpoint_id`, and `right_endpoint_id`; Boolean `federated`
and `pending`; and integer `route_hops`. Peer-derived node and edge
arrays are ordered by `peer_id`; consumers must still not depend on JSON
object key order.

No field implies multi-hop forwarding. The design that could change this is
explicitly unimplemented in
[`protocol/YUME_2_0_FEDERATION_TRANSIT.md`](protocol/YUME_2_0_FEDERATION_TRANSIT.md).

## Interface changes

This JSON facade is a development interface, separate from the C ABI in
[ABI.md](ABI.md). Update its callers and tests with any changed operation or
field. Do not add fallback requests for an earlier development shape.

The current operations use `invite_selector` for invite acceptance/rejection,
require `{"all":true}` to delete all history, return the bounded `history.list`
document, and report federation timestamps as `last_handshake_ms`.
Callers should read the documented result fields and ignore JSON object order.
