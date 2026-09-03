# YTP/1 foundation diagnostics

Diagnostics are typed and scoped to the object that failed. They are not a
second configuration or control channel.

## Operator diagnostics

Run:

```bash
yume-doctor-ytp1 --config /path/to/yume.json
```

The experimental schema-1 doctor reports the first configuration JSON pointer or credential path that
fails validation. It rechecks file identity, size, timestamps, permissions,
and bounds around reads so a changed or replaced secret fails closed. It never
prints private key, PSK, admission, or exporter bytes. It does not validate a
kit for the current transport-v2 `yume` or `yumed` binaries; their diagnostic
reference is preserved in the
[0.2 documentation](https://github.com/FixCraft-Inc/yume/tree/f0cc9e7/docs/DIAGNOSTICS.md).

## C ABI diagnostics

Every ABI operation returns a stable `yume_status`. Use
`yume_get_status_info()` for its name and retry classification. Use
`yume_handle_get_diagnostic()` on a runtime, config, endpoint, stream, or
packet handle for bounded explanatory text and the relevant JSON pointer.
Never parse diagnostic prose to recover a status code.

Callbacks receive borrowed records valid only during the call. The only ABI
handle operation permitted during a callback is diagnostic lookup; lifecycle
and I/O re-entry fail with `YUME_STATUS_INVALID_STATE`, and void destroy calls
are ignored. Do not log callback payloads that may contain peer identifiers or
application metadata unless the embedding application's policy permits it.

## Evidence diagnostics

Transport-profile captures, NetLogs, browser profiles, sanitizer logs, fuzz
crashes, and benchmark traces are evidence artifacts, not ordinary logs. Store
them only in approved ignored/private locations, redact secrets, record exact
tool and profile versions, and keep immutable hashes with candidate results.

Production timing and metrics must be bounded, disabled unless configured, and
must not expose plaintext, keys, nonces, AUTH messages, identity-to-PSK mappings,
secret paths, or full peer-controlled strings.
